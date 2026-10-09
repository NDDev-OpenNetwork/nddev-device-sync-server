use super::{
    config::{SmtpConfig, SmtpTls},
    store::Store,
};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};
use nddev_device_sync_application::identity::{
    EmailDelivery, EmailMessage, IdentityError, IdentityStore, Locale,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;
use tracing::Instrument;

const QUEUE_CAPACITY: usize = 16;
struct Job {
    message: EmailMessage,
    span: tracing::Span,
}
struct Inner {
    sender: mpsc::Sender<Job>,
    ready: Arc<AtomicBool>,
    last_probe: Arc<AtomicU64>,
    busy: Arc<AtomicBool>,
    worker: tokio::task::JoinHandle<()>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.worker.abort();
        let dropped = QUEUE_CAPACITY - self.sender.capacity()
            + usize::from(self.busy.load(Ordering::Relaxed));
        tracing::info!(
            event.name = "email.delivery.stopped",
            dropped_count = dropped,
            outcome = "stopped"
        );
    }
}
#[derive(Clone, Default)]
pub struct Mailer(Option<Arc<Inner>>);

async fn probe(transport: &AsyncSmtpTransport<Tokio1Executor>) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(5), transport.test_connection()).await,
        Ok(Ok(true))
    )
}

impl Mailer {
    pub async fn new(config: Option<&SmtpConfig>, store: Store) -> Result<Self, IdentityError> {
        let Some(config) = config else {
            return Ok(Self::default());
        };
        let builder = match config.tls {
            SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                .map_err(|_| IdentityError::InvalidInput)?,
            SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .map_err(|_| IdentityError::InvalidInput)?,
            SmtpTls::Loopback => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
            }
        }
        .port(config.port)
        .timeout(Some(Duration::from_secs(5)));
        let builder = match (&config.username, &config.password) {
            (Some(user), Some(password)) => {
                builder.credentials(Credentials::new(user.clone(), password.expose().into()))
            }
            _ => builder,
        };
        let transport = builder.build();
        let from = Mailbox::new(
            Some("NDDev OpenNetwork".into()),
            config
                .from
                .as_str()
                .parse()
                .map_err(|_| IdentityError::InvalidInput)?,
        );
        let ready = Arc::new(AtomicBool::new(probe(&transport).await));
        tracing::info!(
            event.name = "email.transport.checked",
            available = ready.load(Ordering::Relaxed),
            outcome = "checked"
        );
        let worker_ready = ready.clone();
        let last_probe = Arc::new(AtomicU64::new(super::now_ms()?));
        let worker_time = last_probe.clone();
        let busy = Arc::new(AtomicBool::new(false));
        let worker_busy = busy.clone();
        let (sender, mut receiver) = mpsc::channel::<Job>(QUEUE_CAPACITY);
        let worker = tokio::spawn(async move {
            let refresh = tokio::time::sleep(Duration::from_secs(60));
            tokio::pin!(refresh);
            let mut backoff_seconds = 60;
            let mut failed_probes = 0_u32;
            loop {
                tokio::select! {
                    _=&mut refresh=>{
                        let available=probe(&transport).await;
                        worker_time.store(super::now_ms().unwrap_or(0),Ordering::Relaxed);
                        let previous=worker_ready.swap(available,Ordering::Relaxed);
                        if previous!=available { tracing::info!(event.name="email.transport.changed", available, outcome=if available {"ready"} else {"unavailable"}); }
                        if available {backoff_seconds=60;failed_probes=0;} else {
                            backoff_seconds=(backoff_seconds*2).min(300);failed_probes=failed_probes.saturating_add(1);
                            tracing::warn!(event.name="email.transport.unavailable",retry_count=failed_probes,backoff_seconds,outcome="unavailable");
                        }
                        refresh.as_mut().reset(tokio::time::Instant::now()+Duration::from_secs(backoff_seconds));
                    },
                    job=receiver.recv()=>{
                        let Some(job)=job else { break; };
                        worker_busy.store(true,Ordering::Relaxed);
                        async {
                            let message=job.message;
                            let delivery=async {
                                if super::now_ms()? >= message.expires_at_ms { return Err(IdentityError::Denied); }
                                let recipient=message.recipient.as_str().parse().map_err(|_|IdentityError::InvalidInput)?;
                                let (subject, body) = match message.locale {
                                    Locale::En => ("NDDev OpenNetwork sign-in code", format!("NDDev OpenNetwork\n\nYour sign-in code: {}\n\nThis code expires five minutes after your request. Do not share it. If you did not request sign-in, ignore this message.\n\nhttps://nddev.ai\n", message.code.expose())),
                                    Locale::Ru => ("Код входа в NDDev OpenNetwork", format!("NDDev OpenNetwork\n\nВаш код входа: {}\n\nКод действует пять минут с момента запроса. Никому его не сообщайте. Если вы не запрашивали вход, проигнорируйте это письмо.\n\nhttps://nddev.ai\n", message.code.expose())),
                                };
                                let email=Message::builder().from(from.clone()).to(Mailbox::new(None,recipient)).subject(subject).header(ContentType::TEXT_PLAIN).body(body).map_err(|_|IdentityError::InvalidInput)?;
                                transport.send(email).await.map_err(|_|IdentityError::Unavailable)?;
                                Ok::<(),IdentityError>(())
                            };
                            let result=tokio::time::timeout(Duration::from_secs(8),delivery).await.unwrap_or(Err(IdentityError::Unavailable));
                            match result {
                                Ok(()) => { worker_ready.store(true,Ordering::Relaxed); worker_time.store(super::now_ms().unwrap_or(0),Ordering::Relaxed); tracing::info!(event.name="email.delivery.accepted", outcome="provider_accepted", mailbox_delivery="unverified"); },
                                Err(error) => {
                                    if error==IdentityError::Unavailable { worker_ready.store(false,Ordering::Relaxed); }
                                    let invalidated=store.invalidate_email(&message.challenge_id).await.is_ok();
                                    tracing::error!(event.name="email.delivery.failed", error.type=%error, challenge_invalidated=invalidated, outcome="error");
                                }
                            }
                        }.instrument(job.span).await;
                        worker_busy.store(false,Ordering::Relaxed);
                    }
                }
            }
        });
        Ok(Self(Some(Arc::new(Inner {
            sender,
            ready,
            last_probe,
            busy,
            worker,
        }))))
    }
}
impl EmailDelivery for Mailer {
    fn available(&self) -> bool {
        self.0.as_ref().is_some_and(|inner| {
            inner.ready.load(Ordering::Relaxed)
                && super::now_ms().is_ok_and(|now| {
                    now.saturating_sub(inner.last_probe.load(Ordering::Relaxed)) <= 120_000
                })
        })
    }
    fn queue(&self, message: EmailMessage) -> Result<(), IdentityError> {
        let inner = self.0.as_ref().ok_or(IdentityError::Unavailable)?;
        inner
            .sender
            .try_send(Job {
                message,
                span: tracing::Span::current(),
            })
            .map_err(|_| {
                tracing::warn!(
                    event.name = "email.delivery.queue_rejected",
                    outcome = "rejected"
                );
                IdentityError::Capacity
            })
    }
}
