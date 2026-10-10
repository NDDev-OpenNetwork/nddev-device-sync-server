use super::config::GithubConfig;
use nddev_device_sync_application::identity::{GithubIdentity, IdentityError, SecretText};
use reqwest::{Client, Response, Url};
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

struct Inner {
    config: GithubConfig,
    client: Client,
    ready: Arc<AtomicBool>,
    last_probe: Arc<AtomicU64>,
    rejected_credentials: AtomicBool,
    probe: tokio::task::JoinHandle<()>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.probe.abort();
    }
}
#[derive(Default)]
pub struct Github(Option<Inner>);

async fn probe(client: &Client) -> bool {
    matches!(client.get("https://api.github.com/").send().await,Ok(response) if response.status().is_success())
}

async fn limited_json<T: DeserializeOwned>(mut response: Response) -> Result<T, IdentityError> {
    if response
        .content_length()
        .is_some_and(|length| length > 16 * 1024)
    {
        return Err(IdentityError::Unavailable);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| IdentityError::Unavailable)?
    {
        if bytes.len() + chunk.len() > 16 * 1024 {
            return Err(IdentityError::Unavailable);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| IdentityError::Unavailable)
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    error: Option<String>,
}
#[derive(Deserialize)]
struct UserResponse {
    id: u64,
}

impl Github {
    pub async fn new(config: Option<&GithubConfig>) -> Result<Self, IdentityError> {
        let Some(config) = config else {
            return Ok(Self::default());
        };
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(1)
            .user_agent("NDDev-OpenNetwork/nddev-device-sync-server")
            .build()
            .map_err(|_| IdentityError::Unavailable)?;
        let ready = Arc::new(AtomicBool::new(probe(&client).await));
        let last_probe = Arc::new(AtomicU64::new(super::now_ms()?));
        tracing::info!(
            module = "identity",
            scope = "http",
            event.name = "github.provider.checked",
            available = ready.load(Ordering::Relaxed),
            credentials_verified = false,
            outcome = "checked"
        );
        let worker_ready = ready.clone();
        let worker_time = last_probe.clone();
        let worker_client = client.clone();
        let probe = tokio::spawn(async move {
            let mut backoff_seconds = 60;
            let mut failed_probes = 0_u32;
            loop {
                tokio::time::sleep(Duration::from_secs(backoff_seconds)).await;
                let available = probe(&worker_client).await;
                worker_time.store(super::now_ms().unwrap_or(0), Ordering::Relaxed);
                if worker_ready.swap(available, Ordering::Relaxed) != available {
                    tracing::info!(
                        module = "identity",
                        scope = "http",
                        event.name = "github.provider.changed",
                        available,
                        outcome = if available { "ready" } else { "unavailable" }
                    );
                }
                if available {
                    backoff_seconds = 60;
                    failed_probes = 0;
                } else {
                    backoff_seconds = (backoff_seconds * 2).min(300);
                    failed_probes = failed_probes.saturating_add(1);
                    tracing::warn!(
                        module = "identity",
                        scope = "http",
                        event.name = "github.provider.unavailable",
                        retry_count = failed_probes,
                        backoff_seconds,
                        outcome = "unavailable"
                    );
                }
            }
        });
        Ok(Self(Some(Inner {
            config: config.clone(),
            client,
            ready,
            last_probe,
            rejected_credentials: AtomicBool::new(false),
            probe,
        })))
    }
}

impl GithubIdentity for Github {
    fn available(&self) -> bool {
        self.0.as_ref().is_some_and(|inner| {
            inner.ready.load(Ordering::Relaxed)
                && !inner.rejected_credentials.load(Ordering::Relaxed)
                && super::now_ms().is_ok_and(|now| {
                    now.saturating_sub(inner.last_probe.load(Ordering::Relaxed)) <= 120_000
                })
        })
    }
    fn authorization_url(
        &self,
        state: &SecretText,
        challenge: &str,
    ) -> Result<String, IdentityError> {
        let inner = self.0.as_ref().ok_or(IdentityError::Unavailable)?;
        let mut url = Url::parse("https://github.com/login/oauth/authorize")
            .map_err(|_| IdentityError::Unavailable)?;
        url.query_pairs_mut().extend_pairs([
            ("client_id", inner.config.client_id.as_str()),
            ("redirect_uri", inner.config.callback.as_str()),
            ("scope", "read:user"),
            ("state", state.expose()),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("allow_signup", "false"),
        ]);
        Ok(url.into())
    }
    async fn identify(
        &self,
        code: &SecretText,
        verifier: &SecretText,
    ) -> Result<u64, IdentityError> {
        let inner = self.0.as_ref().ok_or(IdentityError::Unavailable)?;
        let work = async {
            let response = inner
                .client
                .post("https://github.com/login/oauth/access_token")
                .header("Accept", "application/json")
                .form(&[
                    ("client_id", inner.config.client_id.as_str()),
                    ("client_secret", inner.config.client_secret.expose()),
                    ("code", code.expose()),
                    ("code_verifier", verifier.expose()),
                    ("redirect_uri", inner.config.callback.as_str()),
                ])
                .send()
                .await
                .map_err(|_| IdentityError::Unavailable)?;
            if !response.status().is_success() {
                return Err(IdentityError::Unavailable);
            }
            let token: TokenResponse = limited_json(response).await?;
            if let Some(error) = token.error {
                if matches!(
                    error.as_str(),
                    "incorrect_client_credentials" | "redirect_uri_mismatch"
                ) {
                    inner.rejected_credentials.store(true, Ordering::Relaxed);
                    return Err(IdentityError::Unavailable);
                }
                return Err(IdentityError::Denied);
            }
            if !token
                .token_type
                .as_deref()
                .is_some_and(|kind| kind.eq_ignore_ascii_case("bearer"))
            {
                return Err(IdentityError::Denied);
            }
            let token = token.access_token.ok_or(IdentityError::Denied)?;
            if token.is_empty()
                || token.len() > 4096
                || !token.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(IdentityError::Denied);
            }
            let response = inner
                .client
                .get("https://api.github.com/user")
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2026-03-10")
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|_| IdentityError::Unavailable)?;
            if !response.status().is_success() {
                return Err(if response.status().as_u16() == 401 {
                    IdentityError::Denied
                } else {
                    IdentityError::Unavailable
                });
            }
            let user: UserResponse = limited_json(response).await?;
            if user.id == 0 {
                return Err(IdentityError::Denied);
            }
            // The access token is deliberately dropped after this one identity read.
            Ok(user.id)
        };
        let result = tokio::time::timeout(Duration::from_secs(5), work)
            .await
            .unwrap_or(Err(IdentityError::Unavailable));
        if result == Err(IdentityError::Unavailable) {
            inner.ready.store(false, Ordering::Relaxed);
        }
        result
    }
}
