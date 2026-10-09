//! Server I/O adapter. Certificate issuance belongs to the operator.
use std::{
    net::{SocketAddr, TcpListener},
    path::Path,
    time::Duration,
};

use axum::Router;
use axum_server::{
    Handle,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use hyper_util::rt::TokioTimer;
use thiserror::Error;
use tokio::io::AsyncReadExt;

use crate::config::{ServerConfig, TlsFiles};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_RELOAD_TIMEOUT: Duration = Duration::from_secs(5);
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("TLS certificate or key is unreadable or invalid")]
    TlsConfiguration,
    #[error("HTTP listener failed")]
    Listener,
    #[error("process signal handler failed")]
    Signal,
}

async fn read_pem(path: &Path, max_bytes: u64) -> Result<Vec<u8>, TransportError> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| TransportError::TlsConfiguration)?;
    if !file
        .metadata()
        .await
        .map_err(|_| TransportError::TlsConfiguration)?
        .is_file()
    {
        return Err(TransportError::TlsConfiguration);
    }
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| TransportError::TlsConfiguration)?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(TransportError::TlsConfiguration);
    }
    Ok(bytes)
}

pub async fn load_tls(files: &TlsFiles) -> Result<RustlsConfig, TransportError> {
    // Exactly one reviewed crypto provider; SQLx uses the same rustls/ring stack.
    let _ = rustls::crypto::ring::default_provider().install_default();
    tokio::time::timeout(TLS_RELOAD_TIMEOUT, async {
        let cert = read_pem(&files.certificate, 256 * 1024).await?;
        let key = read_pem(&files.private_key, 16 * 1024).await?;
        RustlsConfig::from_pem(cert, key)
            .await
            .map_err(|_| TransportError::TlsConfiguration)
    })
    .await
    .map_err(|_| TransportError::TlsConfiguration)?
}

pub async fn reload_tls(current: &RustlsConfig, files: &TlsFiles) -> Result<(), TransportError> {
    // Publish only a complete, parsed, matching pair. Failed reloads keep the old pair.
    let replacement = load_tls(files).await?;
    current.reload_from_config(replacement.get_inner());
    Ok(())
}

fn configure_http<A>(server: &mut axum_server::Server<SocketAddr, A>) {
    server
        .http_builder()
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_headers(64)
        .max_buf_size(32 * 1024);
    server
        .http_builder()
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(64)
        .max_header_list_size(16 * 1024)
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(10));
}

pub async fn serve_listener(
    listener: TcpListener,
    app: Router,
    tls: Option<RustlsConfig>,
    handle: Handle<SocketAddr>,
) -> Result<(), TransportError> {
    listener
        .set_nonblocking(true)
        .map_err(|_| TransportError::Listener)?;
    let mut server = axum_server::from_tcp(listener)
        .map_err(|_| TransportError::Listener)?
        .handle(handle);
    configure_http(&mut server);
    match tls {
        Some(tls) => {
            server
                .acceptor(RustlsAcceptor::new(tls).handshake_timeout(TLS_HANDSHAKE_TIMEOUT))
                .serve(app.into_make_service())
                .await
        }
        None => server.serve(app.into_make_service()).await,
    }
    .map_err(|_| TransportError::Listener)
}

pub async fn serve(config: &ServerConfig, app: Router) -> Result<(), TransportError> {
    let tls = match &config.tls {
        Some(files) => Some(load_tls(files).await?),
        None => None,
    };
    let listener = TcpListener::bind(config.addr).map_err(|_| TransportError::Listener)?;
    let address = listener
        .local_addr()
        .map_err(|_| TransportError::Listener)?;
    let handle = Handle::new();
    // Register Unix signals before serving; early SIGTERM never skips graceful drain.
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| TransportError::Signal)?;
    #[cfg(unix)]
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .map_err(|_| TransportError::Signal)?;
    let control = async {
        loop {
            #[cfg(unix)]
            let terminate_signal = terminate.recv();
            #[cfg(not(unix))]
            let terminate_signal = std::future::pending::<Option<()>>();
            #[cfg(unix)]
            let reload_signal = hangup.recv();
            #[cfg(not(unix))]
            let reload_signal = std::future::pending::<Option<()>>();
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    result.map_err(|_| TransportError::Signal)?;
                    break;
                },
                _ = terminate_signal => break,
                _ = reload_signal => {
                    if let (Some(tls), Some(files)) = (&tls, &config.tls) {
                        match reload_tls(tls, files).await {
                            Ok(()) => tracing::info!(event.name = "tls.reload.completed", outcome = "ok"),
                            Err(_) => tracing::error!(event.name = "tls.reload.failed", error.type = "tls_configuration", outcome = "error"),
                        }
                    }
                }
            }
        }
        Ok::<(), TransportError>(())
    };
    tracing::info!(event.name = "server.started", address = %address, transport = if tls.is_some() { "https" } else { "http" }, outcome = "ok");
    let server = serve_listener(listener, app, tls.clone(), handle.clone());
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result,
        control_result = control => {
            tracing::info!(event.name = "server.shutdown.started", deadline_seconds = SHUTDOWN_TIMEOUT.as_secs());
            handle.graceful_shutdown(Some(SHUTDOWN_TIMEOUT));
            let result = server.await;
            tracing::info!(event.name = "server.shutdown.completed", outcome = if result.is_ok() { "ok" } else { "error" });
            control_result.and(result)
        }
    }
}
