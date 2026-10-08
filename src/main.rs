use nddev_device_sync_server::{AppState, config::ServerConfig, init_logging, router};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let config = ServerConfig::from_env()?;
    let listener = TcpListener::bind(config.addr).await?;
    let address = listener.local_addr()?;
    let state = AppState::from_config(config).await?;
    tracing::info!(event = "server.start", address = %address, service = "nddev-device-sync-server");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!(event = "server.shutdown");
}
