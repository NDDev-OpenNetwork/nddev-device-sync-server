use std::process::ExitCode;

use nddev_device_sync_server::{
    AppState,
    config::{ServerConfig, migration_database_url},
    database, init_logging, router, transport,
};

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Adapter errors expose stable classes, never driver messages, paths or URLs.
            tracing::error!(event.name = "process.failed", error.type = %error, outcome = "error");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["serve"] => {
            let config = ServerConfig::from_env()?;
            let state = AppState::from_config(config.clone()).await?;
            transport::serve(&config, router(state)).await?;
        }
        ["migrate"] => database::migrate(&migration_database_url()?).await?,
        ["--help"] | ["help"] => println!(
            "Usage: nddev-device-sync-server [serve|migrate]\nTLS: NDS_TLS_CERT_FILE + NDS_TLS_KEY_FILE\nRuntime: DATABASE_URL or DATABASE_URL_FILE\nMigration: NDS_MIGRATION_DATABASE_URL or NDS_MIGRATION_DATABASE_URL_FILE"
        ),
        _ => return Err("invalid command; use --help".into()),
    }
    Ok(())
}
