use std::process::ExitCode;

use nddev_device_sync_server::{
    AppState,
    config::{ServerConfig, migration_database_url},
    database,
    logging::init_logging,
    router, transport,
};

#[tokio::main]
async fn main() -> ExitCode {
    let logging = match init_logging() {
        Ok(guard) => guard,
        Err(error) => {
            tracing::error!(event.name = "process.failed", module = "process", error.type = %error, outcome = "error");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = logging.validate() {
        tracing::error!(event.name = "process.failed", module = "process", error.type = %error, outcome = "error");
        return ExitCode::FAILURE;
    }
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Adapter errors expose stable classes, never driver messages, paths or URLs.
            tracing::error!(event.name = "process.failed", module = "process", error.type = process_error_class(error.as_ref()), outcome = "error");
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

fn process_error_class(error: &(dyn std::error::Error + 'static)) -> &'static str {
    use nddev_device_sync_server::{
        config::ConfigError, database::DatabaseError, transport::TransportError,
    };
    if let Some(error) = error.downcast_ref::<ConfigError>() {
        return match error {
            ConfigError::Address => "configuration_address",
            ConfigError::TlsPair => "configuration_tls_pair",
            ConfigError::ConflictingSecret => "configuration_secret_conflict",
            ConfigError::SecretFile => "configuration_secret_file",
            ConfigError::SecretValue => "configuration_secret_value",
            ConfigError::MigrationDatabaseMissing => "configuration_migration_database_missing",
            ConfigError::AdmissionLimit => "configuration_admission_limit",
            ConfigError::Identity => "configuration_identity",
            ConfigError::IdentityHttpsRequired => "configuration_identity_https_required",
        };
    }
    if let Some(error) = error.downcast_ref::<DatabaseError>() {
        return match error {
            DatabaseError::Connection => "database_connection",
            DatabaseError::RuntimeRole => "database_runtime_role",
            DatabaseError::Migration => "database_migration",
            DatabaseError::MigrationTimeout => "database_migration_timeout",
            DatabaseError::Identity => "database_identity",
        };
    }
    if let Some(error) = error.downcast_ref::<TransportError>() {
        return match error {
            TransportError::TlsConfiguration => "transport_tls_configuration",
            TransportError::Listener => "transport_listener",
            TransportError::Signal => "transport_signal",
        };
    }
    "invalid_command"
}
