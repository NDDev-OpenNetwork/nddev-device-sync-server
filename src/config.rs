use std::{env, net::SocketAddr};

use thiserror::Error;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub database_url: Option<String>,
    pub version: String,
    pub channel: String,
    pub standards_release: String,
    pub source_url: String,
    pub telemetry_enabled: bool,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid NDS_SERVER_ADDR: {0}")]
    Address(#[from] std::net::AddrParseError),
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let addr = env::var("NDS_SERVER_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".into())
            .parse()?;
        Ok(Self {
            addr,
            database_url: env::var("DATABASE_URL").ok(),
            version: env::var("NDS_VERSION").unwrap_or_else(|_| "0.0.1-alpha.4".into()),
            channel: env::var("NDS_RELEASE_CHANNEL").unwrap_or_else(|_| "alpha".into()),
            standards_release: env::var("NDS_STANDARDS_RELEASE")
                .unwrap_or_else(|_| "v0.0.1-alpha.7".into()),
            source_url: env::var("NDS_SOURCE_URL").unwrap_or_else(|_| {
                "https://github.com/NDDev-OpenNetwork/nddev-device-sync-server".into()
            }),
            telemetry_enabled: env::var("NDS_TELEMETRY_ENABLED")
                .map(|value| !matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "off"))
                .unwrap_or(true),
        })
    }
}
