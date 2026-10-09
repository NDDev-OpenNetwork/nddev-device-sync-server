use std::{env, fmt, fs::File, io::Read, net::SocketAddr, path::PathBuf};

use thiserror::Error;

pub const DEFAULT_VERSION: &str = "0.0.1-alpha.8";
pub const DEFAULT_CHANNEL: &str = "alpha";
pub const DEFAULT_STANDARDS_RELEASE: &str = "v0.0.1-alpha.9";

/// A secret is deliberately absent from Debug, including nested config values.
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone)]
pub struct TlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

impl fmt::Debug for TlsFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TlsFiles([REDACTED])")
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub database_url: Option<SecretString>,
    pub tls: Option<TlsFiles>,
    pub version: String,
    pub channel: String,
    pub standards_release: String,
    pub source_url: String,
    pub telemetry_enabled: bool,
    pub max_connections: usize,
    pub max_requests: usize,
    pub identity: Option<crate::identity::config::AuthConfig>,
}

#[derive(Debug, Error, PartialEq)]
pub enum ConfigError {
    #[error("invalid NDS_SERVER_ADDR")]
    Address,
    #[error("configure both NDS_TLS_CERT_FILE and NDS_TLS_KEY_FILE")]
    TlsPair,
    #[error("configure either a secret environment variable or its _FILE variant")]
    ConflictingSecret,
    #[error("secret file is unreadable or invalid")]
    SecretFile,
    #[error("secret is empty or exceeds 16 KiB")]
    SecretValue,
    #[error("NDS_MIGRATION_DATABASE_URL or its _FILE variant is required")]
    MigrationDatabaseMissing,
    #[error("admission limit is outside its supported range")]
    AdmissionLimit,
    #[error("invalid identity configuration")]
    Identity,
    #[error("identity requires HTTPS except on a loopback listener")]
    IdentityHttpsRequired,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| env::var(key).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let addr = get("NDS_SERVER_ADDR")
            .unwrap_or_else(|| "127.0.0.1:8080".into())
            .parse()
            .map_err(|_| ConfigError::Address)?;
        let tls = match (get("NDS_TLS_CERT_FILE"), get("NDS_TLS_KEY_FILE")) {
            (None, None) => None,
            (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => Some(TlsFiles {
                certificate: cert.into(),
                private_key: key.into(),
            }),
            _ => return Err(ConfigError::TlsPair),
        };
        let config = Self {
            addr,
            database_url: read_secret(get("DATABASE_URL"), get("DATABASE_URL_FILE"))?,
            tls,
            version: get("NDS_VERSION").unwrap_or_else(|| DEFAULT_VERSION.into()),
            channel: get("NDS_RELEASE_CHANNEL").unwrap_or_else(|| DEFAULT_CHANNEL.into()),
            standards_release: get("NDS_STANDARDS_RELEASE")
                .unwrap_or_else(|| DEFAULT_STANDARDS_RELEASE.into()),
            source_url: get("NDS_SOURCE_URL").unwrap_or_else(|| {
                "https://github.com/NDDev-OpenNetwork/nddev-device-sync-server".into()
            }),
            telemetry_enabled: get("NDS_TELEMETRY_ENABLED")
                .map(|value| !matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "off"))
                .unwrap_or(true),
            max_connections: admission_limit(get("NDS_MAX_CONNECTIONS"), 256, 4096)?,
            max_requests: admission_limit(get("NDS_MAX_REQUESTS"), 64, 1024)?,
            identity: get("NDS_AUTH_CONFIG_FILE")
                .map(|path| crate::identity::config::AuthConfig::read(&path))
                .transpose()?,
        };
        if config.identity.is_some() && config.tls.is_none() && !config.addr.ip().is_loopback() {
            return Err(ConfigError::IdentityHttpsRequired);
        }
        Ok(config)
    }
}

fn admission_limit(
    value: Option<String>,
    default: usize,
    maximum: usize,
) -> Result<usize, ConfigError> {
    match value {
        None => Ok(default),
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|value| (1..=maximum).contains(value))
            .ok_or(ConfigError::AdmissionLimit),
    }
}

/// Called only by the migration command: runtime never loads this credential.
pub fn migration_database_url() -> Result<SecretString, ConfigError> {
    read_secret(
        env::var("NDS_MIGRATION_DATABASE_URL").ok(),
        env::var("NDS_MIGRATION_DATABASE_URL_FILE").ok(),
    )?
    .ok_or(ConfigError::MigrationDatabaseMissing)
}

pub(crate) fn read_secret(
    value: Option<String>,
    file: Option<String>,
) -> Result<Option<SecretString>, ConfigError> {
    const MAX_BYTES: u64 = 16 * 1024;
    let value = match (value, file) {
        (Some(_), Some(_)) => return Err(ConfigError::ConflictingSecret),
        (None, None) => return Ok(None),
        (Some(value), None) => value,
        (None, Some(path)) => {
            let file = File::open(path).map_err(|_| ConfigError::SecretFile)?;
            if !file
                .metadata()
                .map_err(|_| ConfigError::SecretFile)?
                .is_file()
            {
                return Err(ConfigError::SecretFile);
            }
            let mut value = String::new();
            file.take(MAX_BYTES + 1)
                .read_to_string(&mut value)
                .map_err(|_| ConfigError::SecretFile)?;
            value
        }
    };
    if value.len() > MAX_BYTES as usize || value.trim().is_empty() {
        return Err(ConfigError::SecretValue);
    }
    Ok(Some(SecretString(value.trim().to_owned())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_and_tls_paths_are_redacted() {
        let config = ServerConfig::from_lookup(|name| {
            match name {
                "DATABASE_URL" => Some("postgres://user:secret@example.invalid/database"),
                "NDS_TLS_CERT_FILE" => Some("/private/certificate.pem"),
                "NDS_TLS_KEY_FILE" => Some("/private/key.pem"),
                _ => None,
            }
            .map(str::to_owned)
        })
        .unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("REDACTED"));
        for sensitive in ["secret@", "private/", "postgres://"] {
            assert!(!debug.contains(sensitive));
        }
    }

    #[test]
    fn partial_tls_configuration_fails_closed() {
        for key in ["NDS_TLS_CERT_FILE", "NDS_TLS_KEY_FILE"] {
            assert_eq!(
                ServerConfig::from_lookup(|name| (name == key).then(|| "file.pem".into()))
                    .unwrap_err(),
                ConfigError::TlsPair
            );
        }
    }

    #[test]
    fn secret_source_is_unambiguous_and_errors_are_redacted() {
        assert_eq!(
            read_secret(Some("secret".into()), Some("private/path".into())).unwrap_err(),
            ConfigError::ConflictingSecret
        );
        assert_eq!(
            read_secret(Some(" ".into()), None).unwrap_err(),
            ConfigError::SecretValue
        );
        assert_eq!(
            read_secret(None, Some("/nonexistent/secret-path".into())).unwrap_err(),
            ConfigError::SecretFile
        );
        assert_eq!(
            read_secret(Some("x".repeat(16 * 1024 + 1)), None).unwrap_err(),
            ConfigError::SecretValue
        );
    }

    #[test]
    fn file_secret_is_trimmed_and_bounded() {
        let path = env::temp_dir().join(format!("nds-config-test-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, "test-value\n").unwrap();
        let secret = read_secret(None, Some(path.to_string_lossy().into()))
            .unwrap()
            .unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(secret.expose(), "test-value");
    }

    #[test]
    fn admission_limits_reject_zero_overflow_and_excessive_values() {
        for (key, maximum) in [("NDS_MAX_CONNECTIONS", 4096), ("NDS_MAX_REQUESTS", 1024)] {
            for value in [
                "0".into(),
                "-1".into(),
                "9999999999999999999999999".into(),
                (maximum + 1).to_string(),
            ] {
                assert_eq!(
                    ServerConfig::from_lookup(|name| (name == key).then(|| value.clone()))
                        .unwrap_err(),
                    ConfigError::AdmissionLimit
                );
            }
        }
    }
}
