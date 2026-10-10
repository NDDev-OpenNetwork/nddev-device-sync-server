//! Thin server configuration adapter; envelope, filtering, bounds and output are
//! owned by the shared SDK. No dependency verbosity can bypass its policy.
use std::time::Duration;

use nddev_device_sync_telemetry::{Config, DebugWindow, Logger};

use crate::{
    SOURCE_COMMIT,
    config::{DEFAULT_CHANNEL, DEFAULT_STANDARDS_RELEASE, DEFAULT_VERSION},
};

#[derive(Debug, thiserror::Error)]
#[error("invalid_logging_configuration")]
pub struct LoggingError;

struct Settings(Config);
impl Settings {
    fn read(get: impl Fn(&str) -> Option<String>) -> Result<Self, LoggingError> {
        let label = |name, default: &str| {
            let value = get(name).unwrap_or_else(|| default.into());
            if value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
            {
                return Err(LoggingError);
            }
            Ok(value)
        };
        let debug = match get("NDS_LOG_MODE").as_deref().unwrap_or("normal") {
            "normal"
                if [
                    "NDS_DEBUG_SCOPE",
                    "NDS_DEBUG_SECONDS",
                    "NDS_DEBUG_EVENT_LIMIT",
                ]
                .iter()
                .all(|name| get(name).is_none()) =>
            {
                None
            }
            "debug" => {
                let scope = match get("NDS_DEBUG_SCOPE").as_deref() {
                    Some(scope @ ("http" | "transport" | "database")) => scope.to_owned(),
                    _ => return Err(LoggingError),
                };
                let seconds = get("NDS_DEBUG_SECONDS")
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|value| (1..=900).contains(value))
                    .ok_or(LoggingError)?;
                let events = get("NDS_DEBUG_EVENT_LIMIT")
                    .unwrap_or_else(|| "1000".into())
                    .parse::<u64>()
                    .ok()
                    .filter(|value| (1..=10000).contains(value))
                    .ok_or(LoggingError)?;
                Some(DebugWindow {
                    scope,
                    duration: Duration::from_secs(seconds),
                    events,
                })
            }
            _ => return Err(LoggingError),
        };
        Ok(Self(Config {
            service: "nddev-device-sync-server".into(),
            version: label("NDS_VERSION", DEFAULT_VERSION)?,
            repository: "NDDev-OpenNetwork/nddev-device-sync-server".into(),
            commit: SOURCE_COMMIT.into(),
            channel: label("NDS_RELEASE_CHANNEL", DEFAULT_CHANNEL)?,
            standards: label("NDS_STANDARDS_RELEASE", DEFAULT_STANDARDS_RELEASE)?,
            environment: label("NDS_ENVIRONMENT", "self-hosted")?,
            target_prefixes: vec!["nddev_device_sync_server".into()],
            default_module: "process".into(),
            debug,
        }))
    }
}

pub struct LoggingGuard {
    _logger: Logger,
    valid: bool,
}
impl LoggingGuard {
    /// Keep the installed safe logger alive while the caller reports malformed
    /// configuration, then let SDK Drop perform its bounded output shutdown.
    pub fn validate(&self) -> Result<(), LoggingError> {
        if self.valid {
            Ok(())
        } else {
            Err(LoggingError)
        }
    }
}

pub fn init_logging() -> Result<LoggingGuard, LoggingError> {
    let parsed = Settings::read(|key| std::env::var(key).ok());
    let valid = parsed.is_ok();
    let settings =
        parsed.unwrap_or_else(|_| Settings::read(|_| None).expect("static logging defaults"));
    let logger = nddev_device_sync_telemetry::install(settings.0).map_err(|_| LoggingError)?;
    Ok(LoggingGuard {
        _logger: logger,
        valid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_requires_valid_scope_duration_and_budget() {
        for (key, invalid) in [
            ("NDS_DEBUG_SCOPE", "all"),
            ("NDS_DEBUG_SECONDS", "0"),
            ("NDS_DEBUG_SECONDS", "901"),
            ("NDS_DEBUG_EVENT_LIMIT", "10001"),
        ] {
            assert!(
                Settings::read(|name| Some(
                    match name {
                        "NDS_LOG_MODE" => "debug",
                        name if name == key => invalid,
                        "NDS_DEBUG_SCOPE" => "http",
                        "NDS_DEBUG_SECONDS" => "30",
                        "NDS_DEBUG_EVENT_LIMIT" => "10",
                        _ => return None,
                    }
                    .into()
                ))
                .is_err()
            );
        }
        assert!(Settings::read(|name| (name == "NDS_DEBUG_SCOPE").then(|| "http".into())).is_err());
        assert!(Settings::read(|_| None).is_ok());
    }
}
