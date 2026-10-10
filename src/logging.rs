//! Thin server configuration adapter; envelope, filtering, bounds and output are
//! owned by the shared SDK. No dependency verbosity can bypass its policy.
use nddev_device_sync_telemetry::otlp::NativeTraces;
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
        let debug = DebugWindow::from_settings(&get).map_err(|_| LoggingError)?;
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
    // Declared after the logger: flush local lifecycle before closing egress.
    _traces: Option<NativeTraces>,
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
    let mut valid = parsed.is_ok();
    let settings =
        parsed.unwrap_or_else(|_| Settings::read(|_| None).expect("static logging defaults"));
    let traces = match telemetry_settings(|key| std::env::var(key).ok()) {
        Ok(Some(origin)) => match NativeTraces::new(&settings.0, &origin) {
            Ok(traces) => Some(traces),
            Err(_) => {
                valid = false;
                None
            }
        },
        Ok(None) => None,
        Err(_) => {
            valid = false;
            None
        }
    };
    let logger = if let Some(traces) = &traces {
        nddev_device_sync_telemetry::install_with_tracer(settings.0, traces.tracer())
    } else {
        nddev_device_sync_telemetry::install(settings.0)
    }
    .map_err(|_| LoggingError)?;
    tracing::info!(
        module = "process",
        event.name = "telemetry.traces.configured",
        available = traces.is_some(),
        outcome = "checked"
    );
    Ok(LoggingGuard {
        _logger: logger,
        _traces: traces,
        valid,
    })
}

fn telemetry_settings(
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<String>, LoggingError> {
    let enabled = match get("NDS_TELEMETRY_ENABLED")
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("true" | "1" | "on") => true,
        Some("false" | "0" | "off") => false,
        _ => return Err(LoggingError),
    };
    if enabled {
        Ok(get("NDS_OTLP_ENDPOINT"))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operator_opt_out_never_constructs_a_collector_client() {
        assert!(
            telemetry_settings(|name| match name {
                "NDS_TELEMETRY_ENABLED" => Some("off".into()),
                "NDS_OTLP_ENDPOINT" => Some("malformed unused collector".into()),
                _ => None,
            })
            .unwrap()
            .is_none()
        );
        assert!(telemetry_settings(|_| None).unwrap().is_none());
        assert!(
            telemetry_settings(|name| (name == "NDS_TELEMETRY_ENABLED").then(|| "typo".into()))
                .is_err()
        );
    }

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
