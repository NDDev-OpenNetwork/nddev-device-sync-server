//! One process envelope and an explicit, finite diagnostic window. Dependency
//! verbosity and arbitrary RUST_LOG directives never bypass this boundary.
use std::io;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::{Map, Value};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::{
    Layer,
    fmt::{
        FmtContext,
        format::{FormatEvent, FormatFields, JsonFields, Writer},
    },
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};

use crate::{
    SOURCE_COMMIT,
    config::{DEFAULT_CHANNEL, DEFAULT_STANDARDS_RELEASE, DEFAULT_VERSION},
};

#[derive(Debug, thiserror::Error)]
#[error(
    "invalid logging configuration; use normal or scoped debug with a 1..900 second duration and 1..10000 event budget"
)]
pub struct LoggingError;

struct Settings {
    metadata: BTreeMap<&'static str, String>,
    debug: Option<(&'static str, Duration, u32)>,
}

impl Settings {
    fn read(get: impl Fn(&str) -> Option<String>) -> Result<Self, LoggingError> {
        let mut metadata = BTreeMap::new();
        for (field, variable, default) in [
            ("service.version", "NDS_VERSION", DEFAULT_VERSION),
            ("release.channel", "NDS_RELEASE_CHANNEL", DEFAULT_CHANNEL),
            (
                "standards.release",
                "NDS_STANDARDS_RELEASE",
                DEFAULT_STANDARDS_RELEASE,
            ),
            ("deployment.environment", "NDS_ENVIRONMENT", "self-hosted"),
        ] {
            let value = get(variable).unwrap_or_else(|| default.into());
            if value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
            {
                return Err(LoggingError);
            }
            metadata.insert(field, value);
        }
        metadata.insert("release.version", metadata["service.version"].clone());
        metadata.insert("service.name", "nddev-device-sync-server".into());
        metadata.insert(
            "source.repository",
            "NDDev-OpenNetwork/nddev-device-sync-server".into(),
        );
        metadata.insert("source.commit", SOURCE_COMMIT.into());
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
                    Some("http") => "http",
                    Some("transport") => "transport",
                    Some("database") => "database",
                    _ => return Err(LoggingError),
                };
                let seconds = get("NDS_DEBUG_SECONDS")
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|value| (1..=900).contains(value))
                    .ok_or(LoggingError)?;
                let events = get("NDS_DEBUG_EVENT_LIMIT")
                    .unwrap_or_else(|| "1000".into())
                    .parse::<u32>()
                    .ok()
                    .filter(|value| (1..=10000).contains(value))
                    .ok_or(LoggingError)?;
                Some((scope, Duration::from_secs(seconds), events))
            }
            _ => return Err(LoggingError),
        };
        Ok(Self { metadata, debug })
    }
}

fn module(target: &str) -> &'static str {
    if target.starts_with("nddev_device_sync_server::identity") {
        return "identity";
    }
    match target.strip_prefix("nddev_device_sync_server") {
        Some("") => "http",
        Some("::transport") => "transport",
        Some("::database") => "database",
        Some("::admission") => "admission",
        _ => "process",
    }
}

struct Envelope(BTreeMap<&'static str, String>);

const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;
#[derive(Clone)]
struct ProducerWriter(Arc<Producer>);
struct Producer {
    instance: uuid::Uuid,
    sequence: Mutex<u64>,
}
impl ProducerWriter {
    fn new() -> Self {
        Self(Arc::new(Producer {
            instance: uuid::Uuid::new_v4(),
            sequence: Mutex::new(0),
        }))
    }
}
impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for ProducerWriter {
    type Writer = Self;
    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}
impl io::Write for ProducerWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if !buffer.starts_with(b"{") || !buffer.ends_with(b"}\n") || buffer.len() < 4 {
            return Err(io::Error::other(
                "log formatter did not emit an object record",
            ));
        }
        let mut sequence = self
            .0
            .sequence
            .lock()
            .map_err(|_| io::Error::other("producer sequence lock unavailable"))?;
        let mut output = io::stdout().lock();
        // Assignment and the complete write share one lock: concurrent formatter
        // completion cannot reorder the producer stream. No queue is introduced.
        if *sequence < MAX_SEQUENCE {
            *sequence += 1;
            write!(
                output,
                "{{\"producer.instance_id\":\"{}\",\"producer.sequence\":{},",
                self.0.instance, *sequence
            )?;
            output.write_all(&buffer[1..])?;
        } else {
            // The optional pair is absent after exhaustion, never wrapped or
            // reused. Consumers report unsequenced/degraded observations.
            output.write_all(buffer)?;
        }
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

impl<S, N> FormatEvent<S, N> for Envelope
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        context: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut encoded = String::new();
        tracing_subscriber::fmt::format().json().format_event(
            context,
            Writer::new(&mut encoded),
            event,
        )?;
        let mut source: Map<String, Value> =
            serde_json::from_str(&encoded).map_err(|_| fmt::Error)?;
        let mut output = Map::new();
        if let Some(Value::Array(spans)) = source.remove("spans") {
            for span in spans {
                if let Value::Object(mut fields) = span {
                    fields.remove("name");
                    output.extend(fields);
                }
            }
        }
        if let Some(Value::Object(fields)) = source.remove("fields") {
            output.extend(fields);
        }
        output.insert(
            "timestamp".into(),
            source.remove("timestamp").ok_or(fmt::Error)?,
        );
        output.insert(
            "severity".into(),
            event
                .metadata()
                .level()
                .as_str()
                .to_ascii_lowercase()
                .into(),
        );
        output
            .entry("module")
            .or_insert_with(|| module(event.metadata().target()).into());
        for (name, value) in &self.0 {
            output.insert((*name).into(), value.clone().into());
        }
        output.remove("producer.instance_id");
        output.remove("producer.sequence");
        writeln!(writer, "{}", Value::Object(output))
    }
}

struct DebugWindow {
    scope: &'static str,
    expires: Instant,
    remaining: AtomicU32,
    active: AtomicBool,
    exhausted: tokio::sync::Notify,
}

impl DebugWindow {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        if !self.active.load(Ordering::Relaxed)
            || Instant::now() >= self.expires
            || module(metadata.target()) != self.scope
        {
            return false;
        }
        if !metadata.is_event() {
            return true;
        }
        match self
            .remaining
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_sub(1)
            }) {
            Ok(1) => {
                self.exhausted.notify_one();
                true
            }
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn disable(&self, reason: &'static str) {
        if self.active.swap(false, Ordering::Relaxed) {
            tracing::info!(
                event.name = "logging.debug.disabled",
                scope = self.scope,
                reason,
                outcome = "ok"
            );
        }
    }
}

pub struct LoggingGuard {
    debug: Option<Arc<DebugWindow>>,
    expiry: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        if let Some(window) = &self.debug {
            window.disable("process_exit");
        }
        if let Some(task) = &self.expiry {
            task.abort();
        }
    }
}

pub fn init_logging() -> Result<LoggingGuard, LoggingError> {
    let parsed = Settings::read(|key| std::env::var(key).ok());
    // Even malformed runtime/logging configuration gets a safe process envelope.
    let settings = parsed
        .as_ref()
        .ok()
        .map(|settings| Settings {
            metadata: settings.metadata.clone(),
            debug: settings.debug,
        })
        .unwrap_or_else(|| Settings::read(|_| None).expect("static logging defaults"));
    let debug = settings.debug.map(|(scope, duration, budget)| {
        Arc::new(DebugWindow {
            scope,
            expires: Instant::now() + duration,
            remaining: AtomicU32::new(budget),
            active: AtomicBool::new(true),
            exhausted: tokio::sync::Notify::new(),
        })
    });
    let filter_window = debug.clone();
    let filter = tracing_subscriber::filter::dynamic_filter_fn(move |metadata, _| {
        if !matches!(metadata.target(), "nddev_device_sync_server")
            && !metadata.target().starts_with("nddev_device_sync_server::")
        {
            return false;
        }
        *metadata.level() <= Level::INFO
            || (*metadata.level() == Level::DEBUG
                && filter_window
                    .as_ref()
                    .is_some_and(|window| window.enabled(metadata)))
    });
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(ProducerWriter::new())
                .fmt_fields(JsonFields::new())
                .event_format(Envelope(settings.metadata))
                .with_filter(filter),
        )
        .try_init()
        .map_err(|_| LoggingError)?;
    parsed?;
    let expiry = debug.as_ref().map(|window| {
        let window = window.clone();
        let (_, duration, budget) = settings.debug.expect("debug settings");
        tracing::info!(
            event.name = "logging.debug.enabled",
            scope = window.scope,
            duration_seconds = duration.as_secs(),
            event_budget = budget,
            outcome = "ok"
        );
        tokio::spawn(async move {
            let reason = tokio::select! {
                _ = tokio::time::sleep_until(window.expires.into()) => "expired",
                _ = window.exhausted.notified() => "event_budget",
            };
            window.disable(reason);
        })
    });
    Ok(LoggingGuard { debug, expiry })
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
