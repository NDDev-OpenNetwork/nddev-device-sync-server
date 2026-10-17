//! In-process collection of real SDK SpanData; no network exporter is implied.
use std::sync::{Arc, Mutex};

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::{
    error::OTelSdkResult,
    trace::{SdkTracerProvider, SpanData, SpanExporter},
};

#[derive(Clone, Debug, Default)]
pub(crate) struct Captured(pub Arc<Mutex<Vec<SpanData>>>);
impl SpanExporter for Captured {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        let mut spans = self.0.lock().unwrap();
        assert!(spans.len() + batch.len() <= 64, "bounded test collector");
        spans.extend(batch);
        Ok(())
    }
}

pub(crate) fn capture() -> (tracing::Dispatch, SdkTracerProvider, Captured) {
    capture_to(std::io::sink())
}

#[derive(Clone, Default)]
pub(crate) struct Events(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Events {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        assert!(
            output.len() + bytes.len() <= 65_536,
            "bounded event collector"
        );
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Events {
    pub(crate) fn values(&self) -> Vec<serde_json::Value> {
        let output = self.0.lock().unwrap();
        String::from_utf8(output.clone())
            .unwrap()
            .lines()
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                nddev_device_sync_telemetry::decode_event(value.clone()).unwrap();
                assert!(
                    !value["event.name"]
                        .as_str()
                        .unwrap()
                        .starts_with("logging.")
                );
                value
            })
            .collect()
    }
}

pub(crate) fn capture_to(
    writer: impl std::io::Write + Send + Sync + 'static,
) -> (tracing::Dispatch, SdkTracerProvider, Captured) {
    let captured = Captured::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(captured.clone())
        .build();
    let config = nddev_device_sync_telemetry::Config {
        service: "nddev-device-sync-server".into(),
        version: "test".into(),
        repository: "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-server".into(),
        commit: crate::SOURCE_COMMIT.into(),
        channel: "alpha".into(),
        standards: "test".into(),
        environment: "test".into(),
        target_prefixes: vec!["nddev_device_sync_server".into()],
        default_module: "process".into(),
        debug: None,
    };
    let (subscriber, _) =
        nddev_device_sync_telemetry::subscriber(config, writer, provider.tracer("server-test"))
            .unwrap();
    (tracing::Dispatch::new(subscriber), provider, captured)
}
