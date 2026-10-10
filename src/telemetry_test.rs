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
    let captured = Captured::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(captured.clone())
        .build();
    let config = nddev_device_sync_telemetry::Config {
        service: "nddev-device-sync-server".into(),
        version: "test".into(),
        repository: "NDDev-OpenNetwork/nddev-device-sync-server".into(),
        commit: crate::SOURCE_COMMIT.into(),
        channel: "alpha".into(),
        standards: "test".into(),
        environment: "test".into(),
        target_prefixes: vec!["nddev_device_sync_server".into()],
        default_module: "process".into(),
        debug: None,
    };
    let (subscriber, _) = nddev_device_sync_telemetry::subscriber(
        config,
        std::io::sink(),
        provider.tracer("server-test"),
    )
    .unwrap();
    (tracing::Dispatch::new(subscriber), provider, captured)
}
