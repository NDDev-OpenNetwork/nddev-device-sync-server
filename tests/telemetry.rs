use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use nddev_device_sync_server::{AppState, config::ServerConfig, router};
use std::{
    io::Write,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;

#[derive(Clone)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// A separate test process owns its tracing subscriber, avoiding global
// callsite-interest races with unrelated route tests.
#[tokio::test]
async fn completion_logs_keep_correlation_and_exclude_request_secrets() {
    let logs = CapturedLogs(Arc::new(Mutex::new(Vec::new())));
    let writer = logs.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();
    let state = AppState::from_config(ServerConfig {
        addr: "127.0.0.1:0".parse().unwrap(),
        database_url: None,
        version: "test".into(),
        channel: "alpha".into(),
        standards_release: "test".into(),
        source_url: "https://example.invalid/source".into(),
        telemetry_enabled: true,
    })
    .await
    .unwrap();
    let response = router(state)
        .oneshot(
            Request::get("/synthetic-path-secret?code=synthetic-query-secret")
                .header("authorization", "Bearer synthetic-header-secret")
                .header(
                    "traceparent",
                    "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for secret in [
        "synthetic-path-secret",
        "synthetic-query-secret",
        "synthetic-header-secret",
    ] {
        assert!(!text.contains(secret));
    }
    let completion: serde_json::Value = text
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|event| event["fields"]["event.name"] == "http.request.completed")
        .expect("completion event");
    assert_eq!(
        completion["span"]["trace_id"],
        "0123456789abcdef0123456789abcdef"
    );
    assert_eq!(completion["span"]["route"], "unmatched");
    assert_eq!(completion["fields"]["outcome"], "rejected");
}
