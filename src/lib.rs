mod admission;
pub mod config;
pub mod database;
pub mod logging;
pub mod transport;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{MatchedPath, Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use database::DATABASE_TIMEOUT;
use nddev_device_sync_application::builtin_modules;
use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tracing::{Instrument, info_span};
use uuid::Uuid;

use config::ServerConfig;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub const SOURCE_COMMIT: &str = match option_env!("NDS_BUILD_COMMIT") {
    Some(value) => value,
    None => "unknown",
};

#[derive(Clone)]
pub struct AppState {
    pub config: ServerConfig,
    pub database: Option<PgPool>,
    pub module_count: usize,
    requests: Arc<Semaphore>,
    pressure: Arc<admission::Pressure>,
}

impl AppState {
    pub async fn from_config(config: ServerConfig) -> Result<Self, database::DatabaseError> {
        let database = if let Some(url) = &config.database_url {
            Some(database::connect_runtime(url).await?)
        } else {
            None
        };
        Ok(Self {
            requests: Arc::new(Semaphore::new(config.max_requests)),
            pressure: Arc::default(),
            config,
            database,
            module_count: builtin_modules().len(),
        })
    }

    #[cfg(test)]
    pub fn test() -> Self {
        Self {
            config: ServerConfig {
                addr: "127.0.0.1:0".parse().expect("valid test address"),
                database_url: None,
                tls: None,
                version: "test".into(),
                channel: "alpha".into(),
                standards_release: "test".into(),
                source_url: "https://nddev.ai".into(),
                telemetry_enabled: true,
                max_connections: 256,
                max_requests: 64,
            },
            database: None,
            module_count: builtin_modules().len(),
            requests: Arc::new(Semaphore::new(64)),
            pressure: Arc::default(),
        }
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: String,
    channel: String,
    standards_release: String,
    source_commit: &'static str,
    module_count: usize,
    telemetry_enabled: bool,
    database_configured: bool,
}

#[derive(Serialize)]
struct ReadyResponse {
    status: &'static str,
    database: &'static str,
}

#[derive(Serialize)]
struct SourceResponse {
    source_url: String,
    license: &'static str,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/ready", get(ready))
        .route("/source", get(source))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, request_trace))
}

async fn request_trace(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let trace_id = request
        .headers()
        .get("traceparent")
        .and_then(|value| value.to_str().ok())
        .and_then(valid_trace_id)
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let span_id = Uuid::new_v4().simple().to_string()[..16].to_owned();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unmatched");
    let method = match request.method().as_str() {
        method @ ("GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "OPTIONS" | "PATCH" | "CONNECT"
        | "TRACE") => method,
        _ => "OTHER",
    };
    let span = info_span!(
        "http.request",
        trace_id = %trace_id,
        span_id = %span_id,
        method,
        route
    );
    let started = Instant::now();
    let mut response = async {
        let permit = state.requests.try_acquire();
        let response = if let Ok(_permit) = permit {
            state.pressure.recover("requests");
            tracing::debug!(event.name = "http.request.started", outcome = "started");
            match tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await {
                Ok(response) => response,
                Err(_) => (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({"error": "request_timeout"})),
                )
                    .into_response(),
            }
        } else {
            state.pressure.reject("requests");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [("retry-after", "1")],
                Json(serde_json::json!({"error": "server_busy"})),
            )
                .into_response()
        };
        if response.status().is_server_error() {
            tracing::error!(
                event.name = "http.request.completed",
                error.type = "http_server_error",
                status = response.status().as_u16(),
                duration_ms = started.elapsed().as_secs_f64() * 1000.0,
                outcome = "error"
            );
        } else {
            tracing::info!(
                event.name = "http.request.completed",
                status = response.status().as_u16(),
                duration_ms = started.elapsed().as_secs_f64() * 1000.0,
                outcome = if response.status().is_client_error() {
                    "rejected"
                } else {
                    "ok"
                }
            );
        }
        response
    }
    .instrument(span)
    .await;
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&trace_id).expect("generated trace id"),
    );
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
}

fn valid_trace_id(value: &str) -> Option<&str> {
    let mut parts = value.split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let parent_id = parts.next()?;
    let flags = parts.next()?;
    if version != "00"
        || parts.next().is_some()
        || trace_id.len() != 32
        || parent_id.len() != 16
        || flags.len() != 2
    {
        return None;
    }
    let lowercase_hex = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
    if !flags.bytes().all(lowercase_hex) {
        return None;
    }
    if !trace_id.bytes().all(lowercase_hex) || trace_id.bytes().all(|c| c == b'0') {
        return None;
    }
    if !parent_id.bytes().all(lowercase_hex) || parent_id.bytes().all(|c| c == b'0') {
        return None;
    }
    Some(trace_id)
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    tracing::debug!(event.name = "health.read", outcome = "ok");
    Json(HealthResponse {
        status: "ok",
        service: "nddev-device-sync-server",
        version: state.config.version,
        channel: state.config.channel,
        standards_release: state.config.standards_release,
        source_commit: SOURCE_COMMIT,
        module_count: state.module_count,
        telemetry_enabled: state.config.telemetry_enabled,
        database_configured: state.database.is_some(),
    })
}

async fn ready(State(state): State<AppState>) -> Response {
    let Some(database) = state.database else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "degraded",
                database: "not_configured",
            }),
        )
            .into_response();
    };
    match tokio::time::timeout(
        DATABASE_TIMEOUT,
        sqlx::query_scalar::<_, i32>("SELECT 1 FROM nddev_schema_meta WHERE key = 'product' AND value = 'nddev-device-sync-server'").fetch_one(&database),
    )
    .await
    {
        Ok(Ok(_)) => Json(ReadyResponse {
            status: "ready",
            database: "ok",
        })
        .into_response(),
        failed => {
            tracing::error!(
                event.name = "database.readiness_failed",
                error.type = if failed.is_err() { "database_timeout" } else { "database_unavailable" },
                outcome = "error"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadyResponse {
                    status: "degraded",
                    database: "error",
                }),
            )
                .into_response()
        }
    }
}

async fn source(State(state): State<AppState>) -> Json<SourceResponse> {
    Json(SourceResponse {
        source_url: state.config.source_url,
        license: "AGPL-3.0-only",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_exposes_pinned_product_state() {
        let response = router(AppState::test())
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .header(
                        "traceparent",
                        "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-request-id"],
            "0123456789abcdef0123456789abcdef"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["status"], "ok");
        assert_eq!(value["channel"], "alpha");
        assert_eq!(value["telemetry_enabled"], true);
    }

    #[tokio::test]
    async fn readiness_is_honest_without_database() {
        let response = router(AppState::test())
            .oneshot(Request::get("/v1/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn rejects_invalid_trace_context() {
        assert!(
            valid_trace_id("00-0123456789abcdef0123456789abcdef-0123456789abcdef-01").is_some()
        );
        assert!(
            valid_trace_id("00-00000000000000000000000000000000-0123456789abcdef-01").is_none()
        );
        assert!(
            valid_trace_id("ff-0123456789abcdef0123456789abcdef-0123456789abcdef-01").is_none()
        );
        for invalid in [
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-zz",
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-FF",
            "00-0123456789ABCDEF0123456789abcdef-0123456789abcdef-01",
            "00-0123456789abcdef0123456789abcdef-0123456789ABCDEF-01",
            "00-0123456789abcdef0123456789abcdef-0000000000000000-01",
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01-extra",
        ] {
            assert!(valid_trace_id(invalid).is_none(), "accepted {invalid}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn slow_handler_is_cancelled_with_a_correlated_timeout() {
        let state = AppState::test();
        let app = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    StatusCode::OK
                }),
            )
            .layer(middleware::from_fn_with_state(state, request_trace));
        let response = app
            .oneshot(Request::get("/slow").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.headers()["x-request-id"].to_str().unwrap().len(),
            32
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
            "request_timeout"
        );
    }

    #[tokio::test]
    async fn invalid_flags_do_not_control_response_correlation() {
        let response = router(AppState::test())
            .oneshot(
                Request::get("/v1/health")
                    .header(
                        "traceparent",
                        "00-0123456789abcdef0123456789abcdef-0123456789abcdef-zz",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_ne!(
            response.headers()["x-request-id"],
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[tokio::test]
    async fn success_and_error_responses_disable_http_storage() {
        for (path, status) in [
            ("/v1/health", StatusCode::OK),
            ("/source", StatusCode::OK),
            ("/v1/ready", StatusCode::SERVICE_UNAVAILABLE),
            ("/missing", StatusCode::NOT_FOUND),
        ] {
            let response = router(AppState::test())
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["cache-control"], "no-store", "{path}");
        }
    }
}
