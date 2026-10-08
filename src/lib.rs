pub mod config;

use std::time::Instant;

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use nddev_device_sync_application::builtin_modules;
use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use tracing::{Instrument, info, info_span};
use uuid::Uuid;

use config::ServerConfig;

pub const SOURCE_COMMIT: &str = match option_env!("NDS_BUILD_COMMIT") {
    Some(value) => value,
    None => "unknown",
};

#[derive(Clone)]
pub struct AppState {
    pub config: ServerConfig,
    pub database: Option<PgPool>,
    pub module_count: usize,
}

impl AppState {
    pub async fn from_config(config: ServerConfig) -> Result<Self, sqlx::Error> {
        let database = if let Some(url) = &config.database_url {
            let pool = PgPoolOptions::new().max_connections(8).connect(url).await?;
            sqlx::migrate!().run(&pool).await?;
            Some(pool)
        } else {
            None
        };
        Ok(Self {
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
                version: "test".into(),
                channel: "alpha".into(),
                standards_release: "test".into(),
                source_url: "https://nddev.ai".into(),
                telemetry_enabled: true,
            },
            database: None,
            module_count: builtin_modules().len(),
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
        .with_state(state)
        .layer(middleware::from_fn(request_trace))
}

async fn request_trace(request: Request, next: Next) -> Response {
    let trace_id = request
        .headers()
        .get("traceparent")
        .and_then(|value| value.to_str().ok())
        .and_then(valid_trace_id)
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let span = info_span!(
        "http.request",
        trace_id = %trace_id,
        method = %request.method(),
        path = %request.uri().path()
    );
    let started = Instant::now();
    let mut response = next.run(request).instrument(span).await;
    tracing::info!(
        event = "http.request.completed",
        status = response.status().as_u16(),
        duration_ms = started.elapsed().as_secs_f64() * 1000.0
    );
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&trace_id).expect("generated trace id"),
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
    if !trace_id.bytes().all(|c| c.is_ascii_hexdigit()) || trace_id.bytes().all(|c| c == b'0') {
        return None;
    }
    if !parent_id.bytes().all(|c| c.is_ascii_hexdigit()) || parent_id.bytes().all(|c| c == b'0') {
        return None;
    }
    Some(trace_id)
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    info!(service = "nddev-device-sync-server", event = "health.read");
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
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&database)
        .await
    {
        Ok(_) => Json(ReadyResponse {
            status: "ready",
            database: "ok",
        })
        .into_response(),
        Err(error) => {
            tracing::error!(event = "database.readiness_failed", error = %error);
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

pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nddev_device_sync_server=info".into()),
        )
        .try_init();
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
    }
}
