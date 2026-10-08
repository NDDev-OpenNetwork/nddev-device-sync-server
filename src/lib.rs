pub mod config;

use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use nddev_device_sync_application::builtin_modules;
use serde::Serialize;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tracing::{info, info_span, Instrument};
use uuid::Uuid;

use config::ServerConfig;

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

async fn request_trace<B>(request: Request<B>, next: Next) -> Response {
    let trace_id = request
        .headers()
        .get("traceparent")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split('-').nth(1))
        .filter(|value| value.len() == 32)
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let span = info_span!(
        "http.request",
        trace_id = %trace_id,
        method = %request.method(),
        path = %request.uri().path()
    );
    next.run(request).instrument(span).await
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    info!(service = "nddev-device-sync-server", event = "health.read");
    Json(HealthResponse {
        status: "ok",
        service: "nddev-device-sync-server",
        version: state.config.version,
        channel: state.config.channel,
        standards_release: state.config.standards_release,
        module_count: state.module_count,
        telemetry_enabled: state.config.telemetry_enabled,
        database_configured: state.database.is_some(),
    })
}

async fn ready(State(state): State<AppState>) -> Response {
    let Some(database) = state.database else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse { status: "degraded", database: "not_configured" }),
        )
            .into_response();
    };
    match sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&database).await {
        Ok(_) => Json(ReadyResponse { status: "ready", database: "ok" }).into_response(),
        Err(error) => {
            tracing::error!(event = "database.readiness_failed", error = %error);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadyResponse { status: "degraded", database: "error" }),
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
                    .header("traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
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
}
