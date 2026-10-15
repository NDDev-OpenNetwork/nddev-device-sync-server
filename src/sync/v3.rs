//! Fixed version3 transport using existing owner/browser/signature authorization.
use super::http::{ApiError, authorize, service};
use crate::{AppState, identity, protocol_sync3 as dto};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use nddev_device_sync_application::sync::{history::*, *};
use serde::Deserialize;
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v3/sync", get(capabilities))
        .route("/v3/sync/operations", post(append))
        .route("/v3/sync/history", get(history))
        .route("/v3/sync/base", get(base))
}
pub(super) struct Error(HistoryFailure);
pub(super) struct LegacyError(HistoryFailure);
impl From<SyncError> for Error {
    fn from(e: SyncError) -> Self {
        Self(e.into())
    }
}
impl From<HistoryFailure> for Error {
    fn from(e: HistoryFailure) -> Self {
        Self(e)
    }
}
impl From<SyncError> for LegacyError {
    fn from(e: SyncError) -> Self {
        Self(e.into())
    }
}
impl From<HistoryFailure> for LegacyError {
    fn from(e: HistoryFailure) -> Self {
        Self(e)
    }
}
pub(super) fn legacy_error(e: HistoryFailure) -> LegacyError {
    LegacyError(e)
}
impl IntoResponse for LegacyError {
    fn into_response(self) -> Response {
        match self.0 {
            HistoryFailure::Standard(e) => ApiError::from(e).into_response(),
            HistoryFailure::Expired(e) => {
                super::telemetry::expired(&e.reason);
                (
                    StatusCode::GONE,
                    Json(serde_json::json!({"error":"cursor_expired"})),
                )
                    .into_response()
            }
        }
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self.0 {
            HistoryFailure::Standard(e) => ApiError::from(e).into_response(),
            HistoryFailure::Expired(e) => {
                super::telemetry::expired(&e.reason);
                let error = match e.reason {
                    ExpiredReason::Basis => dto::SyncExpiredError::BasisExpired,
                    ExpiredReason::Cursor => dto::SyncExpiredError::CursorExpired,
                    ExpiredReason::Checkpoint => dto::SyncExpiredError::CheckpointExpired,
                    ExpiredReason::LegacyMissing => dto::SyncExpiredError::LegacyOutcomeUnknown,
                };
                (
                    StatusCode::GONE,
                    Json(dto::SyncExpired {
                        schema_version: 3,
                        error,
                        floor_seq: e.history.floor as i64,
                        head_seq: e.history.head as i64,
                    }),
                )
                    .into_response()
            }
        }
    }
}
pub(super) fn original(e: RetainedEntry) -> Result<dto::SyncRow, SyncError> {
    Ok(dto::SyncRow {
        server_seq: e.original.server_seq as i64,
        operation_body: String::from_utf8(e.original.request_body)
            .map_err(|_| SyncError::Unavailable)?,
        result_body: String::from_utf8(e.original.result_body)
            .map_err(|_| SyncError::Unavailable)?,
        result_status: i64::from(e.original_status),
    })
}
fn encoded<T: serde::Serialize>(body: T) -> Result<Response, Error> {
    let bytes = serde_json::to_vec(&body).map_err(|_| SyncError::Unavailable)?;
    if bytes.len() > MAX_PAGE_BYTES {
        return Err(SyncError::Unavailable.into());
    }
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response())
}
async fn capabilities(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    if !body.is_empty() {
        return Err(SyncError::Invalid.into());
    }
    let now = identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) = authorize(&state, &headers, "GET", &uri, &body, now).await?;
    let mode = service(&state)?
        .history
        .read_mode(&auth, signed, now)
        .await?;
    encoded(dto::SyncCapabilities {
        schema_version: 3,
        read_operation_versions: vec![2, 3],
        new_operation_version: i64::from(mode),
        history_retention: mode == 3,
    })
}
async fn append(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    if body.len() > MAX_OPERATION_BYTES {
        return Err(SyncError::Invalid.into());
    }
    let now = identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) = authorize(&state, &headers, "POST", &uri, &body, now).await?;
    let wire: dto::SyncOperationV3 =
        serde_json::from_slice(&body).map_err(|_| SyncError::Invalid)?;
    let operation = super::codec::version3(wire, body.len())?;
    let result = service(&state)?
        .history
        .append_versioned(&auth, signed, operation, body.to_vec(), now)
        .await?;
    tracing::info!(
        module = "sync",
        scope = "http",
        event.name = "sync.operation.completed",
        outcome = if result.status == 201 {
            "accepted"
        } else {
            "rejected"
        }
    );
    Ok((
        StatusCode::from_u16(result.status).map_err(|_| SyncError::Unavailable)?,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        result.body,
    )
        .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryCursor {
    after_seq: u64,
    limit: Option<usize>,
}
async fn history(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    query: Result<Query<HistoryCursor>, QueryRejection>,
    body: Bytes,
) -> Result<Response, Error> {
    if !body.is_empty() {
        return Err(SyncError::Invalid.into());
    }
    let Query(cursor) = query.map_err(|_| SyncError::Invalid)?;
    let now = identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) = authorize(&state, &headers, "GET", &uri, &body, now).await?;
    let p = service(&state)?
        .history
        .history_page(
            &auth,
            signed,
            cursor.after_seq,
            cursor.limit.unwrap_or(MAX_PAGE_ITEMS),
            now,
        )
        .await?;
    let entries = p
        .contents
        .entries
        .into_iter()
        .map(original)
        .collect::<Result<Vec<_>, _>>()?;
    encoded(dto::SyncDeltaPage {
        schema_version: 3,
        floor_seq: p.history.floor as i64,
        head_seq: p.history.head as i64,
        next_after_seq: p.contents.next_after as i64,
        has_more: p.contents.has_more,
        entries,
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseCursor {
    base_seq: u64,
    after_member_seq: u64,
    limit: Option<usize>,
}
async fn base(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    query: Result<Query<BaseCursor>, QueryRejection>,
    body: Bytes,
) -> Result<Response, Error> {
    if !body.is_empty() {
        return Err(SyncError::Invalid.into());
    }
    let Query(cursor) = query.map_err(|_| SyncError::Invalid)?;
    let now = identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) = authorize(&state, &headers, "GET", &uri, &body, now).await?;
    let p = service(&state)?
        .history
        .base_page(
            &auth,
            signed,
            BaseRead {
                base: cursor.base_seq,
                after_member: cursor.after_member_seq,
                limit: cursor.limit.unwrap_or(MAX_PAGE_ITEMS),
            },
            now,
        )
        .await?;
    let entries = p
        .entries
        .into_iter()
        .map(original)
        .collect::<Result<Vec<_>, _>>()?;
    encoded(dto::SyncBasePage {
        schema_version: 3,
        base_seq: p.base as i64,
        total_members: i32::try_from(p.total_members).map_err(|_| SyncError::Unavailable)?,
        next_member_seq: p.next_member as i64,
        has_more: p.has_more,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nddev_device_sync_domain::sync::history::HistoryVersion;
    #[tokio::test]
    async fn expired_v3_is_not_an_applied_or_conflict_receipt() {
        let response = Error(HistoryFailure::Expired(ExpiredHistory {
            reason: ExpiredReason::Basis,
            history: HistoryVersion {
                head: 7,
                floor: 7,
                base: 7,
            },
        }))
        .into_response();
        assert_eq!(response.status(), StatusCode::GONE);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let result: dto::SyncExpired = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.floor_seq, 7);
        assert!(serde_json::from_slice::<crate::protocol_sync::Sync>(&bytes).is_err());
    }
    #[tokio::test]
    async fn expired_legacy_uses_only_the_reserved_v2_error_code() {
        let response = LegacyError(HistoryFailure::Expired(ExpiredHistory {
            reason: ExpiredReason::LegacyMissing,
            history: HistoryVersion {
                head: 7,
                floor: 7,
                base: 7,
            },
        }))
        .into_response();
        assert_eq!(response.status(), StatusCode::GONE);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            serde_json::json!({"error":"cursor_expired"})
        );
    }
    #[test]
    fn raw_entry_projection_keeps_original_order_whitespace_and_status() {
        let request = b"  {\"schema_version\":2, \"operation_id\":\"owned\"}\n".to_vec();
        let result = b" {\"outcome\":\"conflict\"}\t".to_vec();
        let row = original(RetainedEntry {
            original: Entry {
                request_body: request.clone(),
                result_body: result.clone(),
                server_seq: 2,
            },
            original_status: 409,
        })
        .unwrap();
        let bytes = serde_json::to_vec(&row).unwrap();
        let decoded: dto::SyncRow = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.operation_body.as_bytes(), request);
        assert_eq!(decoded.result_body.as_bytes(), result);
        assert_eq!(decoded.result_status, 409);
    }
}
