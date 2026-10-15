use crate::{AppState, identity, protocol_sync as dto};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nddev_device_sync_application::sync::history::HistoryStore;
use nddev_device_sync_application::sync::*;
use nddev_device_sync_http_signatures as signatures;
use serde::Deserialize;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v2/sync/operations", post(append).get(page))
        .merge(super::v3::routes())
}
pub struct ApiError(SyncError);
impl From<SyncError> for ApiError {
    fn from(error: SyncError) -> Self {
        Self(error)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            SyncError::Invalid => StatusCode::BAD_REQUEST,
            SyncError::Denied => StatusCode::UNAUTHORIZED,
            SyncError::Revoked => StatusCode::FORBIDDEN,
            SyncError::Signature => StatusCode::BAD_REQUEST,
            SyncError::Nonce
            | SyncError::Idempotency
            | SyncError::Revision
            | SyncError::KeyConflict
            | SyncError::KeyRegistration
            | SyncError::CapacityExhausted => StatusCode::CONFLICT,
            SyncError::Capacity | SyncError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        tracing::warn!(module="sync",scope="http",event.name="sync.request.rejected",error.type=%self.0,outcome="rejected");
        let mut response = (
            status,
            Json(serde_json::json!({"error":self.0.to_string()})),
        )
            .into_response();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            response
                .headers_mut()
                .insert("retry-after", HeaderValue::from_static("2"));
        }
        response
    }
}
fn identity_error(error: nddev_device_sync_application::identity::IdentityError) -> SyncError {
    match error {
        nddev_device_sync_application::identity::IdentityError::Denied => SyncError::Denied,
        _ => SyncError::Unavailable,
    }
}
pub(super) fn service(state: &AppState) -> Result<&super::Service, SyncError> {
    state.sync.as_deref().ok_or(SyncError::Unavailable)
}
fn one(headers: &HeaderMap, name: &str) -> Result<String, SyncError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(SyncError::Signature)?;
    if values.next().is_some() {
        return Err(SyncError::Signature);
    }
    value
        .to_str()
        .map(str::to_owned)
        .map_err(|_| SyncError::Signature)
}
struct Key {
    public: ed25519_dalek::VerifyingKey,
    id: String,
}
impl signatures::VerifyingKey for Key {
    fn key_id(&self) -> String {
        self.id.clone()
    }
    fn alg(&self) -> signatures::AlgorithmName {
        signatures::AlgorithmName::Ed25519
    }
    fn verify(&self, data: &[u8], signature: &[u8]) -> signatures::HttpSigResult<()> {
        let signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| signatures::HttpSigError::InvalidSignature("invalid".into()))?;
        self.public
            .verify_strict(data, &signature)
            .map_err(|_| signatures::HttpSigError::InvalidSignature("invalid".into()))
    }
}
pub(crate) async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    uri: &axum::http::Uri,
    body: &[u8],
    now: u64,
) -> Result<(AuthenticatedSession, SignedRequest), SyncError> {
    service(state)?;
    let bearer = identity::http::bearer(headers).map_err(identity_error)?;
    let auth = state
        .identity
        .as_ref()
        .ok_or(SyncError::Unavailable)?
        .authenticate(bearer, now)
        .await
        .map_err(identity_error)?;
    let headers = signatures::Headers {
        signature: one(headers, "signature")?,
        signature_input: one(headers, "signature-input")?,
        content_digest: one(headers, "content-digest")?,
    };
    let id = signatures::device_id(&headers, now / 1000).map_err(|_| SyncError::Signature)?;
    let pool = state.database.as_ref().ok_or(SyncError::Unavailable)?;
    let public: Option<Vec<u8>> = tokio::time::timeout(
        crate::database::DATABASE_TIMEOUT,
        sqlx::query_scalar(
            "SELECT public_key FROM nds_devices WHERE device_id=$1 AND user_id=$2 AND tenant_id=$3",
        )
        .bind(&id)
        .bind(auth.session.owner.user_id.as_str())
        .bind(auth.session.owner.tenant_id.as_str())
        .fetch_optional(pool),
    )
    .await
    .map_err(|_| SyncError::Unavailable)?
    .map_err(|_| SyncError::Unavailable)?;
    let public: [u8; 32] = public
        .ok_or(SyncError::Denied)?
        .try_into()
        .map_err(|_| SyncError::Unavailable)?;
    let key = Key {
        public: ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|_| SyncError::Unavailable)?,
        id,
    };
    let origin = state
        .config
        .public_origin
        .as_ref()
        .ok_or(SyncError::Unavailable)?
        .origin()
        .ascii_serialization();
    let target = format!(
        "{origin}{}",
        uri.path_and_query().ok_or(SyncError::Invalid)?.as_str()
    );
    let proof = signatures::verify(method, &target, body, &headers, &key, now / 1000)
        .map_err(|_| SyncError::Signature)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, body);
    Ok((
        auth,
        SignedRequest {
            device: DeviceId::new(proof.device_id).map_err(|_| SyncError::Signature)?,
            nonce: proof.nonce,
            expires_at_ms: proof
                .expires
                .checked_mul(1000)
                .ok_or(SyncError::Signature)?,
            fingerprint: digest
                .as_ref()
                .try_into()
                .map_err(|_| SyncError::Unavailable)?,
        },
    ))
}
pub(super) fn decoded<const N: usize>(value: &str) -> Result<[u8; N], SyncError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SyncError::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(SyncError::Invalid);
    }
    bytes.try_into().map_err(|_| SyncError::Invalid)
}
fn operation(dto: dto::SyncOperation, size: usize) -> Result<Operation, SyncError> {
    Ok(super::codec::legacy(dto, size)?.operation)
}

async fn append(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, super::v3::LegacyError> {
    if body.len() > MAX_OPERATION_BYTES {
        return Err(SyncError::Invalid.into());
    }
    let now = identity::now_ms().map_err(identity_error)?;
    let (auth, signed) = authorize(&state, &headers, "POST", &uri, &body, now).await?;
    let dto: dto::SyncOperation = serde_json::from_slice(&body).map_err(|_| SyncError::Invalid)?;
    let operation = operation(dto, body.len())?;
    let value = service(&state)?
        .history
        .append_versioned(
            &auth,
            signed,
            nddev_device_sync_domain::sync::history::VersionedOperation {
                operation,
                version: nddev_device_sync_domain::sync::history::OperationVersion::V2,
            },
            body.to_vec(),
            now,
        )
        .await
        .map_err(super::v3::legacy_error)?;
    let status = StatusCode::from_u16(value.status).map_err(|_| SyncError::Unavailable)?;
    tracing::info!(
        module = "sync",
        scope = "http",
        event.name = "sync.operation.completed",
        outcome = if status == StatusCode::CREATED {
            "accepted"
        } else {
            "rejected"
        }
    );
    Ok((status, [(CONTENT_TYPE, "application/json")], value.body).into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    after_seq: Option<u64>,
    limit: Option<usize>,
}
async fn page(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    query: Result<Query<Cursor>, QueryRejection>,
    body: Bytes,
) -> Result<Response, super::v3::LegacyError> {
    if !body.is_empty() {
        return Err(SyncError::Invalid.into());
    }
    let Query(cursor) = query.map_err(|_| SyncError::Invalid)?;
    let now = identity::now_ms().map_err(identity_error)?;
    let (auth, signed) = authorize(&state, &headers, "GET", &uri, &body, now).await?;
    let p = service(&state)?
        .history
        .read_history_page(
            &auth,
            signed,
            cursor.after_seq.unwrap_or(0),
            cursor.limit.unwrap_or(2),
            now,
            true,
        )
        .await?;
    // V2 objects cannot represent a V3 original; never return a partial success or
    // advance an old decoder over an unsupported version after activation.
    for e in &p.contents.entries {
        if serde_json::from_slice::<dto::SyncOperation>(&e.original.request_body).is_err() {
            return Err(
                nddev_device_sync_application::sync::history::HistoryFailure::Expired(
                    nddev_device_sync_application::sync::history::ExpiredHistory {
                        reason: nddev_device_sync_application::sync::history::ExpiredReason::Cursor,
                        history: p.history,
                    },
                )
                .into(),
            );
        }
    }
    let page = Page {
        entries: p.contents.entries.into_iter().map(|e| e.original).collect(),
        next_after: p.contents.next_after,
        has_more: p.contents.has_more,
    };
    Ok(Json(bounded_page(
        page,
        cursor.after_seq.unwrap_or(0),
        MAX_PAGE_BYTES,
    )?)
    .into_response())
}

/// Measure the actual wire entries, including base64 and result metadata. The
/// fixed envelope reserves the longest valid cursor and boolean representation;
/// it cannot underestimate the final JSON response. Never split an operation or
/// advance the cursor past an entry that did not fit in this response.
fn bounded_page(page: Page, after: u64, max_bytes: usize) -> Result<dto::SyncPage, SyncError> {
    let mut response = dto::SyncPage {
        entries: Vec::new(),
        next_after_seq: i64::try_from(after).map_err(|_| SyncError::Unavailable)?,
        has_more: page.has_more,
    };
    let mut encoded_bytes = serde_json::to_vec(&dto::SyncPage {
        entries: Vec::new(),
        next_after_seq: MAX_REVISION as i64,
        has_more: false,
    })
    .map_err(|_| SyncError::Unavailable)?
    .len();
    if encoded_bytes > max_bytes {
        return Err(SyncError::Unavailable);
    }
    for stored in page.entries {
        let entry = dto::SyncEntry {
            operation: serde_json::from_slice(&stored.request_body)
                .map_err(|_| SyncError::Unavailable)?,
            result: serde_json::from_slice(&stored.result_body)
                .map_err(|_| SyncError::Unavailable)?,
        };
        let size = serde_json::to_vec(&entry)
            .map_err(|_| SyncError::Unavailable)?
            .len();
        let next_size = encoded_bytes
            .saturating_add(size)
            .saturating_add(usize::from(!response.entries.is_empty()));
        if next_size > max_bytes {
            if response.entries.is_empty() {
                return Err(SyncError::Unavailable);
            }
            response.has_more = true;
            break;
        }
        encoded_bytes = next_size;
        response.next_after_seq =
            i64::try_from(stored.server_seq).map_err(|_| SyncError::Unavailable)?;
        response.entries.push(entry);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn persistent_capacity_is_an_error_without_retry_after_or_receipt() {
        let response = ApiError(SyncError::CapacityExhausted).into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response.headers().get("retry-after").is_none());
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"error":"sync_capacity_exhausted"})
        );
        assert!(serde_json::from_slice::<dto::Sync>(&body).is_err());
        assert!(serde_json::from_slice::<dto::SyncPage>(&body).is_err());
    }

    #[tokio::test]
    async fn temporary_admission_retains_service_unavailable_and_retry_after() {
        let response = ApiError(SyncError::Capacity).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get("retry-after").unwrap(), "2");
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"error":"server_busy"})
        );
    }

    fn entry(sequence: u64, ciphertext_bytes: usize) -> Entry {
        let id = format!("operation-{sequence}");
        let operation: dto::SyncOperation = serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "operation_id": id,
            "device_id": "generated-device",
            "entity_id": "generated-record",
            "entity_type": "vault_record",
            "base_revision": sequence - 1,
            "idempotency_key": id,
            "payload": {
                "algorithm": "aes-256-gcm",
                "key_id": "generated-key",
                "nonce": URL_SAFE_NO_PAD.encode([0_u8; 12]),
                "ciphertext": URL_SAFE_NO_PAD.encode(vec![0_u8; ciphertext_bytes])
            }
        }))
        .unwrap();
        Entry {
            request_body: serde_json::to_vec(&operation).unwrap(),
            result_body: serde_json::to_vec(&dto::SyncApplied {
                operation_id: id,
                outcome: dto::SyncAppliedOutcome::Applied,
                revision: sequence as i64,
                server_seq: sequence as i64,
            })
            .unwrap(),
            server_seq: sequence,
        }
    }

    #[test]
    fn small_entries_use_the_requested_count_without_exceeding_the_wire_budget() {
        let result = bounded_page(
            Page {
                entries: (1..=100).map(|sequence| entry(sequence, 32)).collect(),
                next_after: 100,
                has_more: true,
            },
            0,
            MAX_PAGE_BYTES,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 100);
        assert_eq!(result.next_after_seq, 100);
        assert!(result.has_more);
        assert!(serde_json::to_vec(&result).unwrap().len() <= MAX_PAGE_BYTES);
    }

    #[test]
    fn byte_limited_pages_preserve_the_complete_ordered_history() {
        let mut cursor = 0_u64;
        let mut seen = Vec::new();
        while cursor < 7 {
            let result = bounded_page(
                Page {
                    entries: (cursor + 1..=7)
                        .map(|sequence| entry(sequence, 16_000))
                        .collect(),
                    next_after: 7,
                    has_more: false,
                },
                cursor,
                MAX_PAGE_BYTES,
            )
            .unwrap();
            assert!(serde_json::to_vec(&result).unwrap().len() <= MAX_PAGE_BYTES);
            assert!(!result.entries.is_empty());
            for entry in result.entries {
                let sequence = match entry.result {
                    dto::Sync::Applied(value) => value.server_seq as u64,
                    _ => panic!("generated applied receipt required"),
                };
                assert_eq!(sequence, cursor + 1);
                cursor = sequence;
                seen.push(cursor);
            }
            assert_eq!(result.next_after_seq as u64, cursor);
            assert_eq!(result.has_more, cursor < 7);
        }
        assert_eq!(seen, (1..=7).collect::<Vec<_>>());
    }

    #[test]
    fn empty_and_maximum_cursor_pages_keep_their_position_and_bound() {
        let empty = bounded_page(
            Page {
                entries: Vec::new(),
                next_after: MAX_REVISION,
                has_more: false,
            },
            MAX_REVISION,
            MAX_PAGE_BYTES,
        )
        .unwrap();
        assert_eq!(empty.next_after_seq as u64, MAX_REVISION);
        assert!(!empty.has_more && empty.entries.is_empty());
        let final_page = bounded_page(
            Page {
                entries: vec![entry(MAX_REVISION, 16_000)],
                next_after: MAX_REVISION,
                has_more: false,
            },
            MAX_REVISION - 1,
            MAX_PAGE_BYTES,
        )
        .unwrap();
        assert_eq!(final_page.next_after_seq as u64, MAX_REVISION);
        assert!(serde_json::to_vec(&final_page).unwrap().len() <= MAX_PAGE_BYTES);
        assert!(matches!(
            bounded_page(
                Page {
                    entries: vec![entry(1, 32)],
                    next_after: 1,
                    has_more: false,
                },
                0,
                64,
            ),
            Err(SyncError::Unavailable)
        ));
    }
}
