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
use nddev_device_sync_application::sync::*;
use nddev_device_sync_http_signatures as signatures;
use serde::Deserialize;

pub fn routes() -> Router<AppState> {
    Router::new().route("/v2/sync/operations", post(append).get(page))
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
            SyncError::Nonce | SyncError::Idempotency | SyncError::Revision => StatusCode::CONFLICT,
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
fn service(state: &AppState) -> Result<&super::Service, SyncError> {
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
async fn authorize(
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
fn decoded<const N: usize>(value: &str) -> Result<[u8; N], SyncError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SyncError::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(SyncError::Invalid);
    }
    bytes.try_into().map_err(|_| SyncError::Invalid)
}
fn operation(dto: dto::SyncOperation, size: usize) -> Result<Operation, SyncError> {
    if dto.schema_version != 2 || dto.base_revision < 0 {
        return Err(SyncError::Invalid);
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&dto.payload.ciphertext)
        .map_err(|_| SyncError::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&ciphertext) != dto.payload.ciphertext {
        return Err(SyncError::Invalid);
    }
    let operation = Operation {
        id: dto.operation_id,
        device: DeviceId::new(dto.device_id).map_err(|_| SyncError::Invalid)?,
        entity_id: dto.entity_id,
        base_revision: dto.base_revision as u64,
        idempotency_key: dto.idempotency_key,
        entity_kind: match dto.entity_type {
            dto::EntityType::DeviceState => EntityKind::DeviceState,
            dto::EntityType::ModuleState => EntityKind::ModuleState,
            dto::EntityType::VaultRecord => EntityKind::VaultRecord,
            dto::EntityType::AccountState => EntityKind::AccountState,
            dto::EntityType::ClipboardItem => EntityKind::ClipboardItem,
        },
        payload: EncryptedPayload {
            key_id: dto.payload.key_id,
            nonce: decoded(&dto.payload.nonce)?,
            ciphertext,
        },
    };
    operation.validate(size)?;
    Ok(operation)
}
async fn append(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    if body.len() > MAX_OPERATION_BYTES {
        return Err(SyncError::Invalid.into());
    }
    let now = identity::now_ms().map_err(identity_error)?;
    let (auth, signed) = authorize(&state, &headers, "POST", &uri, &body, now).await?;
    let dto: dto::SyncOperation = serde_json::from_slice(&body).map_err(|_| SyncError::Invalid)?;
    let operation = operation(dto, body.len())?;
    let value = service(&state)?
        .append(&auth, signed, operation, body.to_vec(), now)
        .await?;
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
) -> Result<Json<dto::SyncPage>, ApiError> {
    if !body.is_empty() {
        return Err(SyncError::Invalid.into());
    }
    let Query(cursor) = query.map_err(|_| SyncError::Invalid)?;
    let now = identity::now_ms().map_err(identity_error)?;
    let (auth, signed) = authorize(&state, &headers, "GET", &uri, &body, now).await?;
    let page = service(&state)?
        .page(
            &auth,
            signed,
            cursor.after_seq.unwrap_or(0),
            cursor.limit.unwrap_or(2),
            now,
        )
        .await?;
    let entries = page
        .entries
        .into_iter()
        .map(|entry| {
            Ok(dto::SyncEntry {
                operation: serde_json::from_slice(&entry.request_body)
                    .map_err(|_| SyncError::Unavailable)?,
                result: serde_json::from_slice(&entry.result_body)
                    .map_err(|_| SyncError::Unavailable)?,
            })
        })
        .collect::<Result<Vec<_>, SyncError>>()?;
    Ok(Json(dto::SyncPage {
        entries,
        next_after_seq: page.next_after as i64,
        has_more: page.has_more,
    }))
}
