pub mod crypto;
mod store;
use crate::{AppState, protocol_vault as dto, sync::http::ApiError};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, State},
    http::HeaderMap,
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nddev_device_sync_application::vault::*;
use std::sync::Arc;
use zeroize::Zeroizing;

pub type Service = VaultKeyService<store::Store>;
pub fn initialize(pool: sqlx::PgPool, wrapping: Arc<crypto::WrappingKey>) -> Service {
    VaultKeyService::new(store::Store::new(pool, wrapping))
}
pub fn routes() -> Router<AppState> {
    Router::new().route("/v2/vault/key", post(ensure))
}
async fn ensure(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<dto::VaultKey>, ApiError> {
    if body.len() > 1024 {
        return Err(SyncError::Invalid.into());
    }
    let service = state.vault.as_ref().ok_or(SyncError::Unavailable)?;
    let now = crate::identity::now_ms().map_err(|_| SyncError::Unavailable)?;
    let (auth, signed) =
        crate::sync::http::authorize(&state, &headers, "POST", &uri, &body, now).await?;
    let request: dto::VaultKeyRequest =
        serde_json::from_slice(&body).map_err(|_| SyncError::Invalid)?;
    let existing = request
        .existing_key
        .map(|value| {
            let encoded = Zeroizing::new(value.key_material);
            let bytes = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(encoded.as_bytes())
                    .map_err(|_| SyncError::Invalid)?,
            );
            let key = KeyMaterial::new(bytes.as_slice())?;
            if encoded.len() != 64
                || URL_SAFE_NO_PAD.encode(bytes.as_slice()) != encoded.as_str()
                || key.id() != value.key_id
            {
                return Err(SyncError::Invalid);
            }
            Ok(key)
        })
        .transpose()?;
    let key = service.ensure(&auth, signed, existing, now).await?;
    tracing::info!(
        module = "vault",
        scope = "http",
        event.name = "vault.key.delivery.completed",
        outcome = "ok"
    );
    Ok(Json(dto::VaultKey {
        key_id: key.id(),
        key_material: URL_SAFE_NO_PAD.encode(key.expose()),
    }))
}
