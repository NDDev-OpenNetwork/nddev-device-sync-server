use super::crypto::{WrappingKey, generate};
use nddev_device_sync_application::vault::*;
use sqlx::Row;
use std::sync::Arc;
use subtle::ConstantTimeEq;

pub struct Store {
    identity: crate::identity::store::Store,
    wrapping: Arc<WrappingKey>,
}
impl Store {
    pub fn new(pool: sqlx::PgPool, wrapping: Arc<WrappingKey>) -> Self {
        Self {
            identity: crate::identity::store::Store::new(pool),
            wrapping,
        }
    }
}
fn unavailable<E>(_: E) -> SyncError {
    SyncError::Unavailable
}

impl VaultKeyStore for Store {
    async fn ensure(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        existing: Option<KeyMaterial>,
        now: u64,
    ) -> Result<KeyMaterial, SyncError> {
        tokio::time::timeout(crate::database::DATABASE_TIMEOUT, async {
            let mut tx = self.identity.transaction().await.map_err(unavailable)?;
            let outcome = async {
                let now = now.max(crate::identity::now_ms().map_err(unavailable)?);
                crate::sync::store::authorize(&mut tx, auth, &signed, now).await?;
                let owner = &auth.session.owner;
                let root: Option<String> = sqlx::query_scalar("SELECT root_key_id FROM public.nds_replica_counters WHERE user_id=$1 AND tenant_id=$2 FOR UPDATE")
                    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_one(&mut *tx).await.map_err(unavailable)?;
                let envelope = sqlx::query("SELECT key_id,nonce,ciphertext FROM nds_vault_keys WHERE user_id=$1 AND tenant_id=$2")
                    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_optional(&mut *tx).await.map_err(unavailable)?;
                if let Some(row) = envelope {
                    let id: String = row.try_get("key_id").map_err(unavailable)?;
                    if root.as_deref() != Some(id.as_str()) { return Err(SyncError::KeyConflict); }
                    let key = self.wrapping.open(owner, &id, &row.try_get::<Vec<u8>,_>("nonce").map_err(unavailable)?,
                        &row.try_get::<Vec<u8>,_>("ciphertext").map_err(unavailable)?)?;
                    if existing.as_ref().is_some_and(|existing| !bool::from(existing.expose().ct_eq(key.expose()))) {
                        return Err(SyncError::KeyConflict);
                    }
                    return Ok(key);
                }
                let key = match (root.as_deref(), existing) {
                    (Some(root), Some(key)) if root == key.id() => key,
                    (Some(_), Some(_)) => return Err(SyncError::KeyConflict),
                    (Some(_), None) => return Err(SyncError::KeyRegistration),
                    (None, Some(key)) => key,
                    (None, None) => generate()?,
                };
                let (nonce, ciphertext) = self.wrapping.seal(owner, &key)?;
                sqlx::query("INSERT INTO nds_vault_keys(user_id,tenant_id,key_id,nonce,ciphertext) VALUES ($1,$2,$3,$4,$5)")
                    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(key.id())
                    .bind(nonce.as_slice()).bind(ciphertext).execute(&mut *tx).await.map_err(unavailable)?;
                sqlx::query("UPDATE public.nds_replica_counters SET root_key_id=$3 WHERE user_id=$1 AND tenant_id=$2")
                    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(key.id()).execute(&mut *tx).await.map_err(unavailable)?;
                Ok(key)
            }.await;
            crate::sync::store::finish(tx, outcome).await
        }).await.map_err(unavailable)?
    }
}
