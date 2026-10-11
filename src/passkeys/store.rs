use crate::identity::store::bounded;
use nddev_device_sync_application::identity::*;
use sqlx::Row;
use webauthn_rs::prelude::Passkey;

#[derive(Clone)]
pub struct Store(pub sqlx::PgPool);
fn unavailable<E>(_: E) -> IdentityError {
    IdentityError::Unavailable
}
impl Store {
    pub async fn owner(&self) -> Result<Owner, IdentityError> {
        bounded(async {
            let row = sqlx::query("SELECT user_id,tenant_id FROM nds_owner WHERE singleton=1")
                .fetch_one(&self.0)
                .await
                .map_err(unavailable)?;
            Ok(Owner {
                user_id: UserId::new(row.try_get::<String, _>("user_id").map_err(unavailable)?)
                    .map_err(unavailable)?,
                tenant_id: TenantId::new(
                    row.try_get::<String, _>("tenant_id").map_err(unavailable)?,
                )
                .map_err(unavailable)?,
            })
        })
        .await
    }
    pub async fn credentials(&self, owner: &Owner) -> Result<Vec<Passkey>, IdentityError> {
        bounded(async {
        let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT credential FROM nds_passkeys WHERE user_id=$1 AND tenant_id=$2 ORDER BY credential_id LIMIT 17")
            .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_all(&self.0).await.map_err(unavailable)?;
        if rows.len() > 16 {
            return Err(IdentityError::Capacity);
        }
        rows.into_iter()
            .map(|value| serde_json::from_value(value).map_err(unavailable))
            .collect()

        }).await
    }
    pub async fn register(
        &self,
        auth: &AuthenticatedSession,
        key: Passkey,
        now: u64,
    ) -> Result<(), IdentityError> {
        bounded(async {
        let identity = crate::identity::store::Store::new(self.0.clone());
        let mut tx = identity.transaction().await?;
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nds_sessions WHERE token_digest=$1 AND user_id=$2 AND tenant_id=$3 AND expires_at_ms>$4)")
            .bind(auth.binding.0.as_slice()).bind(auth.session.owner.user_id.as_str()).bind(auth.session.owner.tenant_id.as_str()).bind(i64::try_from(now).map_err(|_| IdentityError::InvalidInput)?)
            .fetch_one(&mut *tx).await.map_err(unavailable)?;
        if !valid || now.saturating_add(SESSION_LIFETIME_MS).saturating_sub(auth.session.expires_at_ms) > 300_000 {
            return Err(IdentityError::Denied);
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM nds_passkeys WHERE user_id=$1 AND tenant_id=$2",
        )
        .bind(auth.session.owner.user_id.as_str())
        .bind(auth.session.owner.tenant_id.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
        if count >= 16 {
            return Err(IdentityError::Capacity);
        }
        sqlx::query("INSERT INTO nds_passkeys(credential_id,user_id,tenant_id,credential,created_at_ms) VALUES ($1,$2,$3,$4,$5)")
            .bind(key.cred_id().as_ref()).bind(auth.session.owner.user_id.as_str()).bind(auth.session.owner.tenant_id.as_str())
            .bind(serde_json::to_value(key).map_err(unavailable)?).bind(i64::try_from(now).map_err(|_| IdentityError::InvalidInput)?).execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)

        }).await
    }
    pub async fn authenticate(
        &self,
        owner: &Owner,
        key: Passkey,
        original: serde_json::Value,
        issue: SessionIssue,
    ) -> Result<Session, IdentityError> {
        bounded(async {
        let identity = crate::identity::store::Store::new(self.0.clone());
        let mut tx = identity.transaction().await?;
        let stored: Option<serde_json::Value> = sqlx::query_scalar("SELECT credential FROM nds_passkeys WHERE credential_id=$1 AND user_id=$2 AND tenant_id=$3 FOR UPDATE")
            .bind(key.cred_id().as_ref()).bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_optional(&mut *tx).await.map_err(unavailable)?;
        if stored.as_ref() != Some(&original) {
            return Err(IdentityError::Denied);
        }
        sqlx::query("UPDATE nds_passkeys SET credential=$2 WHERE credential_id=$1")
            .bind(key.cred_id().as_ref())
            .bind(serde_json::to_value(key).map_err(unavailable)?)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let session = crate::identity::store::insert_session(&mut tx, issue).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(session)

        }).await
    }
}
