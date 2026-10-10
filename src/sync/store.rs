use crate::identity::{now_ms, store::Store as IdentityStore};
use nddev_device_sync_application::sync::*;
use sqlx::{Postgres, Row, Transaction};
use std::future::Future;
type Tx<'a> = Transaction<'a, Postgres>;
pub struct Store {
    identity: IdentityStore,
}
impl Store {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            identity: IdentityStore::new(pool),
        }
    }
}
fn unavailable<E>(_: E) -> SyncError {
    SyncError::Unavailable
}
fn integer(value: u64) -> Result<i64, SyncError> {
    value.try_into().map_err(unavailable)
}
fn counter(value: i64) -> Result<u64, SyncError> {
    value.try_into().map_err(unavailable)
}
async fn bounded<T>(work: impl Future<Output = Result<T, SyncError>>) -> Result<T, SyncError> {
    tokio::time::timeout(crate::database::DATABASE_TIMEOUT, work)
        .await
        .map_err(unavailable)?
}
async fn finish<T>(tx: Tx<'_>, result: Result<T, SyncError>) -> Result<T, SyncError> {
    if matches!(result, Err(SyncError::Unavailable)) {
        return result;
    }
    tx.commit().await.map_err(unavailable)?;
    result
}
async fn authorize(
    tx: &mut Tx<'_>,
    auth: &AuthenticatedSession,
    signed: &SignedRequest,
    now: u64,
) -> Result<u64, SyncError> {
    let owner = &auth.session.owner;
    let session:Option<i64>=sqlx::query_scalar("SELECT expires_at_ms FROM nds_sessions WHERE token_digest=$1 AND user_id=$2 AND tenant_id=$3")
        .bind(auth.binding.0.as_slice()).bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_optional(&mut **tx).await.map_err(unavailable)?;
    if !session.is_some_and(|expires| expires > now as i64) {
        return Err(SyncError::Denied);
    }
    let status:Option<String>=sqlx::query_scalar("SELECT status FROM nds_devices WHERE device_id=$1 AND user_id=$2 AND tenant_id=$3 FOR UPDATE")
        .bind(signed.device.as_str()).bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_optional(&mut **tx).await.map_err(unavailable)?;
    match status.as_deref() {
        Some("active") => {}
        Some("revoked") => return Err(SyncError::Revoked),
        _ => return Err(SyncError::Denied),
    }
    sqlx::query(
        "INSERT INTO nds_sync_counters(user_id,tenant_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(owner.user_id.as_str())
    .bind(owner.tenant_id.as_str())
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    let floor:i64=sqlx::query_scalar("UPDATE nds_sync_counters SET clock_floor_ms=GREATEST(clock_floor_ms,$3) WHERE user_id=$1 AND tenant_id=$2 RETURNING clock_floor_ms")
        .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(integer(now)?).fetch_one(&mut **tx).await.map_err(unavailable)?;
    let now = counter(floor)?;
    if session.is_none_or(|expires| expires <= floor) {
        return Err(SyncError::Denied);
    }
    if signed.expires_at_ms <= now {
        return Err(SyncError::Signature);
    }
    sqlx::query("DELETE FROM nds_sync_nonces WHERE expires_at_ms <= $1")
        .bind(floor)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM nds_sync_nonces WHERE device_id=$1")
        .bind(signed.device.as_str())
        .fetch_one(&mut **tx)
        .await
        .map_err(unavailable)?;
    if count >= 512 {
        return Err(SyncError::Capacity);
    }
    let inserted=sqlx::query("INSERT INTO nds_sync_nonces(device_id,nonce,expires_at_ms) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
        .bind(signed.device.as_str()).bind(&signed.nonce).bind(integer(signed.expires_at_ms)?).execute(&mut **tx).await.map_err(unavailable)?;
    if inserted.rows_affected() != 1 {
        return Err(SyncError::Nonce);
    }
    Ok(now)
}

impl SyncStore for Store {
    async fn append(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        operation: Operation,
        body: Vec<u8>,
        now: u64,
    ) -> Result<StoredResult, SyncError> {
        bounded(async {
            let mut tx=self.identity.transaction().await.map_err(unavailable)?;
            let now=now.max(now_ms().map_err(unavailable)?);
            let outcome=async {
                authorize(&mut tx,auth,&signed,now).await?;
                let owner=&auth.session.owner;
                // Both names bind to one immutable receipt; neither can be reused
                // with different exact request bytes or a different operation.
                let receipts=sqlx::query("SELECT fingerprint,status,result_body FROM nds_sync_operations WHERE user_id=$1 AND tenant_id=$2 AND device_id=$3 AND (idempotency_key=$4 OR operation_id=$5)")
                    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(signed.device.as_str()).bind(&operation.idempotency_key).bind(&operation.id).fetch_all(&mut *tx).await.map_err(unavailable)?;
                if let Some(receipt)=receipts.first() {
                    if receipts.len()!=1 || receipt.try_get::<Vec<u8>,_>("fingerprint").map_err(unavailable)?!=signed.fingerprint {
                        return Err(SyncError::Idempotency);
                    }
                    return Ok(StoredResult {status:receipt.try_get::<i16,_>("status").map_err(unavailable)?.try_into().map_err(unavailable)?,body:receipt.try_get("result_body").map_err(unavailable)?});
                }
                let counters=sqlx::query("SELECT server_seq,operation_count,stored_bytes FROM nds_sync_counters WHERE user_id=$1 AND tenant_id=$2 FOR UPDATE")
                    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_one(&mut *tx).await.map_err(unavailable)?;
                let seq=counter(counters.try_get("server_seq").map_err(unavailable)?)?.checked_add(1).filter(|value|*value<=MAX_REVISION).ok_or(SyncError::Revision)?;
                let count=counter(counters.try_get("operation_count").map_err(unavailable)?)?;
                let retained=counter(counters.try_get("stored_bytes").map_err(unavailable)?)?;
                let current:Option<i64>=sqlx::query_scalar("SELECT revision FROM nds_sync_entities WHERE user_id=$1 AND tenant_id=$2 AND entity_type=$3 AND entity_id=$4 FOR UPDATE")
                    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(operation.entity_kind.as_str()).bind(&operation.entity_id).fetch_optional(&mut *tx).await.map_err(unavailable)?;
                let current=current.map(counter).transpose()?.unwrap_or(0);
                let decision=operation.decide(current)?;
                let (status,result)=match decision {
                    Decision::Apply{revision}=>(201,serde_json::to_vec(&crate::protocol_sync::SyncApplied{operation_id:operation.id.clone(),outcome:crate::protocol_sync::SyncAppliedOutcome::Applied,revision:integer(revision)?,server_seq:integer(seq)?}).map_err(unavailable)?),
                    Decision::Conflict{base_revision,current_revision}=>(409,serde_json::to_vec(&crate::protocol_sync::SyncConflict{operation_id:operation.id.clone(),outcome:crate::protocol_sync::SyncConflictOutcome::Conflict,resolution_state:crate::protocol_sync::ResolutionState::Unresolved,base_revision:integer(base_revision)?,current_revision:integer(current_revision)?,server_seq:integer(seq)?}).map_err(unavailable)?),
                };
                // Count retained request/result and an entity replacement as well;
                // conservative accounting keeps the total finite without pruning.
                let cost=(body.len()*2+result.len()) as u64;
                if count>=MAX_OPERATIONS || retained.checked_add(cost).is_none_or(|value|value>MAX_STORED_BYTES) { return Err(SyncError::Capacity); }
                if let Decision::Apply{revision}=decision {
                    if current==0 {
                        let entities:i64=sqlx::query_scalar("SELECT count(*) FROM nds_sync_entities WHERE user_id=$1 AND tenant_id=$2").bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_one(&mut *tx).await.map_err(unavailable)?;
                        if entities>=MAX_ENTITY_COUNT as i64 { return Err(SyncError::Capacity); }
                    }
                    sqlx::query("INSERT INTO nds_sync_entities(user_id,tenant_id,entity_type,entity_id,revision,request_body) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT(user_id,tenant_id,entity_type,entity_id) DO UPDATE SET revision=EXCLUDED.revision,request_body=EXCLUDED.request_body")
                        .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(operation.entity_kind.as_str()).bind(&operation.entity_id).bind(integer(revision)?).bind(&body).execute(&mut *tx).await.map_err(unavailable)?;
                }
                sqlx::query("INSERT INTO nds_sync_operations(user_id,tenant_id,device_id,operation_id,idempotency_key,fingerprint,server_seq,request_body,result_body,status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
                    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(signed.device.as_str()).bind(&operation.id).bind(&operation.idempotency_key).bind(signed.fingerprint.as_slice()).bind(integer(seq)?).bind(&body).bind(&result).bind(status as i16).execute(&mut *tx).await.map_err(unavailable)?;
                sqlx::query("UPDATE nds_sync_counters SET server_seq=$3,operation_count=operation_count+1,stored_bytes=stored_bytes+$4 WHERE user_id=$1 AND tenant_id=$2")
                    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(integer(seq)?).bind(integer(cost)?).execute(&mut *tx).await.map_err(unavailable)?;
                Ok(StoredResult{status,body:result})
            }.await;
            finish(tx,outcome).await
        }).await
    }
    async fn page(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        after: u64,
        limit: usize,
        now: u64,
    ) -> Result<Page, SyncError> {
        bounded(async {
            let mut tx=self.identity.transaction().await.map_err(unavailable)?;
            let now=now.max(now_ms().map_err(unavailable)?);
            let outcome=async {
                authorize(&mut tx,auth,&signed,now).await?;
                let owner=&auth.session.owner;
                let head:i64=sqlx::query_scalar("SELECT server_seq FROM nds_sync_counters WHERE user_id=$1 AND tenant_id=$2").bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_one(&mut *tx).await.map_err(unavailable)?;
                if after>counter(head)? { return Err(SyncError::Invalid); }
                let rows=sqlx::query("SELECT server_seq,request_body,result_body FROM nds_sync_operations WHERE user_id=$1 AND tenant_id=$2 AND server_seq>$3 ORDER BY server_seq LIMIT $4")
                    .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(integer(after)?).bind((limit+1) as i64).fetch_all(&mut *tx).await.map_err(unavailable)?;
                let has_more=rows.len()>limit;
                let entries=rows.into_iter().take(limit).map(|row| Ok(Entry{server_seq:counter(row.try_get("server_seq").map_err(unavailable)?)?,request_body:row.try_get("request_body").map_err(unavailable)?,result_body:row.try_get("result_body").map_err(unavailable)?})).collect::<Result<Vec<_>,SyncError>>()?;
                Ok(Page{next_after:entries.last().map_or(after,|entry|entry.server_seq),entries,has_more})
            }.await;
            finish(tx,outcome).await
        }).await
    }
}
