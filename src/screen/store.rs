use crate::{identity::store::Store as IdentityStore, protocol_screen as dto};
use nddev_device_sync_application::{
    screen::*,
    sync::{AuthenticatedSession, SignedRequest, SyncError},
};
use nddev_device_sync_domain::{
    DeviceId,
    devices::{Device, DeviceStatus},
    identity::ProtectedDigest,
    modules::ModuleError,
    screen::{EndpointBinding, ScreenError, ViewIntent, ViewProjection, ViewState},
};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use std::future::Future;
type Tx<'a> = Transaction<'a, Postgres>;
pub const MAX_RETAINED_VIEWS: i64 = 64;
pub struct Store {
    identity: IdentityStore,
    origin: String,
}
impl Store {
    pub fn new(pool: sqlx::PgPool, origin: String) -> Self {
        Self {
            identity: IdentityStore::new(pool),
            origin,
        }
    }
}
fn unavailable<E>(_: E) -> ScreenError {
    ScreenError::Module(ModuleError::Unavailable)
}
fn invalid<E>(_: E) -> ScreenError {
    ScreenError::Module(ModuleError::InvalidInput)
}
fn integer(v: u64) -> Result<i64, ScreenError> {
    v.try_into().map_err(invalid)
}
fn unsigned(v: i64) -> Result<u64, ScreenError> {
    v.try_into().map_err(unavailable)
}
fn sync_error(e: SyncError) -> ScreenError {
    match e {
        SyncError::Unavailable => unavailable(e),
        SyncError::Capacity => ScreenError::Module(ModuleError::Busy),
        SyncError::Invalid => invalid(e),
        _ => ScreenError::Denied,
    }
}
async fn bounded<T>(work: impl Future<Output = Result<T, ScreenError>>) -> Result<T, ScreenError> {
    tokio::time::timeout(crate::database::DATABASE_TIMEOUT, work)
        .await
        .map_err(unavailable)?
}
async fn finish<T>(tx: Tx<'_>, result: Result<T, ScreenError>) -> Result<T, ScreenError> {
    // Reuse the canonical nonce/failure commit boundary; only unavailable I/O
    // rolls back. Never acknowledge before commit, even on replay/denied proof.
    let outcome = result.as_ref().map(|_| ()).map_err(|e| {
        if *e == unavailable(()) {
            SyncError::Unavailable
        } else {
            SyncError::Invalid
        }
    });
    if let Err(SyncError::Unavailable) = crate::sync::store::finish(tx, outcome).await {
        return Err(unavailable(()));
    }
    result
}
async fn authorize(
    tx: &mut Tx<'_>,
    auth: &AuthenticatedSession,
    signed: &SignedRequest,
    now: u64,
) -> Result<u64, ScreenError> {
    let now = now.max(crate::identity::now_ms().map_err(unavailable)?);
    let floor = crate::sync::store::authorize(tx, auth, signed, now)
        .await
        .map_err(sync_error)?;
    let owner = &auth.session.owner;
    sqlx::query(
        "DELETE FROM nds_screen_views WHERE user_id=$1 AND tenant_id=$2 AND expires_at_ms <= $3",
    )
    .bind(owner.user_id.as_str())
    .bind(owner.tenant_id.as_str())
    .bind(integer(floor)?)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    // Existing canonical facts retire permission, but keep early-ended receipts
    // through their original expiry. No receipt history or authority renewal.
    sqlx::query("UPDATE nds_screen_views v SET state='ended',native_grant=NULL WHERE v.user_id=$1 AND v.tenant_id=$2 AND v.state<>'ended' AND (NOT EXISTS(SELECT 1 FROM nds_sessions s WHERE s.token_digest=v.viewer_session AND s.user_id=v.user_id AND s.tenant_id=v.tenant_id AND s.expires_at_ms>$3) OR EXISTS(SELECT 1 FROM nds_devices d WHERE d.device_id IN(v.viewer_device,v.host_device) AND d.status<>'active'))").bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(integer(floor)?).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(floor)
}
async fn device(
    tx: &mut Tx<'_>,
    auth: &AuthenticatedSession,
    id: &DeviceId,
) -> Result<Device, ScreenError> {
    let owner = &auth.session.owner;
    let row =
        sqlx::query("SELECT * FROM nds_devices WHERE device_id=$1 AND user_id=$2 AND tenant_id=$3")
            .bind(id.as_str())
            .bind(owner.user_id.as_str())
            .bind(owner.tenant_id.as_str())
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?
            .ok_or(ScreenError::Denied)?;
    let value = crate::devices::store::device(&row).map_err(unavailable)?;
    if value.status != DeviceStatus::Active {
        return Err(ScreenError::Denied);
    }
    Ok(value)
}
fn binding_row(row: PgRow) -> Result<EndpointBinding, ScreenError> {
    Ok(EndpointBinding {
        device: DeviceId::new(row.try_get::<String, _>("device_id").map_err(unavailable)?)
            .map_err(unavailable)?,
        endpoint: row
            .try_get::<Vec<u8>, _>("endpoint")
            .map_err(unavailable)?
            .try_into()
            .map_err(unavailable)?,
        instance_id: *row
            .try_get::<uuid::Uuid, _>("instance_id")
            .map_err(unavailable)?
            .as_bytes(),
        revision: unsigned(row.try_get("revision").map_err(unavailable)?)?,
    })
}
async fn binding(
    tx: &mut Tx<'_>,
    auth: &AuthenticatedSession,
    id: &DeviceId,
) -> Result<Option<EndpointBinding>, ScreenError> {
    let owner = &auth.session.owner;
    sqlx::query(
        "SELECT * FROM nds_screen_bindings WHERE device_id=$1 AND user_id=$2 AND tenant_id=$3",
    )
    .bind(id.as_str())
    .bind(owner.user_id.as_str())
    .bind(owner.tenant_id.as_str())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .map(binding_row)
    .transpose()
}
fn intent(row: &PgRow) -> Result<ViewIntent, ScreenError> {
    let dto: dto::ScreenView = serde_json::from_slice(
        &row.try_get::<Vec<u8>, _>("original_projection")
            .map_err(unavailable)?,
    )
    .map_err(unavailable)?;
    let mut projection = super::http::projection(dto).map_err(unavailable)?;
    match row.try_get::<&str, _>("state").map_err(unavailable)? {
        "requested" => {}
        "ready" => projection.ready(projection.permit().lease.admitted_at_ms())?,
        "ended" => projection.end(),
        _ => return Err(unavailable(())),
    }
    let session = ProtectedDigest(
        row.try_get::<Vec<u8>, _>("viewer_session")
            .map_err(unavailable)?
            .try_into()
            .map_err(unavailable)?,
    );
    Ok(ViewIntent::restore(projection, session))
}
async fn load(
    tx: &mut Tx<'_>,
    auth: &AuthenticatedSession,
    id: &str,
) -> Result<PgRow, ScreenError> {
    let id = uuid::Uuid::parse_str(id).map_err(|_| ScreenError::Denied)?;
    let owner = &auth.session.owner;
    sqlx::query("SELECT * FROM nds_screen_views WHERE view_id=$1 AND user_id=$2 AND tenant_id=$3")
        .bind(id)
        .bind(owner.user_id.as_str())
        .bind(owner.tenant_id.as_str())
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?
        .ok_or(ScreenError::Denied)
}
async fn revalidate(
    tx: &mut Tx<'_>,
    auth: &AuthenticatedSession,
    signed: &SignedRequest,
    value: &ViewIntent,
    actor: ViewActor,
    now: u64,
) -> Result<(), ScreenError> {
    let owner = &auth.session.owner;
    let alive: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nds_sessions WHERE token_digest=$1 AND user_id=$2 AND tenant_id=$3 AND expires_at_ms>$4)").bind(value.viewer_session().0.as_slice()).bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(integer(now)?).fetch_one(&mut **tx).await.map_err(unavailable)?;
    if !alive {
        return Err(ScreenError::Denied);
    }
    let permit = value.permit();
    let viewer = device(tx, auth, &permit.viewer).await?;
    let host = device(tx, auth, &permit.host).await?;
    let viewer_binding = binding(tx, auth, &permit.viewer)
        .await?
        .ok_or(ScreenError::Denied)?;
    let host_binding = binding(tx, auth, &permit.host)
        .await?
        .ok_or(ScreenError::Denied)?;
    revalidate_view(
        auth,
        signed,
        ViewRows {
            viewer: &viewer,
            host: &host,
            viewer_binding: &viewer_binding,
            host_binding: &host_binding,
            viewer_active: None,
            host_active: None,
        },
        permit,
        actor,
        now,
    )
}
impl ScreenStore for Store {
    async fn binding(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        target: &DeviceId,
        now: u64,
    ) -> Result<Option<EndpointBinding>, ScreenError> {
        bounded(async {
            let mut tx = self.identity.transaction().await.map_err(unavailable)?;
            let result = async {
                authorize(&mut tx, auth, &signed, now).await?;
                device(&mut tx, auth, target).await?;
                binding(&mut tx, auth, target).await
            }
            .await;
            finish(tx, result).await
        })
        .await
    }
    async fn bind(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        claim: EndpointClaim,
        signature: [u8; 64],
        now: u64,
    ) -> Result<EndpointBinding, ScreenError> {
        bounded(async {
            let mut tx = self.identity.transaction().await.map_err(unavailable)?;
            let result = async {
                let now = authorize(&mut tx, auth, &signed, now).await?;
                let device = device(&mut tx, auth, &signed.device).await?;
                let current = binding(&mut tx, auth, &signed.device).await?;
                let (candidate, bytes) = validate_endpoint_claim(auth, &signed, &device, current.as_ref(), claim, &self.origin, now)?;
                let key = crate::devices::verifying_key(&nddev_device_sync_domain::devices::PublicDeviceKey(candidate.endpoint)).ok_or(ScreenError::Denied)?;
                if key.verify_strict(&bytes, &ed25519_dalek::Signature::from_bytes(&signature)).is_err() {
                    return Err(ScreenError::Denied);
                }
                // Verify BOTH fresh proofs BEFORE returning same current row.
                if current.as_ref().is_some_and(|v| v.instance_id == candidate.instance_id) {
                    return Ok(candidate);
                }
                let duplicate: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nds_screen_bindings WHERE endpoint=$1 AND device_id<>$2)").bind(candidate.endpoint.as_slice()).bind(candidate.device.as_str()).fetch_one(&mut *tx).await.map_err(unavailable)?;
                if duplicate {
                    return Err(ScreenError::Denied);
                }
                let owner = &auth.session.owner;
                sqlx::query("INSERT INTO nds_screen_bindings(device_id,user_id,tenant_id,endpoint,instance_id,revision) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(device_id) DO UPDATE SET endpoint=EXCLUDED.endpoint,instance_id=EXCLUDED.instance_id,revision=EXCLUDED.revision").bind(candidate.device.as_str()).bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(candidate.endpoint.as_slice()).bind(uuid::Uuid::from_bytes(candidate.instance_id)).bind(integer(candidate.revision)?).execute(&mut *tx).await.map_err(unavailable)?;
                retire_device(&mut tx, candidate.device.as_str()).await.map_err(unavailable)?;
                Ok(candidate)
            }
            .await;
            finish(tx, result).await
        })
        .await
    }
    async fn create(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        request: ViewRequest,
        body: Vec<u8>,
        now: u64,
    ) -> Result<ViewIntent, ScreenError> {
        bounded(async {
            let mut tx = self.identity.transaction().await.map_err(unavailable)?;
            let result = async {
                let now = authorize(&mut tx, auth, &signed, now).await?;
                let owner = &auth.session.owner;
                let row = sqlx::query("SELECT * FROM nds_screen_views WHERE user_id=$1 AND tenant_id=$2 AND viewer_device=$3 AND idempotency_key=$4").bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(signed.device.as_str()).bind(&request.idempotency_key).fetch_optional(&mut *tx).await.map_err(unavailable)?;
                if let Some(row) = row {
                    if row.try_get::<Vec<u8>, _>("fingerprint").map_err(unavailable)? != signed.fingerprint || row.try_get::<Vec<u8>, _>("request_body").map_err(unavailable)? != body {
                        return Err(ScreenError::Closed);
                    }
                    let value = intent(&row)?;
                    revalidate(&mut tx, auth, &signed, &value, ViewActor::Viewer, now).await?;
                    // Current terminal state is never projected back to Requested.
                    return Ok(value);
                }
                let viewer = device(&mut tx, auth, &signed.device).await?;
                let host = device(&mut tx, auth, &request.target).await?;
                let viewer_binding = binding(&mut tx, auth, &signed.device).await?.ok_or(ScreenError::Denied)?;
                let host_binding = binding(&mut tx, auth, &request.target).await?.ok_or(ScreenError::Denied)?;
                let active = sqlx::query("SELECT * FROM nds_screen_views WHERE user_id=$1 AND tenant_id=$2 AND state<>'ended' AND (viewer_device IN($3,$4) OR host_device IN($3,$4)) LIMIT 2").bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(viewer.id.as_str()).bind(host.id.as_str()).fetch_all(&mut *tx).await.map_err(unavailable)?;
                let active = active.iter().map(intent).collect::<Result<Vec<_>, _>>()?;
                let permit = authorize_view(
                    auth,
                    &signed,
                    ViewRows {
                        viewer: &viewer,
                        host: &host,
                        viewer_binding: &viewer_binding,
                        host_binding: &host_binding,
                        viewer_active: active.iter().find(|v| v.occupies(&viewer.id, now)),
                        host_active: active.iter().find(|v| v.occupies(&host.id, now)),
                    },
                    request,
                    now,
                )?;
                let count: i64 = sqlx::query_scalar("SELECT count(*) FROM nds_screen_views WHERE user_id=$1 AND tenant_id=$2").bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_one(&mut *tx).await.map_err(unavailable)?;
                if count >= MAX_RETAINED_VIEWS {
                    return Err(ScreenError::Module(ModuleError::Busy));
                }
                let value = ViewProjection::restore(uuid::Uuid::new_v4().to_string(), permit, ViewState::Requested).map_err(invalid)?;
                let projection = serde_json::to_vec(&super::http::public(&value)?).map_err(unavailable)?;
                let input: dto::ScreenViewRequest = serde_json::from_slice(&body).map_err(invalid)?;
                sqlx::query("INSERT INTO nds_screen_views(view_id,user_id,tenant_id,viewer_device,host_device,viewer_session,idempotency_key,fingerprint,request_body,original_projection,expires_at_ms,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'requested')")
                    .bind(uuid::Uuid::parse_str(value.id()).map_err(unavailable)?)
                    .bind(owner.user_id.as_str())
                    .bind(owner.tenant_id.as_str())
                    .bind(value.permit().viewer.as_str())
                    .bind(value.permit().host.as_str())
                    .bind(auth.binding.0.as_slice())
                    .bind(input.idempotency_key)
                    .bind(signed.fingerprint.as_slice())
                    .bind(body)
                    .bind(projection)
                    .bind(integer(value.permit().lease.expires_at_ms())?)
                    .execute(&mut *tx)
                    .await
                    .map_err(unavailable)?;
                Ok(ViewIntent::restore(value, auth.binding))
            }
            .await;
            finish(tx, result).await
        })
        .await
    }
    async fn incoming(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        now: u64,
    ) -> Result<Option<ViewIntent>, ScreenError> {
        bounded(async {
            let mut tx = self.identity.transaction().await.map_err(unavailable)?;
            let result = async {
                let now = authorize(&mut tx, auth, &signed, now).await?;
                let owner = &auth.session.owner;
                let row = sqlx::query("SELECT * FROM nds_screen_views WHERE user_id=$1 AND tenant_id=$2 AND host_device=$3 AND state<>'ended' LIMIT 1").bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(signed.device.as_str()).fetch_optional(&mut *tx).await.map_err(unavailable)?;
                if let Some(row) = row {
                    let value = intent(&row)?;
                    revalidate(&mut tx, auth, &signed, &value, ViewActor::Host, now).await?;
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            }
            .await;
            finish(tx, result).await
        })
        .await
    }
    async fn view(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        id: &str,
        now: u64,
    ) -> Result<(ViewIntent, Option<Vec<u8>>), ScreenError> {
        bounded(async {
            let mut tx = self.identity.transaction().await.map_err(unavailable)?;
            let result = async {
                let now = authorize(&mut tx, auth, &signed, now).await?;
                let row = load(&mut tx, auth, id).await?;
                let value = intent(&row)?;
                revalidate(&mut tx, auth, &signed, &value, ViewActor::Viewer, now).await?;
                Ok((value, row.try_get("native_grant").map_err(unavailable)?))
            }
            .await;
            finish(tx, result).await
        })
        .await
    }
    async fn ready(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        id: &str,
        native_grant: Vec<u8>,
        now: u64,
    ) -> Result<ViewIntent, ScreenError> {
        bounded(async {
            let mut tx = self.identity.transaction().await.map_err(unavailable)?;
            let result = async {
                let now = authorize(&mut tx, auth, &signed, now).await?;
                native_grant_payload(&native_grant)?;
                let row = load(&mut tx, auth, id).await?;
                let mut value = intent(&row)?;
                revalidate(&mut tx, auth, &signed, &value, ViewActor::Host, now).await?;
                if value.state(now) == ViewState::Ended {
                    return Err(ScreenError::Closed);
                }
                if let Some(old) = row
                    .try_get::<Option<Vec<u8>>, _>("native_grant")
                    .map_err(unavailable)?
                {
                    if old != native_grant {
                        return Err(ScreenError::Closed);
                    }
                    return Ok(value);
                }
                value.ready(now)?;
                sqlx::query(
                    "UPDATE nds_screen_views SET state='ready',native_grant=$2 WHERE view_id=$1",
                )
                .bind(uuid::Uuid::parse_str(id).map_err(invalid)?)
                .bind(native_grant)
                .execute(&mut *tx)
                .await
                .map_err(unavailable)?;
                Ok(value)
            }
            .await;
            finish(tx, result).await
        })
        .await
    }
    async fn end(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        id: &str,
        now: u64,
    ) -> Result<(), ScreenError> {
        bounded(async {
            let mut tx = self.identity.transaction().await.map_err(unavailable)?;
            let result = async {
                authorize(&mut tx, auth, &signed, now).await?;
                let row = load(&mut tx, auth, id).await?;
                let viewer: String = row.try_get("viewer_device").map_err(unavailable)?;
                let host: String = row.try_get("host_device").map_err(unavailable)?;
                if signed.device.as_str() != viewer && signed.device.as_str() != host {
                    return Err(ScreenError::Denied);
                }
                sqlx::query(
                    "UPDATE nds_screen_views SET state='ended',native_grant=NULL WHERE view_id=$1",
                )
                .bind(uuid::Uuid::parse_str(id).map_err(invalid)?)
                .execute(&mut *tx)
                .await
                .map_err(unavailable)?;
                Ok(())
            }
            .await;
            finish(tx, result).await
        })
        .await
    }
}
/// Called only inside existing device/session revocation transactions.
pub(crate) async fn retire_device(tx: &mut Tx<'_>, device: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE nds_screen_views SET state='ended',native_grant=NULL WHERE viewer_device=$1 OR host_device=$1").bind(device).execute(&mut **tx).await?;
    Ok(())
}
pub(crate) async fn retire_session(tx: &mut Tx<'_>, digest: &[u8]) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE nds_screen_views SET state='ended',native_grant=NULL WHERE viewer_session=$1",
    )
    .bind(digest)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
