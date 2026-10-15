//! Concrete PG I/O for the sealed Core history contract. No policy/DTO/AAD copy.
use super::*;
use crate::sync::telemetry::AppendEffect;
use nddev_device_sync_application::sync::history::*;
use nddev_device_sync_domain::sync::history::*;
use sqlx::postgres::PgRow;
use std::future::Future;

struct Counters {
    version: HistoryVersion,
    mode: i16,
    count: u64,
    bytes: u64,
    root: Option<String>,
}
async fn counters(tx: &mut Tx<'_>, auth: &AuthenticatedSession) -> Result<Counters, SyncError> {
    let owner = &auth.session.owner;
    let row=sqlx::query("SELECT server_seq,floor_seq,base_seq,admission_version,operation_count,stored_bytes,root_key_id FROM public.nds_replica_counters WHERE user_id=$1 AND tenant_id=$2 FOR UPDATE")
  .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).fetch_one(&mut **tx).await.map_err(unavailable)?;
    let c = Counters {
        version: HistoryVersion {
            head: counter(row.try_get("server_seq").map_err(unavailable)?)?,
            floor: counter(row.try_get("floor_seq").map_err(unavailable)?)?,
            base: counter(row.try_get("base_seq").map_err(unavailable)?)?,
        },
        mode: row.try_get("admission_version").map_err(unavailable)?,
        count: counter(row.try_get("operation_count").map_err(unavailable)?)?,
        bytes: counter(row.try_get("stored_bytes").map_err(unavailable)?)?,
        root: row.try_get("root_key_id").map_err(unavailable)?,
    };
    c.version.validate()?;
    Ok(c)
}
fn expired(reason: ExpiredReason, history: HistoryVersion) -> HistoryFailure {
    HistoryFailure::Expired(ExpiredHistory { reason, history })
}
async fn finish_history<T>(
    tx: Tx<'_>,
    result: Result<T, HistoryFailure>,
) -> Result<T, HistoryFailure> {
    let result = match result {
        Ok(value) => Ok(Ok(value)),
        Err(HistoryFailure::Expired(value)) => Ok(Err(value)),
        Err(HistoryFailure::Standard(error)) => Err(error),
    };
    finish(tx, result)
        .await
        .map_err(HistoryFailure::Standard)?
        .map_err(HistoryFailure::Expired)
}
async fn bounded_history<T>(
    work: impl Future<Output = Result<T, HistoryFailure>>,
) -> Result<T, HistoryFailure> {
    tokio::time::timeout(crate::database::DATABASE_TIMEOUT, work)
        .await
        .map_err(|_| HistoryFailure::Standard(SyncError::Unavailable))?
}
struct Metadata {
    sequence: u64,
    kind: EntityKind,
    entity: String,
    decision: Decision,
    version: OperationVersion,
    request_bytes: u32,
    result_bytes: u32,
}
impl Metadata {
    fn view(&self) -> RetainedMeta<'_> {
        RetainedMeta {
            sequence: self.sequence,
            kind: self.kind,
            entity: &self.entity,
            decision: self.decision,
            version: self.version,
            request_bytes: self.request_bytes,
            result_bytes: self.result_bytes,
        }
    }
}
fn metadata(row: &PgRow) -> Result<Metadata, SyncError> {
    let status: i16 = row.try_get("status").map_err(unavailable)?;
    let basis: Option<i64> = row.try_get("basis_seq").map_err(unavailable)?;
    let version = match row.try_get::<i16, _>("wire_version").map_err(unavailable)? {
        2 => OperationVersion::V2,
        3 => OperationVersion::V3 {
            basis_seq: counter(basis.ok_or(SyncError::Unavailable)?)?,
            lifecycle: Lifecycle {
                resolved_through_seq: counter(
                    row.try_get("resolved_through_seq").map_err(unavailable)?,
                )?,
            },
        },
        _ => return Err(SyncError::Unavailable),
    };
    let decision = match status {
        201 => Decision::Apply {
            revision: counter(
                row.try_get::<Option<i64>, _>("applied_revision")
                    .map_err(unavailable)?
                    .ok_or(SyncError::Unavailable)?,
            )?,
        },
        409 => Decision::Conflict {
            base_revision: counter(row.try_get("base_revision").map_err(unavailable)?)?,
            current_revision: counter(
                row.try_get::<Option<i64>, _>("current_revision")
                    .map_err(unavailable)?
                    .ok_or(SyncError::Unavailable)?,
            )?,
        },
        _ => return Err(SyncError::Unavailable),
    };
    let m = Metadata {
        sequence: counter(row.try_get("server_seq").map_err(unavailable)?)?,
        kind: crate::sync::codec::kind(
            &row.try_get::<String, _>("entity_type")
                .map_err(unavailable)?,
        )?,
        entity: row.try_get("entity_id").map_err(unavailable)?,
        decision,
        version,
        request_bytes: u32::try_from(
            row.try_get::<i32, _>("request_bytes")
                .map_err(unavailable)?,
        )
        .map_err(unavailable)?,
        result_bytes: u32::try_from(row.try_get::<i32, _>("result_bytes").map_err(unavailable)?)
            .map_err(unavailable)?,
    };
    validate_original_lengths(m.request_bytes as usize, m.result_bytes as usize)?;
    Ok(m)
}
async fn current_meta(
    tx: &mut Tx<'_>,
    auth: &AuthenticatedSession,
    op: &Operation,
) -> Result<Option<Metadata>, SyncError> {
    let sql = "SELECT o.server_seq,o.entity_type,o.entity_id,o.base_revision,o.wire_version,o.basis_seq,o.resolved_through_seq,o.applied_revision,o.current_revision,o.request_bytes,o.result_bytes,o.status FROM public.nds_replica_entities e JOIN public.nds_replica_operations o ON o.user_id=e.user_id AND o.tenant_id=e.tenant_id AND o.server_seq=e.applied_seq WHERE e.user_id=$1 AND e.tenant_id=$2 AND e.entity_type=$3 AND e.entity_id=$4";
    sqlx::query(sql)
        .bind(auth.session.owner.user_id.as_str())
        .bind(auth.session.owner.tenant_id.as_str())
        .bind(op.entity_kind.as_str())
        .bind(&op.entity_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?
        .as_ref()
        .map(metadata)
        .transpose()
}
async fn all_meta(
    tx: &mut Tx<'_>,
    auth: &AuthenticatedSession,
) -> Result<Vec<Metadata>, SyncError> {
    let sql = "SELECT o.server_seq,o.entity_type,o.entity_id,o.base_revision,o.wire_version,o.basis_seq,o.resolved_through_seq,o.applied_revision,o.current_revision,o.request_bytes,o.result_bytes,o.status FROM public.nds_replica_operations o WHERE o.user_id=$1 AND o.tenant_id=$2 ORDER BY o.server_seq LIMIT $3";
    let rows = sqlx::query(sql)
        .bind(auth.session.owner.user_id.as_str())
        .bind(auth.session.owner.tenant_id.as_str())
        .bind((MAX_OPERATIONS + 1) as i64)
        .fetch_all(&mut **tx)
        .await
        .map_err(unavailable)?;
    if rows.len() > MAX_OPERATIONS as usize {
        return Err(SyncError::Unavailable);
    }
    rows.iter().map(metadata).collect()
}
fn pressure_plan(
    rows: &[RetainedMeta<'_>],
    extra: RetainedMeta<'_>,
    current: HistoryVersion,
) -> Result<RetentionPlan, SyncError> {
    let next = HistoryVersion {
        head: extra.sequence,
        ..current
    };
    let caps = RetentionCaps::default();
    // A raised declaration under pressure is the explicit meaningful resolver
    // path. Never bypass Core's witness/CAS contract with a generic older cut.
    let previous = rows.iter().rev().find(|r| {
        r.kind == extra.kind
            && r.entity == extra.entity
            && matches!(r.decision, Decision::Apply { .. })
    });
    let floor = previous.map_or(0, |r| match r.version {
        OperationVersion::V2 => 0,
        OperationVersion::V3 { lifecycle, .. } => lifecycle.resolved_through_seq,
    });
    let declared = match extra.version {
        OperationVersion::V2 => 0,
        OperationVersion::V3 { lifecycle, .. } => lifecycle.resolved_through_seq,
    };
    if declared > floor {
        let witness = rows
            .iter()
            .filter(|r| {
                r.kind == extra.kind
                    && r.entity == extra.entity
                    && matches!(r.decision, Decision::Conflict { .. })
                    && r.sequence <= declared
            })
            .map(|r| r.sequence)
            .collect::<Vec<_>>();
        return atomic_resolution(rows, extra, &witness, current, current, caps);
    }
    // A failed CAS under pressure is not an opportunity to publish maintenance.
    if !matches!(extra.decision, Decision::Apply { .. }) {
        return Err(SyncError::CapacityExhausted);
    }
    // First find the earliest safe cut that fits, preserving the maximum possible
    // suffix. Candidate changes occur only at existing Applied rows. No fixed age
    // or guaranteed wave is invented; at most16 bounded Core plans, including the initial/final checks.
    match retention_plan(rows, Some(extra), next, current.head, caps) {
        Ok(last) => {
            let mut cuts = rows
                .iter()
                .filter(|r| {
                    r.sequence >= current.floor
                        && r.sequence <= current.head
                        && matches!(r.decision, Decision::Apply { .. })
                })
                .map(|r| r.sequence)
                .collect::<Vec<_>>();
            cuts.push(current.head);
            cuts.sort_unstable();
            cuts.dedup();
            let (mut low, mut high) = (0, cuts.len() - 1);
            let mut best = last;
            while low < high {
                let mid = low + (high - low) / 2;
                match retention_plan(rows, Some(extra), next, cuts[mid], caps) {
                    Ok(plan) => {
                        best = plan;
                        high = mid
                    }
                    Err(SyncError::CapacityExhausted) => low = mid + 1,
                    Err(error) => return Err(error),
                }
            }
            if best.base != cuts[low] {
                best = retention_plan(rows, Some(extra), next, cuts[low], caps)?;
            }
            Ok(best)
        }
        Err(error) => Err(error),
    }
}
struct PendingWrite<'a> {
    request: &'a VersionedOperation,
    body: &'a [u8],
    out: &'a StoredResult,
    meta: RetainedMeta<'a>,
}
async fn commit_original(
    tx: &mut Tx<'_>,
    auth: &AuthenticatedSession,
    signed: &SignedRequest,
    write: PendingWrite<'_>,
    c: &Counters,
    plan: Option<&RetentionPlan>,
) -> Result<(), SyncError> {
    let op = &write.request.operation;
    let owner = &auth.session.owner;
    let keep = plan
        .map(|p| {
            p.keep
                .iter()
                .copied()
                .map(integer)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let members = plan
        .map(|p| {
            p.members
                .iter()
                .copied()
                .map(integer)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    // All mutations below share the already-held auth/owner transaction. A failure
    // aborts originals/members/entity/counters together. No body is normalized.
    if let Some(keep) = &keep {
        sqlx::query(
            "DELETE FROM public.nds_replica_base_members WHERE user_id=$1 AND tenant_id=$2",
        )
        .bind(owner.user_id.as_str())
        .bind(owner.tenant_id.as_str())
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
        sqlx::query("DELETE FROM public.nds_replica_operations WHERE user_id=$1 AND tenant_id=$2 AND NOT(server_seq=ANY($3))").bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(keep).execute(&mut **tx).await.map_err(unavailable)?;
    }
    let (wire, basis, resolved) = match write.request.version {
        OperationVersion::V2 => (2_i16, None, 0),
        OperationVersion::V3 {
            basis_seq,
            lifecycle,
        } => (
            3_i16,
            Some(integer(basis_seq)?),
            integer(lifecycle.resolved_through_seq)?,
        ),
    };
    let (applied, current) = match write.meta.decision {
        Decision::Apply { revision } => (Some(integer(revision)?), None),
        Decision::Conflict {
            current_revision, ..
        } => (None, Some(integer(current_revision)?)),
    };
    sqlx::query("INSERT INTO public.nds_replica_operations(user_id,tenant_id,device_id,operation_id,idempotency_key,fingerprint,server_seq,request_body,result_body,status,entity_type,entity_id,base_revision,wire_version,basis_seq,resolved_through_seq,applied_revision,current_revision,request_bytes,result_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)")
  .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(signed.device.as_str()).bind(&op.id).bind(&op.idempotency_key).bind(signed.fingerprint.as_slice()).bind(integer(write.meta.sequence)?).bind(write.body).bind(&write.out.body).bind(i16::try_from(write.out.status).map_err(unavailable)?)
  .bind(op.entity_kind.as_str()).bind(&op.entity_id).bind(integer(op.base_revision)?).bind(wire).bind(basis).bind(resolved).bind(applied).bind(current).bind(i32::try_from(write.body.len()).map_err(unavailable)?).bind(i32::try_from(write.out.body.len()).map_err(unavailable)?).execute(&mut **tx).await.map_err(unavailable)?;
    if let Some(revision) = applied {
        sqlx::query("INSERT INTO public.nds_replica_entities(user_id,tenant_id,entity_type,entity_id,revision,request_body,applied_seq) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(user_id,tenant_id,entity_type,entity_id) DO UPDATE SET revision=EXCLUDED.revision,request_body=EXCLUDED.request_body,applied_seq=EXCLUDED.applied_seq")
   .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(op.entity_kind.as_str()).bind(&op.entity_id).bind(revision).bind(write.body).bind(integer(write.meta.sequence)?).execute(&mut **tx).await.map_err(unavailable)?;
    }
    if let Some(members) = members {
        sqlx::query("INSERT INTO public.nds_replica_base_members(user_id,tenant_id,server_seq) SELECT $1,$2,s FROM unnest($3::bigint[]) AS m(s)").bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(members).execute(&mut **tx).await.map_err(unavailable)?;
    }
    let (count, bytes) = plan.map_or((c.count + 1, c.bytes + write.meta.cost()), |p| {
        (p.keep.len() as u64, p.bytes)
    });
    let changed=sqlx::query("UPDATE public.nds_replica_counters SET server_seq=$3,operation_count=$4,stored_bytes=$5,root_key_id=COALESCE(root_key_id,$6),floor_seq=COALESCE($7,floor_seq),base_seq=COALESCE($7,base_seq) WHERE user_id=$1 AND tenant_id=$2 AND server_seq=$8 AND floor_seq=$9")
  .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(integer(write.meta.sequence)?).bind(integer(count)?).bind(integer(bytes)?).bind(&op.payload.key_id).bind(plan.map(|p|integer(p.base)).transpose()?).bind(integer(c.version.head)?).bind(integer(c.version.floor)?).execute(&mut **tx).await.map_err(unavailable)?;
    if changed.rows_affected() != 1 {
        return Err(SyncError::Unavailable);
    }
    Ok(())
}
async fn read_entries(
    tx: &mut Tx<'_>,
    auth: &AuthenticatedSession,
    after: u64,
    limit: usize,
    base: bool,
    legacy: bool,
) -> Result<(Vec<RetainedEntry>, bool), SyncError> {
    let owner = &auth.session.owner;
    let sql = if base {
        "SELECT o.server_seq,o.request_bytes,o.result_bytes FROM public.nds_replica_operations o JOIN public.nds_replica_base_members m ON m.user_id=o.user_id AND m.tenant_id=o.tenant_id AND m.server_seq=o.server_seq WHERE o.user_id=$1 AND o.tenant_id=$2 AND o.server_seq>$3 ORDER BY o.server_seq LIMIT $4"
    } else {
        "SELECT o.server_seq,o.request_bytes,o.result_bytes FROM public.nds_replica_operations o WHERE o.user_id=$1 AND o.tenant_id=$2 AND o.server_seq>$3 ORDER BY o.server_seq LIMIT $4"
    };
    let refs = sqlx::query(sql)
        .bind(owner.user_id.as_str())
        .bind(owner.tenant_id.as_str())
        .bind(integer(after)?)
        .bind((limit + 1) as i64)
        .fetch_all(&mut **tx)
        .await
        .map_err(unavailable)?;
    // Conservative JSON-string byte budget from actual original lengths; final
    // transport serialization is measured again. Valid max row always fits.
    let mut budget = 256_usize;
    let mut selected = Vec::new();
    for row in refs.iter().take(limit) {
        let request = usize::try_from(
            row.try_get::<i32, _>("request_bytes")
                .map_err(unavailable)?,
        )
        .map_err(unavailable)?;
        let result = usize::try_from(row.try_get::<i32, _>("result_bytes").map_err(unavailable)?)
            .map_err(unavailable)?;
        validate_original_lengths(request, result)?;
        let next = budget
            + if legacy {
                // Legacy HTTP measures projected objects before advancing its cursor.
                request + result
            } else {
                2 * (request + result) + 256
            };
        if next > MAX_PAGE_BYTES {
            break;
        }
        budget = next;
        selected.push(row.try_get::<i64, _>("server_seq").map_err(unavailable)?);
    }
    if !refs.is_empty() && selected.is_empty() {
        return Err(SyncError::Unavailable);
    }
    let more = selected.len() < refs.len();
    if selected.is_empty() {
        return Ok((Vec::new(), false));
    }
    let rows=sqlx::query("SELECT server_seq,request_body,result_body,status FROM public.nds_replica_operations WHERE user_id=$1 AND tenant_id=$2 AND server_seq=ANY($3) ORDER BY server_seq").bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str()).bind(&selected).fetch_all(&mut **tx).await.map_err(unavailable)?;
    if rows.len() != selected.len() {
        return Err(SyncError::Unavailable);
    }
    let mut entries = Vec::new();
    for row in rows {
        let original = Entry {
            server_seq: counter(row.try_get("server_seq").map_err(unavailable)?)?,
            request_body: row.try_get("request_body").map_err(unavailable)?,
            result_body: row.try_get("result_body").map_err(unavailable)?,
        };
        let status = u16::try_from(row.try_get::<i16, _>("status").map_err(unavailable)?)
            .map_err(unavailable)?;
        crate::sync::codec::validate_original(
            &original.request_body,
            &original.result_body,
            status,
            original.server_seq,
        )
        .map_err(|_| SyncError::Unavailable)?;
        entries.push(RetainedEntry {
            original,
            original_status: status,
        });
    }
    Ok((entries, more))
}
impl Store {
    pub(crate) async fn read_mode(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        now: u64,
    ) -> Result<i16, HistoryFailure> {
        bounded_history(async {
            let mut tx = self.identity.transaction().await.map_err(unavailable)?;
            let result = async {
                authorize(
                    &mut tx,
                    auth,
                    &signed,
                    now.max(now_ms().map_err(unavailable)?),
                )
                .await?;
                Ok(counters(&mut tx, auth).await?.mode)
            }
            .await;
            finish_history(tx, result).await
        })
        .await
    }
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
        self.append_versioned(
            auth,
            signed,
            VersionedOperation {
                operation,
                version: OperationVersion::V2,
            },
            body,
            now,
        )
        .await
        .map_err(|e| match e {
            HistoryFailure::Standard(e) => e,
            HistoryFailure::Expired(_) => SyncError::Invalid,
        })
    }
    async fn page(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        after: u64,
        limit: usize,
        now: u64,
    ) -> Result<Page, SyncError> {
        let p = self
            .history_page(auth, signed, after, limit, now)
            .await
            .map_err(|e| match e {
                HistoryFailure::Standard(e) => e,
                HistoryFailure::Expired(_) => SyncError::Invalid,
            })?;
        Ok(Page {
            entries: p.contents.entries.into_iter().map(|e| e.original).collect(),
            next_after: p.contents.next_after,
            has_more: p.contents.has_more,
        })
    }
}

impl HistoryStore for Store {
    async fn append_versioned(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        q: VersionedOperation,
        body: Vec<u8>,
        now: u64,
    ) -> Result<StoredResult, HistoryFailure> {
        if signed.device != q.operation.device {
            return Err(SyncError::Denied.into());
        }
        crate::sync::telemetry::append(bounded_history(async {
            let mut tx = self.identity.transaction().await.map_err(unavailable)?;
            let result = async {
                let now = now.max(now_ms().map_err(unavailable)?);
                authorize(&mut tx, auth, &signed, now).await?;
                let op = &q.operation;
                let owner = &auth.session.owner;
                let retained = sqlx::query("SELECT fingerprint,status,result_body FROM public.nds_replica_operations WHERE user_id=$1 AND tenant_id=$2 AND device_id=$3 AND(idempotency_key=$4 OR operation_id=$5)")
                    .bind(owner.user_id.as_str())
                    .bind(owner.tenant_id.as_str())
                    .bind(signed.device.as_str())
                    .bind(&op.idempotency_key)
                    .bind(&op.id)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(unavailable)?;
                if !retained.is_empty() {
                    if retained.len() != 1
                        || retained[0].try_get::<Vec<u8>, _>("fingerprint").map_err(unavailable)? != signed.fingerprint
                    {
                        return Err(SyncError::Idempotency.into());
                    }
                    return Ok((StoredResult {
                        status: retained[0].try_get::<i16, _>("status").map_err(unavailable)?.try_into().map_err(unavailable)?,
                        body: retained[0].try_get("result_body").map_err(unavailable)?,
                    }, AppendEffect::Replayed));
                }
                q.validate(body.len())?;
                let c = counters(&mut tx, auth).await?;
                match admission(Lookup::Missing, q.version, c.version, c.mode == 2)? {
                    Admission::New => {}
                    Admission::Unknown(UnknownOutcome::BasisExpired) => return Err(expired(ExpiredReason::Basis, c.version)),
                    Admission::Unknown(UnknownOutcome::LegacyMissing) => return Err(expired(ExpiredReason::LegacyMissing, c.version)),
                    Admission::ReplayOriginal => return Err(SyncError::Unavailable.into()),
                }
                if c.root.as_ref().is_some_and(|key| key != &op.payload.key_id) {
                    return Err(SyncError::KeyConflict.into());
                }
                let previous = current_meta(&mut tx, auth, op).await?;
                let revision = previous.as_ref().map_or(0, |m| match m.decision {
                    Decision::Apply { revision } => revision,
                    _ => 0,
                });
                let decision = op.decide(revision)?;
                let seq = c.version.head.checked_add(1).filter(|s| *s <= MAX_REVISION).ok_or(SyncError::Revision)?;
                Receipt { operation_id: op.id.clone(), server_seq: seq, decision }.validate_for(op)?;
                let (status, result) = match decision {
                    Decision::Apply { revision } => (201, serde_json::to_vec(&crate::protocol_sync::SyncApplied {
                        operation_id: op.id.clone(), outcome: crate::protocol_sync::SyncAppliedOutcome::Applied,
                        revision: integer(revision)?, server_seq: integer(seq)?,
                    }).map_err(unavailable)?),
                    Decision::Conflict { base_revision, current_revision } => (409, serde_json::to_vec(&crate::protocol_sync::SyncConflict {
                        operation_id: op.id.clone(), outcome: crate::protocol_sync::SyncConflictOutcome::Conflict,
                        resolution_state: crate::protocol_sync::ResolutionState::Unresolved,
                        base_revision: integer(base_revision)?, current_revision: integer(current_revision)?, server_seq: integer(seq)?,
                    }).map_err(unavailable)?),
                };
                validate_original_lengths(body.len(), result.len())?;
                let extra = RetainedMeta {
                    sequence: seq, kind: op.entity_kind, entity: &op.entity_id, decision, version: q.version,
                    request_bytes: body.len() as u32, result_bytes: result.len() as u32,
                };
                if matches!(decision, Decision::Apply { .. }) {
                    if let Some(old) = &previous {
                        if applied_projection(old.view(), extra)? != AppliedProjection::Replace {
                            return Err(SyncError::Invalid.into());
                        }
                    } else {
                        let entities: i64 = sqlx::query_scalar("SELECT count(*) FROM public.nds_replica_entities WHERE user_id=$1 AND tenant_id=$2")
                            .bind(owner.user_id.as_str()).bind(owner.tenant_id.as_str())
                            .fetch_one(&mut *tx).await.map_err(unavailable)?;
                        if entities >= MAX_ENTITY_COUNT as i64 {
                            return Err(SyncError::CapacityExhausted.into());
                        }
                    }
                }
                let plan = if c.count < MAX_OPERATIONS && c.bytes.checked_add(extra.cost()).is_some_and(|bytes| bytes <= MAX_STORED_BYTES) {
                    None
                } else {
                    if c.mode != 3 { return Err(SyncError::CapacityExhausted.into()); }
                    let metadata = all_meta(&mut tx, auth).await?;
                    let views = metadata.iter().map(Metadata::view).collect::<Vec<_>>();
                    Some(pressure_plan(&views, extra, c.version)?)
                };
                let out = StoredResult { status, body: result };
                commit_original(&mut tx, auth, &signed, PendingWrite { request: &q, body: &body, out: &out, meta: extra }, &c, plan.as_ref()).await?;
                Ok((out, AppendEffect::Committed { retention: plan.is_some() }))
            }.await;
            finish_history(tx, result).await
        })).await
    }
    async fn history_page(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        after: u64,
        limit: usize,
        now: u64,
    ) -> Result<HistoryPage, HistoryFailure> {
        self.read_history_page(auth, signed, after, limit, now, false)
            .await
    }
    async fn base_page(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        token: BaseRead,
        now: u64,
    ) -> Result<BasePage, HistoryFailure> {
        bounded_history(async {
            let mut tx = self.identity.transaction().await.map_err(unavailable)?;
            let result = async {
                authorize(&mut tx, auth, &signed, now.max(now_ms().map_err(unavailable)?)).await?;
                let c = counters(&mut tx, auth).await?;
                if token.base != c.version.base {
                    return Err(expired(ExpiredReason::Checkpoint, c.version));
                }
                if token.after_member > token.base || !(1..=MAX_PAGE_ITEMS).contains(&token.limit) {
                    return Err(SyncError::Invalid.into());
                }
                let total: i64 = sqlx::query_scalar("SELECT count(*) FROM public.nds_replica_base_members WHERE user_id=$1 AND tenant_id=$2")
                    .bind(auth.session.owner.user_id.as_str()).bind(auth.session.owner.tenant_id.as_str())
                    .fetch_one(&mut *tx).await.map_err(unavailable)?;
                let (entries, has_more) = read_entries(&mut tx, auth, token.after_member, token.limit, true, false).await?;
                let next = entries.last().map_or(token.after_member, |e| e.original.server_seq);
                Ok(BasePage { base: token.base, total_members: usize::try_from(total).map_err(unavailable)?, entries, next_member: next, has_more })
            }.await;
            finish_history(tx, result).await
        }).await
    }
}

impl Store {
    pub(crate) async fn read_history_page(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        after: u64,
        limit: usize,
        now: u64,
        legacy: bool,
    ) -> Result<HistoryPage, HistoryFailure> {
        bounded_history(async {
            let mut tx = self.identity.transaction().await.map_err(unavailable)?;
            let result = async {
                authorize(
                    &mut tx,
                    auth,
                    &signed,
                    now.max(now_ms().map_err(unavailable)?),
                )
                .await?;
                let c = counters(&mut tx, auth).await?;
                if after < c.version.floor {
                    return Err(expired(ExpiredReason::Cursor, c.version));
                }
                if after > c.version.head || !(1..=MAX_PAGE_ITEMS).contains(&limit) {
                    return Err(SyncError::Invalid.into());
                }
                let (entries, has_more) =
                    read_entries(&mut tx, auth, after, limit, false, legacy).await?;
                let next = entries.last().map_or(after, |e| e.original.server_seq);
                Ok(HistoryPage {
                    history: c.version,
                    contents: Page {
                        entries,
                        next_after: next,
                        has_more,
                    },
                })
            }
            .await;
            finish_history(tx, result).await
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn m(sequence: u64, revision: Option<u64>, r: u64) -> RetainedMeta<'static> {
        RetainedMeta {
            sequence,
            kind: EntityKind::VaultRecord,
            entity: "owned",
            decision: revision.map_or(
                Decision::Conflict {
                    base_revision: 0,
                    current_revision: 1,
                },
                |revision| Decision::Apply { revision },
            ),
            version: OperationVersion::V3 {
                basis_seq: sequence - 1,
                lifecycle: Lifecycle {
                    resolved_through_seq: r,
                },
            },
            request_bytes: 500,
            result_bytes: 150,
        }
    }
    #[test]
    fn pressure_resolution_never_bypasses_canonical_witness_or_failed_cas() {
        let rows = [m(1, Some(1), 0), m(2, None, 0)];
        let h = HistoryVersion {
            head: 2,
            floor: 0,
            base: 0,
        };
        let failed = m(3, None, 2);
        assert_eq!(
            pressure_plan(&rows, failed, h).err(),
            Some(SyncError::KeyConflict)
        );
        let rows = [
            rows[0],
            rows[1],
            RetainedMeta {
                entity: "other",
                ..m(3, Some(1), 0)
            },
        ];
        let h = HistoryVersion { head: 3, ..h };
        assert_eq!(
            pressure_plan(&rows, m(4, Some(2), 3), h).err(),
            Some(SyncError::Invalid)
        );
        let plan = pressure_plan(&rows, m(4, Some(2), 2), h).unwrap();
        assert_eq!(plan.base, 4);
        assert_eq!(plan.keep, vec![3, 4]);
    }
}
