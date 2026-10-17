//! Generated wire projection only. Core owns validation, identity and lifecycle.
use super::http::decoded;
use crate::{protocol_sync as v2, protocol_sync3 as v3};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nddev_device_sync_domain::{DeviceId, sync::history::*, sync::*};
pub(super) fn kind(value: &str) -> Result<EntityKind, SyncError> {
    Ok(match value {
        "device_state" => EntityKind::DeviceState,
        "module_state" => EntityKind::ModuleState,
        "vault_record" => EntityKind::VaultRecord,
        "account_state" => EntityKind::AccountState,
        "clipboard_item" => EntityKind::ClipboardItem,
        "repository_state" => EntityKind::RepositoryState,
        _ => return Err(SyncError::Invalid),
    })
}
fn payload(key_id: String, nonce: &str, ciphertext: &str) -> Result<EncryptedPayload, SyncError> {
    let cipher = URL_SAFE_NO_PAD
        .decode(ciphertext)
        .map_err(|_| SyncError::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&cipher) != ciphertext {
        return Err(SyncError::Invalid);
    }
    Ok(EncryptedPayload {
        key_id,
        nonce: decoded(nonce)?,
        ciphertext: cipher,
    })
}
pub(super) fn legacy(v: v2::SyncOperation, size: usize) -> Result<VersionedOperation, SyncError> {
    if v.schema_version != 2 {
        return Err(SyncError::Invalid);
    }
    let entity_kind = match v.entity_type {
        v2::EntityType::DeviceState => EntityKind::DeviceState,
        v2::EntityType::ModuleState => EntityKind::ModuleState,
        v2::EntityType::VaultRecord => EntityKind::VaultRecord,
        v2::EntityType::AccountState => EntityKind::AccountState,
        v2::EntityType::ClipboardItem => EntityKind::ClipboardItem,
    };
    let q = VersionedOperation {
        version: OperationVersion::V2,
        operation: Operation {
            id: v.operation_id,
            device: DeviceId::new(v.device_id).map_err(|_| SyncError::Invalid)?,
            entity_kind,
            entity_id: v.entity_id,
            base_revision: v.base_revision.try_into().map_err(|_| SyncError::Invalid)?,
            idempotency_key: v.idempotency_key,
            payload: payload(v.payload.key_id, &v.payload.nonce, &v.payload.ciphertext)?,
        },
    };
    q.validate(size)?;
    Ok(q)
}
pub(super) fn version3(
    v: v3::SyncOperationV3,
    size: usize,
) -> Result<VersionedOperation, SyncError> {
    if v.schema_version != 3 {
        return Err(SyncError::Invalid);
    }
    let entity_kind = match v.entity_type {
        v3::EntityType::DeviceState => EntityKind::DeviceState,
        v3::EntityType::ModuleState => EntityKind::ModuleState,
        v3::EntityType::VaultRecord => EntityKind::VaultRecord,
        v3::EntityType::AccountState => EntityKind::AccountState,
        v3::EntityType::ClipboardItem => EntityKind::ClipboardItem,
        v3::EntityType::RepositoryState => EntityKind::RepositoryState,
    };
    let q = VersionedOperation {
        version: OperationVersion::V3 {
            basis_seq: v.basis_seq.try_into().map_err(|_| SyncError::Invalid)?,
            lifecycle: Lifecycle {
                resolved_through_seq: v
                    .lifecycle
                    .resolved_through_seq
                    .try_into()
                    .map_err(|_| SyncError::Invalid)?,
            },
        },
        operation: Operation {
            id: v.operation_id,
            device: DeviceId::new(v.device_id).map_err(|_| SyncError::Invalid)?,
            entity_kind,
            entity_id: v.entity_id,
            base_revision: v.base_revision.try_into().map_err(|_| SyncError::Invalid)?,
            idempotency_key: v.idempotency_key,
            payload: payload(v.payload.key_id, &v.payload.nonce, &v.payload.ciphertext)?,
        },
    };
    q.validate(size)?;
    Ok(q)
}
pub(super) fn validate_original(
    request: &[u8],
    result: &[u8],
    status: u16,
    seq: u64,
) -> Result<(), SyncError> {
    validate_original_lengths(request.len(), result.len())?;
    let version = serde_json::from_slice::<serde_json::Value>(request)
        .map_err(|_| SyncError::Invalid)?["schema_version"]
        .as_u64()
        .ok_or(SyncError::Invalid)?;
    let op = match version {
        2 => legacy(
            serde_json::from_slice(request).map_err(|_| SyncError::Invalid)?,
            request.len(),
        )?,
        3 => version3(
            serde_json::from_slice(request).map_err(|_| SyncError::Invalid)?,
            request.len(),
        )?,
        _ => return Err(SyncError::Invalid),
    };
    let (receipt, wanted) = match serde_json::from_slice::<v2::Sync>(result)
        .map_err(|_| SyncError::Invalid)?
    {
        v2::Sync::Applied(v) => (
            Receipt {
                operation_id: v.operation_id,
                server_seq: v.server_seq.try_into().map_err(|_| SyncError::Invalid)?,
                decision: Decision::Apply {
                    revision: v.revision.try_into().map_err(|_| SyncError::Invalid)?,
                },
            },
            201,
        ),
        v2::Sync::Conflict(v) => (
            Receipt {
                operation_id: v.operation_id,
                server_seq: v.server_seq.try_into().map_err(|_| SyncError::Invalid)?,
                decision: Decision::Conflict {
                    base_revision: v.base_revision.try_into().map_err(|_| SyncError::Invalid)?,
                    current_revision: v
                        .current_revision
                        .try_into()
                        .map_err(|_| SyncError::Invalid)?,
                },
            },
            409,
        ),
    };
    if status != wanted || seq != receipt.server_seq {
        return Err(SyncError::Invalid);
    }
    receipt.validate_for(&op.operation)
}
