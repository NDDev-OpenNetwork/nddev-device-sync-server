// Generated; do not edit. AGPL-3.0-only. NDDev OpenNetwork — https://nddev.ai
// Source: NDDev-OpenNetwork/nddev-device-sync-protocol/contracts/v2/control-plane.schema.json
// Schema SHA-256: 0f0019b3feba57ab70ff8259953c421414a6edb26c99fbcd8762d6af275564a2
// Generator script SHA-256: 16399027930927c761d73ba3e2fd3424730a92d33dd2401c273a5049628a24f1
// Tool: quicktype-core 26.0.0; dependency lock SHA-256: 643e0f2ba88602f4acb9546c401d4838e8e106a9180c0e6f3a760985081bfcf6
// DTO generation is not schema, authorization or cryptographic validation.

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub display_name: String,

    pub platform: Platform,

    pub public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Android,

    Ios,

    Linux,

    Macos,

    Windows,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentChallenge {
    pub challenge: String,

    pub challenge_id: String,

    pub device_id: String,

    pub expires_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentProof {
    pub challenge_id: String,

    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceList {
    pub devices: Vec<Device>,

    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub created_at: String,

    pub device_id: String,

    pub display_name: String,

    pub platform: Platform,

    pub public_key: String,

    pub status: Status,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,

    Revoked,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Error {
    pub error: ErrorEnum,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorEnum {
    #[serde(rename = "authentication_failed")]
    AuthenticationFailed,

    #[serde(rename = "authorization_denied")]
    AuthorizationDenied,

    #[serde(rename = "challenge_expired")]
    ChallengeExpired,

    #[serde(rename = "cursor_expired")]
    CursorExpired,

    #[serde(rename = "dependency_unavailable")]
    DependencyUnavailable,

    #[serde(rename = "device_revoked")]
    DeviceRevoked,

    #[serde(rename = "idempotency_conflict")]
    IdempotencyConflict,

    #[serde(rename = "invalid_request")]
    InvalidRequest,

    #[serde(rename = "invalid_signature")]
    InvalidSignature,

    #[serde(rename = "method_unavailable")]
    MethodUnavailable,

    #[serde(rename = "operation_conflict")]
    OperationConflict,

    #[serde(rename = "rate_limited")]
    RateLimited,

    #[serde(rename = "replayed_nonce")]
    ReplayedNonce,

    #[serde(rename = "request_timeout")]
    RequestTimeout,

    #[serde(rename = "revision_exhausted")]
    RevisionExhausted,

    #[serde(rename = "server_busy")]
    ServerBusy,
}

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
