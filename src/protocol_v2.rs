// Generated; do not edit. AGPL-3.0-only. NDDev OpenNetwork — https://nddev.ai
// Source: NDDev-OpenNetwork/nddev-device-sync-protocol/contracts/v2/control-plane.schema.json
// Schema SHA-256: 445e6a18fe4c8c47af5622fa4abdad7a5f193e1d46357348fe800dece0ba0021
// Generator script SHA-256: 64d6c1aef18ee0821827739b0e338fef7db9b503b9885f7af1c5145a6b0da98a
// Tool: quicktype-core 26.0.0; dependency lock SHA-256: 643e0f2ba88602f4acb9546c401d4838e8e106a9180c0e6f3a760985081bfcf6
// DTO generation is not schema, authorization or cryptographic validation.

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthMethods {
    pub email_otp: MethodAvailability,

    pub github: MethodAvailability,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodAvailability {
    Available,

    Unavailable,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailChallengeRequest {
    pub email: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailChallenge {
    pub challenge_id: String,

    pub expires_in_seconds: i32,

    pub resend_after_seconds: i32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailVerifyRequest {
    pub challenge_id: String,

    pub code: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionIssued {
    pub session: Session,

    pub session_token: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub auth_method: AuthMethod,

    pub expires_at: String,

    pub tenant_id: String,

    pub user_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    #[serde(rename = "email_otp")]
    EmailOtp,

    Github,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubStart {
    pub authorization_url: String,

    pub exchange_token: String,

    pub expires_in_seconds: i32,

    pub flow_id: String,

    pub poll_after_seconds: i32,

    /// Comparison code displayed by the initiating app and browser approval page; not a bearer
    /// credential or email OTP.
    pub verification_code: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubExchangeRequest {
    pub exchange_token: String,

    pub flow_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubPending {
    pub retry_after_seconds: i32,

    pub status: Status,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubApprovalForm {
    pub csrf_token: String,

    pub decision: Decision,

    pub flow_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,

    Deny,
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
