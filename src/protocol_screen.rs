// Generated; do not edit. AGPL-3.0-only. NDDev OpenNetwork — https://nddev.ai
// Source: NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-protocol/contracts/v2/screen.schema.json
// Schema SHA-256: f3699e6c9e1ffc763395435a4afea787efd0ac43fc016a3f65ab80f9491db7cb
// Generator script SHA-256: 5d64ede7af40a61ff03e2757878764939c60e8ad3c9aebeebe14490c03a1501b
// Tool: quicktype-core 26.0.0; dependency lock SHA-256: 643e0f2ba88602f4acb9546c401d4838e8e106a9180c0e6f3a760985081bfcf6
// DTO generation is not schema, authorization or cryptographic validation.
// Shared schema SHA-256: 3e9bf15d93a62b90732aae63a6a5f5180b21138459c5c7b43a2f455939436c12

use serde::{Deserialize, Serialize};

/// Required null means the authenticated same-owner active target has no screen binding; it
/// never creates an identity or authorizes capture.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenBindingResponse {
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub binding: Option<ScreenBinding>,
}

/// Current canonical binding, stored only after current NDS enrolled-device authority AND
/// native endpoint PoP; metadata alone is not permission.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenBinding {
    pub device_id: String,

    pub endpoint_public_key: String,

    pub instance_id: String,

    pub revision: i64,
}

/// Register only the signing enrolled device. A new UUID CASes current base and increments
/// revision even samekey. Same current UUID/key/original base returns original binding AFTER
/// fresh nonce consumption and both proof checks. Changed key/base or superseded original
/// base conflicts.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenBindRequest {
    pub base_revision: i64,

    pub endpoint_public_key: String,

    /// Unix milliseconds, exact JSON-safe integer. Equals THIS HTTP Signature-Input expires
    /// seconds multiplied by1000; future<=60000ms and within current NDS session expiry.
    pub expires_at_ms: i64,

    pub instance_id: String,

    /// Exact nonce from THIS existing NDS HTTP Signature-Input context. Refresh
    /// signature/nonce/expiry/endpoint proof on retry while retaining instance/key/original base.
    pub nonce: String,

    /// Endpoint-key Ed25519 PoP over Core NDS-RDS-ENDPOINT-BINDING-V2 transcript: configured
    /// origin, signing device id, decoded endpoint key, instance UUID bytes, original base
    /// revision, exact signed nonce/expiry. Not the NDS enrolled-device HTTP signature.
    pub signature: String,
}

/// Signing device is viewer; target is an active same-owner host. Current exact distinct
/// endpoint bindings and original viewer session are checked atomically. Requested
/// lifetime<=300000ms; accepted expiry is explicitly returned at whole seconds. Exact
/// original request bytes determine idempotent create replay; never renew/resurrect an old
/// intent.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenViewRequest {
    pub display: i64,

    /// Unix milliseconds, exact JSON-safe integer. Requested upper bound,<=300000ms from actual
    /// admission and within current viewer session expiry; accepted whole-second boundary is
    /// explicitly returned.
    pub expires_at_ms: i64,

    pub host_revision: i64,

    pub idempotency_key: String,

    pub max_fps: i32,

    pub output_height: i32,

    pub target_device_id: String,

    pub viewer_revision: i64,
}

/// Current signed host role sees at most one participant intent; no
/// list/paging/cache/registry. Actual local opt-in/current Accounts fence/platform source
/// access are still required before native capture.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenIncoming {
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub view: Option<ScreenView>,
}

/// Public immutable Core projection; no creator session digest, owner authority, key
/// material, locator, capabilities, frames or capture consent. Original
/// admission/expiry/profile survive replay/expired reconstruction. Ready means stored native
/// artifact, not received/decoded/presented pixels; ended/expired metadata cannot reopen a
/// host.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenView {
    /// Unix milliseconds, exact JSON-safe integer. ORIGINAL canonical admission timestamp;
    /// retain on replay/expired reconstruction.
    pub admitted_at_ms: i64,

    pub display: i64,

    /// Unix milliseconds, exact JSON-safe integer. ORIGINAL accepted whole-second expiry; no
    /// renewal or restored lifetime.
    pub expires_at_ms: i64,

    pub host_device_id: String,

    pub host_endpoint: String,

    pub host_revision: i64,

    pub max_fps: i32,

    pub output_height: i32,

    pub state: State,

    pub view_id: String,

    pub viewer_device_id: String,

    pub viewer_endpoint: String,

    pub viewer_revision: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Ended,

    Ready,

    Requested,
}

/// Viewer-only current authorized delivery. Recheck original viewer session, both active
/// participant rows and exact bindings before delivering Rust-only grant; cached
/// metadata/grant never permits reopen.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenViewResponse {
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub native_grant: Option<String>,

    pub view: ScreenView,
}

/// Signed host role submits exact original opaque native artifact after actual local
/// opt-in/current fence/source guards. Server stores metadata and<=8192decoded bytes
/// atomically after participant/original-session/current-binding rechecks; it never becomes
/// native issuer or validates native pixels. Exact retry does not issue a different artifact.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenReadyRequest {
    pub native_grant: String,
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

    #[serde(rename = "recent_authentication_required")]
    RecentAuthenticationRequired,

    #[serde(rename = "replayed_nonce")]
    ReplayedNonce,

    #[serde(rename = "request_timeout")]
    RequestTimeout,

    #[serde(rename = "revision_exhausted")]
    RevisionExhausted,

    #[serde(rename = "server_busy")]
    ServerBusy,

    #[serde(rename = "sync_capacity_exhausted")]
    SyncCapacityExhausted,

    #[serde(rename = "vault_key_registration_required")]
    VaultKeyRegistrationRequired,
}

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
