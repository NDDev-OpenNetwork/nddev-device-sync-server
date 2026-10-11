// Generated; do not edit. AGPL-3.0-only. NDDev OpenNetwork — https://nddev.ai
// Source: NDDev-OpenNetwork/nddev-device-sync-protocol/contracts/v2/observability.schema.json
// Schema SHA-256: c75f4778536ac505fcf322f4f77b05a9c9e5e4fd9a2f44fbef081161ccacd9ee
// Generator script SHA-256: 12e8a175bd449a596e56c964f78c1c4edae0d716b5d06b81241919d29f70f25d
// Tool: quicktype-core 26.0.0; dependency lock SHA-256: 643e0f2ba88602f4acb9546c401d4838e8e106a9180c0e6f3a760985081bfcf6
// DTO generation is not schema, authorization or cryptographic validation.
// Shared schema SHA-256: 9d3d166e405548c028c4fbf7b68a76e43e38517dc9ea1f1c549a17c66e1470ce

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentPage {
    pub generated_at: String,

    pub incidents: Vec<Incident>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Incident {
    pub dedup_key: String,

    pub first_seen: String,

    pub incident_id: String,

    pub kind: Kind,

    pub last_seen: String,

    pub occurrences: i64,

    pub owner: Owner,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,

    pub revision: i64,

    pub service_name: String,

    pub severity: Severity,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub silenced_until: Option<String>,

    pub state: IncidentState,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Admission,

    Database,

    Delivery,

    Process,

    #[serde(rename = "source_gap")]
    SourceGap,

    #[serde(rename = "source_stale")]
    SourceStale,

    Tls,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    Operator,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,

    Warning,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    Acknowledged,

    Open,

    Resolved,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentAction {
    pub expected_revision: i64,

    /// Canonical UUIDv7 created within ten minutes of the request. This bounds replay lifetime
    /// below receipt retention.
    pub operation_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SilenceAction {
    pub expected_revision: i64,

    /// Canonical UUIDv7 created within ten minutes of the request. This bounds replay lifetime
    /// below receipt retention.
    pub operation_id: String,

    pub until: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressReceipt {
    pub accepted: i32,

    pub duplicates: i32,

    pub export_mode: ExportMode,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportMode {
    Disabled,

    Enabled,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityStatus {
    pub delivered_events: i64,

    pub expired_events: i64,

    pub export_mode: ExportMode,

    pub logs: SignalDelivery,

    pub metrics: SignalDelivery,

    pub queued_bytes: i32,

    pub queued_events: i32,

    pub sources: Vec<SourceHealth>,

    pub traces: SignalDelivery,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalDelivery {
    pub failures: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,

    pub state: State,

    pub successes: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Degraded,

    Disabled,

    Healthy,

    Unknown,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceHealth {
    pub gap_observations: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_at: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_received_at: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sequence: Option<i64>,

    pub service_name: String,

    pub state: SourceState,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    Fresh,

    #[serde(rename = "gap_observed")]
    GapObserved,

    Inactive,

    Missing,

    Stale,

    Unsequenced,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityError {
    pub error: Error,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    #[serde(rename = "capacity_exhausted")]
    CapacityExhausted,

    #[serde(rename = "dependency_unavailable")]
    DependencyUnavailable,

    #[serde(rename = "idempotency_conflict")]
    IdempotencyConflict,

    #[serde(rename = "invalid_request")]
    InvalidRequest,

    #[serde(rename = "invalid_transition")]
    InvalidTransition,

    #[serde(rename = "not_found")]
    NotFound,

    #[serde(rename = "revision_conflict")]
    RevisionConflict,

    Unauthorized,
}
