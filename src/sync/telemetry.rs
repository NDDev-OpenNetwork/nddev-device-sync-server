//! Adapter effect projection; no durable state, policy, identifiers or payloads.
use nddev_device_sync_application::sync::{StoredResult, SyncError, history::*};
use std::future::Future;

/// Carried only through the existing transaction's result. This is not a receipt.
pub(super) enum AppendEffect {
    Replayed,
    Committed { retention: bool },
}

/// `confirmed` includes the existing COMMIT and its outer deadline. A failed or
/// cancelled acknowledgement cannot establish a rollback or a durable cut.
pub(super) async fn append(
    confirmed: impl Future<Output = Result<(StoredResult, AppendEffect), HistoryFailure>>,
) -> Result<StoredResult, HistoryFailure> {
    match confirmed.await {
        Ok((stored, effect)) => {
            let event = match effect {
                AppendEffect::Replayed => "sync.operation.replayed",
                AppendEffect::Committed { .. } => "sync.operation.committed",
            };
            tracing::info!(
                module = "sync",
                scope = "database",
                event.name = event,
                status = stored.status,
                outcome = if stored.status == 201 {
                    "accepted"
                } else {
                    "rejected"
                }
            );
            if matches!(effect, AppendEffect::Committed { retention: true }) {
                tracing::info!(
                    module = "sync",
                    scope = "database",
                    event.name = "sync.retention.committed",
                    status = stored.status,
                    outcome = "ok"
                );
            }
            Ok(stored)
        }
        Err(error) => {
            if matches!(error, HistoryFailure::Standard(SyncError::Unavailable)) {
                // Unavailable includes failures before COMMIT as well as a lost
                // acknowledgement. Do not claim COMMIT was sent or rolled back.
                tracing::warn!(
                    module = "sync",
                    scope = "database",
                    event.name = "sync.operation.unconfirmed",
                    outcome = "pending",
                    error.type = "sync_unavailable"
                );
            }
            Err(error)
        }
    }
}

pub(super) fn expired(reason: &ExpiredReason) {
    let class = match reason {
        ExpiredReason::Basis => "basis_expired",
        ExpiredReason::Cursor => "cursor_expired",
        ExpiredReason::Checkpoint => "checkpoint_expired",
        ExpiredReason::LegacyMissing => "legacy_outcome_unknown",
    };
    tracing::info!(
        module = "sync",
        scope = "http",
        event.name = "sync.history.expired",
        status = 410_u16,
        error.type = class,
        outcome = "rejected"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, response::IntoResponse};
    use std::task::Poll;
    use tracing::{Instrument, instrument::WithSubscriber};

    #[tokio::test]
    async fn confirmed_effects_preserve_receipt_and_sdk_correlation() {
        for status in [201, 409] {
            for kind in 0..3 {
                let events = crate::telemetry_test::Events::default();
                let (dispatch, _provider, _spans) =
                    crate::telemetry_test::capture_to(events.clone());
                let span = tracing::dispatcher::with_default(&dispatch, || {
                    nddev_device_sync_telemetry::http_server_span("POST", "/v3/sync/operations")
                        .unwrap()
                });
                let context = nddev_device_sync_telemetry::trace_context(&span);
                use opentelemetry::trace::TraceContextExt;
                let id = context.span().span_context().trace_id().to_string();
                let body = b"  private-original-receipt\n".to_vec();
                let stored = StoredResult {
                    status,
                    body: body.clone(),
                };
                let effect = match kind {
                    0 => AppendEffect::Replayed,
                    1 => AppendEffect::Committed { retention: false },
                    _ => AppendEffect::Committed { retention: true },
                };
                let result = append(async { Ok((stored, effect)) })
                    .instrument(span)
                    .with_subscriber(dispatch)
                    .await
                    .unwrap_or_else(|_| panic!("confirmed result must pass through"));
                assert_eq!(result.status, status);
                assert_eq!(result.body, body);
                let values = events.values();
                assert_eq!(values.len(), if kind == 2 { 2 } else { 1 });
                assert_eq!(
                    values[0]["event.name"],
                    if kind == 0 {
                        "sync.operation.replayed"
                    } else {
                        "sync.operation.committed"
                    }
                );
                assert_eq!(
                    values[0]["outcome"],
                    if status == 201 {
                        "accepted"
                    } else {
                        "rejected"
                    }
                );
                if kind == 2 {
                    assert_eq!(values[1]["event.name"], "sync.retention.committed");
                }
                for value in values {
                    assert_eq!(value["status"], status);
                    assert_eq!(value["trace_id"], id);
                    assert_eq!(value["scope"], "database");
                    assert!(value["span_id"].as_str().is_some_and(|id| id.len() == 16));
                    assert!(value.get("reason").is_none());
                    assert!(!value.to_string().contains("private-original-receipt"));
                }
            }
        }
    }

    #[tokio::test]
    async fn pending_or_failed_confirmation_never_emits_commit_or_cut() {
        for confirmed in [true, false] {
            let events = crate::telemetry_test::Events::default();
            let (dispatch, _provider, _spans) = crate::telemetry_test::capture_to(events.clone());
            async {
                let (send, receive) = tokio::sync::oneshot::channel();
                let mut work = std::pin::pin!(append(async { receive.await.unwrap() }));
                std::future::poll_fn(|cx| {
                    assert!(work.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert!(events.values().is_empty());
                let outcome = if confirmed {
                    Ok((
                        StoredResult {
                            status: 201,
                            body: vec![],
                        },
                        AppendEffect::Committed { retention: true },
                    ))
                } else {
                    Err(HistoryFailure::Standard(SyncError::Unavailable))
                };
                assert!(send.send(outcome).is_ok());
                assert_eq!(work.await.is_ok(), confirmed);
                let values = events.values();
                if confirmed {
                    assert_eq!(values.len(), 2);
                    assert_eq!(values[1]["event.name"], "sync.retention.committed");
                } else {
                    assert_eq!(values.len(), 1);
                    assert_eq!(values[0]["event.name"], "sync.operation.unconfirmed");
                    assert_eq!(values[0]["outcome"], "pending");
                    assert_eq!(values[0]["error.type"], "sync_unavailable");
                    assert!(values[0].get("status").is_none());
                }
            }
            .with_subscriber(dispatch)
            .await;
        }
        let events = crate::telemetry_test::Events::default();
        let (dispatch, _provider, _spans) = crate::telemetry_test::capture_to(events.clone());
        let result = append(async { Err(HistoryFailure::Standard(SyncError::CapacityExhausted)) })
            .with_subscriber(dispatch)
            .await;
        assert!(matches!(
            result,
            Err(HistoryFailure::Standard(SyncError::CapacityExhausted))
        ));
        assert!(events.values().is_empty());
    }

    #[tokio::test]
    async fn typed_expiry_events_preserve_v3_and_legacy_wire_contracts() {
        for legacy in [false, true] {
            let events = crate::telemetry_test::Events::default();
            let (dispatch, _provider, _spans) = crate::telemetry_test::capture_to(events.clone());
            async {
                for (reason, class) in [
                    (ExpiredReason::Basis, "basis_expired"),
                    (ExpiredReason::Cursor, "cursor_expired"),
                    (ExpiredReason::Checkpoint, "checkpoint_expired"),
                    (ExpiredReason::LegacyMissing, "legacy_outcome_unknown"),
                ] {
                    let failure = HistoryFailure::Expired(ExpiredHistory {
                        reason,
                        history: nddev_device_sync_domain::sync::history::HistoryVersion {
                            head: 11,
                            floor: 7,
                            base: 7,
                        },
                    });
                    let response = if legacy {
                        crate::sync::v3::LegacyError::from(failure).into_response()
                    } else {
                        crate::sync::v3::Error::from(failure).into_response()
                    };
                    assert_eq!(response.status(), StatusCode::GONE);
                    let body = axum::body::to_bytes(response.into_body(), 1024)
                        .await
                        .unwrap();
                    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    if legacy {
                        assert_eq!(value, serde_json::json!({"error":"cursor_expired"}));
                    } else {
                        assert_eq!(value["error"], class);
                        assert_eq!(value["head_seq"], 11);
                        assert_eq!(value["floor_seq"], 7);
                        assert_eq!(value["schema_version"], 3);
                        assert!(
                            serde_json::from_slice::<crate::protocol_sync::Sync>(&body).is_err()
                        );
                    }
                    let values = events.values();
                    let event = values.last().unwrap();
                    assert_eq!(event["event.name"], "sync.history.expired");
                    assert_eq!(event["error.type"], class);
                    assert_eq!(event["status"], 410);
                    assert_eq!(event["outcome"], "rejected");
                    assert!(event.get("reason").is_none());
                    assert!(event.get("head_seq").is_none());
                    assert!(event.get("floor_seq").is_none());
                }
                assert_eq!(events.values().len(), 4);
            }
            .with_subscriber(dispatch)
            .await;
        }
    }
}
