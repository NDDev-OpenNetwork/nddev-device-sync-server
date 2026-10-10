# nddev-device-sync-server

Public AGPL-3.0-only Rust control-plane server for `nddev-device-sync`.

Part of [NDDev OpenNetwork](https://nddev.ai).

The current server provides:

- one shared SDK JSON envelope for process, migration and request events;
- real local OpenTelemetry request/SMTP spans and native W3C `traceparent` correlation;
- `/v1/health`, `/v1/ready` and `/source` endpoints;
- PostgreSQL readiness and an explicit migration command with a separate identity;
- direct Rust/rustls HTTPS, bounded connection drain and safe certificate reload;
- finite connection/handler admission and scoped, expiring debug diagnostics;
- email OTP and GitHub PKCE for one explicitly configured owner;
- browser pairing approval, expiring/revocable sessions and bounded abuse controls;
- session-bound Ed25519 device enrollment, paged owner inventory and revocation;
- signed encrypted sync operations, immutable idempotency receipts and explicit conflicts;
- generated wire types and immutable core/protocol source pins;
- compatible health metadata without a speculative core module registry.

The legacy `module_count` health field is zero: the server composes no local-tool
adapters. The native agent owns the actual manifest inventory and observations.

Native vault storage and key pairing are separate client work. Without private identity configuration, `/v2/auth/methods`
reports unavailable methods. Provider readiness does not prove a completed
sign-in or delivery to an external mailbox.

## Local development

```sh
just fmt-check
just test
just clippy
just protocol-check
just integration-postgres
```

The PostgreSQL/SMTP acceptance also validates actual process NDJSON against the
closed telemetry schema at the manifest's exact protocol commit, including
formats and the 16 KiB event limit. Its canonical Python validator runs in a
temporary virtual environment with hash-locked dependencies; Python 3 with
`venv` and pip support is required. OpenSSL provides an independent Ed25519
signer for real enrollment acceptance. Event values are neither saved nor printed.

Set `DATABASE_URL_FILE` (or `DATABASE_URL`) to enable PostgreSQL readiness.
Run the explicit `migrate` command with `NDS_MIGRATION_DATABASE_URL_FILE` first;
runtime startup does not execute DDL. Without a runtime database URL the process
still starts for route tests, while `/v1/ready` reports degraded.

See [self-hosting](docs/self-hosting.md) for HTTPS, mounted secrets, role separation,
Compose, certificate reload and resource bounds, and [dependency decisions](docs/dependencies.md).

Requests have a 15-second handler deadline; pool acquisition and database
readiness queries have a 3-second deadline. Completion logs retain the request
trace/span context and use matched route patterns, never raw URL paths or query
strings. Database readiness errors expose a stable error class rather than
driver messages. The maintained W3C propagator validates incoming `traceparent`
and `tracestate`, including future-version handling; malformed or repeated
traceparent headers start a fresh SDK trace. Each propagation header is capped
at 512 bytes before native parsing. Remote sampling does not suppress
local error/security events. SMTP jobs retain immutable parent IDs, not the live
HTTP span, and create their own delivery span.
All HTTP responses, including readiness failures and timeouts, use
`Cache-Control: no-store`. An instance that requires direct origin access must
also use DNS-only records and omit CDN/proxy response caching in its deployment.

The local JSON log remains available for diagnosis. The telemetry-enabled health
field describes operator intent. Configure `NDS_OTLP_ENDPOINT` with the origin of
an operator-owned Vector collector to export actual native request and operation
spans through the shared SDK. Setting `NDS_TELEMETRY_ENABLED=off` prevents exporter
construction; local error/security records remain available. Collector accounts
are not installed in this server. Tracing admission, retries and shutdown are
bounded; the SDK records successful batches, failures and dropped spans. Confirm
actual OpenObserve receipt independently of the configuration flag.
