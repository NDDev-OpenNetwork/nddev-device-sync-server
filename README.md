# nddev-device-sync-server

Public AGPL-3.0-only Rust control-plane server for `nddev-device-sync`.

Part of [NDDev OpenNetwork](https://nddev.ai).

The current server provides:

- one structured JSON envelope for process, migration and request events;
- request correlation through `traceparent` or generated trace IDs;
- `/v1/health`, `/v1/ready` and `/source` endpoints;
- PostgreSQL readiness and an explicit migration command with a separate identity;
- direct Rust/rustls HTTPS, bounded connection drain and safe certificate reload;
- finite connection/handler admission and scoped, expiring debug diagnostics;
- email OTP and GitHub PKCE for one explicitly configured owner;
- browser pairing approval, expiring/revocable sessions and bounded abuse controls;
- generated wire types and immutable core/protocol source pins;
- a module count exposed from the compiled core registry.

Device enrollment, sync mutations, vault and the observability gateway are
separate next steps. Without private identity configuration, `/v2/auth/methods`
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
`venv` and pip support is required. Event values are neither saved nor printed.

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
driver messages. The server accepts version `00` W3C trace context with lowercase
hexadecimal identifiers and flags, replacing invalid input with a fresh trace ID.
All HTTP responses, including readiness failures and timeouts, use
`Cache-Control: no-store`. An instance that requires direct origin access must
also use DNS-only records and omit CDN/proxy response caching in its deployment.

The local JSON log remains available for diagnosis. The telemetry-enabled health
field describes operator intent; delivery through the future observability
service and its enabled/disabled behavior remain a separate implementation step.
