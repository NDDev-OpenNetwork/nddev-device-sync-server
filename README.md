# nddev-device-sync-server

Public AGPL-3.0-only Rust control-plane server for `nddev-device-sync`.

The first vertical slice provides:

- one structured JSON envelope for process, migration and request events;
- request correlation through `traceparent` or generated trace IDs;
- `/v1/health`, `/v1/ready` and `/source` endpoints;
- PostgreSQL readiness and an explicit migration command with a separate identity;
- direct Rust/rustls HTTPS, bounded connection drain and safe certificate reload;
- finite connection/handler admission and scoped, expiring debug diagnostics;
- pinned consumption of the public core and protocol releases;
- a module count exposed from the compiled core registry.

GitHub OAuth, device enrollment, sync mutations, vault and observability
gateway are separate next steps. They are not silently emulated by this
foundation server.

## Local development

```sh
just fmt-check
just test
just clippy
```

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
