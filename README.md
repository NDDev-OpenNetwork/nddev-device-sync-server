# nddev-device-sync-server

Public AGPL-3.0-only Rust control-plane server for `nddev-device-sync`.

The first vertical slice provides:

- structured JSON startup/request logs;
- request correlation through `traceparent` or generated trace IDs;
- `/v1/health`, `/v1/ready` and `/source` endpoints;
- PostgreSQL readiness and a baseline migration;
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

Set `DATABASE_URL` to enable PostgreSQL readiness and migrations. Without it,
the process still starts for route tests, while `/v1/ready` reports degraded.

