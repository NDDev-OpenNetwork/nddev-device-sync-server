# Direct HTTPS alpha foundation

The application terminates TLS using Rust/rustls. No reverse proxy, CDN, HTTP
cache, certificate issuance service or backup/recovery job is included. DNS-only
records and a publicly trusted certificate belong to the operator. Reachability
from a region must be measured there; direct DNS cannot guarantee routing.

## Configuration

| Setting | Meaning |
| --- | --- |
| `NDS_SERVER_ADDR` | Listener, defaults to loopback `127.0.0.1:8080` |
| `DATABASE_URL_FILE` | Runtime PostgreSQL URL, from a mounted secret file |
| `DATABASE_URL` | Alternative for local development; never configure both forms |
| `NDS_MIGRATION_DATABASE_URL_FILE` | Separate migration credential; read only by `migrate` |
| `NDS_MIGRATION_DATABASE_URL` | Alternative migration secret for local development |
| `NDS_TLS_CERT_FILE`, `NDS_TLS_KEY_FILE` | PEM certificate chain and matching private key; both required to enable HTTPS |

Absent TLS configuration enables HTTP for local development. A partial or invalid
pair fails startup; there is no fallback from failed TLS to plaintext. Production
must set both files. Database URLs are redacted in Debug; errors exclude SQLx
messages, secret contents and TLS paths. Secret URL files are limited to 16 KiB.
TLS files are bounded to 256 KiB (chain) and 16 KiB (key), with a five-second load
deadline. Use trusted local regular files, readable only by their service users.

Runtime startup never executes migrations. It rejects a role with superuser,
role/database creation or `public` schema creation privileges. The runtime
identity needs access only to application tables. `/v1/ready` checks the baseline
schema record as well as connectivity; an unmigrated database is not ready.

Run `nddev-device-sync-server migrate` explicitly before `serve`. Migrations have
a sixty-second deadline and a separate credential. The Compose initializer
creates `nds_migrator` (schema owner) and `nds_runtime` (read access for the current
health slice). Runtime cannot modify the SQLx ledger or create schema objects.
Future mutation migrations must grant only the required table/sequence writes.
Administrative access stays with PostgreSQL; observability credentials are not
provisioned until the observability service exists.

## Compose template

`compose.yaml` creates isolated application/database networks, a PostgreSQL 18
named volume, a one-shot migration service and the non-root HTTPS server. Only
HTTPS is published. Application and PostgreSQL run with read-only root filesystems,
no Linux capabilities, bounded CPU/memory/processes, bounded local logs and health
checks. The data volume is live storage, with no backup or recovery service.

Prepare an operator-owned directory outside the source checkout with five files:

- `postgres_admin_password`, `postgres_migrator_password`, `postgres_runtime_password`:
  distinct generated passwords;
- `migration_database_url`: `postgres://nds_migrator:<encoded-password>@postgres/nds`;
- `runtime_database_url`: `postgres://nds_runtime:<encoded-password>@postgres/nds`.

Passwords inside URLs must be percent-encoded. Do not put secrets in command
arguments, `.env` files, Git or logs. Compose file secrets are bind-mounted, so
host ownership/mode must permit UID 999 to read PostgreSQL password files and UID
10001 to read each app URL file. Verify permissions without printing contents.
Role initialization occurs only on an empty database volume. Changed secret
files do not automatically rotate database roles. Never delete a volume to
repair credentials or re-run initialization.

Set non-secret deployment inputs outside Git:

```sh
export NDS_IMAGE='registry.example.invalid/nds/server@sha256:<reviewed-image-digest>'
export NDS_SOURCE_COMMIT='<full-source-commit>'
export NDS_PUBLIC_HOST='sync.example.invalid'
export NDS_HTTPS_BIND='0.0.0.0'
export NDS_SECRETS_DIRECTORY='/operator-owned/secrets'
export NDS_TLS_DIRECTORY='/operator-owned/tls'
docker compose config --quiet
docker compose up -d
```

The template defaults to publishing on loopback until an operator chooses a
public bind address. Its container healthcheck validates the certificate hostname
and chain (never `curl -k`). Local integration with a private CA must explicitly
mount that CA and configure curl's trust bundle. For a development build, supply
a local `NDS_IMAGE` tag, a full `NDS_SOURCE_COMMIT`, and run `docker compose build`.
Release deployments must instead consume the reviewed built image by digest.

The baseline is not an OAuth/login application yet. It exposes `/v1/health`,
`/v1/ready`, and `/source`, with request IDs and `Cache-Control: no-store` on both
successful and error responses. Certificate private keys and database URLs never
enter HTTP responses. The observability pipeline remains a separate slice.

## Certificate renewal and shutdown

The operator owns issuance, renewal and expiry monitoring. Mount the parent TLS
directory, containing `current/fullchain.pem` and `current/privkey.pem`, read-only
into the application. Under the issuer's update lock, validate and replace the
active matching pair, then signal the application only after both files are
complete. Keep keys readable by application UID/GID 10001 and not by unrelated
users. A `current` symlink may point to the active directory within this mount;
do not retain old certificate generations as recovery copies. Mounting a
single file would retain the old inode after replacement. The application's
last valid configuration remains only in memory if a reload is rejected.

On Unix, signal the running service after replacement:

```sh
docker compose kill --signal SIGHUP nddev-sync-server
```

The reload has a five-second deadline. A valid pair is atomically published for
new handshakes; existing connections continue. A failed pair keeps the last valid
configuration and emits `tls.reload.failed`; fix the pair and signal again.
There is no periodic polling, unbounded retry queue, or certificate acquisition.
On non-Unix systems use a controlled restart after validating both files.

TLS handshakes have a five-second deadline. HTTP/1 header reads have a ten-second
deadline, HTTP/2 concurrent streams are capped at 64, and idle HTTP/2 peers have
bounded keepalive checks. Handlers have the existing fifteen-second deadline.
SIGTERM/Ctrl+C stops accepting and drains for at most twenty seconds, then closes
remaining connections. Compose allows twenty-five seconds before forced exit.
