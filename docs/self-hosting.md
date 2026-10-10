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
| `NDS_MAX_CONNECTIONS` | Accepted connection tasks including TLS handshakes; default 256, range 1–4096 |
| `NDS_MAX_REQUESTS` | Active handlers across all connections; default 64, range 1–1024 |
| `NDS_ENVIRONMENT` | Non-secret deployment label for every local event; default `self-hosted` |

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
creates `nds_migrator` (schema owner) and `nds_runtime`. The baseline grants
metadata reads; the identity migration grants bootstrap-owner insertion,
challenge/rate-state mutations and session insertion/deletion. Runtime cannot
reassign the owner, modify the SQLx ledger or create schema objects.
Enrollment adds device insertion/status updates and bounded challenge state.
Session writers, revocation, observed expiry and enrollment authorization share
one bounded PostgreSQL advisory transaction lock. Runtime has no session UPDATE
grant and cannot extend expiry or alter a stored session binding.
Device rows have no runtime DELETE grant, preserving revoked identities.
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

The server exposes `/v1/health`, `/v1/ready`, `/source` and the implemented v2
identity/device routes, with request IDs and `Cache-Control: no-store`. Identity is
unavailable until configured privately. `/v1/ready` requires schema version 3;
use the explicit migrator before starting the updated runtime. The observability
pipeline remains a separate slice.

## Owner identity

Set `NDS_AUTH_CONFIG_FILE` to an operator-owned JSON file, at most 16 KiB.
For Compose, use `compose.yaml` plus `compose.identity.yaml` and set
`NDS_AUTH_DIRECTORY`; the overlay mounts this directory read-only at
`/run/nds-auth`. Paths inside the JSON refer to readable files in that mount.
Protect it from unrelated users and never put the file or secrets in Git.

| JSON field | Contract |
| --- | --- |
| `owner_email` | Explicit permitted ASCII mailbox; trim and lowercase comparison |
| `pepper_file` | Separate file containing canonical unpadded base64url of 32 cryptographically random bytes |
| `smtp` | Optional object: `host`, `port`, `tls`, `from`; optional paired `username` and `password_file` |
| `smtp.tls` | `tls` for implicit TLS, `starttls` for mandatory STARTTLS, or `loopback` only for literal loopback relay addresses |
| `github` | Optional object: stable numeric `owner_id`, `client_id`, `client_secret_file`, `callback_url` |
| `github.callback_url` | Exact HTTPS URL ending in `/v2/auth/github/callback`, without user info, query or fragment |

At least one provider must be configured. SMTP ports are configurable, including
implicit TLS on 2465 for providers supporting it. External relays always require
TLS certificate validation. The GitHub adapter only calls fixed github.com and
api.github.com endpoints and never follows redirects. Its provider access token
exists only for the bounded code exchange and identity read.

Bootstrap creates one persistent internal user/tenant identity from this private
configuration. A later different email/pepper/GitHub binding fails startup;
runtime cannot silently reassign the owner. Configure both desired bindings
before initial startup. Provider linking or credential rotation requires a
separate reviewed operation. Public registration is absent.

Email challenges use eight-digit codes, five-minute expiry, five attempts and
a sixty-second resend delay. A permitted resend invalidates the previous code.
Subject limits allow five challenges/hour and source limits ten starts/fifteen
minutes. Source identity uses the socket IP; forwarding headers and ephemeral
ports cannot change it. Store protected HMAC verifiers, never plaintext codes.
Responses are generic for permitted and other valid mailboxes. SMTP uses a
sixteen-item memory queue and an eight-second delivery deadline, with no retry
of an uncertain delivery. Required local failures remain visible. Provider
acceptance is not proof of mailbox delivery.

GitHub flows last five minutes, are bounded to 128 and disappear on process
restart. After stable provider ID verification, the browser shows the same
comparison code as the initiating app. An explicit approval requires its
one-use HttpOnly/Secure/SameSite cookie, CSRF proof and exact origin. GET callback
alone never approves an initiating app. The app polls at most once every two
seconds and consumes its opaque exchange capability once. An interrupted or
failed exchange may require starting sign-in again.

Both methods issue the same eight-hour owner session; at most 32 active sessions
are retained. Session digests persist in PostgreSQL; GET `/v2/session` validates
ownership/expiry and DELETE revokes the current session. A session does not
recover device/vault keys. Expired challenge/session/rate state is pruned on
identity activity within fixed table capacities. Pending SMTP work is discarded
on shutdown; already-delivered unexpired OTP verifiers survive restart under
the unchanged pepper.

`Accept-Language: en` or `ru` on the initial request selects email and approval
text, defaulting to English. The locale is bound to the pending flow. Anonymous
`/v2/auth/methods` reads cached provider state only: bounded startup/background
checks, sixty-second refresh and failure backoff capped at five minutes.
Stale readiness becomes unavailable. GitHub readiness is not evidence of a
successful credential/owner exchange; prove that with an actual sign-in.
Authentication requires HTTPS unless the HTTP listener is loopback-only.

## Device identity

An authenticated owner requests `/v2/devices/challenges` with platform, display
name and the per-installation public Ed25519 key. Native secure storage owns the
private key. The server rejects malformed, noncanonical, weak and non-prime-order
public keys before allocating a challenge. Proof signs the exact protocol
domain prefix and decoded 32-byte challenge; `/v2/devices/enrollments` requires
the same initiating session, rechecked and locked inside the database transaction.
A challenge lasts at most five minutes and no longer than that session, allows
five attempts and is consumed once. Expired or exhausted proof cannot revive.

Personal alpha bounds are eight pending challenges, 32 active devices and 128
retained device identities per owner. Source limits allow ten starts per fifteen
minutes and use the socket IP. Terminal challenge rows are discarded on new
enrollment activity. Device rows persist: revocation is terminal for that public
key, and retained-identity exhaustion fails closed until a separately reviewed
lifecycle change exists. No automatic pruning or key rotation is implemented.

GET `/v2/devices` returns owned devices including revoked ones and an opaque
cursor. The requested limit is 1–100; each response contains at most 32 items
to bound encoded size even for maximal Unicode names. DELETE
`/v2/devices/{device_id}` is idempotent for an owned device and retains its row.
If a completion response is uncertain, retain the local key and inspect the
owned device list. Enrollment does not supply vault decryption keys, restore
secrets or yet authorize a sync endpoint; signed sync is a separate slice.

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

Admission has no application wait queue. At connection capacity, an accepted
socket closes before a TLS handshake or connection task is created. At handler
capacity, requests receive `503 server_busy`, `Retry-After: 1`, correlation and
`no-store`; clients must use bounded backoff. Permits return on completion,
disconnect, timeout or failed handshake. Pressure events aggregate rejection
counts at the first rejection, powers of two and recovery; rejected HTTP
requests still emit their normal error events. These bounds complement container
limits. Streaming handlers must define their own body lifetime bounds before
they are introduced.

## Local logging

Every process event uses one flat JSON envelope, including startup failures,
migrations, TLS reload and shutdown. Version/channel/standards/environment
labels permit only 1–128 ASCII letters, digits, dots, underscores and hyphens.
Normal logging is the default. `RUST_LOG` does not enable dependency dumps.
Local logs remain available when telemetry export is disabled; the exporter
itself is not implemented by this foundation.

Each emitted record carries a per-process `producer.instance_id` and ordered
`producer.sequence` assigned under the stdout write lock. Filtered events do not
consume sequence numbers. The optional pair is omitted after the exact JSON
integer limit instead of wrapping. Gaps can expose discontinuity; they do not
alone prove an exact dropped-event count.

For a diagnostic window, explicitly set `NDS_LOG_MODE=debug`,
`NDS_DEBUG_SCOPE=http|transport|database`, and `NDS_DEBUG_SECONDS=1..900`.
`NDS_DEBUG_EVENT_LIMIT` defaults to 1000, with a supported range of 1–10000.
The process automatically returns to normal at expiry or budget exhaustion;
enable/disable transitions include scope and reason. Debug adds only named
events with bounded fields, never bodies, credentials or raw URLs. Both modes
use the bounded Compose log retention. Remove all `NDS_DEBUG_*` settings when
setting `NDS_LOG_MODE=normal`; contradictory settings fail startup safely.
