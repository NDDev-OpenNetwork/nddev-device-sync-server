# HTTPS adapter dependency decisions

The server maintainers own these dependencies. Cargo.lock pins exact versions;
updates require the route, TLS, redaction and migration integration checks plus
cargo-audit. All licenses below are compatible with this AGPL-3.0-only server.

| Dependency | Purpose | License | Removal condition |
| --- | --- | --- | --- |
| axum-server 0.8 | Maintained rustls acceptor, HTTP protocol driver and bounded connection drain | MIT | Axum provides equivalent TLS lifecycle support |
| rustls 0.23 with ring | Explicit shared TLS crypto provider; HTTPS and SQLx use the same stack | Apache-2.0 OR ISC OR MIT | Transport standard replaces rustls |
| hyper-util 0.1 | Tokio timer for HTTP header and HTTP/2 keepalive deadlines; already transitive | MIT | axum-server exposes these timers directly |
| tower 0.5 | Existing Service trait for admission before connection task creation; already locked | MIT | axum-server provides equivalent bounded admission |
| rcgen 0.14 (tests) | Ephemeral test certificates; no private-key fixtures in Git | MIT OR Apache-2.0 | TLS integration tests move to another reviewed fixture generator |
| tokio-rustls 0.26 (tests) | Verify real encrypted handshakes and presented certificate changes | MIT OR Apache-2.0 | Equivalent TLS client is already present for another test need |

Official APIs: [axum-server](https://docs.rs/axum-server/0.8.0/axum_server/),
[rustls](https://docs.rs/rustls/0.23.32/rustls/).

Container bases use official-image manifest-list digests verified through the
Docker registry on 2026-10-09. Review updates to Rust 1.99, Debian bookworm-slim
and PostgreSQL 18.x together with OS/security package updates. The final app image
also contains Debian ca-certificates (trust roots) and curl (bounded verified
HTTPS readiness probe). Publish and consume that built image by digest; a source
build with current apt packages is not a bit-for-bit reproducible release.

`deny.toml` records the reviewed compatible licenses actually present in the
locked graph and restricts Git dependencies to the pinned core repository.
It does not change the product license or waive advisory findings. The added
TLS runtime crates use MIT/Apache/ISC; rcgen-generated test material remains
local and ephemeral.
