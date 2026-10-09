# Server adapter dependency decisions

The server maintainers own these dependencies. Cargo.lock pins exact versions;
updates require the route, TLS, redaction and migration integration checks plus
cargo-audit. All licenses below are compatible with this AGPL-3.0-only server.

| Dependency | Purpose | License | Removal condition |
| --- | --- | --- | --- |
| axum-server 0.8 | Maintained rustls acceptor, HTTP protocol driver and bounded connection drain | MIT | Axum provides equivalent TLS lifecycle support |
| rustls 0.23 with ring | Explicit shared TLS crypto provider; HTTPS and SQLx use the same stack | Apache-2.0 OR ISC OR MIT | Transport standard replaces rustls |
| hyper-util 0.1 | Tokio timer for HTTP header and HTTP/2 keepalive deadlines; already transitive | MIT | axum-server exposes these timers directly |
| tower 0.5 | Existing Service trait for admission before connection task creation; already locked | MIT | axum-server provides equivalent bounded admission |
| lettre 0.11 | Maintained SMTP/TLS transport and safe MIME encoding; no pool or alternate HTTP mail adapter | MIT | An existing owned email adapter provides equivalent verified delivery |
| reqwest 0.13 | Fixed-endpoint GitHub HTTPS exchange, redirects disabled and response/time bounds | MIT OR Apache-2.0 | Another owned HTTP adapter covers the same provider contract |
| ring 0.17 | OS randomness, HMAC-SHA256 protected verifiers and standard PKCE digest; already used by TLS | Apache-2.0 AND ISC | The reviewed shared crypto provider changes |
| subtle 2.6 | Constant-time comparison of fixed-size protected verifiers | BSD-3-Clause | The shared crypto provider exposes the same reviewed operation |
| base64 0.22 | Canonical RFC 4648 unpadded base64url credentials and PKCE encoding | MIT OR Apache-2.0 | An existing owned codec provides the same format |
| time 0.3 | Checked RFC 3339 session expiry output; already present in the locked graph | MIT OR Apache-2.0 | An existing owned date-time adapter covers this wire contract |
| rcgen 0.14 (tests) | Ephemeral test certificates; no private-key fixtures in Git | MIT OR Apache-2.0 | TLS integration tests move to another reviewed fixture generator |
| tokio-rustls 0.26 (tests) | Verify real encrypted handshakes and presented certificate changes | MIT OR Apache-2.0 | Equivalent TLS client is already present for another test need |

Official APIs: [axum-server](https://docs.rs/axum-server/0.8.0/axum_server/),
[rustls](https://docs.rs/rustls/0.23.32/rustls/).
Identity adapters follow [GitHub OAuth documentation](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
and [lettre SMTP APIs](https://docs.rs/lettre/0.11.23/lettre/transport/smtp/struct.AsyncSmtpTransport.html).
For Resend, [its SMTP contract](https://resend.com/docs/send-with-smtp) includes
implicit TLS on 2465. Provider reachability and isolated Mailpit acceptance do
not substitute for actual external mailbox or GitHub owner sign-in evidence.

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

The new SMTP graph includes `quoted_printable` under
[0BSD](https://spdx.org/licenses/0BSD.html). Its packaged license was reviewed
as a permissive dependency license and explicitly added to `deny.toml`;
the application remains AGPL-3.0-only. Dependency updates require the real
PostgreSQL/SMTP lifecycle checks and the provider/crypto boundary tests.
