# Development workflow

Use the pinned toolchain and the repository's `just` recipes. Keep runtime
credentials, private estate data and live telemetry outside this repository.

`main` and `dev` are permanent branches. Make scoped changes on a working
branch, submit a pull request to `dev`, and promote reviewed changes from
`dev` to `main`. Use Conventional Commits and signed commits. Do not delete
permanent branches or rewrite published history.

The `NDS checks / quality` job runs on GitHub-hosted Ubuntu with read-only
repository permissions and immutable action pins. It checks this repository's
current foundation. A green result is not deployment, release, integration or
cross-platform acceptance. Full release gates remain those in the locked
central standards.

## Standards compatibility

The identity slice adopts `v0.0.1-alpha.9`
(`16a477beac6127adf73ef102df74a48451d607f1`). ADR 0003 permits email OTP and
GitHub PKCE for one explicitly configured owner. `module.yaml` records the
immutable paired core and protocol commits. These development commits do not
rename published releases or imply enrollment/sync acceptance.

`just protocol-check` regenerates the owned authentication DTO from the exact
protocol commit, its locked quicktype tool and rustfmt. It reads existing local
Git objects when available or downloads only the pinned source files into a
temporary directory. It never clones another checkout or edits the generated
consumer as a substitute for changing its canonical schema.

Run `just integration-postgres` for the explicit migration boundary. It creates
only a new loopback-only PostgreSQL container with tmpfs storage and generated
test secrets, validates migrations from zero and repeated runs, proves the
runtime cannot create tables or modify the SQLx ledger, rejects an administrative
runtime identity, and stops that test container. The same isolated database and
a pinned Mailpit SMTP mailbox exercise real OTP delivery, concurrent replay,
resend/attempt/expiry rules, owner binding, session persistence/revocation and
socket-source rate limits. Private operator databases and mailboxes are not used.
Local SMTP capture does not prove delivery to an external provider's mailbox;
live GitHub identity/consent acceptance remains a separate observation.

For a real client, `scripts/check-postgres.py --fixture-receipt <new-absolute-path>
--fixture-seconds 1800` starts the same isolated runtime and writes a private
receipt containing its loopback API, Mailpit API and generated owner address.
Create the receipt's `stop_marker` to finish early; the bounded lease also stops
the owned processes/containers automatically. The receipt must be outside Git.
