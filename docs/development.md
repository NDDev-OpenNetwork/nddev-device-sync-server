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

The module standards lock remains at `v0.0.1-alpha.7` (`592531d`).
Central `v0.0.1-alpha.8` (`c73a525`) changes assembly catalog metadata only;
the normative `standarts/` files are identical. The older lock is compatible
with the current assembly. Update locks only through the canonical source
release, not through a mutable branch.

The server currently consumes core and protocol alpha.5. Core runtime sources
and wire schemas are unchanged through alpha.7; these pins remain explicit
until the next coordinated contract change. OAuth, enrollment and sync-log
acceptance are separate from the existing health/readiness route checks.

Run `just integration-postgres` for the explicit migration boundary. It creates
only a new loopback-only PostgreSQL container with tmpfs storage and generated
test secrets, validates migrations from zero and repeated runs, proves the
runtime cannot create tables or modify the SQLx ledger, rejects an administrative
runtime identity, and stops that test container. No operator database or named
volume is inspected or modified. CI runs this after `just check`.
