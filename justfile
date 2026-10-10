set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

fmt-check:
    cargo fmt --all -- --check

test:
    cargo test --workspace

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

check: fmt-check test clippy

protocol-check:
    python3 scripts/check-protocol.py

protocol-generate:
    python3 scripts/check-protocol.py --write


# Real PostgreSQL + SMTP mailbox, tmpfs data and generated synthetic identities.
integration-postgres:
    cargo build --locked
    python3 scripts/check-postgres.py
