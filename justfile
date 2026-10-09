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


# Uses a new disposable PostgreSQL container, tmpfs data and synthetic secrets.
integration-postgres:
    cargo build --locked
    python3 scripts/check-postgres.py
