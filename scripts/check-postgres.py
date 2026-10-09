#!/usr/bin/env python3
"""Disposable loopback-only PostgreSQL acceptance; never uses operator credentials."""
import json
import argparse
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from identity_acceptance import check_identity

arguments = argparse.ArgumentParser(description="Real isolated PostgreSQL/SMTP acceptance or a bounded client fixture")
arguments.add_argument("--fixture-receipt", type=Path)
arguments.add_argument("--fixture-seconds", type=int, default=1200)
options = arguments.parse_args()
if not 60 <= options.fixture_seconds <= 3600:
    arguments.error("fixture lifetime must be 60..3600 seconds")
if options.fixture_receipt is not None:
    repository = Path(__file__).resolve().parent.parent
    receipt = options.fixture_receipt.resolve()
    if not options.fixture_receipt.is_absolute() or receipt.is_relative_to(repository) or receipt.exists():
        arguments.error("fixture receipt must be a new absolute path outside the repository")

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c"
BINARY = ROOT / "target/debug/nddev-device-sync-server"
name = "nds-db-check-" + uuid.uuid4().hex[:12]
created = False
server = None
lock_holder = None


def command(*args, **kwargs):
    kwargs.setdefault("timeout", 90)
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()


def sql(statement, role="postgres", check=True):
    return subprocess.run(["docker", "exec", "-i", name, "psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-U", role, "-d", "nds", "-f", "-"], input=statement, check=check, capture_output=True, text=True, timeout=10)


def wait_ready(port, wanted):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/ready", timeout=1) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
        except urllib.error.URLError:
            time.sleep(0.1)
            continue
        if status == wanted:
            return
        time.sleep(0.1)
    raise AssertionError("readiness did not reach expected status")


try:
    with tempfile.TemporaryDirectory(prefix="nds-db-check-") as directory:
        directory = Path(directory)
        passwords = {kind: secrets.token_hex(24) for kind in ["admin", "migrator", "runtime"]}
        mounts = []
        for kind, password in passwords.items():
            path = directory / f"postgres_{kind}_password"
            path.write_text(password)
            path.chmod(0o444)  # Ephemeral parent is private; postgres UID reads bind-mounted file.
            mounts.extend(["--mount", f"type=bind,src={path},dst=/run/secrets/{path.name},readonly"])
        command("docker", "run", "--rm", "--detach", "--name", name, "--user", "postgres", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--memory", "512m", "--cpus", "1", "--pids-limit", "128", "--publish", "127.0.0.1::5432", "--tmpfs", "/var/lib/postgresql:uid=999,gid=999,mode=0700,size=256m", "--tmpfs", "/var/run/postgresql:uid=999,gid=999,mode=3775,size=16m", "--tmpfs", "/tmp:uid=999,gid=999,mode=1777,size=16m", "--env", "POSTGRES_DB=nds", "--env", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres_admin_password", *mounts, "--mount", f"type=bind,src={ROOT / 'deploy/postgres-init.sh'},dst=/docker-entrypoint-initdb.d/10-nds-roles.sh,readonly", IMAGE)
        created = True
        host_port = json.loads(command("docker", "inspect", name))[0]["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"]
        for _ in range(100):
            # Initdb restarts PostgreSQL after provisioning roles. Every probe
            # must tolerate that transition rather than chaining a checked query.
            result = sql("SELECT count(*) FROM pg_roles WHERE rolname='nds_runtime'", check=False)
            if result.returncode == 0 and result.stdout.strip() == "1":
                # Wait for final TCP server, not the initialization socket server.
                try:
                    with socket.create_connection(("127.0.0.1", int(host_port)), timeout=0.2):
                        break
                except OSError:
                    pass
            time.sleep(0.1)
        else:
            raise AssertionError("disposable PostgreSQL did not initialize")
        urls = {}
        for kind, password in passwords.items():
            role = "postgres" if kind == "admin" else "nds_" + kind
            path = directory / f"{kind}_url"
            path.write_text(f"postgres://{role}:{password}@127.0.0.1:{host_port}/nds\n")
            urls[kind] = str(path)
        env = {key: value for key, value in os.environ.items() if not key.startswith(("NDS_", "DATABASE_URL")) and key != "RUST_LOG"}
        env["DATABASE_URL_FILE"] = urls["runtime"]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env["NDS_SERVER_ADDR"] = f"127.0.0.1:{port}"
        env["NDS_MAX_REQUESTS"] = "1"
        env["NDS_LOG_MODE"] = "normal"
        for key in ["NDS_DEBUG_SCOPE", "NDS_DEBUG_SECONDS", "NDS_DEBUG_EVENT_LIMIT"]:
            env.pop(key, None)
        server = subprocess.Popen([BINARY, "serve"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        wait_ready(port, 503)
        assert sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").stdout.strip() == "0", "runtime created schema before migrations"
        server.terminate()
        logs = server.communicate(timeout=25)[0]
        assert server.returncode == 0
        server = None
        migration_env = env | {"NDS_MIGRATION_DATABASE_URL_FILE": urls["migrator"]}
        for _ in range(2):
            logs += command(str(BINARY), "migrate", env=migration_env) + "\n"
        assert sql("SELECT count(*) FROM _sqlx_migrations WHERE success").stdout.strip() == "2"
        assert sql("CREATE TABLE prohibited(id INT)", "nds_runtime", check=False).returncode != 0
        assert sql("UPDATE _sqlx_migrations SET success=false WHERE false", "nds_runtime", check=False).returncode != 0
        server = subprocess.Popen([BINARY, "serve"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        wait_ready(port, 200)
        # Actual PostgreSQL lock contention holds the only request permit. The
        # second HTTP request must reject immediately, and recover after release.
        lock_holder = subprocess.Popen(["docker", "exec", name, "psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "nds", "-c", "BEGIN; LOCK TABLE nddev_schema_meta IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(2); COMMIT;"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(100):
            if sql("SELECT count(*) FROM pg_locks WHERE relation='nddev_schema_meta'::regclass AND mode='AccessExclusiveLock' AND granted").stdout.strip() == "1":
                break
            time.sleep(0.01)
        else:
            raise AssertionError("lock holder did not acquire table lock")
        with ThreadPoolExecutor(max_workers=1) as executor:
            waiting = executor.submit(urllib.request.urlopen, f"http://127.0.0.1:{port}/v1/ready", timeout=5)
            for _ in range(100):
                if sql("SELECT count(*) FROM pg_stat_activity WHERE usename='nds_runtime' AND wait_event_type='Lock'").stdout.strip() == "1":
                    break
                time.sleep(0.01)
            else:
                raise AssertionError("readiness did not wait on real database contention")
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/health", timeout=1)
                raise AssertionError("request admission did not reject saturation")
            except urllib.error.HTTPError as error:
                assert error.code == 503
                assert error.headers["Cache-Control"] == "no-store"
                assert error.headers["Retry-After"] == "1"
                assert len(error.headers["X-Request-Id"]) == 32
                assert json.load(error)["error"] == "server_busy"
            with waiting.result(timeout=5) as response:
                assert response.status == 200
        lock_holder.communicate(timeout=5)
        assert lock_holder.returncode == 0
        lock_holder = None
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/health", timeout=1) as response:
            assert response.status == 200
        server.terminate()
        logs += server.communicate(timeout=25)[0]
        assert server.returncode == 0
        server = None
        rejected = subprocess.run([BINARY, "serve"], env=env | {"DATABASE_URL_FILE": urls["admin"]}, capture_output=True, text=True, timeout=8)
        assert rejected.returncode != 0
        logs += rejected.stdout + rejected.stderr
        assert "administrative or schema creation privileges" in rejected.stdout
        for password in passwords.values():
            assert password not in logs
        assert str(directory) not in logs
        events = [json.loads(line) for line in logs.splitlines() if line.strip()]
        for event in events:
            for field in ["timestamp", "severity", "service.name", "service.version", "deployment.environment", "release.channel", "release.version", "source.repository", "source.commit", "module", "event.name"]:
                assert isinstance(event[field], str), f"missing envelope field {field}"
        for event_name in ["database.migration.started", "database.migration.completed", "process.failed", "admission.saturated", "admission.recovered"]:
            assert any(event["event.name"] == event_name for event in events)
        print("PostgreSQL acceptance passed: migrations replay safely; restricted runtime performs no DDL; real database contention proves bounded request admission and recovery; process/migration envelopes and secrets are verified.")
        check_identity(BINARY, directory, env, sql, command, options.fixture_receipt, options.fixture_seconds)
finally:
    if lock_holder is not None:
        lock_holder.terminate()
        lock_holder.communicate(timeout=5)
    if server is not None:
        server.terminate()
        server.communicate(timeout=25)
    if created:
        command("docker", "stop", "--time", "10", name)
