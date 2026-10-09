#!/usr/bin/env python3
"""Disposable loopback-only PostgreSQL acceptance; never uses operator credentials."""
import json
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

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c"
BINARY = ROOT / "target/debug/nddev-device-sync-server"
name = "nds-db-check-" + uuid.uuid4().hex[:12]
created = False
server = None


def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()


def sql(statement, role="postgres", check=True):
    return subprocess.run(["docker", "exec", name, "psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-U", role, "-d", "nds", "-c", statement], check=check, capture_output=True, text=True)


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
            result = sql("SELECT 1", check=False)
            if result.returncode == 0 and sql("SELECT count(*) FROM pg_roles WHERE rolname='nds_runtime'").stdout.strip() == "1":
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
        env = {key: value for key, value in os.environ.items() if key not in {"DATABASE_URL", "DATABASE_URL_FILE", "NDS_MIGRATION_DATABASE_URL", "NDS_MIGRATION_DATABASE_URL_FILE", "NDS_TLS_CERT_FILE", "NDS_TLS_KEY_FILE"}}
        env["DATABASE_URL_FILE"] = urls["runtime"]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env["NDS_SERVER_ADDR"] = f"127.0.0.1:{port}"
        server = subprocess.Popen([BINARY, "serve"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        wait_ready(port, 503)
        assert sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").stdout.strip() == "0", "runtime created schema before migrations"
        server.terminate()
        logs = server.communicate(timeout=25)[0]
        assert server.returncode == 0
        server = None
        migration_env = env | {"NDS_MIGRATION_DATABASE_URL_FILE": urls["migrator"]}
        for _ in range(2):
            logs += command(str(BINARY), "migrate", env=migration_env)
        assert sql("SELECT count(*) FROM _sqlx_migrations WHERE success").stdout.strip() == "1"
        assert sql("CREATE TABLE prohibited(id INT)", "nds_runtime", check=False).returncode != 0
        assert sql("UPDATE _sqlx_migrations SET success=false WHERE false", "nds_runtime", check=False).returncode != 0
        server = subprocess.Popen([BINARY, "serve"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        wait_ready(port, 200)
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
        print("PostgreSQL acceptance passed: empty schema is not ready; runtime performs no DDL; migrations replay safely; restricted runtime is ready; admin role rejected; logs redacted.")
finally:
    if server is not None:
        server.terminate()
        server.communicate(timeout=25)
    if created:
        command("docker", "stop", "--time", "10", name)
