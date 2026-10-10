"""Real HTTP + PostgreSQL + isolated SMTP mailbox acceptance. No external mail."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import secrets
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from enrollment_acceptance import check_enrollment

MAILPIT = "axllent/mailpit:v1.31.4@sha256:b68349e3a014b90c5610bfb26b2ae36f3892d7b8cf25ee140c6c71c98d2fcf48"


def check_identity(binary, directory, env, sql, command, validate_events, fixture_receipt=None, fixture_seconds=1200):
    mailbox = "nds-mail-check-" + uuid.uuid4().hex[:12]
    server = None
    created = False
    logs = ""
    sensitive = []
    captures = {}
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        command("docker", "run", "--rm", "--detach", "--name", mailbox, "--user", "10001:10001", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64", "--publish", "127.0.0.1::1025", "--publish", "127.0.0.1::8025", "--tmpfs", "/data:uid=10001,gid=10001,mode=0700,size=32m", "--env", "MP_DATABASE=/data/mailpit.db", "--env", "MP_MAX_MESSAGES=25", "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=2", MAILPIT)
        created = True
        ports = json.loads(command("docker", "inspect", mailbox))[0]["NetworkSettings"]["Ports"]
        smtp_port = int(ports["1025/tcp"][0]["HostPort"])
        mail_url = "http://127.0.0.1:" + ports["8025/tcp"][0]["HostPort"]
        owner = "owner-" + uuid.uuid4().hex + "@example.invalid"
        unknown = "other-" + uuid.uuid4().hex + "@example.invalid"
        sensitive += [owner, unknown]
        pepper = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        sensitive.append(pepper)
        pepper_file = Path(directory) / "identity_pepper"
        pepper_file.write_text(pepper)
        pepper_file.chmod(0o600)
        config = {"owner_email": owner, "pepper_file": str(pepper_file), "smtp": {"host": "127.0.0.1", "port": smtp_port, "tls": "loopback", "from": "nds-" + uuid.uuid4().hex + "@example.invalid"}}
        config_file = Path(directory) / "identity.json"
        config_file.write_text(json.dumps(config))
        config_file.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = env | {"NDS_AUTH_CONFIG_FILE": str(config_file), "NDS_SERVER_ADDR": f"127.0.0.1:{port}", "NDS_MAX_REQUESTS": "64"}

        def request(path, body=None, token=None, method=None, headers=None):
            headers = (headers or {}) | ({"Content-Type": "application/json"} if body is not None else {})
            if token is not None:
                headers["Authorization"] = "Bearer " + token
            req = urllib.request.Request(f"http://127.0.0.1:{port}" + path, data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
            try:
                response = http.open(req, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                raw = response.read(65537)
                assert len(raw) <= 65536, "response exceeded the protocol byte budget"
                assert response.headers["Cache-Control"] == "no-store"
                assert len(response.headers["X-Request-Id"]) == 32
                return response.status, json.loads(raw) if raw else None

        def start():
            child = subprocess.Popen([binary, "serve"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            capture = {"lines": [], "bytes": 0, "overflow": False}
            def drain():
                for line in child.stdout:
                    capture["bytes"] += len(line)
                    if capture["bytes"] > 2 * 1024 * 1024:
                        capture["overflow"] = True
                        child.terminate()
                        break
                    capture["lines"].append(line)
            reader = threading.Thread(target=drain, daemon=True)
            captures[child.pid] = (capture, reader)
            reader.start()
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                try:
                    if request("/v1/ready")[0] == 200:
                        return child
                except (urllib.error.URLError, OSError):
                    pass
                if child.poll() is not None:
                    break
                time.sleep(0.05)
            stop(child)
            raise AssertionError("identity process did not become ready")

        def stop(child):
            child.terminate()
            child.wait(timeout=25)
            saved = captures.pop(child.pid, None)
            if saved is None:
                return ""
            capture, reader = saved
            reader.join(timeout=2)
            assert not reader.is_alive() and not capture["overflow"], "bounded process log capture failed"
            return "".join(capture["lines"])

        def messages():
            with http.open(mail_url + "/api/v1/messages", timeout=2) as response:
                return json.load(response)["messages"]

        def code(expected_count):
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                items = messages()
                if len(items) == expected_count:
                    with http.open(mail_url + "/api/v1/message/" + items[0]["ID"], timeout=2) as response:
                        message = json.load(response)
                    assert any(recipient["Address"] == owner for recipient in message["To"])
                    match = re.search(r"(?:code|код входа): (\d{8})", message["Text"])
                    assert match, "actual SMTP message did not contain an OTP"
                    sensitive.append(match[1])
                    return match[1]
                time.sleep(0.05)
            raise AssertionError("SMTP mailbox did not receive expected message count")

        deadline = time.monotonic() + 10
        while True:
            try:
                assert messages() == []
                break
            except (urllib.error.URLError, OSError):
                assert time.monotonic() < deadline, "isolated SMTP mailbox did not start"
                time.sleep(0.05)
        assert sql("SELECT count(*) FROM nds_owner").stdout.strip() == "0"
        server = start()
        assert request("/v2/auth/methods") == (200, {"email_otp": "available", "github": "unavailable"})
        if fixture_receipt is not None:
            receipt = Path(fixture_receipt)
            stop_marker = receipt.with_suffix(".stop")
            state = {"base_url": f"http://127.0.0.1:{port}", "mailpit_url": mail_url, "owner_email": owner, "expires_at_unix": int(time.time()) + fixture_seconds, "stop_marker": str(stop_marker), "status": "running"}
            with receipt.open("x") as handle:
                json.dump(state, handle)
            receipt.chmod(0o600)
            print("Isolated identity fixture ready; receipt saved outside the repository.", flush=True)
            deadline = time.monotonic() + fixture_seconds
            try:
                while time.monotonic() < deadline and not stop_marker.exists():
                    if server.poll() is not None:
                        raise AssertionError("isolated identity server exited")
                    time.sleep(1)
            finally:
                state["status"] = "stopped"
                receipt.write_text(json.dumps(state))
                logs = stop(server)
                server = None
                validate_events(logs)
            return
        denied_status, denied_receipt = request("/v2/auth/email/challenges", {"email": unknown})
        status, receipt = request("/v2/auth/email/challenges", {"email": owner.upper()}, headers={"Accept-Language": "ru"})
        assert status == denied_status == 202
        assert denied_receipt.keys() == receipt.keys()
        assert len(denied_receipt["challenge_id"]) == len(receipt["challenge_id"]) == 43
        assert denied_receipt["expires_in_seconds"] == receipt["expires_in_seconds"] == 300
        assert denied_receipt["resend_after_seconds"] == receipt["resend_after_seconds"] == 60
        first_code = code(1)
        assert request("/v2/auth/email/verify", {"challenge_id": denied_receipt["challenge_id"], "code": first_code})[0] == 401
        assert request("/v2/auth/email/challenges", {"email": owner, "user_id": uuid.uuid4().hex})[0] == 400
        assert request("/v2/auth/email/challenges", {"email": " " * 255 + owner})[0] == 400
        assert request("/v2/auth/email/verify", {"challenge_id": receipt["challenge_id"], "code": first_code, "extra": "rejected"})[0] == 400
        assert sql("SELECT count(*) FROM nds_owner").stdout.strip() == "1"
        assert sql("SELECT bool_and(octet_length(verifier)=32) FROM nds_email_challenges").stdout.strip() == "t"
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(request, "/v2/auth/email/verify", {"challenge_id": receipt["challenge_id"], "code": first_code}) for _ in range(2)]
            results = [future.result(timeout=8) for future in futures]
        assert sorted(status for status, _ in results) == [200, 401], "concurrent OTP replay created multiple sessions"
        issued = next(body for status, body in results if status == 200)
        token = issued["session_token"]
        sensitive.append(token)
        assert len(token) == 43
        assert issued["session"]["auth_method"] == "email_otp"
        assert request("/v2/session", token=token) == (200, issued["session"])
        assert request("/v2/session")[0] == 401
        assert request("/v2/session", token=token, headers={"X-Forwarded-For": "192.0.2.90"})[0] == 200
        assert sql("SELECT bool_and(octet_length(token_digest)=32) FROM nds_sessions").stdout.strip() == "t"
        logs += stop(server)
        assert server.returncode == 0
        server = start()
        assert request("/v2/session", token=token) == (200, issued["session"]), "session or bootstrap owner changed on restart"
        wrong_config = Path(directory) / "different-owner.json"
        wrong_config.write_text(json.dumps(config | {"owner_email": unknown}))
        wrong_config.chmod(0o600)
        rejected = subprocess.run([binary, "serve"], env=env | {"NDS_AUTH_CONFIG_FILE": str(wrong_config), "NDS_SERVER_ADDR": "127.0.0.1:0"}, capture_output=True, text=True, timeout=8)
        assert rejected.returncode != 0 and "identity setup unavailable" in rejected.stdout
        logs += rejected.stdout + rejected.stderr
        assert request("/v2/session", token=token) == (200, issued["session"])
        plaintext = subprocess.run([binary, "serve"], env=env | {"NDS_SERVER_ADDR": "0.0.0.0:0"}, capture_output=True, text=True, timeout=8)
        assert plaintext.returncode != 0 and "identity requires HTTPS" in plaintext.stdout
        logs += plaintext.stdout + plaintext.stderr
        assert request("/v2/session", token=token, method="DELETE")[0] == 204
        assert request("/v2/session", token=token)[0] == 401

        # Reset only synthetic fixture budgets between independent cases. No
        # operator clock, credentials or database is touched by this test.
        sql("DELETE FROM nds_auth_limits; DELETE FROM nds_email_challenges;")
        _, old = request("/v2/auth/email/challenges", {"email": owner})
        old_code = code(2)
        _, suppressed = request("/v2/auth/email/challenges", {"email": owner})
        assert len(messages()) == 2
        assert request("/v2/auth/email/verify", {"challenge_id": suppressed["challenge_id"], "code": old_code})[0] == 401
        sql("UPDATE nds_email_challenges SET created_at_ms=created_at_ms-61000")
        _, new = request("/v2/auth/email/challenges", {"email": owner})
        new_code = code(3)
        assert request("/v2/auth/email/verify", {"challenge_id": old["challenge_id"], "code": old_code})[0] == 401
        wrong = ("0" if new_code[0] != "0" else "1") + new_code[1:]
        for _ in range(5):
            assert request("/v2/auth/email/verify", {"challenge_id": new["challenge_id"], "code": wrong})[0] == 401
        assert request("/v2/auth/email/verify", {"challenge_id": new["challenge_id"], "code": new_code})[0] == 401
        sql("DELETE FROM nds_auth_limits; DELETE FROM nds_email_challenges;")
        _, expired = request("/v2/auth/email/challenges", {"email": owner})
        expired_code = code(4)
        sql("UPDATE nds_email_challenges SET created_at_ms=created_at_ms-600000, expires_at_ms=expires_at_ms-600000")
        assert request("/v2/auth/email/verify", {"challenge_id": expired["challenge_id"], "code": expired_code})[0] == 401
        assert sql("SELECT count(*) FROM nds_email_challenges").stdout.strip() == "0"
        sql("DELETE FROM nds_auth_limits;")
        _, session_receipt = request("/v2/auth/email/challenges", {"email": owner})
        session_code = code(5)
        status, session_issued = request("/v2/auth/email/verify", {"challenge_id": session_receipt["challenge_id"], "code": session_code})
        assert status == 200
        sensitive.append(session_issued["session_token"])

        def second_session():
            expected_count = len(messages()) + 1
            sql("DELETE FROM nds_auth_limits; DELETE FROM nds_email_challenges;")
            status, receipt = request("/v2/auth/email/challenges", {"email": owner})
            assert status == 202
            status, issued = request("/v2/auth/email/verify", {"challenge_id": receipt["challenge_id"], "code": code(expected_count)})
            assert status == 200
            return issued["session_token"]

        def restart_enrollment():
            nonlocal server, logs
            logs += stop(server)
            assert server.returncode == 0
            server = start()

        sensitive += check_enrollment(request, session_issued["session_token"], second_session, restart_enrollment, directory, sql)
        expired_logout = second_session()
        sensitive.append(expired_logout)
        mail_count = len(messages())
        sql("UPDATE nds_sessions SET expires_at_ms=0")
        assert request("/v2/session", token=expired_logout, method="DELETE")[0] == 401
        assert sql("SELECT count(*) FROM nds_sessions").stdout.strip() == "1", "expired logout deletion rolled back"
        assert request("/v2/session", token=session_issued["session_token"])[0] == 401
        assert sql("SELECT count(*) FROM nds_sessions").stdout.strip() == "0"
        sql("DELETE FROM nds_auth_limits; DELETE FROM nds_email_challenges;")
        for attempt in range(11):
            status, _ = request("/v2/auth/email/challenges", {"email": uuid.uuid4().hex + "@example.invalid"}, headers={"X-Forwarded-For": f"192.0.2.{attempt + 1}"})
            assert status == (202 if attempt < 10 else 429), "socket-source budget was bypassed through headers or new ports"
        assert len(messages()) == mail_count
        assert request("/v2/auth/github/start", {})[0] == 503
        sql("DELETE FROM nds_auth_limits; DELETE FROM nds_email_challenges;")
        command("docker", "stop", "--time", "5", mailbox)
        created = False
        _, unavailable_receipt = request("/v2/auth/email/challenges", {"email": owner})
        deadline = time.monotonic() + 8
        while request("/v2/auth/methods")[1]["email_otp"] != "unavailable":
            assert time.monotonic() < deadline, "SMTP failure did not degrade readiness"
            time.sleep(0.05)
        while sql("SELECT bool_and(consumed) FROM nds_email_challenges").stdout.strip() != "t":
            assert time.monotonic() < deadline, "failed delivery challenge was not invalidated"
            time.sleep(0.05)
        assert request("/v2/auth/email/challenges", {"email": unknown})[0] == 503
        logs += stop(server)
        assert server.returncode == 0
        server = None
        for secret in sensitive:
            assert secret not in logs, "identity logs exposed sensitive fixture material"
        assert str(directory) not in logs
        validate_events(logs)
        events = [json.loads(line) for line in logs.splitlines() if line]
        assert any(event.get("event.name") == "email.delivery.accepted" and event["mailbox_delivery"] == "unverified" for event in events)
        assert any(event.get("event.name") == "identity.session.issued" for event in events)
        print("Identity acceptance passed: real isolated SMTP mailbox delivery; generic owner/other receipts; atomic replay denial; resend, attempts and expiry; persistent/revoked sessions; immutable bootstrap ownership; socket-only source limits; redacted logs. Live GitHub and external mailbox acceptance remain separate.")
    finally:
        try:
            if server is not None:
                stop(server)
        finally:
            if created:
                command("docker", "stop", "--time", "5", mailbox)
