"""Actual owned HTTP/PG screen control; independent OpenSSL HTTP + endpoint proofs.
Opaque bytes exercise server storage only, never pretend to be a native grant.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import time
import urllib.error
import urllib.request
import uuid


def check_screen(request, token, second_session, restart, directory, sql, origin):
    directory = Path(directory) / "screen"
    directory.mkdir(mode=0o700)
    secrets_for_redaction = [token]
    encode = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    literal = lambda s: "'" + s.replace("'", "''") + "'"
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def openssl(*args):
        return subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True, timeout=5).stdout

    def key():
        path = directory / (uuid.uuid4().hex + ".pem")
        openssl("genpkey", "-algorithm", "ED25519", "-out", path)
        path.chmod(0o600)
        secrets_for_redaction.extend(path.read_text().splitlines()[1:-1])
        public = openssl("pkey", "-in", path, "-pubout", "-outform", "DER")
        assert public[:12] == bytes.fromhex("302a300506032b6570032100") and len(public) == 44
        return path, public[12:]

    def sign(path, content):
        message = directory / (uuid.uuid4().hex + ".bin")
        message.write_bytes(content)
        try:
            return openssl("pkeyutl", "-sign", "-inkey", path, "-rawin", "-in", message)
        finally:
            message.unlink()

    def enroll(index):
        path, public = key()
        status, challenge = request("/v2/devices/challenges", {"platform": "linux", "display_name": f"Screen acceptance {index}", "public_key": encode(public)}, token=token)
        assert status == 201
        status, device = request("/v2/devices/enrollments", {"challenge_id": challenge["challenge_id"],
            "signature": encode(sign(path, b"NDS-ENROLLMENT-V2\0" + base64.urlsafe_b64decode(challenge["challenge"] + "=")))}, token=token)
        assert status == 201
        endpoint_key, endpoint = key()
        return {"key": path, "device": device["device_id"], "endpoint_key": endpoint_key, "endpoint": endpoint, "instance": str(uuid.uuid4()), "revision": 0}

    def context():
        return encode(secrets.token_bytes(24)), (int(time.time()) + 60) * 1000

    def send(device, path, body=None, *, method=None, session=token, nonce=None, expiry=None, sign_key=None, target=None):
        method = method or ("GET" if body is None else "POST")
        raw = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode())
        nonce, expiry = nonce or context()[0], expiry or context()[1]
        digest = "sha-256=:" + base64.b64encode(hashlib.sha256(raw).digest()).decode() + ":"
        params = f'("@method" "@target-uri" "content-digest");created={int(time.time())};expires={expiry//1000};nonce="{nonce}";alg="ed25519";keyid="{device["device"]}"'
        signature = sign(sign_key or device["key"], f'"@method": {method}\n"@target-uri": {target or origin+path}\n"content-digest": {digest}\n"@signature-params": {params}'.encode())
        headers = {"Authorization": "Bearer " + session, "Signature-Input": "nds=" + params,
            "Signature": "nds=:" + base64.b64encode(signature).decode() + ":", "Content-Digest": digest, "Content-Type": "application/json"}
        req = urllib.request.Request(origin + path, data=raw if method == "POST" else None, headers=headers, method=method)
        try:
            response = http.open(req, timeout=8)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            value = response.read(65537)
            assert len(value) <= 65536 and response.headers["Cache-Control"] == "no-store"
            assert len(response.headers["X-Request-Id"]) == 32
            return response.status, json.loads(value) if value else None

    def claim(device, base=None, *, instance=None, key_override=None):
        nonce, expiry = context()
        endpoint = device["endpoint"]
        instance = instance or device["instance"]
        base = device["revision"] if base is None else base
        transcript = b"NDS-RDS-ENDPOINT-BINDING-V2\0"
        for field in [origin.encode(), device["device"].encode()]:
            transcript += len(field).to_bytes(2, "big") + field
        transcript += endpoint + uuid.UUID(instance).bytes + base.to_bytes(8, "big")
        transcript += len(nonce).to_bytes(2, "big") + nonce.encode() + expiry.to_bytes(8, "big")
        value = {"endpoint_public_key": encode(endpoint), "instance_id": instance, "base_revision": base,
            "nonce": nonce, "expires_at_ms": expiry, "signature": encode(sign(key_override or device["endpoint_key"], transcript))}
        return value, {"nonce": nonce, "expiry": expiry}

    def bind(device, base=None, **options):
        value, signed = claim(device, base, **options)
        return send(device, "/v2/rds/bindings", value, **signed)

    def create_value(viewer, host, seconds=120):
        return {"target_device_id": host["device"], "viewer_revision": viewer["revision"], "host_revision": host["revision"],
            "display": 0, "max_fps": 30, "output_height": 1080, "expires_at_ms": (int(time.time()) + seconds) * 1000,
            "idempotency_key": uuid.uuid4().hex}

    def ended(viewer, view):
        assert send(viewer, "/v2/rds/views/" + view["view_id"] + "/end", b"") == (204, None)

    viewer, host, other = [enroll(i) for i in range(3)]
    assert send(viewer, "/v2/rds/views/incoming", session=encode(secrets.token_bytes(32)))[0] == 401
    assert send(viewer, "/v2/rds/bindings/foreign-device") == (403, {"error": "authorization_denied"})
    for device in [viewer, host, other]:
        assert send(viewer, "/v2/rds/bindings/" + device["device"])[1] == {"binding": None}
        assert bind(device, key_override=key()[0])[0] == 403
        value, signed = claim(device)
        assert send(device, "/v2/rds/bindings", value | {"user_id": "foreign-owner"}, **signed)[0] == 400
        assert send(device, "/v2/rds/bindings", value | {"nonce": value["nonce"] + "x"}, **signed)[0] == 403
        value, signed = claim(device)
        assert send(device, "/v2/rds/bindings", value | {"expires_at_ms": value["expires_at_ms"] - 1000}, **signed)[0] == 403
        value, signed = claim(device)
        assert send(device, "/v2/rds/bindings", value | {"endpoint_public_key": encode(bytes(32))}, **signed)[0] == 403
        value, signed = claim(device)
        assert send(device, "/v2/rds/bindings", value, sign_key=key()[0], **signed)[0] == 400
        assert send(device, "/v2/rds/bindings", value, target="https://foreign.invalid/v2/rds/bindings", **signed)[0] == 400
        status, result = bind(device)
        assert status == 200 and result["revision"] == 1
        device["revision"] = 1
        # Lost ACK refreshes both actual signatures and preserves instance/base0.
        assert bind(device, 0) == (200, result)
        assert bind(device, 1)[0] == 403, "same UUID with changed original base was accepted"
        alternate_key, alternate_public = key()
        changed_key = device | {"endpoint_key": alternate_key, "endpoint": alternate_public}
        assert bind(changed_key, 0)[0] == 403, "same UUID with changed endpoint key was accepted"
        value, signed = claim(device, 0)
        value["signature"] = encode(bytes(64))
        assert send(device, "/v2/rds/bindings", value, **signed)[0] == 403, "same-row replay skipped endpoint proof"
        value, signed = claim(device, 0)
        assert send(device, "/v2/rds/bindings", value, **signed)[0] == 200
        assert send(device, "/v2/rds/bindings", value, **signed)[0] == 403, "fresh nonce was not consumed"

    # Real concurrent original request: only one canonical participant intent.
    body = json.dumps(create_value(viewer, host), separators=(",", ":")).encode()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: send(viewer, "/v2/rds/views", body), range(2)))
    assert results[0] == results[1] and results[0][0] == 201
    current = results[0][1]
    changed_bytes = json.dumps(json.loads(body), indent=1).encode()
    assert send(viewer, "/v2/rds/views", changed_bytes) == (409, {"error": "operation_conflict"})
    assert send(host, "/v2/rds/views/incoming")[1]["view"] == current
    assert send(other, "/v2/rds/views/incoming")[1] == {"view": None}
    assert send(host, "/v2/rds/views/" + current["view_id"])[0] == 403
    assert send(other, "/v2/rds/views/" + current["view_id"] + "/end", b"")[0] == 403
    assert send(viewer, "/v2/rds/views", create_value(viewer, host))[0] == 503
    artifact = encode(secrets.token_bytes(8192))
    secrets_for_redaction.append(artifact)
    ready_path = "/v2/rds/views/" + current["view_id"] + "/ready"
    assert send(viewer, ready_path, {"native_grant": artifact})[0] == 403
    assert send(host, ready_path, {"native_grant": encode(bytes(8193))})[0] == 400
    # Real write privilege refusal rolls back nonce, floor and artifact state.
    # Restoring ONLY this owned role grant permits the same unused nonce.
    rollback_nonce, rollback_expiry = context()
    sql("REVOKE UPDATE(native_grant) ON nds_screen_views FROM nds_runtime")
    assert send(host, ready_path, {"native_grant": artifact}, nonce=rollback_nonce, expiry=rollback_expiry)[0] == 503
    assert sql("SELECT state FROM nds_screen_views").stdout.strip() == "requested"
    assert sql(f"SELECT count(*) FROM nds_sync_nonces WHERE device_id={literal(host['device'])} AND nonce={literal(rollback_nonce)}").stdout.strip() == "0"
    sql("GRANT UPDATE(native_grant) ON nds_screen_views TO nds_runtime")
    assert send(host, ready_path, {"native_grant": artifact}, nonce=rollback_nonce, expiry=rollback_expiry)[0] == 200
    status, ready = send(host, ready_path, {"native_grant": artifact})
    assert status == 200 and ready["state"] == "ready"
    assert send(host, ready_path, {"native_grant": artifact}) == (200, ready)
    assert send(host, ready_path, {"native_grant": "AA"})[0] == 409
    assert send(viewer, "/v2/rds/views/" + current["view_id"])[1] == {"view": ready, "native_grant": artifact}
    restart()
    assert bind(host, 0)[1]["revision"] == 1
    assert send(viewer, "/v2/rds/views/" + current["view_id"])[1]["native_grant"] == artifact
    # New same-key instance advances exactly once across concurrent fresh proofs.
    host["instance"] = str(uuid.uuid4())
    with ThreadPoolExecutor(max_workers=2) as pool:
        bindings = list(pool.map(lambda _: bind(host, 1), range(2)))
    assert bindings[0] == bindings[1] and bindings[0][1]["revision"] == 2
    host["revision"] = 2
    assert send(viewer, "/v2/rds/views/" + current["view_id"])[0] == 403
    assert sql("SELECT state||':'||coalesce(octet_length(native_grant),0) FROM nds_screen_views").stdout.strip() == "ended:0"
    ended(viewer, current)

    request_body = create_value(viewer, host)
    status, current = send(viewer, "/v2/rds/views", request_body)
    assert status == 201
    ended(viewer, current)
    ended(host, current)
    replay = send(viewer, "/v2/rds/views", request_body)
    assert replay[0] == 201 and replay[1] == current | {"state": "ended"}, "early-End receipt reopened"
    assert send(host, "/v2/rds/views/" + current["view_id"] + "/ready", {"native_grant": "AA"})[0] == 409

    # Distinct NEW creates compete for the same participant slot under the
    # actual common auth transaction, while distinct new binding UUIDs CAS.
    requests = [create_value(viewer, host) for _ in range(2)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda body: send(viewer, "/v2/rds/views", body), requests))
    assert sorted(status for status, _ in outcomes) == [201, 503]
    ended(viewer, next(value for status, value in outcomes if status == 201))
    attempts = [claim(host, 2, instance=str(uuid.uuid4())) for _ in range(2)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda attempt: send(host, "/v2/rds/bindings", attempt[0], **attempt[1]), attempts))
    assert sorted(status for status, _ in outcomes) == [200, 403]
    winner = next(value for status, value in outcomes if status == 200)
    host["instance"], host["revision"] = winner["instance_id"], winner["revision"]
    assert host["revision"] == 3

    # Persisted rollback floor rejects an old request; cleanup does not reset CAS.
    short = create_value(viewer, host, 2)
    status, expires = send(viewer, "/v2/rds/views", short)
    assert status == 201
    time.sleep(2.1)
    assert send(viewer, "/v2/rds/views/" + expires["view_id"] + "/end", b"") == (403, {"error": "authorization_denied"})
    assert send(viewer, "/v2/rds/views", short)[0] == 409
    # The finite receipt horizon is closed. A new future request may reuse the
    # expired key, but receives a distinct id and admission, never a renewed id.
    fresh = short | {"expires_at_ms": (int(time.time()) + 120) * 1000}
    status, after_expiry = send(viewer, "/v2/rds/views", fresh)
    assert status == 201 and after_expiry["view_id"] != expires["view_id"]
    ended(viewer, after_expiry)
    floor = int(time.time() * 1000) + 5000
    sql(f"UPDATE nds_sync_counters SET clock_floor_ms={floor}")
    old = create_value(viewer, host, 2)
    assert send(viewer, "/v2/rds/views", old)[0] == 409
    time.sleep(5.1)

    # The cap includes early-ended receipts; replay/end/Ready never check cap.
    sql("DELETE FROM nds_screen_views")  # Owned test only; no product eviction.
    first_receipt = None
    for _ in range(63):
        payload = create_value(viewer, host, 120)
        status, row = send(viewer, "/v2/rds/views", payload)
        assert status == 201
        ended(viewer, row)
        first_receipt = first_receipt or (payload, row)
    payload = create_value(viewer, host, 120)
    status, row = send(viewer, "/v2/rds/views", payload)
    assert status == 201
    assert send(viewer, "/v2/rds/views", create_value(viewer, other))[0] == 503
    assert send(viewer, "/v2/rds/views", first_receipt[0])[1]["state"] == "ended"
    assert send(host, "/v2/rds/views/" + row["view_id"] + "/ready", {"native_grant": "AA"})[0] == 200
    ended(viewer, row)
    assert sql("SELECT count(*) FROM nds_screen_views").stdout.strip() == "64"

    # Expire ONLY owned rows to exercise real cleanup at persisted floor.
    sql("UPDATE nds_screen_views SET expires_at_ms=1")
    assert send(host, "/v2/rds/views/incoming")[1] == {"view": None}
    assert sql("SELECT count(*) FROM nds_screen_views").stdout.strip() == "0"
    assert send(viewer, "/v2/rds/views/" + row["view_id"] + "/end", b"")[0] == 403
    assert send(viewer, "/v2/rds/views/" + str(uuid.uuid4()) + "/end", b"")[0] == 403
    assert send(viewer, "/v2/rds/bindings/" + host["device"])[1]["binding"]["revision"] == 3

    # Original viewer session revoke is terminal even for a current host session.
    original = second_session()
    secrets_for_redaction.append(original)
    status, row = send(viewer, "/v2/rds/views", create_value(viewer, host), session=original)
    assert status == 201
    assert request("/v2/session", token=original, method="DELETE")[0] == 204
    assert send(host, "/v2/rds/views/" + row["view_id"] + "/ready", {"native_grant": "AA"})[0] == 403
    ended(host, row)  # No live original viewer session required for cleanup.

    status, row = send(viewer, "/v2/rds/views", create_value(viewer, host))
    assert status == 201
    assert request("/v2/devices/" + viewer["device"], token=token, method="DELETE")[0] == 204
    assert send(host, "/v2/rds/views/" + row["view_id"] + "/ready", {"native_grant": "AA"})[0] == 403
    ended(host, row)  # Old binding/revoked peer does not prevent participant end.
    assert send(viewer, "/v2/rds/views/incoming")[0] == 403

    # Existing common authorization lock really bounds I/O, not a mock timeout.
    with ThreadPoolExecutor(max_workers=2) as pool:
        blocker = pool.submit(sql, f"BEGIN; SELECT pg_advisory_xact_lock({0x4e44533241555448}); SELECT pg_sleep(4); COMMIT;")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if sql("SELECT count(*) FROM pg_stat_activity WHERE usename='postgres' AND wait_event='PgSleep'").stdout.strip() == "1":
                break
            time.sleep(0.01)
        at = time.monotonic()
        timeout_nonce, timeout_expiry = context()
        assert send(host, "/v2/rds/views/incoming", nonce=timeout_nonce, expiry=timeout_expiry)[0] == 503
        assert time.monotonic() - at < 4
        blocker.result(timeout=6)
    assert send(host, "/v2/rds/views/incoming", nonce=timeout_nonce, expiry=timeout_expiry)[0] == 200

    for statement in ["TRUNCATE nds_screen_views", "DELETE FROM nds_screen_bindings WHERE false",
                      "UPDATE nds_screen_views SET viewer_session=viewer_session WHERE false",
                      "UPDATE nds_screen_views SET expires_at_ms=expires_at_ms WHERE false",
                      "UPDATE nds_screen_bindings SET user_id=user_id WHERE false"]:
        assert sql(statement, "nds_runtime", check=False).returncode != 0
    ids = ",".join(literal(d["device"]) for d in [viewer, host, other])
    sql(f"DELETE FROM nds_screen_views; DELETE FROM nds_screen_bindings WHERE device_id IN({ids}); DELETE FROM nds_sync_nonces WHERE device_id IN({ids}); DELETE FROM nds_enrollment_challenges WHERE device_id IN({ids}); DELETE FROM nds_devices WHERE device_id IN({ids}); DELETE FROM nds_auth_limits;")
    print("Owned screen HTTP/PG acceptance: actual fresh enrollment, RFC9421/endpointPoPV2, lost-ACK/concurrent binding/create, exact opaque Ready retry, retained End/cap/expiry/clock-floor/session/device revoke, timeout and least privilege passed.")
    return secrets_for_redaction
