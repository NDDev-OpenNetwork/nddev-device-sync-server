"""Exercise production signed HTTP against generated, disposable SQL history.

Only the caller's isolated PostgreSQL fixture is seeded or reset. Product limits
and runtime privileges stay unchanged; the product exposes no history reset API.
"""
import base64
import json
import time


def check_capacity(send, key, device, operation, original_body, original, sql):
    assert len(device) == 43 and all(c.isalnum() or c in "_-" for c in device)
    path = "/v2/sync/operations"

    def state():
        return sql("SELECT json_build_array(server_seq,operation_count,stored_bytes,"
                   "(SELECT count(*) FROM nds_replica_operations),"
                   "(SELECT count(*) FROM nds_replica_entities)) FROM nds_replica_counters").stdout.strip()

    def reject(body):
        before = state()
        status, raw, headers = send(key, device, path, body, include_headers=True)
        assert status == 409 and json.loads(raw) == {"error": "sync_capacity_exhausted"}
        assert "retry-after" not in {name.lower() for name in headers}
        assert state() == before, "capacity rejection partially committed"

    def clear_history():
        sql("DELETE FROM nds_replica_base_members; DELETE FROM nds_replica_entities; DELETE FROM nds_replica_operations; "
            "DELETE FROM nds_replica_nonces; DELETE FROM nds_replica_counters;")

    def seed(start, count, *, separate_entities=False, large=False):
        last = start + count - 1
        entity = "'capacity-entity-'||i" if separate_entities else "'capacity-history'"
        revision = "1" if separate_entities else f"i-{start}+1"
        base = "0" if separate_entities else f"i-{start}"
        ciphertext = "A" * (21867 if large else 43)
        sql(f"""INSERT INTO nds_replica_operations
            (user_id,tenant_id,device_id,operation_id,idempotency_key,fingerprint,
             server_seq,request_body,result_body,status,entity_type,entity_id,
             base_revision,wire_version,applied_revision,request_bytes,result_bytes)
            SELECT d.user_id,d.tenant_id,d.device_id,'capacity-'||i,'capacity-'||i,
                   sha256(b),i,b,r,201,'vault_record',{entity},{base},2,
                   {revision},octet_length(b),octet_length(r) FROM nds_devices d
            CROSS JOIN generate_series({start},{last}) i
            CROSS JOIN LATERAL (SELECT
              convert_to(json_build_object('schema_version',2,'operation_id','capacity-'||i,
                'device_id',d.device_id,'entity_type','vault_record','entity_id',{entity},
                'base_revision',{base},'idempotency_key','capacity-'||i,
                'payload',json_build_object('algorithm','aes-256-gcm',
                  'key_id','acceptance-key','nonce','AAAAAAAAAAAAAAAA',
                  'ciphertext','{ciphertext}'))::text,'UTF8') b,
              convert_to(json_build_object('operation_id','capacity-'||i,'outcome','applied',
                'revision',{revision},'server_seq',i)::text,'UTF8') r) q
            WHERE d.device_id='{device}';""")

    def entities_and_counter(*, separate_entities=False):
        entity = "'capacity-entity-'||server_seq" if separate_entities else "'capacity-history'"
        revision = "1" if separate_entities else "server_seq"
        where = "operation_id LIKE 'capacity-%'" if separate_entities else "server_seq=(SELECT max(server_seq) FROM nds_replica_operations)"
        sql(f"""INSERT INTO nds_replica_entities
            (user_id,tenant_id,entity_type,entity_id,revision,request_body,applied_seq)
            SELECT user_id,tenant_id,'vault_record',{entity},{revision},request_body,server_seq
            FROM nds_replica_operations WHERE {where};
            INSERT INTO nds_replica_counters(user_id,tenant_id,server_seq,operation_count,
              stored_bytes,root_key_id)
            SELECT user_id,tenant_id,max(server_seq),count(*),
              sum(2*octet_length(request_body)+octet_length(result_body)), 'acceptance-key'
            FROM nds_replica_operations GROUP BY user_id,tenant_id;
        """)

    def bytes_for(value):
        return json.dumps(value, separators=(",", ":")).encode()

    # Preserve the original receipt and existing history; fill the lifetime log
    # with valid generated entries rather than forging its operation counter.
    head = int(sql("SELECT server_seq FROM nds_replica_counters").stdout.strip())
    seed(head + 1, 16384 - head)
    sql("UPDATE nds_replica_counters SET server_seq=16384,operation_count="
        "(SELECT count(*) FROM nds_replica_operations),stored_bytes="
        "(SELECT sum(2*octet_length(request_body)+octet_length(result_body)) "
        "FROM nds_replica_operations)")
    # The generated filler is one additional entity, retaining its latest body.
    sql("INSERT INTO nds_replica_entities(user_id,tenant_id,entity_type,entity_id,revision,request_body,applied_seq) "
        f"SELECT user_id,tenant_id,'vault_record','capacity-history',server_seq-{head},request_body,server_seq "
        "FROM nds_replica_operations WHERE server_seq=16384")
    assert send(key, device, path, original_body) == original
    changed = json.dumps(json.loads(original_body), indent=1).encode()
    status, raw = send(key, device, path, changed)
    assert status == 409 and json.loads(raw) == {"error": "idempotency_conflict"}
    value = operation(device)
    value["entity_id"] = "capacity-overflow"
    reject(bytes_for(value))
    status, raw = send(key, device, path + "?after_seq=16380&limit=100")
    page = json.loads(raw)
    assert status == 200 and page["next_after_seq"] == 16384 and not page["has_more"]
    assert [entry["result"]["server_seq"] for entry in page["entries"]] == list(range(16381, 16385))

    # A full nonce window is independently temporary, including at full history.
    sql("DELETE FROM nds_replica_nonces")
    expiry = int(time.time() * 1000) + 30000
    sql(f"INSERT INTO nds_replica_nonces(device_id,nonce,expires_at_ms) "
        f"SELECT '{device}','capacity-nonce-'||i,{expiry} FROM generate_series(1,512) i")
    status, raw, headers = send(key, device, path + "?after_seq=16384", include_headers=True)
    assert status == 503 and json.loads(raw) == {"error": "server_busy"}
    assert {name.lower(): value for name, value in headers.items()}["retry-after"] == "2"
    sql(f"UPDATE nds_replica_nonces SET expires_at_ms={int(time.time() * 1000) - 1000}")
    status, raw = send(key, device, path + "?after_seq=16384")
    assert status == 200 and json.loads(raw) == {"entries": [], "next_after_seq": 16384, "has_more": False}

    clear_history()
    seed(1, 4096, separate_entities=True)
    entities_and_counter(separate_entities=True)
    value = operation(device)
    value["entity_id"] = "entity-overflow"
    reject(bytes_for(value))
    _, count, retained, rows, entities = json.loads(state())
    assert count == rows == entities == 4096 and retained < 256 * 1024 * 1024

    # Each retained byte is accounted from real bodies/receipts. A large seed
    # reaches near the byte budget; actual signed append reaches its boundary.
    clear_history()
    seed(1, 6000, large=True)
    entities_and_counter()
    replay_body = bytes.fromhex(sql("SELECT encode(request_body,'hex') FROM nds_replica_operations WHERE server_seq=1").stdout.strip())
    replay_result = bytes.fromhex(sql("SELECT encode(result_body,'hex') FROM nds_replica_operations WHERE server_seq=1").stdout.strip())
    for _ in range(128):
        before = state()
        head, count, retained, _, _ = json.loads(before)
        assert count < 16384 and retained <= 256 * 1024 * 1024
        value = operation(device, revision=head)
        value["entity_id"] = "capacity-history"
        value["payload"]["ciphertext"] = base64.urlsafe_b64encode(bytes(16400)).decode().rstrip("=")
        body = bytes_for(value)
        status, raw, headers = send(key, device, path, body, include_headers=True)
        if status == 201:
            continue
        assert status == 409 and json.loads(raw) == {"error": "sync_capacity_exhausted"}
        assert "retry-after" not in {name.lower() for name in headers}
        assert state() == before
        assert send(key, device, path, replay_body) == (201, replay_result)
        break
    else:
        raise AssertionError("generated byte-limit fixture did not reach capacity")
    assert sql("SELECT count(*) FROM nds_replica_entities").stdout.strip() == "1"
    print(f"Generated byte capacity: {count} retained operations, {retained} logical bytes.")
    print("Signed capacity acceptance passed: lifetime operation, entity and actual retained-byte limits; "
          "persistent 409 without Retry-After; atomic rejection and exact replay; temporary nonce expiry; readable full history.")
