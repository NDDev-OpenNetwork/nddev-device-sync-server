"""Real signed HTTP, restart and PostgreSQL acceptance in an owned fixture."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import secrets
import uuid


def check_vault(enroll, send, request, token, restart, directory, sql):
    first, first_id = enroll(3)
    second, second_id = enroll(4)
    empty = b'{"existing_key":null}'
    route = '/v2/vault/key'
    assert request(route, {'existing_key': None})[0] == 401
    with ThreadPoolExecutor(max_workers=8) as pool:
        delivered = list(pool.map(lambda index: send(first if index % 2 else second,
            first_id if index % 2 else second_id, route, empty), range(8)))
    assert all(status == 200 for status, _ in delivered)
    keys = [json.loads(body) for _, body in delivered]
    key = keys[0]
    assert all(value == key for value in keys)
    material = base64.urlsafe_b64decode(key['key_material'])
    assert len(material) == 48 and str(uuid.UUID(bytes=material[:16])) == key['key_id']
    assert sql('SELECT count(*) FROM nds_vault_keys').stdout.strip() == '1'
    assert sql('SELECT octet_length(ciphertext) FROM nds_vault_keys').stdout.strip() == '64'
    assert sql(f"SELECT position(decode('{material.hex()}','hex') in ciphertext) FROM nds_vault_keys").stdout.strip() == '0'
    assert sql('UPDATE nds_vault_keys SET ciphertext=ciphertext WHERE false', 'nds_runtime', check=False).returncode != 0
    assert sql('DELETE FROM nds_vault_keys WHERE false', 'nds_runtime', check=False).returncode != 0
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip('=')
    assert send(first, first_id, route, empty, nonce=nonce)[0] == 200
    status, error = send(first, first_id, route, empty, nonce=nonce)
    assert status == 409 and json.loads(error) == {'error': 'replayed_nonce'}
    wrong = dict(key)
    wrong['key_material'] = base64.urlsafe_b64encode(material[:-1] + bytes([material[-1] ^ 1])).decode()
    status, error = send(first, first_id, route, json.dumps({'existing_key': wrong}).encode())
    assert status == 409 and json.loads(error) == {'error': 'operation_conflict'}
    restart()
    assert json.loads(send(second, second_id, route, empty)[1]) == key

    # A schema-5 binding with no managed envelope must retain its original key.
    # Administrative setup/cleanup is confined to this disposable database.
    legacy_id = uuid.uuid4()
    legacy = {'key_id': str(legacy_id), 'key_material': base64.urlsafe_b64encode(
        legacy_id.bytes + secrets.token_bytes(32)).decode()}
    sql(f"DELETE FROM nds_vault_keys; UPDATE nds_replica_counters SET root_key_id='{legacy_id}';")
    status, error = send(second, second_id, route, empty)
    assert status == 409 and json.loads(error) == {'error': 'vault_key_registration_required'}
    status, registered = send(first, first_id, route, json.dumps({'existing_key': legacy}).encode())
    assert status == 200 and json.loads(registered) == legacy
    restart()
    assert json.loads(send(second, second_id, route, empty)[1]) == legacy

    wrapping = directory.parent / 'vault_kek'
    original = wrapping.read_text()
    wrapping.write_text(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))
    try:
        restart()
        assert send(second, second_id, route, empty)[0] == 503
        assert sql('SELECT count(*) FROM nds_vault_keys').stdout.strip() == '1'
    finally:
        wrapping.write_text(original)
        restart()
    assert json.loads(send(second, second_id, route, empty)[1]) == legacy
    assert request('/v2/devices/' + first_id, token=token, method='DELETE')[0] == 204
    assert send(first, first_id, route, empty)[0] == 403
    assert send(second, second_id, route, empty)[0] == 200
    sql('DELETE FROM nds_vault_keys; DELETE FROM nds_replica_nonces; DELETE FROM nds_replica_counters; DELETE FROM nds_enrollment_challenges; DELETE FROM nds_devices; DELETE FROM nds_auth_limits;')
    print('Server-managed vault acceptance passed: concurrent native delivery, encrypted storage, restart, retained-key transition, wrong wrapping key, nonce replay and revocation.')
    return [key['key_material'], legacy['key_material'], wrong['key_material'], original]
