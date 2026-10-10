-- All retained operations are ciphertext. No sequence is allocated outside the
-- owner transaction: the counter row defines committed order without gaps.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='3') THEN
        RAISE EXCEPTION 'sync log requires schema version 3';
    END IF;
END $$;
CREATE TABLE nds_sync_counters (
    user_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
    server_seq BIGINT NOT NULL DEFAULT 0 CHECK (server_seq BETWEEN 0 AND 9007199254740991),
    operation_count BIGINT NOT NULL DEFAULT 0 CHECK (operation_count BETWEEN 0 AND 16384),
    stored_bytes BIGINT NOT NULL DEFAULT 0 CHECK (stored_bytes BETWEEN 0 AND 268435456),
    clock_floor_ms BIGINT NOT NULL DEFAULT 0 CHECK (clock_floor_ms >= 0),
    PRIMARY KEY (user_id, tenant_id),
    FOREIGN KEY (user_id, tenant_id) REFERENCES nds_owner(user_id, tenant_id)
);
CREATE TABLE nds_sync_nonces (
    device_id TEXT NOT NULL REFERENCES nds_devices(device_id), nonce TEXT NOT NULL CHECK (length(nonce) BETWEEN 16 AND 128),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > 0), PRIMARY KEY (device_id, nonce)
);
CREATE INDEX nds_sync_nonce_expiry ON nds_sync_nonces(expires_at_ms);
CREATE TABLE nds_sync_entities (
    user_id TEXT NOT NULL, tenant_id TEXT NOT NULL, entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL CHECK (length(entity_id) BETWEEN 1 AND 256),
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    request_body BYTEA NOT NULL CHECK (octet_length(request_body) BETWEEN 1 AND 24576),
    PRIMARY KEY (user_id, tenant_id, entity_type, entity_id),
    FOREIGN KEY (user_id, tenant_id) REFERENCES nds_owner(user_id, tenant_id)
);
CREATE TABLE nds_sync_operations (
    user_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES nds_devices(device_id),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128),
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 256),
    fingerprint BYTEA NOT NULL CHECK (octet_length(fingerprint)=32),
    server_seq BIGINT NOT NULL CHECK (server_seq BETWEEN 1 AND 9007199254740991),
    request_body BYTEA NOT NULL CHECK (octet_length(request_body) BETWEEN 1 AND 24576),
    result_body BYTEA NOT NULL CHECK (octet_length(result_body) BETWEEN 1 AND 2048),
    status SMALLINT NOT NULL CHECK (status IN (201,409)),
    PRIMARY KEY (user_id,tenant_id,device_id,operation_id),
    UNIQUE (user_id,tenant_id,device_id,idempotency_key),
    UNIQUE (user_id,tenant_id,server_seq),
    FOREIGN KEY (user_id,tenant_id) REFERENCES nds_owner(user_id,tenant_id)
);
GRANT SELECT, INSERT, UPDATE ON nds_sync_counters, nds_sync_entities TO nds_runtime;
GRANT SELECT, INSERT, DELETE ON nds_sync_nonces TO nds_runtime;
GRANT SELECT, INSERT ON nds_sync_operations TO nds_runtime;
UPDATE nddev_schema_meta SET value='4',updated_at=NOW() WHERE key='schema_version';
