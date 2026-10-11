-- Owner keys are operational encrypted envelopes under a wrapping key outside
-- PostgreSQL. The server has decryption authority; no recovery copy is created.
DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='5') THEN
        RAISE EXCEPTION 'server-managed vault requires schema version 5';
    END IF;
END $$;
CREATE TABLE nds_vault_keys (
    user_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL CHECK(length(key_id)=36),
    nonce BYTEA NOT NULL CHECK(octet_length(nonce)=12),
    ciphertext BYTEA NOT NULL CHECK(octet_length(ciphertext)=64),
    PRIMARY KEY(user_id,tenant_id),
    FOREIGN KEY(user_id,tenant_id) REFERENCES nds_owner(user_id,tenant_id)
);
GRANT SELECT,INSERT ON nds_vault_keys TO nds_runtime;
UPDATE nddev_schema_meta SET value='6',updated_at=NOW() WHERE key='schema_version';
