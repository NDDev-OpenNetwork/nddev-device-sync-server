DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='6') THEN
        RAISE EXCEPTION 'passkeys require schema version 6';
    END IF;
END $$;
CREATE TABLE nds_passkeys (
    credential_id BYTEA PRIMARY KEY CHECK(octet_length(credential_id) BETWEEN 1 AND 1024),
    user_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
    credential JSONB NOT NULL CHECK(octet_length(credential::text)<=16384),
    created_at_ms BIGINT NOT NULL CHECK(created_at_ms>=0),
    FOREIGN KEY(user_id,tenant_id) REFERENCES nds_owner(user_id,tenant_id)
);
ALTER TABLE nds_sessions DROP CONSTRAINT nds_sessions_auth_method_check;
ALTER TABLE nds_sessions ADD CONSTRAINT nds_sessions_auth_method_check
    CHECK(auth_method IN ('email_otp','github','passkey'));
GRANT SELECT,INSERT,UPDATE ON nds_passkeys TO nds_runtime;
UPDATE nddev_schema_meta SET value='7',updated_at=NOW() WHERE key='schema_version';
