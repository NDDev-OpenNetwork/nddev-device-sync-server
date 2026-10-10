-- Public device identities only. A private device signing key never reaches
-- the server; retained revoked rows prevent silently reassigning that identity.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='2') THEN
        RAISE EXCEPTION 'device enrollment requires schema version 2';
    END IF;
END $$;

CREATE TABLE nds_devices (
    device_id TEXT PRIMARY KEY CHECK (length(device_id) = 43),
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    ordinal SMALLINT NOT NULL CHECK (ordinal BETWEEN 1 AND 128),
    platform TEXT NOT NULL CHECK (platform IN ('macos','linux','windows','ios','android')),
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    status TEXT NOT NULL CHECK (status IN ('active','revoked')),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms >= 0),
    FOREIGN KEY (user_id, tenant_id) REFERENCES nds_owner(user_id, tenant_id),
    UNIQUE (user_id, tenant_id, ordinal),
    UNIQUE (user_id, tenant_id, public_key)
);

ALTER TABLE nds_sessions ADD CONSTRAINT nds_session_owner_binding
    UNIQUE (token_digest, user_id, tenant_id);

CREATE TABLE nds_enrollment_challenges (
    challenge_id TEXT PRIMARY KEY CHECK (length(challenge_id) = 43),
    device_id TEXT NOT NULL UNIQUE CHECK (length(device_id) = 43),
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    session_digest BYTEA NOT NULL CHECK (octet_length(session_digest) = 32),
    platform TEXT NOT NULL CHECK (platform IN ('macos','linux','windows','ios','android')),
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    challenge BYTEA NOT NULL CHECK (octet_length(challenge) = 32),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms >= 0),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > created_at_ms),
    attempts_remaining SMALLINT NOT NULL CHECK (attempts_remaining BETWEEN 0 AND 5),
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (session_digest, user_id, tenant_id)
        REFERENCES nds_sessions(token_digest, user_id, tenant_id) ON DELETE CASCADE
);

GRANT SELECT, INSERT ON nds_devices TO nds_runtime;
GRANT UPDATE (status) ON nds_devices TO nds_runtime;
GRANT SELECT, INSERT, DELETE ON nds_enrollment_challenges TO nds_runtime;
GRANT UPDATE (attempts_remaining, consumed) ON nds_enrollment_challenges TO nds_runtime;

UPDATE nddev_schema_meta SET value='3', updated_at=NOW() WHERE key='schema_version';
