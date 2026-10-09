-- One explicitly configured owner. Runtime may insert the initial binding but
-- cannot silently replace it; provider linking/rotation needs a reviewed action.
CREATE TABLE nds_owner (
    singleton SMALLINT PRIMARY KEY CHECK (singleton = 1),
    user_id TEXT NOT NULL UNIQUE CHECK (length(user_id) BETWEEN 1 AND 128),
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
    email_binding BYTEA NOT NULL CHECK (octet_length(email_binding) = 32),
    github_id BIGINT CHECK (github_id > 0),
    UNIQUE (user_id, tenant_id)
);

CREATE TABLE nds_auth_limits (
    key BYTEA PRIMARY KEY CHECK (octet_length(key) = 32),
    count INTEGER NOT NULL CHECK (count >= 0),
    ends_at_ms BIGINT NOT NULL CHECK (ends_at_ms >= 0)
);

CREATE TABLE nds_email_challenges (
    challenge_id TEXT PRIMARY KEY CHECK (length(challenge_id) = 43),
    subject BYTEA NOT NULL CHECK (octet_length(subject) = 32),
    verifier BYTEA NOT NULL CHECK (octet_length(verifier) = 32),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms >= 0),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > created_at_ms),
    attempts_remaining SMALLINT NOT NULL CHECK (attempts_remaining BETWEEN 0 AND 5),
    eligible BOOLEAN NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX nds_email_challenges_subject ON nds_email_challenges(subject, created_at_ms);

CREATE TABLE nds_sessions (
    token_digest BYTEA PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    auth_method TEXT NOT NULL CHECK (auth_method IN ('email_otp', 'github')),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms >= 0),
    FOREIGN KEY (user_id, tenant_id) REFERENCES nds_owner(user_id, tenant_id)
);

GRANT SELECT, INSERT ON nds_owner TO nds_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON nds_auth_limits, nds_email_challenges TO nds_runtime;
GRANT SELECT, INSERT, DELETE ON nds_sessions TO nds_runtime;

INSERT INTO nddev_schema_meta(key, value) VALUES ('schema_version', '2');
