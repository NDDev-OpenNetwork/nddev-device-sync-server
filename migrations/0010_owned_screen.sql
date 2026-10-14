-- Finite control metadata only. No private keys, native stores or screen frames.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='9') THEN
        RAISE EXCEPTION 'owned screen control requires schema version 9';
    END IF;
END $$;
CREATE TABLE nds_screen_bindings (
    device_id TEXT PRIMARY KEY REFERENCES nds_devices(device_id),
    user_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
    endpoint BYTEA NOT NULL UNIQUE CHECK (octet_length(endpoint)=32),
    instance_id UUID NOT NULL CHECK (instance_id <> '00000000-0000-0000-0000-000000000000'),
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    FOREIGN KEY (user_id,tenant_id) REFERENCES nds_owner(user_id,tenant_id)
);
CREATE TABLE nds_screen_views (
    view_id UUID PRIMARY KEY,
    user_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
    viewer_device TEXT NOT NULL REFERENCES nds_devices(device_id),
    host_device TEXT NOT NULL REFERENCES nds_devices(device_id),
    viewer_session BYTEA NOT NULL CHECK (octet_length(viewer_session)=32),
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 256),
    fingerprint BYTEA NOT NULL CHECK (octet_length(fingerprint)=32),
    request_body BYTEA NOT NULL CHECK (octet_length(request_body) BETWEEN 1 AND 65536),
    original_projection BYTEA NOT NULL CHECK (octet_length(original_projection) BETWEEN 1 AND 2048),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms BETWEEN 1 AND 9007199254740991),
    state TEXT NOT NULL CHECK (state IN ('requested','ready','ended')),
    native_grant BYTEA CHECK (octet_length(native_grant) BETWEEN 1 AND 8192),
    CHECK (viewer_device<>host_device),
    CHECK ((state='ready')=(native_grant IS NOT NULL)),
    UNIQUE(user_id,tenant_id,viewer_device,idempotency_key),
    FOREIGN KEY (user_id,tenant_id) REFERENCES nds_owner(user_id,tenant_id)
    -- Original session is a revocation reference, never cascading receipt deletion.
);
CREATE INDEX nds_screen_view_expiry ON nds_screen_views(user_id,tenant_id,expires_at_ms);
GRANT SELECT, INSERT ON nds_screen_bindings, nds_screen_views TO nds_runtime;
GRANT UPDATE(endpoint,instance_id,revision) ON nds_screen_bindings TO nds_runtime;
GRANT UPDATE(state,native_grant) ON nds_screen_views TO nds_runtime;
GRANT DELETE ON nds_screen_views TO nds_runtime;
UPDATE nddev_schema_meta SET value='10',updated_at=NOW() WHERE key='schema_version';
