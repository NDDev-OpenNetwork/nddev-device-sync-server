DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='7') THEN
        RAISE EXCEPTION 'passkey session linkage requires schema version 7';
    END IF;
END $$;
-- Existing passkey sessions remain explicitly unlinked. Credential revocation
-- also invalidates those legacy sessions; no issuing credential is guessed.
ALTER TABLE nds_sessions ADD COLUMN passkey_credential_id BYTEA
    REFERENCES nds_passkeys(credential_id) ON DELETE CASCADE;
ALTER TABLE nds_sessions ADD CONSTRAINT nds_sessions_passkey_method_check
    CHECK(passkey_credential_id IS NULL OR auth_method='passkey');
CREATE INDEX nds_sessions_passkey ON nds_sessions(passkey_credential_id)
    WHERE passkey_credential_id IS NOT NULL;
GRANT DELETE ON nds_passkeys TO nds_runtime;
UPDATE nddev_schema_meta SET value='8',updated_at=NOW() WHERE key='schema_version';
