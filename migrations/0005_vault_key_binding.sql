-- Establish one immutable ciphertext-key identity per owner. This is public key
-- metadata only; native vault decryption material is never stored here.
DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='4') THEN
        RAISE EXCEPTION 'vault key binding requires schema version 4';
    END IF;
    IF EXISTS(SELECT 1 FROM nds_sync_operations GROUP BY user_id,tenant_id
        HAVING count(DISTINCT (convert_from(request_body,'UTF8')::jsonb #>> '{payload,key_id}'))>1) THEN
        RAISE EXCEPTION 'existing ciphertext key bindings require explicit owner resolution';
    END IF;
END $$;
ALTER TABLE nds_sync_counters ADD COLUMN root_key_id TEXT
    CHECK(root_key_id IS NULL OR (length(root_key_id) BETWEEN 1 AND 128 AND root_key_id ~ '^[A-Za-z0-9_.:-]+$'));
UPDATE nds_sync_counters c SET root_key_id=o.key_id FROM (
    SELECT user_id,tenant_id,min(convert_from(request_body,'UTF8')::jsonb #>> '{payload,key_id}') AS key_id
    FROM nds_sync_operations GROUP BY user_id,tenant_id
) o WHERE c.user_id=o.user_id AND c.tenant_id=o.tenant_id;
UPDATE nddev_schema_meta SET value='5',updated_at=NOW() WHERE key='schema_version';
