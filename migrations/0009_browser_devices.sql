DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='8') THEN
        RAISE EXCEPTION 'browser enrollment requires schema version 8';
    END IF;
END $$;
-- Browser installations retain the same independent device proof, ownership,
-- revocation and encrypted operation protocol as native installations.
ALTER TABLE nds_devices DROP CONSTRAINT nds_devices_platform_check;
ALTER TABLE nds_devices ADD CONSTRAINT nds_devices_platform_check
    CHECK(platform IN ('macos','linux','windows','ios','android','web'));
ALTER TABLE nds_enrollment_challenges DROP CONSTRAINT nds_enrollment_challenges_platform_check;
ALTER TABLE nds_enrollment_challenges ADD CONSTRAINT nds_enrollment_challenges_platform_check
    CHECK(platform IN ('macos','linux','windows','ios','android','web'));
UPDATE nddev_schema_meta SET value='9',updated_at=NOW() WHERE key='schema_version';
