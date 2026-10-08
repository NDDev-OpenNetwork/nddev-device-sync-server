CREATE TABLE IF NOT EXISTS nddev_schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO nddev_schema_meta (key, value)
VALUES ('product', 'nddev-device-sync-server')
ON CONFLICT (key) DO NOTHING;

