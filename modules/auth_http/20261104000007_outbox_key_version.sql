-- Existing outbox rows were encrypted before key versioning.
-- Default "legacy" preserves the ability to decrypt them with the original key.
-- Roll out updated workers before activating a new key ID in API processes.
ALTER TABLE auth_http_outbox
    ADD COLUMN encryption_key_id TEXT NOT NULL DEFAULT 'legacy',
    ADD CONSTRAINT auth_http_outbox_key_id_format
        CHECK (encryption_key_id ~ '^[A-Za-z0-9_-]{1,32}$');

CREATE INDEX auth_http_outbox_pending_key_idx
    ON auth_http_outbox (encryption_key_id)
    WHERE delivered_at IS NULL AND dead_at IS NULL;
