-- Add contextual fields without rewriting the immutable initial audit migration.
-- Existing events remain explicitly marked as legacy (no verified actor context).
ALTER TABLE audit_events
    ADD COLUMN actor_kind TEXT NOT NULL DEFAULT 'legacy'
        CHECK (actor_kind IN ('legacy', 'user', 'service', 'system')),
    ADD COLUMN tenant_id TEXT
        CHECK (tenant_id IS NULL OR char_length(tenant_id) BETWEEN 1 AND 128),
    ADD COLUMN request_id TEXT
        CHECK (request_id IS NULL OR char_length(request_id) BETWEEN 1 AND 128),
    ADD CONSTRAINT audit_events_named_actor_check
        CHECK (
            actor_kind NOT IN ('user', 'service')
            OR (actor_id IS NOT NULL AND char_length(actor_id) BETWEEN 1 AND 128)
        );

CREATE INDEX audit_events_tenant_recent_idx
    ON audit_events (tenant_id, created_at DESC, id DESC)
    WHERE tenant_id IS NOT NULL;
