-- Installed by PrimaryKit Rust. Apply through SQLx migrations.
-- Writing audit events inside the business transaction preserves consistency.
CREATE TABLE audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id TEXT,
    action TEXT NOT NULL CHECK (char_length(action) BETWEEN 1 AND 100),
    resource_type TEXT NOT NULL CHECK (char_length(resource_type) BETWEEN 1 AND 100),
    resource_id TEXT NOT NULL CHECK (char_length(resource_id) BETWEEN 1 AND 200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX audit_events_resource_idx
    ON audit_events (resource_type, resource_id, created_at DESC);
