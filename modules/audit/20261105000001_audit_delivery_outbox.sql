-- Installed with the opt-in audit module; apply AFTER the immutable audit migrations.
-- Queue only the event identifier and trusted destination name. The append-only
-- event row remains the source of truth; no credentials or arbitrary URLs here.
CREATE TABLE audit_delivery_outbox (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    audit_event_id BIGINT NOT NULL REFERENCES audit_events(id) ON DELETE RESTRICT,
    destination TEXT NOT NULL
        CHECK (destination ~ '^[A-Za-z0-9_.-]{1,128}$'),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
    lease_generation BIGINT NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    leased_until TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    dead_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT audit_delivery_once_per_destination
        UNIQUE (audit_event_id, destination),
    CONSTRAINT audit_delivery_terminal_state_check
        CHECK (delivered_at IS NULL OR dead_at IS NULL)
);

-- Workers claim rows with FOR UPDATE SKIP LOCKED, ordered by next due time.
CREATE INDEX audit_delivery_outbox_due_idx
    ON audit_delivery_outbox (available_at, id)
    WHERE delivered_at IS NULL AND dead_at IS NULL AND attempts < 8;

-- The final delivery can crash before acknowledgement; expired eighth
-- attempts must be moved to a terminal state, not remain pending indefinitely.
CREATE INDEX audit_delivery_outbox_exhausted_idx
    ON audit_delivery_outbox (leased_until, id)
    WHERE delivered_at IS NULL AND dead_at IS NULL AND attempts >= 8;
