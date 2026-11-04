-- The inbound receipt must commit in the same transaction as domain changes.
-- Retain idempotency keys longer than the provider's maximum retry horizon.
CREATE TABLE webhook_inbox (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source TEXT NOT NULL CHECK (char_length(source) BETWEEN 1 AND 128),
    event_id TEXT NOT NULL CHECK (char_length(event_id) BETWEEN 1 AND 128),
    body_hash CHAR(64) NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(source, event_id)
);
CREATE INDEX webhook_inbox_received_idx ON webhook_inbox(received_at);

-- Destination is a trusted config key, not a user-controlled URL.
-- Limit DB access: payload data can contain sensitive business information.
CREATE TABLE webhook_outbox (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    destination TEXT NOT NULL CHECK (char_length(destination) BETWEEN 1 AND 128),
    event_id TEXT NOT NULL CHECK (char_length(event_id) BETWEEN 1 AND 128),
    body_hash CHAR(64) NOT NULL,
    payload BYTEA NOT NULL CHECK (octet_length(payload) <= 262144),
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_until TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    dead_at TIMESTAMPTZ,
    UNIQUE(destination, event_id)
);
CREATE INDEX webhook_outbox_due_idx ON webhook_outbox(available_at, id)
    WHERE delivered_at IS NULL AND dead_at IS NULL;
