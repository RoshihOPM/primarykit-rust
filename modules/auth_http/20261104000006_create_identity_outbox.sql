-- Secrets remain encrypted in the delivery outbox. The encryption key is
-- held outside PostgreSQL and must be shared by all delivery workers.
-- Do not grant direct SELECT access to outbox ciphertext to API readers.
CREATE TABLE auth_http_outbox (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash CHAR(64) NOT NULL
        REFERENCES auth_http_one_time_tokens(token_hash) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('verify', 'reset')),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    locked_until TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    dead_at TIMESTAMPTZ
);
CREATE INDEX auth_http_outbox_due_idx
    ON auth_http_outbox (available_at, id)
    WHERE delivered_at IS NULL AND dead_at IS NULL;
CREATE INDEX auth_http_attempts_window_idx
    ON auth_http_attempts(window_start);
CREATE INDEX auth_sessions_expires_idx ON auth_sessions(expires_at);
