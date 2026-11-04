-- Distributed per-identity fixed-window throttling. Keys are SHA-256 digests.
-- Cleanup of expired counters and used tokens must run periodically.
CREATE TABLE auth_http_attempts (
    key_hash CHAR(64) PRIMARY KEY,
    window_start TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    attempts INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE auth_http_one_time_tokens (
    token_hash CHAR(64) PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('verify', 'reset')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE INDEX auth_http_one_time_expiration_idx
    ON auth_http_one_time_tokens (expires_at);
CREATE INDEX auth_http_one_time_user_idx
    ON auth_http_one_time_tokens (user_id, purpose);
