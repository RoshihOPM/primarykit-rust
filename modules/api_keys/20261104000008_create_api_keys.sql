-- Opaque, 256-bit API keys; only SHA-256 digests are stored.
CREATE TABLE api_keys (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 200),
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 120),
    token_hash CHAR(64) NOT NULL UNIQUE,
    scopes TEXT[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX api_keys_user_tenant_idx ON api_keys(user_id, tenant_id);
CREATE INDEX api_keys_active_expiry_idx ON api_keys(expires_at)
    WHERE revoked_at IS NULL;
