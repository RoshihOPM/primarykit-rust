-- Demonstrates filtering application resources by ownership and trusted
-- tenant identity *in the same SQL operation* as permission verification.
CREATE TABLE owned_records (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 200),
    owner_user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 10000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX owned_records_tenant_owner_idx
    ON owned_records (tenant_id, owner_user_id, id);
