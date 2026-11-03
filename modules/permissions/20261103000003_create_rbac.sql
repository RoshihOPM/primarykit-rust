-- Tenant-scoped RBAC. Never grant permissions solely from untrusted tenant IDs.
CREATE TABLE rbac_roles (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 200),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    UNIQUE (tenant_id, name)
);

CREATE TABLE rbac_role_permissions (
    role_id BIGINT NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK (char_length(permission) BETWEEN 1 AND 200),
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE rbac_user_roles (
    user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX rbac_user_roles_role_idx ON rbac_user_roles(role_id);
