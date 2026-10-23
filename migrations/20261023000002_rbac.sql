-- +goose Up

-- The permission catalog, synced from configuration on start because services
-- check these keys in code. Admins compose roles from it but cannot add keys.
CREATE TABLE permissions (
    key         text PRIMARY KEY CHECK (key ~ '^[a-z0-9_-]+(:[a-z0-9_-]+){1,2}$'),
    description text NOT NULL DEFAULT '',
    is_system   boolean NOT NULL DEFAULT false
);

-- Roles are per tenant. A null tenant_id marks a template role, copied into
-- each new tenant at creation.
CREATE TABLE roles (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid REFERENCES tenants(id),
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    is_system   boolean NOT NULL DEFAULT false,
    version     int NOT NULL DEFAULT 1,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, tenant_id)
);

-- Role names are unique per tenant, and separately unique among templates,
-- case-insensitively.
CREATE UNIQUE INDEX roles_name_per_tenant ON roles (tenant_id, lower(name)) WHERE tenant_id IS NOT NULL;
CREATE UNIQUE INDEX roles_name_template   ON roles (lower(name)) WHERE tenant_id IS NULL;

CREATE TABLE role_permissions (
    role_id        uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_key text NOT NULL REFERENCES permissions(key),
    PRIMARY KEY (role_id, permission_key)
);

-- Assignments. The composite foreign key to roles(id, tenant_id) makes it
-- impossible to grant a role from another tenant, and the one to
-- tenant_members requires the user to be a member of that tenant.
CREATE TABLE user_roles (
    tenant_id  uuid NOT NULL,
    user_id    uuid NOT NULL REFERENCES users(id),
    role_id    uuid NOT NULL,
    granted_by uuid REFERENCES users(id),
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id, role_id),
    FOREIGN KEY (role_id, tenant_id) REFERENCES roles (id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES tenant_members (tenant_id, user_id)
);
CREATE INDEX user_roles_role ON user_roles (role_id);

-- +goose Down
DROP TABLE user_roles;
DROP TABLE role_permissions;
DROP TABLE roles;
DROP TABLE permissions;
