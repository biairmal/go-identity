-- +goose Up

-- Tenants. Single mode keeps exactly one row (the default tenant), so the
-- schema is identical in both modes and a client can switch later without
-- migrating data.
CREATE TABLE tenants (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name        text NOT NULL,
    status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    version     int  NOT NULL DEFAULT 1,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Users. The email is encrypted and found through its blind index, so the
-- plain value never reaches the database. Secrets live in credentials.
CREATE TABLE users (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email_enc            bytea NOT NULL,
    email_hash           bytea NOT NULL UNIQUE,
    email_verified_at    timestamptz,
    display_name         text NOT NULL DEFAULT '',
    status               text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'disabled')),
    is_super_admin       boolean NOT NULL DEFAULT false,
    must_change_password boolean NOT NULL DEFAULT false,
    failed_logins        int NOT NULL DEFAULT 0,
    locked_until         timestamptz,
    last_sign_in_at      timestamptz,
    version              int NOT NULL DEFAULT 1,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

-- At most one super admin, enforced by the database rather than by code.
CREATE UNIQUE INDEX users_one_super_admin ON users (is_super_admin) WHERE is_super_admin;

-- Membership: one user can belong to several tenants with different roles.
CREATE TABLE tenant_members (
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    user_id    uuid NOT NULL REFERENCES users(id),
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('invited', 'active', 'removed')),
    joined_at  timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX tenant_members_user ON tenant_members (user_id);

-- Password hashes, kept out of users so a user read never loads a secret.
CREATE TABLE credentials (
    user_id       uuid PRIMARY KEY REFERENCES users(id),
    password_hash text NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Linked external sign-in methods.
CREATE TABLE identities (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          uuid NOT NULL REFERENCES users(id),
    provider         text NOT NULL CHECK (provider IN ('google')),
    provider_subject text NOT NULL,
    email_at_link    bytea,
    linked_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_subject)
);
CREATE INDEX identities_user ON identities (user_id);

-- +goose Down
DROP TABLE identities;
DROP TABLE credentials;
DROP TABLE tenant_members;
DROP TABLE users;
DROP TABLE tenants;
