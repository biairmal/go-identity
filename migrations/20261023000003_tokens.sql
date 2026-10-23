-- +goose Up

-- Refresh-token families. Every secret is stored as a hash; the raw token
-- exists only in the response that issued it.
CREATE TABLE refresh_tokens (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id           uuid NOT NULL,
    user_id             uuid NOT NULL REFERENCES users(id),
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    token_hash          bytea NOT NULL UNIQUE,
    issued_at           timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    rotated_at          timestamptz,
    revoked_at          timestamptz,
    user_agent          text NOT NULL DEFAULT '',
    ip                  inet
);
CREATE INDEX refresh_tokens_family ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user   ON refresh_tokens (user_id) WHERE revoked_at IS NULL;

-- Single-use tokens for email verification, password reset, invites and the
-- Google exchange code.
CREATE TABLE one_time_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id),
    tenant_id  uuid REFERENCES tenants(id),
    purpose    text NOT NULL CHECK (purpose IN ('verify_email', 'reset_password', 'invite', 'oauth_exchange')),
    token_hash bytea NOT NULL UNIQUE,
    payload    jsonb NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- In-flight Google sign-ins. The state is stored hashed like every other
-- secret; rows live for ten minutes.
CREATE TABLE oauth_states (
    state_hash    bytea PRIMARY KEY,
    code_verifier text NOT NULL,
    nonce         text NOT NULL,
    redirect_to   text NOT NULL,
    tenant_slug   text,
    expires_at    timestamptz NOT NULL
);

-- +goose Down
DROP TABLE oauth_states;
DROP TABLE one_time_tokens;
DROP TABLE refresh_tokens;
