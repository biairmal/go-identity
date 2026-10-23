-- +goose Up

-- Append-only change history. Writes happen in the same transaction as the
-- change they describe, so an audit row and its change cannot diverge.
CREATE TABLE audit_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    tenant_id   uuid,
    actor_id    uuid,
    action      text NOT NULL,
    target_type text NOT NULL DEFAULT '',
    target_id   text NOT NULL DEFAULT '',
    before      jsonb,
    after       jsonb,
    ip          inet,
    request_id  text NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_tenant_at ON audit_log (tenant_id, at DESC);
CREATE INDEX audit_log_actor_at  ON audit_log (actor_id, at DESC);

-- Keep the log append-only for application code: the role may insert and
-- read, never change or remove a row. TRUNCATE stays granted so the test kit
-- can reset the schema between tests. The role owns the table and could grant
-- itself these rights back, so this guards against an accidental UPDATE or
-- DELETE from a repository, not against a determined superuser.
REVOKE UPDATE, DELETE ON audit_log FROM identity;

-- Signing-key metadata. Private keys stay in the mounted secret and never
-- reach the database; this table only tracks which kid is in which state.
CREATE TABLE signing_keys (
    kid          text PRIMARY KEY,
    public_jwk   jsonb NOT NULL,
    status       text NOT NULL CHECK (status IN ('next', 'active', 'retiring', 'retired')),
    activated_at timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE signing_keys;
DROP TABLE audit_log;
