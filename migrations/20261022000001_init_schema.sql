-- +goose Up
-- pgcrypto is also created by deploy/sql/bootstrap.sql, where the role may lack the privilege.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Side effects that leave the service (email, queue messages), written in the
-- same transaction as the change and sent by the worker.
CREATE TABLE outbox (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    topic      text NOT NULL,
    key        text NOT NULL DEFAULT '',
    payload    jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at    timestamptz,
    attempts   int NOT NULL DEFAULT 0,
    last_error text NOT NULL DEFAULT ''
);
CREATE INDEX outbox_unsent ON outbox (created_at) WHERE sent_at IS NULL;

-- +goose Down
-- pgcrypto stays: other schemas in the database may use it.
DROP TABLE outbox;
