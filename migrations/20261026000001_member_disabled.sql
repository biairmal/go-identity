-- +goose Up

-- A tenant admin disables a membership, not the account: the user stays able
-- to sign in to their other tenants (TRD 5.2).
ALTER TABLE tenant_members DROP CONSTRAINT tenant_members_status_check;
ALTER TABLE tenant_members ADD CONSTRAINT tenant_members_status_check
    CHECK (status IN ('invited', 'active', 'disabled', 'removed'));

-- +goose Down
UPDATE tenant_members SET status = 'removed' WHERE status = 'disabled';
ALTER TABLE tenant_members DROP CONSTRAINT tenant_members_status_check;
ALTER TABLE tenant_members ADD CONSTRAINT tenant_members_status_check
    CHECK (status IN ('invited', 'active', 'removed'));
