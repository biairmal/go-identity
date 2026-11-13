-- +goose Up

-- Serves the per-target page of the audit log (GET /v1/admin/audit with
-- target_type and target_id), so the busiest tenant's page for one user does
-- not scan the tenant's whole log.
CREATE INDEX audit_log_tenant_target_at ON audit_log (tenant_id, target_type, target_id, at DESC);

-- +goose Down
DROP INDEX audit_log_tenant_target_at;
