package app

import (
	"context"

	"github.com/biairmal/go-identity/internal/module/audit"
	"github.com/biairmal/go-identity/internal/module/rbac"
	"github.com/biairmal/go-identity/internal/module/tenant"
)

// Adapters satisfy the ports modules declare, so no module imports another.
// Each one is a thin translation: it maps the consumer's port type to the
// provider's own type and calls it.

// tenantAudit adapts the audit writer to the port tenant declares.
type tenantAudit struct{ w *audit.Writer }

// Write maps a tenant audit event to the audit module's event.
func (a tenantAudit) Write(ctx context.Context, e *tenant.AuditEvent) error {
	return a.w.Write(ctx, &audit.Event{
		TenantID:   e.TenantID,
		ActorID:    e.ActorID,
		Action:     audit.Action(e.Action),
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		Before:     e.Before,
		After:      e.After,
	})
}

// rbacAudit adapts the audit writer to the port rbac declares.
type rbacAudit struct{ w *audit.Writer }

// Write maps an rbac audit event to the audit module's event.
func (a rbacAudit) Write(ctx context.Context, e *rbac.AuditEvent) error {
	return a.w.Write(ctx, &audit.Event{
		TenantID:   e.TenantID,
		ActorID:    e.ActorID,
		Action:     audit.Action(e.Action),
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		Before:     e.Before,
		After:      e.After,
	})
}
