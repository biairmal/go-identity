package app

import (
	"context"

	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/audit"
	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/module/rbac"
	"github.com/biairmal/go-identity/internal/module/tenant"
	"github.com/biairmal/go-identity/internal/module/user"
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

// userAudit adapts the audit writer to the port user declares.
type userAudit struct{ w *audit.Writer }

// Write maps a user audit event to the audit module's event.
func (a userAudit) Write(ctx context.Context, e *user.AuditEvent) error {
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

// userPasswords adapts the auth/password package to the port user declares,
// so the hashing parameters and the policy stay owned by auth.
type userPasswords struct{}

// Hash returns the argon2id PHC string of plain.
func (userPasswords) Hash(plain string) (string, error) { return password.Hash(plain) }

// Validate checks plain against the password policy.
func (userPasswords) Validate(plain string) error { return password.Validate(plain) }

// userMemberships adapts the tenant service to the port user declares.
type userMemberships struct{ svc *tenant.Service }

// DefaultTenantID returns the default tenant's ID.
func (m userMemberships) DefaultTenantID(ctx context.Context) (uuid.UUID, error) {
	return m.svc.DefaultID(ctx)
}

// AddActiveMember makes the user an active member of the tenant.
func (m userMemberships) AddActiveMember(ctx context.Context, tenantID, userID uuid.UUID) error {
	return m.svc.EnsureActiveMember(ctx, tenantID, userID)
}
