package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/audit"
	identityauth "github.com/biairmal/go-identity/internal/module/auth"
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

// tenantMemberships adapts the tenant service to the membership ports user
// and auth declare.
type tenantMemberships struct{ svc *tenant.Service }

// DefaultTenantID returns the default tenant's ID.
func (m tenantMemberships) DefaultTenantID(ctx context.Context) (uuid.UUID, error) {
	return m.svc.DefaultID(ctx)
}

// AddActiveMember makes the user an active member of the tenant.
func (m tenantMemberships) AddActiveMember(ctx context.Context, tenantID, userID uuid.UUID) error {
	return m.svc.EnsureActiveMember(ctx, tenantID, userID)
}

// BySlug returns the tenant's ID and whether it accepts sign-ins.
func (m tenantMemberships) BySlug(ctx context.Context, slug string) (uuid.UUID, bool, error) {
	t, err := m.svc.BySlug(ctx, slug)
	if err != nil {
		return uuid.Nil, false, err
	}
	return t.ID, t.Active(), nil
}

// authAudit adapts the audit writer to the port auth declares.
type authAudit struct{ w *audit.Writer }

// Write maps an auth audit event to the audit module's event.
func (a authAudit) Write(ctx context.Context, e *identityauth.AuditEvent) error {
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

// authUsers adapts the user service to the port auth declares. It is the
// only place auth's Account meets user's User.
type authUsers struct{ svc *user.Service }

// FindByEmail returns the account with this address.
func (a authUsers) FindByEmail(ctx context.Context, email string) (*identityauth.Account, error) {
	u, err := a.svc.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return toAccount(u), nil
}

// Get returns one account.
func (a authUsers) Get(ctx context.Context, id uuid.UUID) (*identityauth.Account, error) {
	u, err := a.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toAccount(u), nil
}

// Create stores the account and its password hash.
func (a authUsers) Create(ctx context.Context, n *identityauth.NewAccount) (uuid.UUID, error) {
	u, err := a.svc.Create(ctx, &user.CreateParams{
		Email: n.Email, DisplayName: n.DisplayName, Status: n.Status,
	}, n.PasswordHash)
	if err != nil {
		return uuid.Nil, err
	}
	return u.ID, nil
}

// VerifyEmail confirms the email and activates a pending account. It reads
// the row first so the status update carries the current version.
func (a authUsers) VerifyEmail(ctx context.Context, id uuid.UUID, at time.Time) error {
	u, err := a.svc.Get(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.VerifyEmail(ctx, u, at)
}

// toAccount keeps the fields auth reads.
func toAccount(u *user.User) *identityauth.Account {
	return &identityauth.Account{
		ID: u.ID, Email: u.Email, DisplayName: u.DisplayName,
		Status: u.Status, EmailVerified: u.EmailVerified(),
	}
}

// authRoles adapts the rbac service to the port auth declares.
type authRoles struct{ svc *rbac.Service }

// Assign resolves each role name in the tenant and grants them together.
// The grant has no actor: the user signed themselves up.
func (a authRoles) Assign(ctx context.Context, tenantID, userID uuid.UUID, names []string) error {
	ids := make([]uuid.UUID, 0, len(names))
	for _, name := range names {
		r, err := a.svc.RoleByName(ctx, tenantID, name)
		if err != nil {
			return err
		}
		ids = append(ids, r.ID)
	}
	if len(ids) == 0 {
		return nil
	}
	return a.svc.AssignRoles(ctx, tenantID, userID, ids, nil)
}
