package app

import (
	"context"
	"errors"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/audit"
	identityauth "github.com/biairmal/go-identity/internal/module/auth"
	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/module/rbac"
	"github.com/biairmal/go-identity/internal/module/session"
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

// Tenant returns the tenant sign-in issues a token for.
func (m tenantMemberships) Tenant(ctx context.Context, id uuid.UUID) (*identityauth.TenantInfo, error) {
	t, err := m.svc.ByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return &identityauth.TenantInfo{ID: t.ID, Slug: t.Slug, Name: t.Name, Active: t.Active()}, nil
}

// Memberships lists the user's tenants for multi-mode sign-in.
func (m tenantMemberships) Memberships(ctx context.Context, userID uuid.UUID) ([]identityauth.Membership, error) {
	ms, err := m.svc.MembershipsOf(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]identityauth.Membership, 0, len(ms))
	for _, ms := range ms {
		out = append(out, identityauth.Membership{
			Tenant: identityauth.TenantInfo{
				ID: ms.TenantID, Slug: ms.Slug, Name: ms.Name, Active: ms.TenantStatus == tenant.StatusActive,
			},
			Active: ms.MemberStatus == tenant.MemberActive,
		})
	}
	return out, nil
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

// PasswordHash returns the stored argon2id hash.
func (a authUsers) PasswordHash(ctx context.Context, id uuid.UUID) (string, error) {
	c, err := a.svc.Credentials(ctx, id)
	if err != nil {
		return "", err
	}
	return c.PasswordHash, nil
}

// UpdatePasswordHash stores a rehash of the same password.
func (a authUsers) UpdatePasswordHash(ctx context.Context, id uuid.UUID, hash string) error {
	return a.svc.UpdatePasswordHash(ctx, id, hash)
}

// SetDisplayName renames the account, reading it first for the current
// version.
func (a authUsers) SetDisplayName(ctx context.Context, id uuid.UUID, name string) error {
	u, err := a.svc.Get(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.SetDisplayName(ctx, id, u.Version, name)
}

// SetPassword stores a newly chosen password and clears a forced change.
func (a authUsers) SetPassword(ctx context.Context, id uuid.UUID, hash string) error {
	return a.svc.SetPassword(ctx, id, hash)
}

// RecordFailedLogin counts one failed sign-in.
func (a authUsers) RecordFailedLogin(ctx context.Context, id uuid.UUID) (int, error) {
	return a.svc.RecordFailedLogin(ctx, id)
}

// Lock blocks sign-in until the given time.
func (a authUsers) Lock(ctx context.Context, id uuid.UUID, until time.Time) error {
	return a.svc.Lock(ctx, id, &until)
}

// ClearFailedLogins resets the failure counter and any lock.
func (a authUsers) ClearFailedLogins(ctx context.Context, id uuid.UUID) error {
	return a.svc.ClearFailedLogins(ctx, id)
}

// RecordSignIn resets the counters and stamps the sign-in time.
func (a authUsers) RecordSignIn(ctx context.Context, id uuid.UUID, at time.Time) error {
	return a.svc.RecordSignIn(ctx, id, at)
}

// EmailKey is the address's blind-index key.
func (a authUsers) EmailKey(email string) string { return a.svc.EmailKey(email) }

// toAccount keeps the fields auth reads.
func toAccount(u *user.User) *identityauth.Account {
	return &identityauth.Account{
		ID: u.ID, Email: u.Email, DisplayName: u.DisplayName,
		Status: u.Status, EmailVerified: u.EmailVerified(),
		IsSuperAdmin: u.IsSuperAdmin, MustChangePassword: u.MustChangePassword,
		LockedUntil: u.LockedUntil,
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

// RoleNames lists the user's roles in the tenant, for the roles claim.
func (a authRoles) RoleNames(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	return a.svc.RoleNames(ctx, tenantID, userID)
}

// Permissions is the user's effective permissions in the tenant, for the
// perms claim.
func (a authRoles) Permissions(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	return a.svc.EffectivePermissions(ctx, tenantID, userID)
}

// authSessions adapts the session service to the port auth declares.
type authSessions struct{ svc *session.Service }

// Issue starts a new refresh-token family.
func (a authSessions) Issue(
	ctx context.Context, userID, tenantID uuid.UUID, d identityauth.Device,
) (*identityauth.IssuedSession, error) {
	issued, err := a.svc.Issue(ctx, userID, tenantID, session.Device{UserAgent: d.UserAgent, IP: d.IP})
	if err != nil {
		return nil, err
	}
	return toIssuedSession(issued), nil
}

// Rotate exchanges a refresh token, mapping the session module's outcomes to
// the errors auth declares. The errorz code is kept, so an unmapped path
// still answers 401.
func (a authSessions) Rotate(
	ctx context.Context, raw string, d identityauth.Device,
) (*identityauth.IssuedSession, error) {
	issued, err := a.svc.Rotate(ctx, raw, session.Device{UserAgent: d.UserAgent, IP: d.IP})
	switch {
	case err == nil:
		return toIssuedSession(issued), nil
	case errors.Is(err, session.ErrReuse):
		return nil, errors.Join(identityauth.ErrRefreshReused, err)
	case errors.Is(err, session.ErrRevoked):
		return nil, errors.Join(identityauth.ErrRefreshRevoked, err)
	case errors.Is(err, session.ErrExpired):
		return nil, errors.Join(identityauth.ErrRefreshExpired, err)
	default:
		return nil, err
	}
}

// Lookup returns the stored token behind a raw value.
func (a authSessions) Lookup(ctx context.Context, raw string) (*identityauth.SessionToken, error) {
	t, err := a.svc.Lookup(ctx, raw)
	if err != nil {
		return nil, err
	}
	return &identityauth.SessionToken{
		FamilyID: t.FamilyID, UserID: t.UserID, TenantID: t.TenantID,
		Revoked: t.Revoked(), Exchangeable: a.svc.Exchangeable(t),
	}, nil
}

// RevokeFamily revokes one family.
func (a authSessions) RevokeFamily(ctx context.Context, familyID uuid.UUID) error {
	return a.svc.RevokeFamily(ctx, familyID)
}

// RevokeAllForUser revokes every family of the user.
func (a authSessions) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	return a.svc.RevokeAllForUser(ctx, userID)
}

// toIssuedSession keeps the fields auth reads from a new token.
func toIssuedSession(issued *session.Issued) *identityauth.IssuedSession {
	t := issued.Token
	return &identityauth.IssuedSession{
		Raw: issued.Raw, FamilyID: t.FamilyID, UserID: t.UserID, TenantID: t.TenantID, ExpiresAt: t.ExpiresAt,
	}
}

// sessionAudit adapts the audit writer to the port session declares.
type sessionAudit struct{ w *audit.Writer }

// Write maps a session audit event to the audit module's event.
func (a sessionAudit) Write(ctx context.Context, e *session.AuditEvent) error {
	return a.w.Write(ctx, &audit.Event{
		TenantID:   e.TenantID,
		ActorID:    e.ActorID,
		Action:     audit.Action(e.Action),
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		After:      e.After,
	})
}

// RemoveMember marks the user's membership of the tenant removed.
func (m tenantMemberships) RemoveMember(ctx context.Context, tenantID, userID, actorID uuid.UUID) error {
	return m.svc.RemoveMember(ctx, tenantID, userID, actorID)
}

// sessionMembers adapts the tenant service to the membership port session
// declares.
type sessionMembers struct{ svc *tenant.Service }

// IsMember reports whether the user is an invited or active member.
func (m sessionMembers) IsMember(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	mb, err := m.svc.Member(ctx, tenantID, userID)
	if errors.Is(err, errorz.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return mb.Status != tenant.MemberRemoved, nil
}

// userRoles adapts the rbac service to the roles port user declares.
type userRoles struct{ svc *rbac.Service }

// RolesOf returns the roles each user holds in the tenant.
func (a userRoles) RolesOf(
	ctx context.Context, tenantID uuid.UUID, userIDs []uuid.UUID,
) (map[uuid.UUID][]user.RoleRef, error) {
	held, err := a.svc.RolesOf(ctx, tenantID, userIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID][]user.RoleRef, len(held))
	for id, refs := range held {
		for _, r := range refs {
			out[id] = append(out[id], user.RoleRef{ID: r.ID, Name: r.Name})
		}
	}
	return out, nil
}

// RemoveAll removes the user's roles in the tenant.
func (a userRoles) RemoveAll(ctx context.Context, tenantID, userID uuid.UUID) error {
	return a.svc.RemoveUserRoles(ctx, tenantID, userID)
}

// GuardRoleManagers runs change under rbac's last-admin protection.
func (a userRoles) GuardRoleManagers(
	ctx context.Context, userID uuid.UUID, change func(context.Context) error,
) error {
	return a.svc.GuardRoleManagers(ctx, userID, change)
}
