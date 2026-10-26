package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Ports this module declares. internal/app wires each one over the module
// that owns the behavior, so auth never imports another module.

// Users reads and writes accounts. internal/app wires it over the user
// module, whose repository encrypts the email.
type Users interface {
	// FindByEmail returns the account with this address, whatever its
	// spelling, or an errorz.NotFound error.
	FindByEmail(ctx context.Context, email string) (*Account, error)
	// Get returns one account, or an errorz.NotFound error.
	Get(ctx context.Context, id uuid.UUID) (*Account, error)
	// Create stores an account with its password hash and returns its ID.
	// An address that is already taken is an errorz.Conflict error.
	Create(ctx context.Context, a *NewAccount) (uuid.UUID, error)
	// VerifyEmail stamps the email as confirmed and activates a pending
	// account.
	VerifyEmail(ctx context.Context, id uuid.UUID, at time.Time) error
	// PasswordHash returns the account's argon2id PHC string, or an
	// errorz.NotFound error when it has no password.
	PasswordHash(ctx context.Context, id uuid.UUID) (string, error)
	// UpdatePasswordHash stores a new hash of the same password, after a
	// rehash with stronger parameters. A forced password change stays.
	UpdatePasswordHash(ctx context.Context, id uuid.UUID, hash string) error
	// SetDisplayName renames the account.
	SetDisplayName(ctx context.Context, id uuid.UUID, name string) error
	// SetPassword stores a newly chosen password and clears a forced password
	// change.
	SetPassword(ctx context.Context, id uuid.UUID, hash string) error
	// RecordFailedLogin counts one failed sign-in and returns the new total.
	RecordFailedLogin(ctx context.Context, id uuid.UUID) (int, error)
	// Lock blocks sign-in until the given time.
	Lock(ctx context.Context, id uuid.UUID, until time.Time) error
	// ClearFailedLogins resets the failure counter and any lock.
	ClearFailedLogins(ctx context.Context, id uuid.UUID) error
	// RecordSignIn resets the failure counter and the lock and stamps the
	// sign-in time.
	RecordSignIn(ctx context.Context, id uuid.UUID, at time.Time) error
	// EmailKey is a stable, non-reversible key for an address, whatever its
	// spelling, for rate limits that must never store the plain address.
	EmailKey(email string) string
}

// Account is the part of a user the sign-in flows read.
type Account struct {
	ID            uuid.UUID
	Email         string
	DisplayName   string
	Status        string
	EmailVerified bool
	// IsSuperAdmin adds the sa claim to the account's tokens.
	IsSuperAdmin bool
	// MustChangePassword restricts sign-in to a password-change token.
	MustChangePassword bool
	// LockedUntil is set while, or after, the account was locked out.
	LockedUntil *time.Time
}

// NewAccount is an account to create with a password.
type NewAccount struct {
	Email        string
	DisplayName  string
	Status       string
	PasswordHash string
}

// Account status values, as the user module stores them.
const (
	StatusPending  = "pending"
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// Tenants resolves the tenant a sign-up joins and adds the membership.
// internal/app wires it over the tenant module.
type Tenants interface {
	// DefaultTenantID returns the default tenant, the only one in single
	// mode.
	DefaultTenantID(ctx context.Context) (uuid.UUID, error)
	// BySlug returns the ID of the tenant with this slug and whether it is
	// active, or an errorz.NotFound error.
	BySlug(ctx context.Context, slug string) (id uuid.UUID, active bool, err error)
	// AddActiveMember makes userID an active member of tenantID.
	AddActiveMember(ctx context.Context, tenantID, userID uuid.UUID) error
	// Tenant returns one tenant, or an errorz.NotFound error.
	Tenant(ctx context.Context, id uuid.UUID) (*TenantInfo, error)
	// Memberships lists the tenants userID belongs to, in any status.
	Memberships(ctx context.Context, userID uuid.UUID) ([]Membership, error)
	// InviteMember makes userID an invited member of tenantID unless it is
	// one already, and returns the previous status ("" for none).
	InviteMember(ctx context.Context, tenantID, userID uuid.UUID) (string, error)
}

// TenantInfo is the part of a tenant sign-in reads.
type TenantInfo struct {
	ID   uuid.UUID
	Slug string
	Name string
	// Active is false for a suspended tenant.
	Active bool
}

// Membership is a tenant seen from one user's side.
type Membership struct {
	Tenant TenantInfo
	// Active is true when the membership allows acting in the tenant.
	Active bool
	// Status is the membership status: invited, active, disabled or removed.
	Status string
}

// Roles grants roles by name. internal/app wires it over the rbac module.
type Roles interface {
	// Assign grants the named roles of tenantID to userID. A name the
	// tenant does not have is an error, not a silent skip.
	Assign(ctx context.Context, tenantID, userID uuid.UUID, names []string) error
	// RoleNames lists the roles userID holds in tenantID.
	RoleNames(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error)
	// Permissions is the union of the permissions of those roles.
	Permissions(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error)
	// CheckGrantable refuses roles the caller may not hand out: unknown in
	// the caller's tenant (400) or granting a permission the caller lacks.
	CheckGrantable(ctx context.Context, roleIDs []uuid.UUID) error
	// GrantRoles grants the tenant's roles among roleIDs, skipping deleted
	// ones.
	GrantRoles(ctx context.Context, tenantID, userID uuid.UUID, roleIDs []uuid.UUID, grantedBy *uuid.UUID) error
}

// Sessions starts, rotates and revokes refresh-token families. internal/app
// wires it over the session module, which owns the rotation rules.
type Sessions interface {
	// Issue starts a new family for a fresh sign-in.
	Issue(ctx context.Context, userID, tenantID uuid.UUID, d Device) (*IssuedSession, error)
	// Rotate exchanges a refresh token for the next one in its family. It
	// fails with ErrRefreshReused (the family is now revoked),
	// ErrRefreshRevoked, ErrRefreshExpired, or an errorz.NotFound error for
	// an unknown token.
	Rotate(ctx context.Context, raw string, d Device) (*IssuedSession, error)
	// Lookup returns the token behind a raw value in any state, or an
	// errorz.NotFound error.
	Lookup(ctx context.Context, raw string) (*SessionToken, error)
	// RevokeFamily revokes one chain of tokens: one device signed out.
	RevokeFamily(ctx context.Context, familyID uuid.UUID) error
	// RevokeAllForUser revokes every family of a user.
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}

// Refresh-token outcomes the Sessions port reports, mapped from the session
// module's own errors by internal/app.
var (
	// ErrRefreshReused is a rotated token presented after the grace window.
	ErrRefreshReused = errors.New("auth: refresh token reused")
	// ErrRefreshRevoked is a token whose family was already revoked.
	ErrRefreshRevoked = errors.New("auth: refresh token revoked")
	// ErrRefreshExpired is a token past its sliding or absolute expiry.
	ErrRefreshExpired = errors.New("auth: refresh token expired")
)

// SessionToken is one stored refresh token as sign-out sees it.
type SessionToken struct {
	FamilyID uuid.UUID
	UserID   uuid.UUID
	TenantID uuid.UUID
	// Revoked is true once the token's family was revoked.
	Revoked bool
	// Exchangeable is true when a refresh with this token would succeed as
	// far as the token goes: not revoked, not expired, and not rotated
	// longer ago than the reuse grace.
	Exchangeable bool
}

// Device describes where a sign-in came from, stored with the session.
type Device struct {
	UserAgent string
	IP        string
}

// IssuedSession is a new refresh token. Raw is the only copy in the clear: it
// goes into the response and is never logged.
type IssuedSession struct {
	Raw       string
	FamilyID  uuid.UUID
	UserID    uuid.UUID
	TenantID  uuid.UUID
	ExpiresAt time.Time
}

// Limiter rate-limits requests by key. internal/app wires it over
// internal/platform/ratelimit; a nil Limiter allows everything.
type Limiter interface {
	// Check consumes one request for key, or returns a RATE_LIMITED error.
	Check(ctx context.Context, key string) error
}

// AuditWriter records sign-up and sign-in events. internal/app wires it over
// the audit module.
type AuditWriter interface {
	Write(ctx context.Context, event *AuditEvent) error
}

// AuditEvent is the subset of an audit entry this module produces. It never
// carries an email, a password or a token.
type AuditEvent struct {
	TenantID   uuid.UUID
	ActorID    uuid.UUID
	Action     string
	TargetType string
	TargetID   string
	Before     any
	After      any
}

// Audit action names this module writes.
const (
	ActionUserInvite     = "user.invite"
	ActionInviteAccepted = "user.invite_accepted"
	ActionRegister       = "auth.register"
	ActionEmailVerified  = "auth.email_verified"
	ActionLogin          = "auth.login"
	ActionLoginFailed    = "auth.login_failed"
	ActionLogout         = "auth.logout"
	ActionLogoutAll      = "auth.logout_all"
	ActionRefreshReuse   = "auth.refresh_reuse"
	ActionPasswordReset  = "auth.password_reset"
	ActionPasswordChange = "auth.password_change"
	ActionIdentityUnlink = "identity.unlink"
)

// TargetUser is the target type of the events above.
const TargetUser = "user"
