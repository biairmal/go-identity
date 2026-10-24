package auth

import (
	"context"
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
}

// Account is the part of a user the sign-in flows read.
type Account struct {
	ID            uuid.UUID
	Email         string
	DisplayName   string
	Status        string
	EmailVerified bool
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
}

// Roles grants roles by name. internal/app wires it over the rbac module.
type Roles interface {
	// Assign grants the named roles of tenantID to userID. A name the
	// tenant does not have is an error, not a silent skip.
	Assign(ctx context.Context, tenantID, userID uuid.UUID, names []string) error
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
	ActionRegister      = "auth.register"
	ActionEmailVerified = "auth.email_verified"
)

// TargetUser is the target type of the events above.
const TargetUser = "user"
