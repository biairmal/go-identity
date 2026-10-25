package user

import (
	"context"

	"github.com/google/uuid"
)

// Ports this module declares. internal/app wires each one over the module
// that owns the behavior, so user never imports another module.

// Passwords hashes and checks passwords. internal/app wires it over the
// auth/password package, which owns the hashing parameters and the policy.
type Passwords interface {
	// Hash returns the encoded hash of plain.
	Hash(plain string) (string, error)
	// Validate returns an error when plain breaks the password policy.
	Validate(plain string) error
}

// Memberships puts a user in the default tenant, which is where the super
// admin lives.
type Memberships interface {
	// DefaultTenantID returns the default tenant's ID.
	DefaultTenantID(ctx context.Context) (uuid.UUID, error)
	// AddActiveMember makes userID an active member of tenantID. An
	// existing membership is left unchanged.
	AddActiveMember(ctx context.Context, tenantID, userID uuid.UUID) error
	// RemoveMember marks userID's membership of tenantID removed, recording
	// actorID as the one who did it.
	RemoveMember(ctx context.Context, tenantID, userID, actorID uuid.UUID) error
}

// Roles is what the admin user endpoints need from rbac, which owns role
// assignments.
type Roles interface {
	// RolesOf returns the roles each of the users holds in the tenant.
	RolesOf(ctx context.Context, tenantID uuid.UUID, userIDs []uuid.UUID) (map[uuid.UUID][]RoleRef, error)
	// RemoveAll removes every role the user holds in the tenant.
	RemoveAll(ctx context.Context, tenantID, userID uuid.UUID) error
	// GuardRoleManagers runs change in the caller's transaction and refuses
	// it with LAST_ADMIN when it leaves a tenant without an active
	// roles:manage holder.
	GuardRoleManagers(ctx context.Context, userID uuid.UUID, change func(context.Context) error) error
}

// RoleRef names one role a user holds.
type RoleRef struct {
	ID   uuid.UUID
	Name string
}

// Sessions revokes a user's refresh-token families.
type Sessions interface {
	// RevokeAllForUser revokes every live session of userID.
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}

// AuditWriter records user changes. internal/app wires it over the audit
// module.
type AuditWriter interface {
	Write(ctx context.Context, event *AuditEvent) error
}

// AuditEvent is the subset of an audit entry this module produces. The
// adapter in internal/app maps it to the audit module's own event.
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
	ActionSuperAdminCreate   = "superadmin.create"
	ActionSuperAdminReset    = "superadmin.reset"
	ActionSuperAdminTransfer = "superadmin.transfer"
	ActionUserDisable        = "user.disable"
	ActionUserEnable         = "user.enable"
)

// TargetUser is the target type this module records.
const TargetUser = "user"
