package tenant

import (
	"context"

	"github.com/google/uuid"
)

// AuditWriter records tenant and membership changes. internal/app wires it
// over the audit module, so tenant never imports it.
type AuditWriter interface {
	Write(ctx context.Context, event *AuditEvent) error
}

// Onboarding sets a newly created tenant up: it copies the template roles and
// invites the first admin into it. It is the one back edge (TRD 3.1):
// internal/app wires it over rbac and auth after auth is built, and it runs
// in the tenant-creation transaction, so a failure rolls the whole thing
// back.
type Onboarding interface {
	// CopyTemplateRoles copies every template role into the new tenant.
	CopyTemplateRoles(ctx context.Context, tenantID uuid.UUID) error
	// InviteFirstAdmin invites email into tenantID as its admin, recording
	// invitedBy as the inviter.
	InviteFirstAdmin(ctx context.Context, tenantID, invitedBy uuid.UUID, email string) error
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
	ActionTenantCreate     = "tenant.create"
	ActionTenantUpdate     = "tenant.update"
	ActionTenantSuspend    = "tenant.suspend"
	ActionTenantReactivate = "tenant.reactivate"
	ActionMemberAdd        = "member.add"
	ActionMemberRemove     = "member.remove"
)

// TargetTenant and TargetMembership are the target types this module records.
const (
	TargetTenant     = "tenant"
	TargetMembership = "membership"
)
