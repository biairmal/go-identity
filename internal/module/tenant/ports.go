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
