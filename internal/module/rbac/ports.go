package rbac

import (
	"context"

	"github.com/google/uuid"
)

// AuditWriter records role and assignment changes. internal/app wires it over
// the audit module, so rbac never imports it.
type AuditWriter interface {
	Write(ctx context.Context, event *AuditEvent) error
}

// AuditEvent is the subset of an audit entry this module produces.
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
	ActionRoleCreate        = "role.create"
	ActionRoleUpdate        = "role.update"
	ActionRoleDelete        = "role.delete"
	ActionRolePermissions   = "role.permissions"
	ActionUserRolesAssigned = "user.roles_assigned"
	ActionTemplateCreate    = "role_template.create"
	ActionTemplateUpdate    = "role_template.update"
	ActionTemplateDelete    = "role_template.delete"
)

// Target types this module records.
const (
	TargetRole     = "role"
	TargetUser     = "user"
	TargetTemplate = "role_template"
)
