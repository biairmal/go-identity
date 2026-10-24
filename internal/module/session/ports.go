package session

import (
	"context"

	"github.com/google/uuid"
)

// AuditWriter records session events. internal/app wires it over the audit
// module.
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
	After      any
}

// ActionLogout is written when a user signs one of their devices out from
// the session list, like POST /v1/auth/logout for the device itself.
const ActionLogout = "auth.logout"
