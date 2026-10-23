package rbac

import (
	"time"

	"github.com/google/uuid"
)

// Role is one role row. A role with no tenant is a template, copied into each
// new tenant at creation.
type Role struct {
	ID          uuid.UUID
	TenantID    *uuid.UUID
	Name        string
	Description string
	IsSystem    bool
	Version     int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Template reports whether the role is a template rather than a tenant's own.
func (r *Role) Template() bool { return r.TenantID == nil }

// CatalogEntry is one permission in the catalog, as stored.
type CatalogEntry struct {
	Key         string
	Description string
	IsSystem    bool
}
