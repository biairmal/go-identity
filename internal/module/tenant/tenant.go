package tenant

import (
	"time"

	"github.com/google/uuid"
)

// Status values of a tenant.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
)

// Membership status values. A removed member keeps the row, so the audit
// history and any later re-invite stay consistent.
const (
	MemberInvited = "invited"
	MemberActive  = "active"
	MemberRemoved = "removed"
)

// Tenant is one tenant row. In single mode there is exactly one, created on
// first start from modules.tenant.default_tenant_slug.
type Tenant struct {
	ID        uuid.UUID
	Slug      string
	Name      string
	Status    string
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Active reports whether the tenant may be signed in to.
func (t *Tenant) Active() bool { return t.Status == StatusActive }

// Member is one tenant_members row.
type Member struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
	Status   string
	JoinedAt *time.Time
}

// Active reports whether the membership allows acting in the tenant.
func (m Member) Active() bool { return m.Status == MemberActive }
