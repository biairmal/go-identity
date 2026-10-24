package tenant

import (
	"context"
	"errors"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/scope"
)

// Service holds the tenant rules. It knows nothing about HTTP.
type Service struct {
	cfg   Config
	repo  *Repository
	audit AuditWriter
	log   logger.Logger
}

// NewService returns a Service. audit may be nil, which skips the audit
// writes; log may be nil.
func NewService(cfg Config, repo *Repository, auditWriter AuditWriter, log logger.Logger) *Service {
	if log == nil {
		log = logger.NewNoOp()
	}
	return &Service{cfg: cfg, repo: repo, audit: auditWriter, log: log}
}

// EnsureDefault creates the configured default tenant if it is missing and
// returns it. It runs on every start, so it must be idempotent: a second
// start, or a second pod, finds the existing row and changes nothing.
func (s *Service) EnsureDefault(ctx context.Context) (*Tenant, error) {
	t, created, err := s.repo.EnsureBySlug(ctx, s.cfg.DefaultTenantSlug, defaultTenantName)
	if err != nil {
		return nil, err
	}
	if !created {
		return t, nil
	}
	s.log.InfoWithContext(ctx, "default tenant created", logger.F("tenant_slug", t.Slug))
	if err := s.writeAudit(ctx, &AuditEvent{
		TenantID: t.ID, Action: ActionTenantCreate, TargetType: TargetTenant, TargetID: t.ID.String(),
		After: map[string]any{"slug": t.Slug, "name": t.Name, "status": t.Status},
	}); err != nil {
		return nil, err
	}
	return t, nil
}

// defaultTenantName is the display name of the tenant created on first start.
// An admin can rename it later.
const defaultTenantName = "Default"

// DefaultID returns the default tenant's ID, which single mode uses as the
// only tenant and the super admin's home tenant.
func (s *Service) DefaultID(ctx context.Context) (uuid.UUID, error) {
	t, err := s.repo.BySlug(ctx, s.cfg.DefaultTenantSlug)
	if err != nil {
		return uuid.Nil, err
	}
	return t.ID, nil
}

// ByID returns one tenant.
func (s *Service) ByID(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	return s.repo.ByID(ctx, id)
}

// List returns every tenant. internal/app uses it at startup to seed roles
// into each one, so rbac does not have to list tenants itself.
func (s *Service) List(ctx context.Context) ([]Tenant, error) { return s.repo.List(ctx) }

// Current returns the tenant of the calling token. The tenant comes only from
// the token claim, never from a request parameter.
func (s *Service) Current(ctx context.Context) (*Tenant, error) {
	id, err := scope.Tenant(ctx)
	if err != nil {
		return nil, err
	}
	return s.repo.ByID(ctx, id)
}

// AddMember makes a user a member of a tenant and records it.
func (s *Service) AddMember(ctx context.Context, tenantID, userID uuid.UUID, status string) error {
	if err := s.repo.AddMember(ctx, tenantID, userID, status); err != nil {
		return err
	}
	return s.writeAudit(ctx, &AuditEvent{
		TenantID: tenantID, Action: ActionMemberAdd,
		TargetType: TargetMembership, TargetID: userID.String(),
		After: map[string]any{"status": status},
	})
}

// EnsureActiveMember makes a user an active member of a tenant: it adds the
// membership when there is none, reactivates an invited or removed one, and
// leaves an active one alone. Every change is audited; a no-op is not.
func (s *Service) EnsureActiveMember(ctx context.Context, tenantID, userID uuid.UUID) error {
	m, err := s.repo.Member(ctx, tenantID, userID)
	switch {
	case errors.Is(err, errorz.ErrNotFound):
		return s.AddMember(ctx, tenantID, userID, MemberActive)
	case err != nil:
		return err
	case m.Active():
		return nil
	}
	if err := s.repo.SetMemberStatus(ctx, tenantID, userID, MemberActive); err != nil {
		return err
	}
	return s.writeAudit(ctx, &AuditEvent{
		TenantID: tenantID, Action: ActionMemberAdd,
		TargetType: TargetMembership, TargetID: userID.String(),
		Before: map[string]any{"status": m.Status},
		After:  map[string]any{"status": MemberActive},
	})
}

// Member returns one membership.
func (s *Service) Member(ctx context.Context, tenantID, userID uuid.UUID) (*Member, error) {
	return s.repo.Member(ctx, tenantID, userID)
}

// MembershipsOf lists the tenants a user belongs to.
func (s *Service) MembershipsOf(ctx context.Context, userID uuid.UUID) ([]Membership, error) {
	return s.repo.MembershipsOf(ctx, userID)
}

// writeAudit records an event when an audit writer is wired.
func (s *Service) writeAudit(ctx context.Context, e *AuditEvent) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Write(ctx, e)
}
