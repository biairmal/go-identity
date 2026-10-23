package rbac

import (
	"context"
	"errors"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/scope"
)

// Service holds the RBAC rules. It knows nothing about HTTP.
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

// EffectivePermissions is the union of the permissions of every role the user
// holds in the tenant. Identity's own admin routes use this rather than the
// token claim, so an admin action never runs on permissions that may be up to
// one access-token lifetime stale.
func (s *Service) EffectivePermissions(
	ctx context.Context, tenantID, userID uuid.UUID,
) ([]string, error) {
	return s.repo.EffectivePermissions(ctx, tenantID, userID)
}

// RoleNames lists the roles the user holds in the tenant, for the token's
// roles claim.
func (s *Service) RoleNames(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	return s.repo.RoleNames(ctx, tenantID, userID)
}

// TenantRoleMap is the role to permissions map of one tenant, served to
// resource services through /v1/internal so their authz keeps tokens small.
func (s *Service) TenantRoleMap(ctx context.Context, tenantID uuid.UUID) (map[string][]string, error) {
	return s.repo.TenantRoleMap(ctx, tenantID)
}

// Permissions lists the catalog an admin composes roles from.
func (s *Service) Permissions(ctx context.Context) ([]CatalogEntry, error) {
	return s.repo.Permissions(ctx)
}

// RolesInTenant lists the roles of the caller's tenant.
func (s *Service) RolesInTenant(ctx context.Context) ([]Role, error) {
	tenantID, err := scope.Tenant(ctx)
	if err != nil {
		return nil, err
	}
	return s.repo.RolesIn(ctx, &tenantID)
}

// RoleByName finds one role in a tenant by name.
func (s *Service) RoleByName(ctx context.Context, tenantID uuid.UUID, name string) (*Role, error) {
	return s.repo.RoleByName(ctx, &tenantID, name)
}

// AssignRoles grants roles to a user in a tenant and records it. The grants
// and the audit row share the caller's transaction.
func (s *Service) AssignRoles(
	ctx context.Context, tenantID, userID uuid.UUID, roleIDs []uuid.UUID, grantedBy *uuid.UUID,
) error {
	for _, roleID := range roleIDs {
		if err := s.repo.AssignRole(ctx, tenantID, userID, roleID, grantedBy); err != nil {
			return err
		}
	}
	names, err := s.repo.RoleNames(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	actor := uuid.Nil
	if grantedBy != nil {
		actor = *grantedBy
	}
	return s.writeAudit(ctx, &AuditEvent{
		TenantID: tenantID, ActorID: actor, Action: ActionUserRolesAssigned,
		TargetType: TargetUser, TargetID: userID.String(),
		After: map[string]any{"roles": names},
	})
}

// writeAudit records an event when an audit writer is wired.
func (s *Service) writeAudit(ctx context.Context, e *AuditEvent) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Write(ctx, e)
}

// isNotFound reports whether err is a not-found error, so seeding can tell an
// absent role from a real failure.
func isNotFound(err error) bool { return errors.Is(err, errorz.ErrNotFound) }
