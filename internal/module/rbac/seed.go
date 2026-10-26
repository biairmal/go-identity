package rbac

import (
	"context"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/google/uuid"
)

// SyncCatalog brings the permissions table in line with the configuration.
// It inserts new keys and updates descriptions, and never deletes: a key a
// role still grants stays, with a warning, because deleting it would silently
// strip permissions from that role. Identity's own system permissions are
// always present and marked as such, whatever the configuration lists; a
// configured entry for one only changes its description.
func (s *Service) SyncCatalog(ctx context.Context) error {
	system := map[string]bool{}
	for _, p := range SystemPermissions() {
		system[p.Key] = true
		if err := s.repo.UpsertPermission(ctx, CatalogEntry{
			Key: p.Key, Description: p.Description, IsSystem: true,
		}); err != nil {
			return err
		}
	}
	for _, p := range s.cfg.Permissions {
		if err := s.repo.UpsertPermission(ctx, CatalogEntry{
			Key: p.Key, Description: p.Description, IsSystem: system[p.Key],
		}); err != nil {
			return err
		}
	}
	return s.warnOrphans(ctx)
}

// warnOrphans logs the granted keys the configuration no longer lists. They
// keep working; the warning tells the operator to clean up or restore them.
func (s *Service) warnOrphans(ctx context.Context) error {
	orphans, err := s.repo.OrphanedPermissions(ctx, s.catalogKeys())
	if err != nil {
		return err
	}
	for _, key := range orphans {
		s.log.WarnWithContext(ctx,
			"permission is granted by a role but missing from the configured catalog",
			logger.F("permission", key))
	}
	return nil
}

// catalogKeys is every key the configuration and identity itself define.
func (s *Service) catalogKeys() []string {
	keys := make([]string, 0, len(s.cfg.Permissions)+len(SystemPermissions()))
	for _, p := range s.cfg.Permissions {
		keys = append(keys, p.Key)
	}
	for _, p := range SystemPermissions() {
		keys = append(keys, p.Key)
	}
	return keys
}

// SeedTenant creates the configured roles in one tenant, skipping the names
// that already exist, so an admin's later edits are never overwritten. It is
// also how a new tenant gets its starting roles (T6.1).
func (s *Service) SeedTenant(ctx context.Context, tenantID uuid.UUID) error {
	if !s.cfg.SeedOnStart {
		return nil
	}
	for _, name := range s.cfg.RoleNames() {
		if err := s.seedRole(ctx, tenantID, name, s.cfg.Roles[name]); err != nil {
			return err
		}
	}
	return nil
}

// SeedTemplates creates the configured roles as templates (tenant_id NULL)
// if they are missing, so a tenant created in multi mode copies the same
// starting roles single mode seeds directly. It runs on every start, is gated
// on SeedOnStart, and never overwrites an admin's later template edits.
func (s *Service) SeedTemplates(ctx context.Context) error {
	if !s.cfg.SeedOnStart {
		return nil
	}
	for _, name := range s.cfg.RoleNames() {
		existing, err := s.repo.RoleByName(ctx, nil, name)
		if err == nil {
			s.log.DebugWithContext(ctx, "template already exists, leaving it as the admin left it",
				logger.F("template", existing.Name))
			continue
		}
		if !isNotFound(err) {
			return err
		}
		role, err := s.repo.CreateRole(ctx, nil, name, "", false)
		if err != nil {
			return err
		}
		if err := s.repo.SetRolePermissions(ctx, role.ID, s.cfg.Roles[name]); err != nil {
			return err
		}
	}
	return nil
}

// seedRole creates one role with its grants, or leaves an existing role of
// that name untouched.
func (s *Service) seedRole(ctx context.Context, tenantID uuid.UUID, name string, keys []string) error {
	existing, err := s.repo.RoleByName(ctx, &tenantID, name)
	if err == nil {
		s.log.DebugWithContext(ctx, "role already exists, leaving it as the admin left it",
			logger.F("role", existing.Name))
		return nil
	}
	if !isNotFound(err) {
		return err
	}
	role, err := s.repo.CreateRole(ctx, &tenantID, name, "", false)
	if err != nil {
		return err
	}
	return s.repo.SetRolePermissions(ctx, role.ID, keys)
}

// CopyTemplateRoles copies every template role, with its grants, into a
// tenant. New tenants start with the same setup; later edits to a template do
// not change tenants that already exist.
func (s *Service) CopyTemplateRoles(ctx context.Context, tenantID uuid.UUID) error {
	templates, err := s.repo.RolesIn(ctx, nil)
	if err != nil {
		return err
	}
	for i := range templates {
		tpl := &templates[i]
		keys, err := s.repo.RolePermissions(ctx, tpl.ID)
		if err != nil {
			return err
		}
		if err := s.seedRole(ctx, tenantID, tpl.Name, keys); err != nil {
			return err
		}
	}
	return nil
}
