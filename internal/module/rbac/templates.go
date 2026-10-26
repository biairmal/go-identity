package rbac

import (
	"context"
	"strings"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/scope"
)

// Role templates (9.7) are the roles copied into each new tenant at creation.
// Only the super admin manages them, which the route group enforces, so these
// methods do not check permissions. Editing a template changes only tenants
// created afterwards.

// ListTemplates returns every template with its permission keys.
func (s *Service) ListTemplates(ctx context.Context) ([]*TemplateResponse, error) {
	tpls, err := s.repo.RolesIn(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := make([]*TemplateResponse, 0, len(tpls))
	for i := range tpls {
		keys, err := s.repo.RolePermissions(ctx, tpls[i].ID)
		if err != nil {
			return nil, err
		}
		out = append(out, newTemplateResponse(&tpls[i], keys))
	}
	return out, nil
}

// CreateTemplate adds a role template. A name already used by a template is
// DUPLICATE; a permission outside the catalog is 400.
func (s *Service) CreateTemplate(ctx context.Context, in *CreateTemplateRequest) (*TemplateResponse, error) {
	in.Name = strings.TrimSpace(in.Name)
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	keys := normalizeKeys(in.Permissions)
	if err := s.checkKnownKeys(ctx, keys); err != nil {
		return nil, err
	}
	actorID, tenantID, err := superActor(ctx)
	if err != nil {
		return nil, err
	}
	var out *TemplateResponse
	err = database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		role, err := s.repo.CreateRole(ctx, nil, in.Name, in.Description, false)
		if err != nil {
			return err
		}
		if err := s.repo.SetRolePermissions(ctx, role.ID, keys); err != nil {
			return err
		}
		out = newTemplateResponse(role, keys)
		return s.writeAudit(ctx, &AuditEvent{
			TenantID: tenantID, ActorID: actorID, Action: ActionTemplateCreate,
			TargetType: TargetTemplate, TargetID: role.ID.String(),
			After: map[string]any{"name": role.Name, "description": role.Description, "permissions": out.Permissions},
		})
	})
	return out, err
}

// UpdateTemplate renames a template, changes its description, or replaces its
// permissions. Requires the current version (If-Match).
func (s *Service) UpdateTemplate(
	ctx context.Context, id uuid.UUID, version int, in *UpdateTemplateRequest,
) (*TemplateResponse, error) {
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		in.Name = &name
	}
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	var keys []string
	if in.Permissions != nil {
		keys = normalizeKeys(*in.Permissions)
		if err := s.checkKnownKeys(ctx, keys); err != nil {
			return nil, err
		}
	}
	actorID, tenantID, err := superActor(ctx)
	if err != nil {
		return nil, err
	}
	var out *TemplateResponse
	err = database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		tpl, err := s.repo.TemplateByID(ctx, id)
		if err != nil {
			return err
		}
		if tpl.Version != version {
			return apierr.New(apierr.ReasonVersionConflict)
		}
		before, err := s.repo.RolePermissions(ctx, id)
		if err != nil {
			return err
		}
		name, description := tpl.Name, tpl.Description
		if in.Name != nil {
			name = *in.Name
		}
		if in.Description != nil {
			description = *in.Description
		}
		if in.Permissions != nil {
			if err := s.repo.SetRolePermissions(ctx, id, keys); err != nil {
				return err
			}
		}
		updated, err := s.repo.UpdateTemplate(ctx, id, version, name, description)
		if err != nil {
			return err
		}
		after, err := s.repo.RolePermissions(ctx, id)
		if err != nil {
			return err
		}
		out = newTemplateResponse(updated, after)
		return s.writeAudit(ctx, &AuditEvent{
			TenantID: tenantID, ActorID: actorID, Action: ActionTemplateUpdate,
			TargetType: TargetTemplate, TargetID: id.String(),
			Before: map[string]any{"name": tpl.Name, "description": tpl.Description, "permissions": nonNil(before)},
			After:  map[string]any{"name": updated.Name, "description": updated.Description, "permissions": after},
		})
	})
	return out, err
}

// DeleteTemplate removes a template. Tenants already created keep their copied
// roles.
func (s *Service) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	actorID, tenantID, err := superActor(ctx)
	if err != nil {
		return err
	}
	return database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		tpl, err := s.repo.TemplateByID(ctx, id)
		if err != nil {
			return err
		}
		if err := s.repo.DeleteTemplate(ctx, id); err != nil {
			return err
		}
		return s.writeAudit(ctx, &AuditEvent{
			TenantID: tenantID, ActorID: actorID, Action: ActionTemplateDelete,
			TargetType: TargetTemplate, TargetID: id.String(),
			Before: map[string]any{"name": tpl.Name},
		})
	})
}

// checkKnownKeys rejects a permission key outside the catalog (400).
func (s *Service) checkKnownKeys(ctx context.Context, keys []string) error {
	catalog, err := s.repo.Permissions(ctx)
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(catalog))
	for _, e := range catalog {
		known[e.Key] = true
	}
	for _, k := range keys {
		if !known[k] {
			msg := "unknown permission " + k
			return errorz.BadRequest().WithMessage("permissions: "+msg).
				WithMeta(apierr.MetaFields, map[string]string{"permissions": msg})
		}
	}
	return nil
}

// superActor is the super admin's user and current tenant, for the audit row
// of a template change. The route group has already checked the sa claim.
func superActor(ctx context.Context) (userID, tenantID uuid.UUID, err error) {
	if userID, err = scope.User(ctx); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if tenantID, err = scope.Tenant(ctx); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return userID, tenantID, nil
}
