package rbac

import (
	"context"
	"hash/fnv"
	"slices"
	"strings"

	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/common/dto"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/httpx"
	"github.com/biairmal/go-identity/internal/platform/scope"
)

// The admin role management of TRD 7 and 9.6. Every method acts in the
// caller's tenant, taken from the token. The rules: an admin grants only
// permissions they hold, cannot change or delete a role they hold that grants
// roles:manage, cannot touch a system role, and no change may leave the
// tenant without an active roles:manage holder.

// actor is the caller of an admin action.
type actor struct {
	userID, tenantID uuid.UUID
	super            bool
	grants           []string
}

// holds reports whether the actor may grant key.
func (a *actor) holds(key string) bool { return authz.Matches(a.grants, key) }

// actor resolves the caller and their permissions (memoised per request).
func (s *Service) actor(ctx context.Context) (*actor, error) {
	userID, err := scope.User(ctx)
	if err != nil {
		return nil, err
	}
	tenantID, err := scope.Tenant(ctx)
	if err != nil {
		return nil, err
	}
	grants, err := s.az.grants(ctx)
	if err != nil {
		return nil, err
	}
	return &actor{userID: userID, tenantID: tenantID, super: authz.IsSuperAdmin(ctx), grants: grants}, nil
}

// ListRoles returns one page of the caller's tenant's roles.
func (s *Service) ListRoles(
	ctx context.Context, search string, page, size int,
) (*RolePageResponse, error) {
	tenantID, err := scope.Tenant(ctx)
	if err != nil {
		return nil, err
	}
	rows, total, err := s.repo.ListRoles(ctx, tenantID, strings.TrimSpace(search), size, (page-1)*size)
	if err != nil {
		return nil, err
	}
	items := make([]*RoleSummaryResponse, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		items = append(items, &RoleSummaryResponse{
			ID: r.ID.String(), Name: r.Name, Description: r.Description, IsSystem: r.IsSystem,
			PermissionCount: r.PermissionCount, UserCount: r.UserCount, Version: r.Version,
		})
	}
	return dto.NewPageResponse(items, total, page, size), nil
}

// GetRole returns one of the caller's tenant's roles with its permissions.
func (s *Service) GetRole(ctx context.Context, id uuid.UUID) (*RoleResponse, error) {
	tenantID, err := scope.Tenant(ctx)
	if err != nil {
		return nil, err
	}
	role, err := s.repo.RoleInTenant(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	keys, err := s.repo.RolePermissions(ctx, role.ID)
	if err != nil {
		return nil, err
	}
	return newRoleResponse(role, keys), nil
}

// CreateRole adds a role to the caller's tenant.
func (s *Service) CreateRole(ctx context.Context, in *CreateRoleRequest) (*RoleResponse, error) {
	in.Name = strings.TrimSpace(in.Name)
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	a, err := s.actor(ctx)
	if err != nil {
		return nil, err
	}
	keys := normalizeKeys(in.Permissions)
	if err := s.checkGrants(ctx, a, keys, nil); err != nil {
		return nil, err
	}
	var out *RoleResponse
	err = database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		role, err := s.repo.CreateRole(ctx, &a.tenantID, in.Name, in.Description, false)
		if err != nil {
			return err
		}
		if err := s.repo.SetRolePermissions(ctx, role.ID, keys); err != nil {
			return err
		}
		out = newRoleResponse(role, keys)
		return s.writeAudit(ctx, &AuditEvent{
			TenantID: a.tenantID, ActorID: a.userID, Action: ActionRoleCreate,
			TargetType: TargetRole, TargetID: role.ID.String(),
			After: map[string]any{"name": role.Name, "description": role.Description, "permissions": out.Permissions},
		})
	})
	return out, err
}

// UpdateRole renames a role or changes its description.
func (s *Service) UpdateRole(
	ctx context.Context, id uuid.UUID, version int, in *UpdateRoleRequest,
) (*RoleResponse, error) {
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		in.Name = &name
	}
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	a, err := s.actor(ctx)
	if err != nil {
		return nil, err
	}
	var out *RoleResponse
	err = database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		role, err := s.editableRole(ctx, a.tenantID, id, version)
		if err != nil {
			return err
		}
		name, description := role.Name, role.Description
		if in.Name != nil {
			name = *in.Name
		}
		if in.Description != nil {
			description = *in.Description
		}
		updated, err := s.repo.UpdateRole(ctx, a.tenantID, id, version, name, description)
		if err != nil {
			return err
		}
		keys, err := s.repo.RolePermissions(ctx, id)
		if err != nil {
			return err
		}
		out = newRoleResponse(updated, keys)
		return s.writeAudit(ctx, &AuditEvent{
			TenantID: a.tenantID, ActorID: a.userID, Action: ActionRoleUpdate,
			TargetType: TargetRole, TargetID: id.String(),
			Before: map[string]any{"name": role.Name, "description": role.Description},
			After:  map[string]any{"name": updated.Name, "description": updated.Description},
		})
	})
	return out, err
}

// SetPermissions replaces the permissions a role grants.
func (s *Service) SetPermissions(
	ctx context.Context, id uuid.UUID, version int, in *SetPermissionsRequest,
) (*RoleResponse, error) {
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	a, err := s.actor(ctx)
	if err != nil {
		return nil, err
	}
	keys := normalizeKeys(in.Permissions)
	var out *RoleResponse
	err = database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		if err := database.LockXact(ctx, adminLock(a.tenantID)); err != nil {
			return err
		}
		role, err := s.editableRole(ctx, a.tenantID, id, version)
		if err != nil {
			return err
		}
		current, err := s.repo.RolePermissions(ctx, id)
		if err != nil {
			return err
		}
		if err := s.checkGrants(ctx, a, keys, current); err != nil {
			return err
		}
		if err := s.checkNotOwnAdminRole(ctx, a, id, current); err != nil {
			return err
		}
		var updated *Role
		err = s.keepARoleManager(ctx, a.tenantID, func() error {
			if err := s.repo.SetRolePermissions(ctx, id, keys); err != nil {
				return err
			}
			updated, err = s.repo.UpdateRole(ctx, a.tenantID, id, version, role.Name, role.Description)
			return err
		})
		if err != nil {
			return err
		}
		out = newRoleResponse(updated, keys)
		return s.writeAudit(ctx, &AuditEvent{
			TenantID: a.tenantID, ActorID: a.userID, Action: ActionRolePermissions,
			TargetType: TargetRole, TargetID: id.String(),
			Before: map[string]any{"permissions": nonNil(current)},
			After:  map[string]any{"permissions": out.Permissions},
		})
	})
	return out, err
}

// DeleteRole deletes a role. A role still assigned to users needs force,
// and then the assignments go with it.
func (s *Service) DeleteRole(ctx context.Context, id uuid.UUID, force bool) error {
	a, err := s.actor(ctx)
	if err != nil {
		return err
	}
	return database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		if err := database.LockXact(ctx, adminLock(a.tenantID)); err != nil {
			return err
		}
		role, err := s.repo.RoleInTenant(ctx, a.tenantID, id)
		if err != nil {
			return err
		}
		if role.IsSystem {
			return apierr.New(apierr.ReasonSystemRole)
		}
		keys, err := s.repo.RolePermissions(ctx, id)
		if err != nil {
			return err
		}
		if err := s.checkNotOwnAdminRole(ctx, a, id, keys); err != nil {
			return err
		}
		users, err := s.repo.RoleUserCount(ctx, id)
		if err != nil {
			return err
		}
		if users > 0 && !force {
			return apierr.New(apierr.ReasonRoleInUse)
		}
		if err := s.keepARoleManager(ctx, a.tenantID, func() error {
			return s.repo.DeleteRole(ctx, a.tenantID, id)
		}); err != nil {
			return err
		}
		return s.writeAudit(ctx, &AuditEvent{
			TenantID: a.tenantID, ActorID: a.userID, Action: ActionRoleDelete,
			TargetType: TargetRole, TargetID: id.String(),
			Before: map[string]any{
				"name": role.Name, "description": role.Description, "permissions": nonNil(keys), "users": users,
			},
		})
	})
}

// editableRole loads a role an admin may change: in the tenant, not a system
// role, and still at version.
func (s *Service) editableRole(ctx context.Context, tenantID, id uuid.UUID, version int) (*Role, error) {
	role, err := s.repo.RoleInTenant(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if role.IsSystem {
		return nil, apierr.New(apierr.ReasonSystemRole)
	}
	if role.Version != version {
		return nil, httpx.ErrVersionConflict()
	}
	return role, nil
}

// checkGrants rejects keys outside the catalog (400) and keys the actor adds
// to current without holding them (PERMISSION_NOT_HELD). Keys the role
// already grants may stay, so an admin can still edit a role that grants
// more than they hold.
func (s *Service) checkGrants(ctx context.Context, a *actor, keys, current []string) error {
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
	for _, k := range keys {
		if !slices.Contains(current, k) && !a.holds(k) {
			return apierr.WithFields(apierr.ReasonPermissionNotHeld, map[string]string{
				"permissions": "you do not hold " + k,
			})
		}
	}
	return nil
}

// checkNotOwnAdminRole refuses a change to a role the actor holds that grants
// roles:manage, so an admin can neither raise nor remove their own admin
// power. The super admin's power does not come from roles.
func (s *Service) checkNotOwnAdminRole(ctx context.Context, a *actor, roleID uuid.UUID, keys []string) error {
	if a.super || !slices.Contains(keys, PermRolesManage) {
		return nil
	}
	holds, err := s.repo.HoldsRole(ctx, a.tenantID, a.userID, roleID)
	if err != nil {
		return err
	}
	if holds {
		return apierr.New(apierr.ReasonSelfEscalation)
	}
	return nil
}

// keepARoleManager runs change and refuses it (LAST_ADMIN) when it leaves a
// tenant that had an active roles:manage holder without one. The caller holds
// the tenant's admin lock, so two concurrent changes cannot each remove one
// of the last two holders.
func (s *Service) keepARoleManager(ctx context.Context, tenantID uuid.UUID, change func() error) error {
	before, err := s.repo.RoleManagers(ctx, tenantID)
	if err != nil {
		return err
	}
	if err := change(); err != nil {
		return err
	}
	after, err := s.repo.RoleManagers(ctx, tenantID)
	if err != nil {
		return err
	}
	if before > 0 && after == 0 {
		return apierr.New(apierr.ReasonLastAdmin)
	}
	return nil
}

// adminLock is the advisory lock key serializing the changes in one tenant
// that can remove a roles:manage holder.
func adminLock(tenantID uuid.UUID) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("rbac:role-managers:"))
	_, _ = h.Write(tenantID[:])
	return int64(h.Sum64()) //nolint:gosec // a lock key: wrapping to negative is fine
}

// normalizeKeys sorts keys and drops duplicates and blanks.
func normalizeKeys(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// nonNil returns s, or an empty slice for nil, so JSON shows [] not null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
