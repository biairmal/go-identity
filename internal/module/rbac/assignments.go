package rbac

import (
	"context"
	"slices"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/database"
)

// memberRemoved is the tenant_members status of a user no longer in the
// tenant; such a user is not found by the admin endpoints.
const memberRemoved = "removed"

// SetUserRoles replaces the roles a member holds in the caller's tenant
// (TRD 7, 9.6). The super admin's roles cannot be changed, an admin cannot
// change their own, every permission of an added role must be one the caller
// holds, and the tenant must keep an active roles:manage holder.
func (s *Service) SetUserRoles(
	ctx context.Context, userID uuid.UUID, in *SetUserRolesRequest,
) (*UserRolesResponse, error) {
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	a, err := s.actor(ctx)
	if err != nil {
		return nil, err
	}
	ids := slices.Clone(in.RoleIDs)
	slices.SortFunc(ids, func(x, y uuid.UUID) int { return slices.Compare(x[:], y[:]) })
	ids = slices.Compact(ids)
	var out *UserRolesResponse
	err = database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		if err := database.LockXact(ctx, adminLock(a.tenantID)); err != nil {
			return err
		}
		if err := s.checkAssignable(ctx, a, userID); err != nil {
			return err
		}
		out, err = s.replaceUserRoles(ctx, a, userID, ids)
		return err
	})
	return out, err
}

// replaceUserRoles checks the new role set and writes it, with its audit row.
func (s *Service) replaceUserRoles(
	ctx context.Context, a *actor, userID uuid.UUID, ids []uuid.UUID,
) (*UserRolesResponse, error) {
	roles, err := s.repo.RolesByID(ctx, a.tenantID, ids)
	if err != nil {
		return nil, err
	}
	if len(roles) != len(ids) {
		return nil, errorz.BadRequest().WithMessage("role_ids: unknown role").
			WithMeta(apierr.MetaFields, map[string]string{"role_ids": "unknown role"})
	}
	held, err := s.repo.UserRoles(ctx, a.tenantID, []uuid.UUID{userID})
	if err != nil {
		return nil, err
	}
	current := held[userID]
	added := addedRoles(ids, current)
	if err := s.checkRoleGrants(ctx, a, added); err != nil {
		return nil, err
	}
	if err := s.keepARoleManager(ctx, a.tenantID, func() error {
		if err := s.repo.UnassignRoles(ctx, a.tenantID, userID, ids); err != nil {
			return err
		}
		for _, id := range added {
			if err := s.repo.AssignRole(ctx, a.tenantID, userID, id, &a.userID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	out := &UserRolesResponse{Roles: make([]RoleRefResponse, 0, len(roles))}
	for i := range roles {
		out.Roles = append(out.Roles, RoleRefResponse{ID: roles[i].ID.String(), Name: roles[i].Name})
	}
	return out, s.writeAudit(ctx, &AuditEvent{
		TenantID: a.tenantID, ActorID: a.userID, Action: ActionUserRolesAssigned,
		TargetType: TargetUser, TargetID: userID.String(),
		Before: map[string]any{"roles": refNames(current)},
		After:  map[string]any{"roles": roleNames(roles)},
	})
}

// checkAssignable refuses a user who is not a member of the tenant (404), the
// super admin (SUPER_ADMIN_PROTECTED) and the caller themselves
// (SELF_ESCALATION).
func (s *Service) checkAssignable(ctx context.Context, a *actor, userID uuid.UUID) error {
	status, superAdmin, err := s.repo.Member(ctx, a.tenantID, userID)
	if err != nil {
		return err
	}
	if status == memberRemoved {
		return errorz.NotFound().WithMessage("rbac: user not found")
	}
	if superAdmin {
		return apierr.New(apierr.ReasonSuperAdminProtected)
	}
	if userID == a.userID {
		return apierr.New(apierr.ReasonSelfEscalation)
	}
	return nil
}

// checkRoleGrants refuses granting a role with a permission the actor does
// not hold, because granting the role grants its permissions.
func (s *Service) checkRoleGrants(ctx context.Context, a *actor, added []uuid.UUID) error {
	if a.super || len(added) == 0 {
		return nil
	}
	keys, err := s.repo.PermissionsOfRoles(ctx, added)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if !a.holds(k) {
			return apierr.WithFields(apierr.ReasonPermissionNotHeld, map[string]string{
				"role_ids": "a role grants " + k + ", which you do not hold",
			})
		}
	}
	return nil
}

// CheckGrantable refuses role IDs the caller may not hand out in their
// tenant: one that is not the tenant's (400), or one granting a permission
// the caller does not hold (PERMISSION_NOT_HELD). An invite checks this when
// it is sent, since the roles are granted later.
func (s *Service) CheckGrantable(ctx context.Context, roleIDs []uuid.UUID) error {
	a, err := s.actor(ctx)
	if err != nil {
		return err
	}
	ids := slices.Clone(roleIDs)
	slices.SortFunc(ids, func(x, y uuid.UUID) int { return slices.Compare(x[:], y[:]) })
	ids = slices.Compact(ids)
	roles, err := s.repo.RolesByID(ctx, a.tenantID, ids)
	if err != nil {
		return err
	}
	if len(roles) != len(ids) {
		return errorz.BadRequest().WithMessage("role_ids: unknown role").
			WithMeta(apierr.MetaFields, map[string]string{"role_ids": "unknown role"})
	}
	return s.checkRoleGrants(ctx, a, ids)
}

// GrantRoles grants the tenant's roles among roleIDs to the user and records
// it; IDs of roles deleted since they were chosen are skipped. It joins the
// caller's transaction.
func (s *Service) GrantRoles(
	ctx context.Context, tenantID, userID uuid.UUID, roleIDs []uuid.UUID, grantedBy *uuid.UUID,
) error {
	roles, err := s.repo.RolesByID(ctx, tenantID, roleIDs)
	if err != nil || len(roles) == 0 {
		return err
	}
	ids := make([]uuid.UUID, 0, len(roles))
	for i := range roles {
		ids = append(ids, roles[i].ID)
	}
	return s.AssignRoles(ctx, tenantID, userID, ids, grantedBy)
}

// RolesOf returns the roles each of the users holds in the tenant.
func (s *Service) RolesOf(
	ctx context.Context, tenantID uuid.UUID, userIDs []uuid.UUID,
) (map[uuid.UUID][]RoleRef, error) {
	return s.repo.UserRoles(ctx, tenantID, userIDs)
}

// RemoveUserRoles removes every role the user holds in the tenant, for a user
// leaving it.
func (s *Service) RemoveUserRoles(ctx context.Context, tenantID, userID uuid.UUID) error {
	return s.repo.UnassignRoles(ctx, tenantID, userID, nil)
}

// GuardRoleManagers runs change, which takes access away from a member of the
// tenant (a disable, a removal), and refuses it with LAST_ADMIN when it leaves
// the tenant without an active roles:manage holder it had. It must run in the
// caller's transaction, and takes the tenant's admin lock first.
func (s *Service) GuardRoleManagers(
	ctx context.Context, tenantID uuid.UUID, change func(context.Context) error,
) error {
	if err := database.LockXact(ctx, adminLock(tenantID)); err != nil {
		return err
	}
	return s.keepARoleManager(ctx, tenantID, func() error { return change(ctx) })
}

// addedRoles returns the IDs in ids the user does not hold yet.
func addedRoles(ids []uuid.UUID, current []RoleRef) []uuid.UUID {
	var out []uuid.UUID
	for _, id := range ids {
		if !slices.ContainsFunc(current, func(r RoleRef) bool { return r.ID == id }) {
			out = append(out, id)
		}
	}
	return out
}

func refNames(refs []RoleRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Name)
	}
	return out
}

func roleNames(roles []Role) []string {
	out := make([]string, 0, len(roles))
	for i := range roles {
		out = append(out, roles[i].Name)
	}
	return out
}
