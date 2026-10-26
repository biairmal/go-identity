package user

import (
	"context"
	"errors"

	"github.com/biairmal/go-sdk/lib/common/dto"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/scope"
)

// Admin serves the tenant admin's user endpoints (TRD 9.6). Every method acts
// in the caller's tenant, taken from the token, and sees only its current
// members. The super admin cannot be disabled, enabled or removed (403
// SUPER_ADMIN_PROTECTED), and no change may leave a tenant without an active
// roles:manage holder (409 LAST_ADMIN).
type Admin struct {
	db       *sqlkit.DB
	repo     *Repository
	creds    *CredentialsRepository
	roles    Roles
	members  Memberships
	sessions Sessions
	audit    AuditWriter
}

// ListQuery is a parsed GET /v1/admin/users query.
type ListQuery struct {
	Search           string
	Status           string
	MembershipStatus string
	RoleID           *uuid.UUID
	Sorts            []dto.SortSpec
	Page             int
	Size             int
}

// List returns one page of the tenant's members with their roles.
func (a *Admin) List(ctx context.Context, q *ListQuery) (*AdminUserPageResponse, error) {
	tenantID, err := scope.Tenant(ctx)
	if err != nil {
		return nil, err
	}
	f := &MemberFilter{
		Search: q.Search, Status: q.Status, MembershipStatus: q.MembershipStatus, RoleID: q.RoleID,
		Limit: q.Size, Offset: (q.Page - 1) * q.Size,
	}
	for _, s := range q.Sorts {
		dir := " ASC"
		if s.Direction == dto.SortDesc {
			dir = " DESC"
		}
		f.OrderBy = append(f.OrderBy, memberSortColumns[s.Field]+dir)
	}
	if len(f.OrderBy) == 0 {
		f.OrderBy = []string{memberSortColumns["display_name"] + " ASC"}
	}
	members, total, err := a.repo.ListMembers(ctx, tenantID, f)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(members))
	for i := range members {
		ids = append(ids, members[i].ID)
	}
	roles, err := a.roles.RolesOf(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	items := make([]*AdminUserResponse, 0, len(members))
	for i := range members {
		items = append(items, newAdminUserResponse(&members[i], roles[members[i].ID]))
	}
	return dto.NewPageResponse(items, total, q.Page, q.Size), nil
}

// Get returns one member with their roles, sign-in methods and version.
func (a *Admin) Get(ctx context.Context, id uuid.UUID) (*AdminUserDetailResponse, error) {
	tenantID, err := scope.Tenant(ctx)
	if err != nil {
		return nil, err
	}
	m, err := a.repo.MemberInTenant(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	roles, err := a.roles.RolesOf(ctx, tenantID, []uuid.UUID{id})
	if err != nil {
		return nil, err
	}
	password := true
	if _, err := a.creds.Get(ctx, id); errors.Is(err, errorz.ErrNotFound) {
		password = false
	} else if err != nil {
		return nil, err
	}
	google, err := a.repo.HasGoogle(ctx, id)
	if err != nil {
		return nil, err
	}
	return &AdminUserDetailResponse{
		AdminUserResponse: *newAdminUserResponse(m, roles[id]),
		Providers:         ProvidersResponse{Password: password, Google: google},
		Version:           m.Version,
	}, nil
}

// Disable blocks the user in the caller's tenant: the membership becomes
// disabled and their sessions in this tenant are revoked. The account and the
// user's other tenants are untouched, and LAST_ADMIN is checked in this tenant
// only. Disabling yourself is SELF_ACTION; disabling a disabled member
// changes nothing.
func (a *Admin) Disable(ctx context.Context, id uuid.UUID) error {
	actorID, tenantID, err := caller(ctx)
	if err != nil {
		return err
	}
	if id == actorID {
		return apierr.New(apierr.ReasonSelfAction)
	}
	return database.WithTx(ctx, a.db, func(ctx context.Context) error {
		m, err := a.target(ctx, tenantID, id)
		if err != nil || m.MembershipStatus == MembershipDisabled {
			return err
		}
		if err := a.roles.GuardRoleManagers(ctx, tenantID, func(ctx context.Context) error {
			return a.members.DisableMember(ctx, tenantID, id)
		}); err != nil {
			return err
		}
		if err := a.sessions.RevokeAllForUserInTenant(ctx, id, tenantID); err != nil {
			return err
		}
		return a.audit.Write(ctx, &AuditEvent{
			TenantID: tenantID, ActorID: actorID, Action: ActionUserDisable,
			TargetType: TargetUser, TargetID: id.String(),
			Before: map[string]any{"membership_status": m.MembershipStatus},
			After:  map[string]any{"membership_status": MembershipDisabled},
		})
	})
}

// Enable lets a disabled member act in the caller's tenant again. Any other
// member is left as they are.
func (a *Admin) Enable(ctx context.Context, id uuid.UUID) error {
	actorID, tenantID, err := caller(ctx)
	if err != nil {
		return err
	}
	return database.WithTx(ctx, a.db, func(ctx context.Context) error {
		m, err := a.target(ctx, tenantID, id)
		if err != nil || m.MembershipStatus != MembershipDisabled {
			return err
		}
		if err := a.members.EnableMember(ctx, tenantID, id); err != nil {
			return err
		}
		return a.audit.Write(ctx, &AuditEvent{
			TenantID: tenantID, ActorID: actorID, Action: ActionUserEnable,
			TargetType: TargetUser, TargetID: id.String(),
			Before: map[string]any{"membership_status": MembershipDisabled},
			After:  map[string]any{"membership_status": MembershipActive},
		})
	})
}

// Remove takes the user out of the caller's tenant: the membership is marked
// removed and their roles there are deleted. The account itself stays.
func (a *Admin) Remove(ctx context.Context, id uuid.UUID) error {
	actorID, tenantID, err := caller(ctx)
	if err != nil {
		return err
	}
	return database.WithTx(ctx, a.db, func(ctx context.Context) error {
		if _, err := a.target(ctx, tenantID, id); err != nil {
			return err
		}
		return a.roles.GuardRoleManagers(ctx, tenantID, func(ctx context.Context) error {
			if err := a.roles.RemoveAll(ctx, tenantID, id); err != nil {
				return err
			}
			return a.members.RemoveMember(ctx, tenantID, id, actorID)
		})
	})
}

// target loads a member an admin may change: in the tenant and not the super
// admin.
func (a *Admin) target(ctx context.Context, tenantID, id uuid.UUID) (*Member, error) {
	m, err := a.repo.MemberInTenant(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if m.IsSuperAdmin {
		return nil, apierr.New(apierr.ReasonSuperAdminProtected)
	}
	return m, nil
}

// caller is the user and tenant of the request's token.
func caller(ctx context.Context) (userID, tenantID uuid.UUID, err error) {
	if userID, err = scope.User(ctx); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if tenantID, err = scope.Tenant(ctx); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return userID, tenantID, nil
}
