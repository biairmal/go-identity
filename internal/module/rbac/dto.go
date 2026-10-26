package rbac

import (
	"hash/fnv"
	"sort"
	"strings"

	"github.com/biairmal/go-sdk/lib/common/dto"
	"github.com/google/uuid"
)

// RolePageResponse is the data of GET /v1/admin/roles.
type RolePageResponse = dto.PageResponse[RoleSummaryResponse]

// PermissionResponse is one catalog entry in GET /v1/admin/permissions.
type PermissionResponse struct {
	Key         string `json:"key"`
	Description string `json:"description"`
	IsSystem    bool   `json:"is_system"`
}

// RoleSummaryResponse is one row of GET /v1/admin/roles.
type RoleSummaryResponse struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	IsSystem        bool   `json:"is_system"`
	PermissionCount int    `json:"permission_count"`
	UserCount       int    `json:"user_count"`
	Version         int    `json:"version"`
}

// RoleResponse is one role with the permission keys it grants.
type RoleResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IsSystem    bool     `json:"is_system"`
	Permissions []string `json:"permissions"`
	Version     int      `json:"version"`
}

// CreateRoleRequest is the body of POST /v1/admin/roles.
type CreateRoleRequest struct {
	Name        string   `json:"name" validate:"required,max=50"`
	Description string   `json:"description" validate:"max=200"`
	Permissions []string `json:"permissions"`
}

// UpdateRoleRequest is the body of PATCH /v1/admin/roles/{id}. Absent fields
// keep their value.
type UpdateRoleRequest struct {
	Name        *string `json:"name" validate:"omitnil,min=1,max=50"`
	Description *string `json:"description" validate:"omitnil,max=200"`
	// Version stands in for the If-Match header.
	Version *int `json:"version"`
}

// SetPermissionsRequest is the body of PUT /v1/admin/roles/{id}/permissions:
// the full set of keys the role grants afterwards.
type SetPermissionsRequest struct {
	Permissions []string `json:"permissions" validate:"required"`
	// Version stands in for the If-Match header.
	Version *int `json:"version"`
}

// SetUserRolesRequest is the body of PUT /v1/admin/users/{id}/roles: the full
// set of roles the user holds in the tenant afterwards.
type SetUserRolesRequest struct {
	RoleIDs []uuid.UUID `json:"role_ids" validate:"required"`
}

// RoleRefResponse names one role a user holds.
type RoleRefResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserRolesResponse is the data of PUT /v1/admin/users/{id}/roles.
type UserRolesResponse struct {
	Roles []RoleRefResponse `json:"roles"`
}

// TemplateResponse is one role template (9.7): the roles copied into each new
// tenant at creation.
type TemplateResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Version     int      `json:"version"`
}

// CreateTemplateRequest is the body of POST /v1/admin/role-templates.
type CreateTemplateRequest struct {
	Name        string   `json:"name" validate:"required,max=50"`
	Description string   `json:"description" validate:"max=200"`
	Permissions []string `json:"permissions"`
}

// UpdateTemplateRequest is the body of PATCH /v1/admin/role-templates/{id}.
// Absent fields keep their value; a present permissions list replaces the
// grants in full.
type UpdateTemplateRequest struct {
	Name        *string   `json:"name" validate:"omitnil,min=1,max=50"`
	Description *string   `json:"description" validate:"omitnil,max=200"`
	Permissions *[]string `json:"permissions"`
	// Version stands in for the If-Match header.
	Version *int `json:"version"`
}

// newTemplateResponse builds the response for a template granting keys.
func newTemplateResponse(role *Role, keys []string) *TemplateResponse {
	if keys == nil {
		keys = []string{}
	}
	return &TemplateResponse{
		ID: role.ID.String(), Name: role.Name, Description: role.Description,
		Permissions: keys, Version: role.Version,
	}
}

// newRoleResponse builds the response for role granting keys.
func newRoleResponse(role *Role, keys []string) *RoleResponse {
	if keys == nil {
		keys = []string{}
	}
	return &RoleResponse{
		ID: role.ID.String(), Name: role.Name, Description: role.Description,
		IsSystem: role.IsSystem, Permissions: keys, Version: role.Version,
	}
}

// InternalRoleMapResponse is GET /v1/internal/roles/permissions?tenant_id=
// (TRD 9.8), consumed by go-sdk authz source identity.
type InternalRoleMapResponse struct {
	TenantID string              `json:"tenant_id"`
	Roles    map[string][]string `json:"roles"`
	// Version changes whenever any role or its permissions change in this
	// tenant, so a caller can tell the map moved without comparing its
	// contents.
	Version int64 `json:"version"`
}

// newInternalRoleMapResponse builds the response, computing its version from
// the map's own content.
func newInternalRoleMapResponse(tenantID uuid.UUID, roles map[string][]string) *InternalRoleMapResponse {
	return &InternalRoleMapResponse{TenantID: tenantID.String(), Roles: roles, Version: roleMapVersion(roles)}
}

// roleMapVersion fingerprints a role map, sorting role names and each role's
// permission keys first, so the result does not depend on map order.
func roleMapVersion(roles map[string][]string) int64 {
	names := make([]string, 0, len(roles))
	for name := range roles {
		names = append(names, name)
	}
	sort.Strings(names)

	h := fnv.New64a()
	for _, name := range names {
		perms := append([]string{}, roles[name]...)
		sort.Strings(perms)
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(strings.Join(perms, ",")))
		_, _ = h.Write([]byte{0})
	}
	return int64(h.Sum64()) //nolint:gosec // a fingerprint, not a security value: wrapping to negative is fine
}
