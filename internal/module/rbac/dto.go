package rbac

import "github.com/biairmal/go-sdk/lib/common/dto"

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
