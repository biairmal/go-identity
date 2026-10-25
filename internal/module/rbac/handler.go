package rbac

import (
	"net/http"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit/response"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/httpx"
	"github.com/biairmal/go-identity/internal/platform/listquery"
)

// roleListQuery allows paging and a name search on GET /v1/admin/roles.
var roleListQuery = listquery.ListParseConfig{AllowedParams: []string{"search"}}

// roleID reads the {id} path parameter. A malformed ID names no role: 404.
func roleID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, errorz.NotFound().WithMessage("rbac: role not found")
	}
	return id, nil
}

// listPermissions answers GET /v1/admin/permissions with the catalog.
//
//	@Summary     List permissions
//	@Description The permission catalog roles are composed from.
//	@Tags        admin
//	@Produce     json
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[[]rbac.PermissionResponse]
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing roles:manage"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/permissions [get]
func (m *Module) listPermissions(r *http.Request) (any, error) {
	catalog, err := m.svc.Permissions(r.Context())
	if err != nil {
		return nil, err
	}
	out := make([]PermissionResponse, 0, len(catalog))
	for _, e := range catalog {
		out = append(out, PermissionResponse(e))
	}
	return out, nil
}

// listRoles answers GET /v1/admin/roles with one page of the tenant's roles.
//
//	@Summary     List roles
//	@Description One page of the tenant's roles, ordered by name.
//	@Tags        admin
//	@Produce     json
//	@Param       page   query int    false "Page, 1-based"
//	@Param       size   query int    false "Page size, max 100"
//	@Param       search query string false "Name contains, case-insensitive"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[rbac.RolePageResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid query"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing roles:manage"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/roles [get]
func (m *Module) listRoles(r *http.Request) (any, error) {
	q := r.URL.Query()
	params, err := listquery.ParseListParams(q, &roleListQuery)
	if err != nil {
		return nil, err
	}
	return m.svc.ListRoles(r.Context(), q.Get("search"), params.Page, params.Size)
}

// createRole answers POST /v1/admin/roles with 201 and the new role.
//
//	@Summary     Create a role
//	@Description Adds a role to the tenant. Only permissions the caller holds can be granted.
//	@Tags        admin
//	@Accept      json
//	@Produce     json
//	@Param       body body rbac.CreateRoleRequest true "Request body"
//	@Security    BearerAuth
//	@Success     201 {object} response.BaseResponse[rbac.RoleResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or unknown permission"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing roles:manage, or PERMISSION_NOT_HELD"
//	@Failure     409 {object} response.BaseResponse[any] "DUPLICATE name"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/roles [post]
func (m *Module) createRole(r *http.Request) (any, error) {
	var in CreateRoleRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	out, err := m.svc.CreateRole(r.Context(), &in)
	if err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusCreated, Data: out}, nil
}

// getRole answers GET /v1/admin/roles/{id}.
//
//	@Summary     Get a role
//	@Description One of the tenant's roles with its permissions and version.
//	@Tags        admin
//	@Produce     json
//	@Param       id path string true "Role ID"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[rbac.RoleResponse]
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing roles:manage"
//	@Failure     404 {object} response.BaseResponse[any] "Role not found"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/roles/{id} [get]
func (m *Module) getRole(r *http.Request) (any, error) {
	id, err := roleID(r)
	if err != nil {
		return nil, err
	}
	return m.svc.GetRole(r.Context(), id)
}

// updateRole answers PATCH /v1/admin/roles/{id}.
//
//	@Summary     Rename a role
//	@Description Changes a role's name or description. Requires If-Match with the role's version.
//	@Tags        admin
//	@Accept      json
//	@Produce     json
//	@Param       id       path   string                 true  "Role ID"
//	@Param       If-Match header string                 false "Role version, e.g. \"3\" (or version in the body)"
//	@Param       body     body   rbac.UpdateRoleRequest true  "Request body"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[rbac.RoleResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing roles:manage, or SYSTEM_ROLE"
//	@Failure     404 {object} response.BaseResponse[any] "Role not found"
//	@Failure     409 {object} response.BaseResponse[any] "DUPLICATE or VERSION_CONFLICT"
//	@Failure     428 {object} response.BaseResponse[any] "No version given"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/roles/{id} [patch]
func (m *Module) updateRole(r *http.Request) (any, error) {
	id, err := roleID(r)
	if err != nil {
		return nil, err
	}
	var in UpdateRoleRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	version, err := httpx.Version(r, in.Version)
	if err != nil {
		return nil, err
	}
	return m.svc.UpdateRole(r.Context(), id, version, &in)
}

// setPermissions answers PUT /v1/admin/roles/{id}/permissions.
//
//	@Summary     Replace a role's permissions
//	@Description Sets the full list of permissions a role grants. Requires If-Match with the role's version.
//	@Tags        admin
//	@Accept      json
//	@Produce     json
//	@Param       id       path   string                     true  "Role ID"
//	@Param       If-Match header string                     false "Role version, e.g. \"3\" (or version in the body)"
//	@Param       body     body   rbac.SetPermissionsRequest true  "Request body"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[rbac.RoleResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or unknown permission"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "PERMISSION_NOT_HELD, SELF_ESCALATION or SYSTEM_ROLE"
//	@Failure     404 {object} response.BaseResponse[any] "Role not found"
//	@Failure     409 {object} response.BaseResponse[any] "LAST_ADMIN or VERSION_CONFLICT"
//	@Failure     428 {object} response.BaseResponse[any] "No version given"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/roles/{id}/permissions [put]
func (m *Module) setPermissions(r *http.Request) (any, error) {
	id, err := roleID(r)
	if err != nil {
		return nil, err
	}
	var in SetPermissionsRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	version, err := httpx.Version(r, in.Version)
	if err != nil {
		return nil, err
	}
	return m.svc.SetPermissions(r.Context(), id, version, &in)
}

// deleteRole answers DELETE /v1/admin/roles/{id} with 204.
//
//	@Summary     Delete a role
//	@Description Deletes a role. A role still assigned needs force=true, which removes the assignments too.
//	@Tags        admin
//	@Produce     json
//	@Param       id    path  string true  "Role ID"
//	@Param       force query bool   false "Delete even when assigned"
//	@Security    BearerAuth
//	@Success     204
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing roles:manage, SELF_ESCALATION or SYSTEM_ROLE"
//	@Failure     404 {object} response.BaseResponse[any] "Role not found"
//	@Failure     409 {object} response.BaseResponse[any] "ROLE_IN_USE or LAST_ADMIN"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/roles/{id} [delete]
func (m *Module) deleteRole(r *http.Request) (any, error) {
	id, err := roleID(r)
	if err != nil {
		return nil, err
	}
	if err := m.svc.DeleteRole(r.Context(), id, r.URL.Query().Get("force") == "true"); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusNoContent}, nil
}

// setUserRoles answers PUT /v1/admin/users/{id}/roles.
//
//	@Summary     Replace a user's roles
//	@Description Sets the full list of roles a user holds in the tenant.
//	@Tags        admin
//	@Accept      json
//	@Produce     json
//	@Param       id   path string                   true "User ID"
//	@Param       body body rbac.SetUserRolesRequest true "Request body"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[rbac.UserRolesResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or unknown role"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "PERMISSION_NOT_HELD, SELF_ESCALATION or SUPER_ADMIN_PROTECTED"
//	@Failure     404 {object} response.BaseResponse[any] "User not found in the tenant"
//	@Failure     409 {object} response.BaseResponse[any] "LAST_ADMIN"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/users/{id}/roles [put]
func (m *Module) setUserRoles(r *http.Request) (any, error) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return nil, errorz.NotFound().WithMessage("rbac: user not found")
	}
	var in SetUserRolesRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	return m.svc.SetUserRoles(r.Context(), id, &in)
}
