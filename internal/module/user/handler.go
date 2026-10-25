package user

import (
	"context"
	"net/http"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit/response"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/listquery"
)

// Permissions the admin user routes require; rbac owns the catalog.
const (
	permUsersRead   = "users:read"
	permUsersManage = "users:manage"
)

// userListQuery is what GET /v1/admin/users accepts besides page and size.
var userListQuery = listquery.ListParseConfig{
	AllowedSortFields:   []string{"display_name", "created_at"},
	AllowedFilterFields: []string{"status", "role"},
	AllowedParams:       []string{"search"},
}

// userID reads the {id} path parameter. A malformed ID names no user: 404.
func userID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, errorz.NotFound().WithMessage("user: not found")
	}
	return id, nil
}

// badQuery is the 400 for one query parameter.
func badQuery(field, msg string) error {
	return errorz.BadRequest().WithMessage(field+": "+msg).WithMeta(apierr.MetaFields, map[string]string{field: msg})
}

// listUsers answers GET /v1/admin/users with one page of the tenant's members.
//
//	@Summary     List users
//	@Description One page of the tenant's members with their roles.
//	@Tags        admin
//	@Produce     json
//	@Param       page   query int    false "Page, 1-based"
//	@Param       size   query int    false "Page size, max 100"
//	@Param       sort   query string false "display_name or created_at, then ,ASC or ,DESC"
//	@Param       status query string false "pending, active or disabled"
//	@Param       role   query string false "Role ID"
//	@Param       search query string false "Display name contains, or the exact email"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[user.AdminUserPageResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid query"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing users:read"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/users [get]
func (m *Module) listUsers(r *http.Request) (any, error) {
	q := r.URL.Query()
	params, err := listquery.ParseListParams(q, &userListQuery)
	if err != nil {
		return nil, err
	}
	lq := &ListQuery{Search: q.Get("search"), Sorts: params.Sorts, Page: params.Page, Size: params.Size}
	if f, ok := params.Filters["status"]; ok {
		switch f.Value {
		case StatusPending, StatusActive, StatusDisabled:
			lq.Status = f.Value
		default:
			return nil, badQuery("status", "must be pending, active or disabled")
		}
	}
	if f, ok := params.Filters["role"]; ok {
		id, err := uuid.Parse(f.Value)
		if err != nil {
			return nil, badQuery("role", "must be a role ID")
		}
		lq.RoleID = &id
	}
	return m.admin.List(r.Context(), lq)
}

// getUser answers GET /v1/admin/users/{id}.
//
//	@Summary     Get a user
//	@Description One member of the tenant with roles, sign-in methods and version.
//	@Tags        admin
//	@Produce     json
//	@Param       id path string true "User ID"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[user.AdminUserDetailResponse]
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing users:read"
//	@Failure     404 {object} response.BaseResponse[any] "Not a member of the tenant"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/users/{id} [get]
func (m *Module) getUser(r *http.Request) (any, error) {
	id, err := userID(r)
	if err != nil {
		return nil, err
	}
	return m.admin.Get(r.Context(), id)
}

// disableUser answers POST /v1/admin/users/{id}/disable with 204.
//
//	@Summary     Disable a user
//	@Description Blocks sign-in and revokes every session. Disabling yourself is refused.
//	@Tags        admin
//	@Produce     json
//	@Param       id path string true "User ID"
//	@Security    BearerAuth
//	@Success     204
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing users:manage, yourself, or SUPER_ADMIN_PROTECTED"
//	@Failure     404 {object} response.BaseResponse[any] "Not a member of the tenant"
//	@Failure     409 {object} response.BaseResponse[any] "LAST_ADMIN"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/users/{id}/disable [post]
func (m *Module) disableUser(r *http.Request) (any, error) {
	return m.noContent(r, m.admin.Disable)
}

// enableUser answers POST /v1/admin/users/{id}/enable with 204.
//
//	@Summary     Enable a user
//	@Description Lets a disabled user sign in again.
//	@Tags        admin
//	@Produce     json
//	@Param       id path string true "User ID"
//	@Security    BearerAuth
//	@Success     204
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing users:manage, or SUPER_ADMIN_PROTECTED"
//	@Failure     404 {object} response.BaseResponse[any] "Not a member of the tenant"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/users/{id}/enable [post]
func (m *Module) enableUser(r *http.Request) (any, error) {
	return m.noContent(r, m.admin.Enable)
}

// removeUser answers DELETE /v1/admin/users/{id} with 204.
//
//	@Summary     Remove a user from the tenant
//	@Description Removes the membership and the user's roles in this tenant; the account stays.
//	@Tags        admin
//	@Produce     json
//	@Param       id path string true "User ID"
//	@Security    BearerAuth
//	@Success     204
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing users:manage, or SUPER_ADMIN_PROTECTED"
//	@Failure     404 {object} response.BaseResponse[any] "Not a member of the tenant"
//	@Failure     409 {object} response.BaseResponse[any] "LAST_ADMIN"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/users/{id} [delete]
func (m *Module) removeUser(r *http.Request) (any, error) {
	return m.noContent(r, m.admin.Remove)
}

// noContent runs an action on the {id} user and answers 204.
func (m *Module) noContent(r *http.Request, action func(ctx context.Context, id uuid.UUID) error) (any, error) {
	id, err := userID(r)
	if err != nil {
		return nil, err
	}
	if err := action(r.Context(), id); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusNoContent}, nil
}
