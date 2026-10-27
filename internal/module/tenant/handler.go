package tenant

import (
	"net/http"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit/response"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/httpx"
	"github.com/biairmal/go-identity/internal/platform/listquery"
)

// tenantListQuery is what GET /v1/admin/tenants accepts besides page and size.
var tenantListQuery = listquery.ListParseConfig{
	AllowedFilterFields: []string{"status"},
	AllowedParams:       []string{"search"},
}

// tenantID reads the {id} path parameter. A malformed ID names no tenant: 404.
func tenantID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, errorz.NotFound().WithMessage("tenant: not found")
	}
	return id, nil
}

// listTenants answers GET /v1/admin/tenants with one page of tenants.
//
//	@Summary     List tenants
//	@Description One page of tenants. Super admin only; 404 in single mode.
//	@Tags        superadmin
//	@Produce     json
//	@Param       page   query int    false "Page, 1-based"
//	@Param       size   query int    false "Page size, max 100"
//	@Param       status query string false "active or suspended"
//	@Param       search query string false "Slug or name contains, case-insensitive"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[tenant.TenantPageResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid query"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Not the super admin"
//	@Failure     404 {object} response.BaseResponse[any] "Single mode"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/tenants [get]
func (m *Module) listTenants(r *http.Request) (any, error) {
	q := r.URL.Query()
	params, err := listquery.ParseListParams(q, &tenantListQuery)
	if err != nil {
		return nil, err
	}
	status := ""
	if f, ok := params.Filters["status"]; ok {
		switch f.Value {
		case StatusActive, StatusSuspended:
			status = f.Value
		default:
			return nil, errorz.BadRequest().WithMessage("status must be active or suspended").
				WithMeta(apierr.MetaFields, map[string]string{"status": "must be active or suspended"})
		}
	}
	return m.svc.ListTenants(r.Context(), status, q.Get("search"), params.Page, params.Size)
}

// createTenant answers POST /v1/admin/tenants with 201 and the new tenant.
//
//	@Summary     Create a tenant
//	@Description Creates a tenant, copies the template roles and invites the first admin. Super admin only.
//	@Tags        superadmin
//	@Accept      json
//	@Produce     json
//	@Param       body body tenant.CreateTenantRequest true "Request body"
//	@Security    BearerAuth
//	@Success     201 {object} response.BaseResponse[tenant.TenantResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Not the super admin"
//	@Failure     404 {object} response.BaseResponse[any] "Single mode"
//	@Failure     409 {object} response.BaseResponse[any] "DUPLICATE slug"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/tenants [post]
func (m *Module) createTenant(r *http.Request) (any, error) {
	var in CreateTenantRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	out, err := m.svc.CreateTenant(r.Context(), &in)
	if err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusCreated, Data: out}, nil
}

// getTenant answers GET /v1/admin/tenants/{id}.
//
//	@Summary     Get a tenant
//	@Description One tenant. Super admin only; 404 in single mode.
//	@Tags        superadmin
//	@Produce     json
//	@Param       id path string true "Tenant ID"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[tenant.TenantResponse]
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Not the super admin"
//	@Failure     404 {object} response.BaseResponse[any] "Tenant not found, or single mode"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/tenants/{id} [get]
func (m *Module) getTenant(r *http.Request) (any, error) {
	id, err := tenantID(r)
	if err != nil {
		return nil, err
	}
	return m.svc.GetTenant(r.Context(), id)
}

// getInternalTenant answers GET /v1/internal/tenants/{id} (TRD 9.8). Service
// tokens only, by service_token scope middleware.
//
//	@Summary     Get a tenant (internal)
//	@Description A tenant by ID. Service tokens only.
//	@Tags        internal
//	@Produce     json
//	@Param       id path string true "Tenant ID"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[tenant.InternalTenantResponse]
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Not a service token"
//	@Failure     404 {object} response.BaseResponse[any] "No such tenant"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/internal/tenants/{id} [get]
func (m *Module) getInternalTenant(r *http.Request) (any, error) {
	id, err := tenantID(r)
	if err != nil {
		return nil, err
	}
	return m.svc.InternalTenant(r.Context(), id)
}

// updateTenant answers PATCH /v1/admin/tenants/{id}.
//
//	@Summary     Update a tenant
//	@Description Renames a tenant or suspends/reactivates it. The default tenant cannot be suspended.
//	@Tags        superadmin
//	@Accept      json
//	@Produce     json
//	@Param       id       path   string                      true  "Tenant ID"
//	@Param       If-Match header string                      false "Tenant version, e.g. \"3\" (or version in the body)"
//	@Param       body     body   tenant.UpdateTenantRequest  true  "Request body"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[tenant.TenantResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body, or the default tenant cannot be suspended"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Not the super admin"
//	@Failure     404 {object} response.BaseResponse[any] "Tenant not found, or single mode"
//	@Failure     409 {object} response.BaseResponse[any] "VERSION_CONFLICT"
//	@Failure     428 {object} response.BaseResponse[any] "No version given"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/tenants/{id} [patch]
func (m *Module) updateTenant(r *http.Request) (any, error) {
	id, err := tenantID(r)
	if err != nil {
		return nil, err
	}
	var in UpdateTenantRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	version, err := httpx.Version(r, in.Version)
	if err != nil {
		return nil, err
	}
	return m.svc.UpdateTenant(r.Context(), id, version, &in)
}
