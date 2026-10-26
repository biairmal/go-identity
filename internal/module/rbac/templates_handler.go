package rbac

import (
	"net/http"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit/response"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// templateID reads the {id} path parameter. A malformed ID names no template:
// 404.
func templateID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, errorz.NotFound().WithMessage("rbac: template not found")
	}
	return id, nil
}

// listTemplates answers GET /v1/admin/role-templates.
//
//	@Summary     List role templates
//	@Description The roles copied into each new tenant at creation. Super admin only; 404 in single mode.
//	@Tags        superadmin
//	@Produce     json
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[[]rbac.TemplateResponse]
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Not the super admin"
//	@Failure     404 {object} response.BaseResponse[any] "Single mode"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/role-templates [get]
func (m *Module) listTemplates(r *http.Request) (any, error) {
	return m.svc.ListTemplates(r.Context())
}

// createTemplate answers POST /v1/admin/role-templates with 201.
//
//	@Summary     Create a role template
//	@Description Adds a template copied into tenants created afterwards. Super admin only.
//	@Tags        superadmin
//	@Accept      json
//	@Produce     json
//	@Param       body body rbac.CreateTemplateRequest true "Request body"
//	@Security    BearerAuth
//	@Success     201 {object} response.BaseResponse[rbac.TemplateResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or unknown permission"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Not the super admin"
//	@Failure     404 {object} response.BaseResponse[any] "Single mode"
//	@Failure     409 {object} response.BaseResponse[any] "DUPLICATE name"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/role-templates [post]
func (m *Module) createTemplate(r *http.Request) (any, error) {
	var in CreateTemplateRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	out, err := m.svc.CreateTemplate(r.Context(), &in)
	if err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusCreated, Data: out}, nil
}

// updateTemplate answers PATCH /v1/admin/role-templates/{id}.
//
//	@Summary     Update a role template
//	@Description Renames a template or replaces its permissions; affects only tenants created later.
//	@Tags        superadmin
//	@Accept      json
//	@Produce     json
//	@Param       id       path   string                     true  "Template ID"
//	@Param       If-Match header string                     false "Template version, e.g. \"3\" (or version in the body)"
//	@Param       body     body   rbac.UpdateTemplateRequest true  "Request body"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[rbac.TemplateResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or unknown permission"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Not the super admin"
//	@Failure     404 {object} response.BaseResponse[any] "Template not found, or single mode"
//	@Failure     409 {object} response.BaseResponse[any] "DUPLICATE or VERSION_CONFLICT"
//	@Failure     428 {object} response.BaseResponse[any] "No version given"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/role-templates/{id} [patch]
func (m *Module) updateTemplate(r *http.Request) (any, error) {
	id, err := templateID(r)
	if err != nil {
		return nil, err
	}
	var in UpdateTemplateRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	version, err := httpx.Version(r, in.Version)
	if err != nil {
		return nil, err
	}
	return m.svc.UpdateTemplate(r.Context(), id, version, &in)
}

// deleteTemplate answers DELETE /v1/admin/role-templates/{id} with 204.
//
//	@Summary     Delete a role template
//	@Description Removes a template. Tenants already created keep their copied roles. Super admin only.
//	@Tags        superadmin
//	@Produce     json
//	@Param       id path string true "Template ID"
//	@Security    BearerAuth
//	@Success     204
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Not the super admin"
//	@Failure     404 {object} response.BaseResponse[any] "Template not found, or single mode"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/role-templates/{id} [delete]
func (m *Module) deleteTemplate(r *http.Request) (any, error) {
	id, err := templateID(r)
	if err != nil {
		return nil, err
	}
	if err := m.svc.DeleteTemplate(r.Context(), id); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusNoContent}, nil
}
