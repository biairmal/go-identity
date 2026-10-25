package audit

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/biairmal/go-sdk/lib/common/dto"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit/response"
	"github.com/biairmal/go-sdk/lib/repository"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/listquery"
	"github.com/biairmal/go-identity/internal/platform/scope"
)

// permAuditRead is the permission GET /v1/admin/audit requires; rbac owns
// the catalog.
const permAuditRead = "audit:read"

// EntryResponse is one entry of GET /v1/admin/audit.
type EntryResponse struct {
	ID         int64           `json:"id"`
	At         time.Time       `json:"at"`
	Actor      *ActorResponse  `json:"actor,omitempty"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	Before     json.RawMessage `json:"before,omitempty" swaggertype:"object"`
	After      json.RawMessage `json:"after,omitempty" swaggertype:"object"`
	IP         string          `json:"ip,omitempty"`
	RequestID  string          `json:"request_id"`
}

// ActorResponse is who made a change. Anonymous events have none.
type ActorResponse struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

// EntryPageResponse is the data of GET /v1/admin/audit.
type EntryPageResponse = dto.PageResponse[EntryResponse]

// auditListQuery is what GET /v1/admin/audit accepts besides page and size.
var auditListQuery = listquery.ListParseConfig{AllowedFilterFields: []string{"actor", "action", "from", "to"}}

// listAudit answers GET /v1/admin/audit with one page of the caller's
// tenant's log, newest first.
//
//	@Summary     Read the audit log
//	@Description The tenant's audit log, newest first. action takes a LIKE pattern such as role.%
//	@Tags        admin
//	@Produce     json
//	@Param       page   query int    false "Page, 1-based"
//	@Param       size   query int    false "Page size, max 100"
//	@Param       actor  query string false "Actor user ID"
//	@Param       action query string false "Action, or a LIKE pattern"
//	@Param       from   query string false "Earliest time, RFC 3339"
//	@Param       to     query string false "Latest time, RFC 3339"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[audit.EntryPageResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid query"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing audit:read"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/audit [get]
func (m *Module) listAudit(r *http.Request) (any, error) {
	tenantID, err := scope.Tenant(r.Context())
	if err != nil {
		return nil, err
	}
	params, err := listquery.ParseListParams(r.URL.Query(), &auditListQuery)
	if err != nil {
		return nil, err
	}
	f, err := filterOf(params)
	if err != nil {
		return nil, err
	}
	entries, total, err := m.repo.List(r.Context(), tenantID, f)
	if err != nil {
		return nil, err
	}
	items := make([]*EntryResponse, 0, len(entries))
	for i := range entries {
		items = append(items, newEntryResponse(&entries[i]))
	}
	return dto.NewPageResponse(items, total, params.Page, params.Size), nil
}

// filterOf turns the parsed query into a repository filter. An action with
// the ;like suffix matches anywhere; a bare one is used as a LIKE pattern.
func filterOf(p *listquery.ListParams) (*Filter, error) {
	f := &Filter{Limit: p.Size, Offset: (p.Page - 1) * p.Size}
	if v, ok := p.Filters["actor"]; ok {
		id, err := uuid.Parse(v.Value)
		if err != nil {
			return nil, badQuery("actor", "must be a user ID")
		}
		f.ActorID = &id
	}
	if v, ok := p.Filters["action"]; ok {
		f.Action = v.Value
		if v.Operator == repository.FilterOperatorLike {
			f.Action = "%" + v.Value + "%"
		}
	}
	for field, dst := range map[string]**time.Time{"from": &f.From, "to": &f.To} {
		v, ok := p.Filters[field]
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339, v.Value)
		if err != nil {
			return nil, badQuery(field, "must be an RFC 3339 time")
		}
		*dst = &t
	}
	return f, nil
}

// badQuery is the 400 for one query parameter.
func badQuery(field, msg string) error {
	return errorz.BadRequest().WithMessage(field+": "+msg).WithMeta(apierr.MetaFields, map[string]string{field: msg})
}

// newEntryResponse maps a stored entry to its API shape.
func newEntryResponse(e *Entry) *EntryResponse {
	out := &EntryResponse{
		ID: e.ID, At: e.At.UTC(), Action: e.Action, TargetType: e.TargetType, TargetID: e.TargetID,
		Before: e.Before, After: e.After, RequestID: e.RequestID,
	}
	if e.ActorID != nil {
		out.Actor = &ActorResponse{ID: e.ActorID.String()}
		if e.ActorName != nil {
			out.Actor.DisplayName = *e.ActorName
		}
	}
	if e.IP != nil {
		out.IP = *e.IP
	}
	return out
}

// swag resolves the annotation types through this file's imports, and nothing
// here returns a response value, so keep the package referenced.
var _ response.Success
