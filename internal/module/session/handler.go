package session

import (
	"net/http"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit/response"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/scope"
)

// SessionResponse is one device in GET /v1/me/sessions. ID is the family ID,
// the value DELETE /v1/me/sessions/{id} takes.
//
//nolint:revive // named for its resource: the package will hold other response DTOs
type SessionResponse struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	UserAgent  string    `json:"user_agent,omitempty"`
	IP         string    `json:"ip,omitempty"`
	// Current marks the session the caller's own token belongs to.
	Current bool `json:"current"`
}

// listMine answers GET /v1/me/sessions with the caller's live sessions.
//
//	@Summary     List my sessions
//	@Description Live sessions (devices) of the signed-in user.
//	@Tags        me
//	@Produce     json
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[[]session.SessionResponse]
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/me/sessions [get]
func (m *Module) listMine(r *http.Request) (any, error) {
	userID, err := scope.User(r.Context())
	if err != nil {
		return nil, err
	}
	sessions, err := m.svc.List(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	current := scope.Session(r.Context())
	out := make([]SessionResponse, 0, len(sessions))
	for _, s := range sessions {
		resp := SessionResponse{
			ID: s.FamilyID.String(), CreatedAt: s.CreatedAt.UTC(), LastUsedAt: s.LastUsedAt.UTC(),
			UserAgent: s.UserAgent, Current: s.FamilyID == current,
		}
		if s.IP != nil {
			resp.IP = *s.IP
		}
		out = append(out, resp)
	}
	return out, nil
}

// revokeMine answers DELETE /v1/me/sessions/{id} with 204: that device can no
// longer refresh. Another user's session, a dead one or a malformed ID is 404.
//
//	@Summary     Sign out a device
//	@Description Revokes one session. Another user's, a dead or a malformed ID is 404.
//	@Tags        me
//	@Produce     json
//	@Param       id path string true "Session (family) ID"
//	@Security    BearerAuth
//	@Success     204
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     404 {object} response.BaseResponse[any] "Session not found"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/me/sessions/{id} [delete]
func (m *Module) revokeMine(r *http.Request) (any, error) {
	ctx := r.Context()
	userID, err := scope.User(ctx)
	if err != nil {
		return nil, err
	}
	tenantID, err := scope.Tenant(ctx)
	if err != nil {
		return nil, err
	}
	familyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return nil, errorz.NotFound().WithMessage("session: not found")
	}
	if err := m.svc.SignOutDevice(ctx, userID, tenantID, familyID); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusNoContent}, nil
}

// revokeForUser answers POST /v1/admin/users/{id}/revoke-sessions with 204.
//
//	@Summary     Revoke a user's sessions
//	@Description Signs a member out of every device in this tenant.
//	@Tags        admin
//	@Produce     json
//	@Param       id path string true "User ID"
//	@Security    BearerAuth
//	@Success     204
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "Missing users:manage"
//	@Failure     404 {object} response.BaseResponse[any] "Not a member of the tenant"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/users/{id}/revoke-sessions [post]
func (m *Module) revokeForUser(r *http.Request) (any, error) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return nil, errorz.NotFound().WithMessage("session: user not found")
	}
	if err := m.svc.RevokeForMember(r.Context(), userID); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusNoContent}, nil
}
