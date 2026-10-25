package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit/response"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/module/auth/token"
	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/httpx"
	"github.com/biairmal/go-identity/internal/platform/scope"
)

// Routes below /v1/me that auth owns; the session list belongs to session.
const (
	mePath           = "/"
	mePasswordPath   = "/password"
	meTenantsPath    = "/tenants"
	meGoogleIdentity = "/identities/google"
)

// Tenant status values in GET /v1/me/tenants.
const (
	tenantActive    = "active"
	tenantSuspended = "suspended"
)

// Profiles serves the signed-in user's own account (TRD 9.5). The target is
// always the caller, taken from the token: no extra permission is needed.
type Profiles struct {
	cfg        *Config
	tx         txFunc
	v          validator.Validator
	users      Users
	tenants    Tenants
	roles      Roles
	sessions   Sessions
	audit      AuditWriter
	identities *IdentityRepository
	issue      *tokenIssuer
	log        logger.Logger
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

// Get returns the caller with their tenant, roles, effective permissions and
// sign-in methods.
func (s *Profiles) Get(ctx context.Context) (*MeResponse, error) {
	userID, tenantID, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	a, err := s.users.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	t, err := s.tenants.Tenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	roles, err := s.roles.RoleNames(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	perms, err := s.roles.Permissions(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	hasPassword, err := s.hasPassword(ctx, userID)
	if err != nil {
		return nil, err
	}
	google, err := s.identities.Linked(ctx, userID, ProviderGoogle)
	if err != nil {
		return nil, err
	}
	return &MeResponse{
		ID: a.ID.String(), Email: a.Email, DisplayName: a.DisplayName,
		EmailVerified: a.EmailVerified, IsSuperAdmin: a.IsSuperAdmin,
		Tenant: tenantSummary(t), Roles: nonNil(roles), Permissions: nonNil(perms),
		Providers: ProvidersResponse{Password: hasPassword, Google: google},
	}, nil
}

// Update renames the caller and returns the updated view.
func (s *Profiles) Update(ctx context.Context, in *UpdateMeRequest) (*MeResponse, error) {
	userID, err := scope.User(ctx)
	if err != nil {
		return nil, err
	}
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	if err := s.users.SetDisplayName(ctx, userID, in.DisplayName); err != nil {
		return nil, err
	}
	return s.Get(ctx)
}

// ChangePassword sets a new password and returns a fresh session: every
// family of the user is revoked, the current one included, and a new one
// starts, so a stolen password or token cannot keep a session alive. The
// current password is required unless the caller holds the restricted
// password-change token (it was proven at sign-in) or the account has no
// password yet. Choosing a password clears a forced change.
func (s *Profiles) ChangePassword(ctx context.Context, in *ChangePasswordRequest, d Device) (*TokenResponse, error) {
	if !s.cfg.Providers.Password.Enabled {
		return nil, apierr.New(apierr.ReasonProviderDisabled)
	}
	userID, tenantID, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	a, err := s.users.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := checkStatus(a); err != nil {
		return nil, err
	}
	if err := s.checkCurrent(ctx, userID, in.CurrentPassword, restrictedToken(ctx)); err != nil {
		return nil, err
	}
	if err := checkPassword("new_password", in.NewPassword, s.cfg.Providers.Password.MinLength); err != nil {
		return nil, err
	}
	hash, err := password.Hash(in.NewPassword)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: hash password")
	}
	t, err := s.tenants.Tenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var resp *TokenResponse
	err = s.tx(ctx, func(ctx context.Context) error {
		if err := s.users.SetPassword(ctx, userID, hash); err != nil {
			return err
		}
		if err := s.sessions.RevokeAllForUser(ctx, userID); err != nil {
			return err
		}
		issued, err := s.sessions.Issue(ctx, userID, tenantID, d)
		if err != nil {
			return err
		}
		a.MustChangePassword = false
		if resp, err = s.issue.session(ctx, a, t, issued); err != nil {
			return err
		}
		return s.audit.Write(ctx, &AuditEvent{
			TenantID: tenantID, ActorID: userID, Action: ActionPasswordChange,
			TargetType: TargetUser, TargetID: userID.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	s.log.InfoWithContext(ctx, "password changed", logger.F("user_id", userID.String()))
	return resp, nil
}

// checkCurrent verifies the current password when one is required. A wrong
// one is INVALID_CREDENTIALS, like a failed sign-in.
func (s *Profiles) checkCurrent(ctx context.Context, userID uuid.UUID, current string, restricted bool) error {
	if restricted {
		return nil
	}
	hash, err := s.users.PasswordHash(ctx, userID)
	if errors.Is(err, errorz.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if current == "" {
		return errorz.BadRequest().WithMessage("current_password: required").
			WithMeta(apierr.MetaFields, map[string]string{"current_password": "required"})
	}
	match, _, err := password.Verify(current, hash)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: verify password")
	}
	if !match {
		return apierr.New(apierr.ReasonInvalidCredentials)
	}
	return nil
}

// restrictedToken reports whether the request's token is the password-change
// token issued while a password change is forced.
func restrictedToken(ctx context.Context) bool {
	claims, ok := sdkauth.ClaimsFromContext(ctx)
	if !ok {
		return false
	}
	v, _ := claims.Get(token.ClaimScope)
	return v == token.ScopePasswordChange
}

// Tenants lists the tenants the caller is an active member of, with each
// tenant's own status.
func (s *Profiles) Tenants(ctx context.Context) ([]TenantResponse, error) {
	userID, err := scope.User(ctx)
	if err != nil {
		return nil, err
	}
	all, err := s.tenants.Memberships(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]TenantResponse, 0, len(all))
	for _, m := range all {
		if !m.Active {
			continue
		}
		status := tenantActive
		if !m.Tenant.Active {
			status = tenantSuspended
		}
		out = append(out, TenantResponse{
			ID: m.Tenant.ID.String(), Slug: m.Tenant.Slug, Name: m.Tenant.Name, Status: status,
		})
	}
	return out, nil
}

// UnlinkGoogle removes the caller's Google identity, unless it is their only
// way to sign in (LAST_SIGN_IN_METHOD). Nothing linked is a no-op.
func (s *Profiles) UnlinkGoogle(ctx context.Context) error {
	userID, tenantID, err := caller(ctx)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(ctx context.Context) error {
		linked, err := s.identities.Linked(ctx, userID, ProviderGoogle)
		if err != nil || !linked {
			return err
		}
		hasPassword, err := s.hasPassword(ctx, userID)
		if err != nil {
			return err
		}
		if !hasPassword {
			return apierr.New(apierr.ReasonLastSignInMethod)
		}
		if err := s.identities.Unlink(ctx, userID, ProviderGoogle); err != nil {
			return err
		}
		return s.audit.Write(ctx, &AuditEvent{
			TenantID: tenantID, ActorID: userID, Action: ActionIdentityUnlink,
			TargetType: TargetUser, TargetID: userID.String(),
			After: map[string]any{"provider": ProviderGoogle},
		})
	})
}

// hasPassword reports whether the account has a password.
func (s *Profiles) hasPassword(ctx context.Context, userID uuid.UUID) (bool, error) {
	_, err := s.users.PasswordHash(ctx, userID)
	if errors.Is(err, errorz.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// nonNil turns a nil list into an empty one, so the JSON is [] not null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// getMe answers GET /v1/me.
//
//	@Summary     Get my profile
//	@Description The signed-in user with tenant, roles, permissions and sign-in methods.
//	@Tags        me
//	@Produce     json
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[auth.MeResponse]
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/me [get]
func (m *Module) getMe(r *http.Request) (any, error) {
	return m.profiles.Get(r.Context())
}

// updateMe answers PATCH /v1/me.
//
//	@Summary     Update my profile
//	@Description Renames the signed-in user.
//	@Tags        me
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.UpdateMeRequest true "Request body"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[auth.MeResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or validation error"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/me [patch]
func (m *Module) updateMe(r *http.Request) (any, error) {
	var in UpdateMeRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	return m.profiles.Update(r.Context(), &in)
}

// changePassword answers POST /v1/me/password with a fresh token response.
//
//	@Summary     Change my password
//	@Description Sets a new password, revokes all sessions and returns a fresh token pair.
//	@Tags        me
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.ChangePasswordRequest true "Request body"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[auth.TokenResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or validation error"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/me/password [post]
func (m *Module) changePassword(r *http.Request) (any, error) {
	var in ChangePasswordRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	return m.profiles.ChangePassword(r.Context(), &in, device(r))
}

// myTenants answers GET /v1/me/tenants.
//
//	@Summary     List my tenants
//	@Description Tenants the signed-in user is an active member of.
//	@Tags        me
//	@Produce     json
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[[]auth.TenantResponse]
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/me/tenants [get]
func (m *Module) myTenants(r *http.Request) (any, error) {
	return m.profiles.Tenants(r.Context())
}

// unlinkGoogle answers DELETE /v1/me/identities/google with 204.
//
//	@Summary     Unlink Google
//	@Description Removes the Google identity unless it is the only way to sign in.
//	@Tags        me
//	@Produce     json
//	@Security    BearerAuth
//	@Success     204
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     409 {object} response.BaseResponse[any] "Last sign-in method"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/me/identities/google [delete]
func (m *Module) unlinkGoogle(r *http.Request) (any, error) {
	if err := m.profiles.UnlinkGoogle(r.Context()); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusNoContent}, nil
}
