package auth

import (
	"context"
	"time"

	"github.com/biairmal/go-identity/internal/module/auth/token"
	"github.com/biairmal/go-identity/internal/platform/clock"
)

// tokenIssuer builds the token response (TRD 9.3) every sign-in path returns:
// login, refresh, and later exchange and switch-tenant. Roles and permissions
// are read from the database each time, so a role change shows in the next
// token issued.
type tokenIssuer struct {
	cfg    *Config
	roles  Roles
	tokens *token.Builder
	clock  clock.Clock
}

// session signs a full access token with the user's current roles in the
// tenant and returns it with the refresh token s.
func (t *tokenIssuer) session(
	ctx context.Context, a *Account, tenant *TenantInfo, s *IssuedSession,
) (*TokenResponse, error) {
	sub := &token.Subject{UserID: a.ID, SuperAdmin: a.IsSuperAdmin, SessionID: s.FamilyID}
	var err error
	if sub.Roles, err = t.roles.RoleNames(ctx, tenant.ID, a.ID); err != nil {
		return nil, err
	}
	if t.cfg.Token.Claims == ClaimsRolesAndPermissions {
		if sub.Permissions, err = t.roles.Permissions(ctx, tenant.ID, a.ID); err != nil {
			return nil, err
		}
	}
	signed, expiry, err := t.tokens.Access(ctx, sub, tenant.ID)
	if err != nil {
		return nil, err
	}
	resp := t.response(a, tenant, signed, expiry)
	resp.RefreshToken = s.Raw
	resp.RefreshExpiresIn = seconds(s.ExpiresAt.Sub(t.clock.Now()))
	return resp, nil
}

// restricted is the token response of a forced password change: a
// short-lived token scoped to the password change, no refresh token.
func (t *tokenIssuer) restricted(ctx context.Context, a *Account, tenant *TenantInfo) (*TokenResponse, error) {
	signed, expiry, err := t.tokens.Access(ctx, &token.Subject{
		UserID: a.ID, Scope: token.ScopePasswordChange, TTL: restrictedTokenTTL,
	}, tenant.ID)
	if err != nil {
		return nil, err
	}
	return t.response(a, tenant, signed, expiry), nil
}

// response fills the fields every token response shares.
func (t *tokenIssuer) response(a *Account, tenant *TenantInfo, accessToken string, expiry time.Time) *TokenResponse {
	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   tokenTypeBearer,
		ExpiresIn:   seconds(expiry.Sub(t.clock.Now())),
		User: UserSummaryResponse{
			ID: a.ID.String(), DisplayName: a.DisplayName, Email: a.Email,
		},
		Tenant:             tenantSummary(tenant),
		MustChangePassword: a.MustChangePassword,
	}
}

// tenantSummary is the response view of a tenant.
func tenantSummary(t *TenantInfo) TenantSummaryResponse {
	return TenantSummaryResponse{ID: t.ID.String(), Slug: t.Slug, Name: t.Name}
}

// seconds rounds a duration to whole seconds for expires_in fields.
func seconds(d time.Duration) int {
	return int(d.Round(time.Second) / time.Second)
}
