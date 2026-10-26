package auth

import "github.com/google/uuid"

// AuthConfigResponse is what the sign-in screen needs to render itself: the
// enabled providers, whether self sign-up is open and the tenancy mode. It is
// built from configuration only and carries nothing secret.
//
//nolint:revive // named for its resource: the package will hold other response DTOs
type AuthConfigResponse struct {
	Providers    ProvidersResponse `json:"providers"`
	Registration bool              `json:"registration"`
	Tenancy      string            `json:"tenancy"`
}

// ProvidersResponse reports which sign-in providers are enabled.
type ProvidersResponse struct {
	Password bool `json:"password"`
	Google   bool `json:"google"`
}

// newAuthConfigResponse reads the public part of the configuration. Client
// IDs and secrets stay behind: the frontend only learns what is switched on.
func newAuthConfigResponse(cfg *Config, tenancy string) AuthConfigResponse {
	return AuthConfigResponse{
		Providers: ProvidersResponse{
			Password: cfg.Providers.Password.Enabled,
			Google:   cfg.Providers.Google.Enabled,
		},
		Registration: cfg.Registration.Enabled,
		Tenancy:      tenancy,
	}
}

// RegisterRequest is the body of POST /v1/auth/register.
type RegisterRequest struct {
	Email       string `json:"email" validate:"required,email,max=254"`
	Password    string `json:"password" validate:"required"`
	DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
	// Tenant is the tenant slug; required in multi mode, ignored in single.
	Tenant string `json:"tenant" validate:"omitempty,max=63"`
}

// VerifyEmailRequest is the body of POST /v1/auth/email/verify.
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// EmailRequest is the body of POST /v1/auth/email/resend and
// /v1/auth/password/forgot.
type EmailRequest struct {
	Email string `json:"email"`
}

// AcceptedResponse is the body of every 202 that must not reveal whether an
// address has an account: it is the same value on every path.
type AcceptedResponse struct {
	Status string `json:"status"`
}

// accepted is the one AcceptedResponse the sign-up flows return.
var accepted = AcceptedResponse{Status: "accepted"}

// ResetPasswordRequest is the body of POST /v1/auth/password/reset.
type ResetPasswordRequest struct {
	Token    string `json:"token" validate:"required,max=256"`
	Password string `json:"password" validate:"required"`
}

// LoginRequest is the body of POST /v1/auth/login.
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email,max=254"`
	Password string `json:"password" validate:"required,max=1024"`
	// Tenant is the tenant slug, used in multi mode.
	Tenant string `json:"tenant" validate:"omitempty,max=63"`
}

// RefreshRequest is the body of POST /v1/auth/refresh, /logout and
// /logout-all. The token travels in the JSON body only; identity sets no
// cookies (TRD 10).
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required,max=256"`
}

// SwitchTenantRequest is the body of POST /v1/auth/switch-tenant.
type SwitchTenantRequest struct {
	TenantID uuid.UUID `json:"tenant_id" validate:"required"`
}

// TokenResponse is the payload of every endpoint that signs a user in. A
// restricted token (forced password change) carries no refresh token.
type TokenResponse struct {
	AccessToken        string                `json:"access_token"`
	TokenType          string                `json:"token_type"`
	ExpiresIn          int                   `json:"expires_in"`
	RefreshToken       string                `json:"refresh_token,omitempty"`
	RefreshExpiresIn   int                   `json:"refresh_expires_in,omitempty"`
	User               UserSummaryResponse   `json:"user"`
	Tenant             TenantSummaryResponse `json:"tenant"`
	MustChangePassword bool                  `json:"must_change_password"`
}

// UserSummaryResponse is the signed-in user in a token response.
type UserSummaryResponse struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
}

// TenantSummaryResponse is a tenant in a token response or a tenant choice.
type TenantSummaryResponse struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// TenantChoiceResponse answers a multi-mode sign-in that named no tenant when
// the user belongs to several: the client repeats the call with one of them.
type TenantChoiceResponse struct {
	TenantRequired bool                    `json:"tenant_required"`
	Tenants        []TenantSummaryResponse `json:"tenants"`
}

// tokenTypeBearer is the token_type of every access token.
const tokenTypeBearer = "Bearer"

// MeResponse is the signed-in user in GET and PATCH /v1/me.
type MeResponse struct {
	ID            string                `json:"id"`
	Email         string                `json:"email"`
	DisplayName   string                `json:"display_name"`
	EmailVerified bool                  `json:"email_verified"`
	IsSuperAdmin  bool                  `json:"is_super_admin"`
	Tenant        TenantSummaryResponse `json:"tenant"`
	Roles         []string              `json:"roles"`
	Permissions   []string              `json:"permissions"`
	// Providers are the sign-in methods the account has: a password, a
	// linked Google identity.
	Providers ProvidersResponse `json:"providers"`
}

// UpdateMeRequest is the body of PATCH /v1/me.
type UpdateMeRequest struct {
	DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
}

// ChangePasswordRequest is the body of POST /v1/me/password. CurrentPassword
// is omitted with the restricted token or when the account has no password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"max=1024"`
	NewPassword     string `json:"new_password" validate:"required"`
}

// TenantResponse is a tenant in GET /v1/me/tenants, with its status.
type TenantResponse struct {
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// InviteRequest is the body of POST /v1/admin/users/invite.
type InviteRequest struct {
	Email   string      `json:"email" validate:"required,email,max=254"`
	RoleIDs []uuid.UUID `json:"role_ids" validate:"required"`
	// DisplayName names a new account; an existing one keeps its own.
	DisplayName string `json:"display_name" validate:"max=100"`
}

// InviteResponse is the 202 of POST /v1/admin/users/invite.
type InviteResponse struct {
	Status string `json:"status"`
}

// InvitePreviewResponse is GET /v1/auth/invite/{token}.
type InvitePreviewResponse struct {
	Tenant      InviteTenantResponse `json:"tenant"`
	EmailMasked string               `json:"email_masked"`
	HasPassword bool                 `json:"has_password"`
}

// InviteTenantResponse names the tenant an invite is for.
type InviteTenantResponse struct {
	Name string `json:"name"`
}

// AcceptInviteRequest is the body of POST /v1/auth/invite/accept.
type AcceptInviteRequest struct {
	Token string `json:"token" validate:"required,max=256"`
	// Password is required only when the account has none; otherwise it is
	// ignored, so an invite never changes an existing password.
	Password    string `json:"password"`
	DisplayName string `json:"display_name" validate:"max=100"`
}
