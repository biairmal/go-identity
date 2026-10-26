package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/biairmal/go-sdk/lib/httpkit/response"

	"github.com/biairmal/go-identity/internal/platform/httpx"
	"github.com/biairmal/go-identity/internal/platform/requestip"
)

// Public endpoints below /v1.
const (
	authConfigPath     = "/auth/config"
	loginPath          = "/auth/login"
	registerPath       = "/auth/register"
	verifyEmailPath    = "/auth/email/verify"
	resendVerifyPath   = "/auth/email/resend"
	refreshPath        = "/auth/refresh"
	logoutPath         = "/auth/logout"
	logoutAllPath      = "/auth/logout-all"
	forgotPasswordPath = "/auth/password/forgot"
	resetPasswordPath  = "/auth/password/reset"
)

// switchTenantPath is authenticated (not public): the token identifies the
// caller, and the body names the tenant to move to.
const switchTenantPath = "/auth/switch-tenant"

// getAuthConfig answers GET /v1/auth/config. Configuration is fixed for the
// life of the process, so the response is built once in New.
//
//	@Summary     Sign-in settings
//	@Description Enabled providers, registration and tenancy mode for the sign-in screen.
//	@Tags        auth
//	@Produce     json
//	@Success     200 {object} response.BaseResponse[auth.AuthConfigResponse]
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/config [get]
func (m *Module) getAuthConfig(*http.Request) (any, error) {
	return m.authConfig, nil
}

// register answers POST /v1/auth/register with 202 and the same body whether
// or not the address already has an account.
//
//	@Summary     Register
//	@Description Creates an account. Answers 202 whether or not the address already has one.
//	@Tags        auth
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.RegisterRequest true "Request body"
//	@Success     202 {object} response.BaseResponse[auth.AcceptedResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or validation error"
//	@Failure     429 {object} response.BaseResponse[any] "Rate limited"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/register [post]
func (m *Module) register(r *http.Request) (any, error) {
	if err := m.limit(r, limitRegisterIP, requestip.Get(r.Context())); err != nil {
		return nil, err
	}
	var in RegisterRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	if err := m.limitEmail(r, limitRegisterMail, in.Email); err != nil {
		return nil, err
	}
	if err := m.registrations.Register(r.Context(), &in); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusAccepted, Data: accepted}, nil
}

// verifyEmail answers POST /v1/auth/email/verify with 204.
//
//	@Summary     Verify email
//	@Description Confirms an email address with the token from the verification mail.
//	@Tags        auth
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.VerifyEmailRequest true "Request body"
//	@Success     204
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or validation error"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/email/verify [post]
func (m *Module) verifyEmail(r *http.Request) (any, error) {
	var in VerifyEmailRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	if err := m.registrations.VerifyEmail(r.Context(), in.Token); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusNoContent}, nil
}

// resendVerification answers POST /v1/auth/email/resend with 202 whatever the
// address, so it cannot be used to find accounts.
//
//	@Summary     Resend verification
//	@Description Sends a new verification mail. Answers 202 whatever the address.
//	@Tags        auth
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.EmailRequest true "Request body"
//	@Success     202 {object} response.BaseResponse[auth.AcceptedResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or validation error"
//	@Failure     429 {object} response.BaseResponse[any] "Rate limited"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/email/resend [post]
func (m *Module) resendVerification(r *http.Request) (any, error) {
	return m.acceptEmail(r, limitResendIP, limitResendMail, m.registrations.ResendVerification)
}

// login answers POST /v1/auth/login with a token response, or with the
// tenants to choose from in multi mode.
//
//	@Summary     Log in
//	@Description Signs in with email and password. Multi mode without a tenant may answer a tenant choice.
//	@Tags        auth
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.LoginRequest true "Request body"
//	@Success     200 {object} response.BaseResponse[auth.TokenResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or validation error"
//	@Failure     401 {object} response.BaseResponse[any] "Invalid credentials"
//	@Failure     403 {object} response.BaseResponse[any] "Account locked, disabled or unverified"
//	@Failure     429 {object} response.BaseResponse[any] "Rate limited"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/login [post]
func (m *Module) login(r *http.Request) (any, error) {
	var in LoginRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	return m.logins.Login(r.Context(), &in, device(r))
}

// switchTenant answers POST /v1/auth/switch-tenant with a token response for
// another of the caller's tenants, in a new refresh family.
//
//	@Summary     Switch tenant
//	@Description Trades the caller's token for one in another of their tenants. Multi mode only.
//	@Tags        auth
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.SwitchTenantRequest true "Request body"
//	@Security    BearerAuth
//	@Success     200 {object} response.BaseResponse[auth.TokenResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "NOT_A_MEMBER, ACCOUNT_DISABLED or TENANT_SUSPENDED"
//	@Failure     404 {object} response.BaseResponse[any] "Single mode"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/switch-tenant [post]
func (m *Module) switchTenant(r *http.Request) (any, error) {
	var in SwitchTenantRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	return m.switches.Switch(r.Context(), &in, device(r))
}

// refresh answers POST /v1/auth/refresh with a new token response.
//
//	@Summary     Refresh tokens
//	@Description Exchanges a refresh token for a new token pair (rotation).
//	@Tags        auth
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.RefreshRequest true "Request body"
//	@Success     200 {object} response.BaseResponse[auth.TokenResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or validation error"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     429 {object} response.BaseResponse[any] "Rate limited"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/refresh [post]
func (m *Module) refresh(r *http.Request) (any, error) {
	var in RefreshRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	return m.refreshes.Refresh(r.Context(), &in, device(r))
}

// logout answers POST /v1/auth/logout with 204, also for a token that no
// longer works.
//
//	@Summary     Log out
//	@Description Revokes the session of the refresh token. Answers 204 also for a token that no longer works.
//	@Tags        auth
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.RefreshRequest true "Request body"
//	@Success     204
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or validation error"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/logout [post]
func (m *Module) logout(r *http.Request) (any, error) {
	var in RefreshRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	if err := m.refreshes.Logout(r.Context(), &in); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusNoContent}, nil
}

// logoutAll answers POST /v1/auth/logout-all with 204, also for a token that
// no longer works.
//
//	@Summary     Log out everywhere
//	@Description Revokes every session of the refresh token's user. Answers 204 also for a token that no longer works.
//	@Tags        auth
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.RefreshRequest true "Request body"
//	@Success     204
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or validation error"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/logout-all [post]
func (m *Module) logoutAll(r *http.Request) (any, error) {
	var in RefreshRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	if err := m.refreshes.LogoutAll(r.Context(), &in); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusNoContent}, nil
}

// device is where a request came from, stored with the session it creates.
func device(r *http.Request) Device {
	return Device{UserAgent: truncateUserAgent(r.UserAgent()), IP: requestip.Get(r.Context())}
}

// limit checks one rate-limit key; an empty value (no client IP) or no
// limiter skips it.
func (m *Module) limit(r *http.Request, prefix, value string) error {
	if m.limiter == nil || value == "" {
		return nil
	}
	return m.limiter.Check(r.Context(), prefix+value)
}

// limitEmail limits by the address's blind-index key, so the plain address
// never reaches the limiter. A blank address is left to validation.
func (m *Module) limitEmail(r *http.Request, prefix, email string) error {
	if m.registrations.users == nil || strings.TrimSpace(email) == "" {
		return nil
	}
	return m.limit(r, prefix, m.registrations.users.EmailKey(email))
}

// forgotPassword answers POST /v1/auth/password/forgot with 202 whatever the
// address, so it cannot be used to find accounts.
//
//	@Summary     Forgot password
//	@Description Sends a reset mail. Answers 202 whatever the address.
//	@Tags        auth
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.EmailRequest true "Request body"
//	@Success     202 {object} response.BaseResponse[auth.AcceptedResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or validation error"
//	@Failure     429 {object} response.BaseResponse[any] "Rate limited"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/password/forgot [post]
func (m *Module) forgotPassword(r *http.Request) (any, error) {
	return m.acceptEmail(r, limitForgotIP, limitForgotEmail, m.resets.Forgot)
}

// acceptEmail runs an email-only flow behind its IP and address rate limits
// and answers 202 with the shared body, whatever fn found.
func (m *Module) acceptEmail(
	r *http.Request, ipPrefix, emailPrefix string, fn func(ctx context.Context, email string) error,
) (any, error) {
	if err := m.limit(r, ipPrefix, requestip.Get(r.Context())); err != nil {
		return nil, err
	}
	var in EmailRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	if err := m.limitEmail(r, emailPrefix, in.Email); err != nil {
		return nil, err
	}
	if err := fn(r.Context(), in.Email); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusAccepted, Data: accepted}, nil
}

// resetPassword answers POST /v1/auth/password/reset with 204.
//
//	@Summary     Reset password
//	@Description Sets a new password with the token from the reset mail.
//	@Tags        auth
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.ResetPasswordRequest true "Request body"
//	@Success     204
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or validation error"
//	@Failure     429 {object} response.BaseResponse[any] "Rate limited"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/password/reset [post]
func (m *Module) resetPassword(r *http.Request) (any, error) {
	if err := m.limit(r, limitResetIP, requestip.Get(r.Context())); err != nil {
		return nil, err
	}
	var in ResetPasswordRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	if err := m.resets.Reset(r.Context(), &in); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusNoContent}, nil
}
