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

// getAuthConfig answers GET /v1/auth/config. Configuration is fixed for the
// life of the process, so the response is built once in New.
func (m *Module) getAuthConfig(*http.Request) (any, error) {
	return m.authConfig, nil
}

// register answers POST /v1/auth/register with 202 and the same body whether
// or not the address already has an account.
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
func (m *Module) resendVerification(r *http.Request) (any, error) {
	return m.acceptEmail(r, limitResendIP, limitResendMail, m.registrations.ResendVerification)
}

// login answers POST /v1/auth/login with a token response, or with the
// tenants to choose from in multi mode.
func (m *Module) login(r *http.Request) (any, error) {
	var in LoginRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	return m.logins.Login(r.Context(), &in, device(r))
}

// refresh answers POST /v1/auth/refresh with a new token response.
func (m *Module) refresh(r *http.Request) (any, error) {
	var in RefreshRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	return m.refreshes.Refresh(r.Context(), &in, device(r))
}

// logout answers POST /v1/auth/logout with 204, also for a token that no
// longer works.
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
