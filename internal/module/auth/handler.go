package auth

import (
	"net/http"

	"github.com/biairmal/go-sdk/lib/httpkit/response"

	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// Public endpoints below /v1.
const (
	authConfigPath   = "/auth/config"
	registerPath     = "/auth/register"
	verifyEmailPath  = "/auth/email/verify"
	resendVerifyPath = "/auth/email/resend"
)

// getAuthConfig answers GET /v1/auth/config. Configuration is fixed for the
// life of the process, so the response is built once in New.
func (m *Module) getAuthConfig(*http.Request) (any, error) {
	return m.authConfig, nil
}

// register answers POST /v1/auth/register with 202 and the same body whether
// or not the address already has an account.
func (m *Module) register(r *http.Request) (any, error) {
	var in RegisterRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
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
	var in ResendVerificationRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	if err := m.registrations.ResendVerification(r.Context(), in.Email); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusAccepted, Data: accepted}, nil
}
