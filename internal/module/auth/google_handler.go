package auth

import (
	"net/http"

	// swag resolves response.BaseResponse in the annotations below through
	// this file's imports.
	_ "github.com/biairmal/go-sdk/lib/httpkit/response"

	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// Google sign-in routes below /v1. link/start is authenticated; the others
// are public.
const (
	googleStartPath     = "/auth/google/start"
	googleCallbackPath  = "/auth/google/callback"
	googleLinkStartPath = "/auth/google/link/start"
	exchangePath        = "/auth/exchange"
)

// redirect adapts a handler that answers with a URL: success is a 302 to it,
// an error the usual JSON envelope through httpx.Handle.
func redirect(fn func(r *http.Request) (string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target, err := fn(r)
		if err != nil {
			httpx.Handle(func(*http.Request) (any, error) { return nil, err })(w, r)
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
	}
}

// googleStart answers GET /v1/auth/google/start with a 302 to Google.
//
//	@Summary     Begin Google sign-in
//	@Description Redirects to Google with state, nonce and a PKCE challenge. redirect_to must be allow-listed.
//	@Tags        auth
//	@Produce     json
//	@Param       redirect_to query string true  "Frontend URL to return to, from modules.auth.frontend_urls"
//	@Param       tenant      query string false "Tenant slug (multi mode)"
//	@Success     302 "Redirect to Google"
//	@Failure     400 {object} response.BaseResponse[any] "redirect_to not allowed"
//	@Failure     404 {object} response.BaseResponse[any] "PROVIDER_DISABLED"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/google/start [get]
func (m *Module) googleStart(r *http.Request) (string, error) {
	q := r.URL.Query()
	return m.google.Start(r.Context(), q.Get("redirect_to"), q.Get("tenant"), nil)
}

// googleLinkStart answers GET /v1/auth/google/link/start with a 302 to
// Google; the callback links the Google account to the caller.
//
//	@Summary     Link Google
//	@Description Same as Google start, but the callback links Google to the signed-in user.
//	@Tags        me
//	@Produce     json
//	@Param       redirect_to query string true "Frontend URL to return to, from modules.auth.frontend_urls"
//	@Security    BearerAuth
//	@Success     302 "Redirect to Google"
//	@Failure     400 {object} response.BaseResponse[any] "redirect_to not allowed"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     404 {object} response.BaseResponse[any] "PROVIDER_DISABLED"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/google/link/start [get]
func (m *Module) googleLinkStart(r *http.Request) (string, error) {
	return m.google.LinkStart(r.Context(), r.URL.Query().Get("redirect_to"))
}

// googleCallback answers GET /v1/auth/google/callback, where Google sends the
// browser back.
//
//	@Summary     Google callback
//	@Description Redirects to redirect_to with code=<exchange code>, linked=1 or error=<reason>; never tokens.
//	@Tags        auth
//	@Produce     json
//	@Param       code  query string false "Authorization code from Google"
//	@Param       state query string true  "State from the start redirect"
//	@Success     302 "Redirect to the frontend"
//	@Failure     400 {object} response.BaseResponse[any] "OAUTH_STATE_INVALID"
//	@Failure     404 {object} response.BaseResponse[any] "PROVIDER_DISABLED"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/google/callback [get]
func (m *Module) googleCallback(r *http.Request) (string, error) {
	return m.google.Callback(r.Context(), r.URL.Query())
}

// exchange answers POST /v1/auth/exchange with a token response.
//
//	@Summary     Exchange a Google callback code
//	@Description Trades the single-use, 60-second code from the Google callback for tokens.
//	@Tags        auth
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.ExchangeRequest true "Request body"
//	@Success     200 {object} response.BaseResponse[auth.TokenResponse]
//	@Failure     400 {object} response.BaseResponse[any] "TOKEN_INVALID or validation error"
//	@Failure     403 {object} response.BaseResponse[any] "ACCOUNT_DISABLED or TENANT_SUSPENDED"
//	@Failure     404 {object} response.BaseResponse[any] "PROVIDER_DISABLED"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/exchange [post]
func (m *Module) exchange(r *http.Request) (any, error) {
	var in ExchangeRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	return m.google.Exchange(r.Context(), &in, device(r))
}
