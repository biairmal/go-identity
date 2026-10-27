package app

import (
	"net/http"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// maybeAuthed sends a request with a bearer token, or with none when token is
// empty.
func (f *loginFixture) maybeAuthed(
	t *testing.T, method, path, token string, body any,
) testkit.Response[map[string]any] {
	t.Helper()
	if token != "" {
		return f.call(t, method, path, token, body)
	}
	return testkit.Do[map[string]any](t, f.srv, method, path, body, nil)
}

// googleRoutes are the Google sign-in routes, with what each is called with.
var googleRoutes = []struct {
	method, path string
	body         any
	authed       bool
}{
	{http.MethodGet, "/v1/auth/google/start?redirect_to=http://localhost:3000/auth/callback", nil, false},
	{http.MethodGet, "/v1/auth/google/callback?code=c&state=s", nil, false},
	{http.MethodGet, "/v1/auth/google/link/start?redirect_to=http://localhost:3000/auth/callback", nil, true},
	{http.MethodPost, "/v1/auth/exchange", map[string]any{"code": "c"}, false},
}

// TestGoogleDisabledIntegration answers 404 PROVIDER_DISABLED on every Google
// route while the provider is off, which is the default.
func TestGoogleDisabledIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	access, _ := f.signInTokens(t)
	for _, rt := range googleRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			token := ""
			if rt.authed {
				token = access
			}
			r := f.maybeAuthed(t, rt.method, rt.path, token, rt.body)
			wantReason(t, rt.path, &r, http.StatusNotFound, "PROVIDER_DISABLED")
		})
	}
}

// TestGoogleRefusalsIntegration covers what the enabled provider refuses
// before Google is ever contacted: a tampered or missing state, a
// redirect_to outside the allow-list, an unknown exchange code and an
// anonymous link.
func TestGoogleRefusalsIntegration(t *testing.T) {
	f := newLoginFixture(t, func(c *Config) {
		g := &c.Modules.Auth.Providers.Google
		g.Enabled, g.ClientID, g.ClientSecret = true, "client", "secret"
		g.IssuerURL = "http://127.0.0.1:1" // never reached by these requests
	})
	tests := []struct {
		name, method, path string
		body               any
		status             int
		reason             string
	}{
		{
			"tampered state", http.MethodGet, "/v1/auth/google/callback?code=c&state=forged", nil,
			http.StatusBadRequest, "OAUTH_STATE_INVALID",
		},
		{
			"missing state", http.MethodGet, "/v1/auth/google/callback?code=c", nil,
			http.StatusBadRequest, "OAUTH_STATE_INVALID",
		},
		{
			"redirect_to elsewhere", http.MethodGet, "/v1/auth/google/start?redirect_to=https://evil.example/cb", nil,
			http.StatusBadRequest, "",
		},
		{"no redirect_to", http.MethodGet, "/v1/auth/google/start", nil, http.StatusBadRequest, ""},
		{
			"unknown exchange code", http.MethodPost, "/v1/auth/exchange",
			map[string]any{"code": "nope"},
			http.StatusBadRequest, "TOKEN_INVALID",
		},
		{
			"link without a token", http.MethodGet,
			"/v1/auth/google/link/start?redirect_to=http://localhost:3000/cb", nil, http.StatusUnauthorized, "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := f.maybeAuthed(t, tt.method, tt.path, "", tt.body)
			if tt.reason != "" {
				wantReason(t, tt.name, &r, tt.status, tt.reason)
			} else if r.Status != tt.status {
				t.Errorf("%s = %d, want %d: %s", tt.path, r.Status, tt.status, r.Raw)
			}
		})
	}
}
