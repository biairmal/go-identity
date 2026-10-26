package app

import (
	"net/http"
	"testing"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// TestRestrictScopedTokens lets a scoped token through only to the routes its
// scope allows, answers PASSWORD_CHANGE_REQUIRED for the password-change
// scope and a plain 403 for any other scope, and leaves unscoped and
// unauthenticated requests alone.
func TestRestrictScopedTokens(t *testing.T) {
	allowed := map[string][]scopedRoute{
		"password_change": {{http.MethodPost, "/v1/me/password"}},
	}
	tests := []struct {
		name         string
		claims       map[string]any // nil = no claims in the context
		method, path string
		status       int
		reason       string
	}{
		{"no claims", nil, http.MethodGet, "/v1/me", http.StatusNoContent, ""},
		{"full token", map[string]any{"sub": "u"}, http.MethodGet, "/v1/me", http.StatusNoContent, ""},
		{
			"password change token on another route",
			map[string]any{"sub": "u", "scope": "password_change"},
			http.MethodGet, "/v1/me", http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED",
		},
		{
			"password change token on the allowed route",
			map[string]any{"sub": "u", "scope": "password_change"},
			http.MethodPost, "/v1/me/password", http.StatusNoContent, "",
		},
		{
			"password change token, allowed path but wrong method",
			map[string]any{"sub": "u", "scope": "password_change"},
			http.MethodGet, "/v1/me/password", http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED",
		},
		{
			"other scope",
			map[string]any{"sub": "svc", "scope": "internal"},
			http.MethodGet, "/v1/admin/users", http.StatusForbidden, "",
		},
		{
			"other scope on the password route",
			map[string]any{"sub": "svc", "scope": "internal"},
			http.MethodPost, "/v1/me/password", http.StatusForbidden, "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
			h := restrictScopedTokens(allowed)(next)
			withClaims := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.claims != nil {
					r = r.WithContext(sdkauth.ContextWithClaims(r.Context(), sdkauth.NewClaims(tt.claims)))
				}
				h.ServeHTTP(w, r)
			})
			srv := testkit.Server(t, withClaims)
			r := testkit.Do[any](t, srv, tt.method, tt.path, nil, nil)
			if r.Status != tt.status {
				t.Fatalf("status = %d, want %d: %s", r.Status, tt.status, r.Raw)
			}
			if tt.reason != "" && (r.Error == nil || r.Error.Meta["reason"] != tt.reason) {
				t.Errorf("error = %s, want reason %s", r.Raw, tt.reason)
			}
		})
	}
}

// TestScopedRoutesAllowPasswordChange pins the one exemption the
// password-change token has, so mounting POST /v1/me/password needs no
// middleware change.
func TestScopedRoutesAllowPasswordChange(t *testing.T) {
	got := scopedRoutes["password_change"]
	if len(got) != 1 || got[0] != (scopedRoute{http.MethodPost, "/v1/me/password"}) {
		t.Errorf("password_change routes = %v", got)
	}
}

// TestScopedRouteMatches checks the exact and the prefix ("*" suffix) forms.
func TestScopedRouteMatches(t *testing.T) {
	tests := []struct {
		name         string
		route        scopedRoute
		method, path string
		want         bool
	}{
		{
			"exact match",
			scopedRoute{http.MethodGet, "/v1/internal/roles/permissions"},
			http.MethodGet, "/v1/internal/roles/permissions", true,
		},
		{
			"exact mismatch",
			scopedRoute{http.MethodGet, "/v1/internal/roles/permissions"},
			http.MethodGet, "/v1/internal/roles/permissions2", false,
		},
		{
			"wrong method",
			scopedRoute{http.MethodGet, "/v1/internal/users/*"},
			http.MethodPost, "/v1/internal/users/1", false,
		},
		{
			"prefix match",
			scopedRoute{http.MethodGet, "/v1/internal/users/*"},
			http.MethodGet, "/v1/internal/users/11111111-1111-1111-1111-111111111111", true,
		},
		{
			"prefix needs the separator",
			scopedRoute{http.MethodGet, "/v1/internal/users/*"},
			http.MethodGet, "/v1/internal/users-other", false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.route.matches(tt.method, tt.path); got != tt.want {
				t.Errorf("matches(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

// TestScopedRoutesAllowInternal pins the internal routes a service token may
// call, so mounting a new /v1/internal route needs a deliberate change here.
func TestScopedRoutesAllowInternal(t *testing.T) {
	want := []scopedRoute{
		{http.MethodGet, "/v1/internal/users/*"},
		{http.MethodGet, "/v1/internal/tenants/*"},
		{http.MethodGet, "/v1/internal/roles/permissions"},
	}
	got := scopedRoutes["internal"]
	if len(got) != len(want) {
		t.Fatalf("internal routes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("internal routes[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

// TestRequireServiceScope lets only a scope:internal token through, and
// refuses an unscoped token, another scope, and no claims at all (auth
// disabled).
func TestRequireServiceScope(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any // nil = no claims in the context
		status int
	}{
		{"no claims", nil, http.StatusForbidden},
		{"ordinary user token", map[string]any{"sub": "u"}, http.StatusForbidden},
		{"password-change token", map[string]any{"sub": "u", "scope": "password_change"}, http.StatusForbidden},
		{"service token", map[string]any{"sub": "svc", "scope": "internal"}, http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
			h := requireServiceScope(next)
			withClaims := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.claims != nil {
					r = r.WithContext(sdkauth.ContextWithClaims(r.Context(), sdkauth.NewClaims(tt.claims)))
				}
				h.ServeHTTP(w, r)
			})
			srv := testkit.Server(t, withClaims)
			r := testkit.Do[any](t, srv, http.MethodGet, "/v1/internal/users/1", nil, nil)
			if r.Status != tt.status {
				t.Fatalf("status = %d, want %d: %s", r.Status, tt.status, r.Raw)
			}
		})
	}
}
