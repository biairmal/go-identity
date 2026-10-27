package app

import (
	"context"
	"net/http"
	"testing"
	"time"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/authz"

	identityauth "github.com/biairmal/go-identity/internal/module/auth"
	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// serviceClientSecret is the plaintext secret every test service client
// authenticates with.
const serviceClientSecret = "correct horse battery staple"

// newServiceClientFixture is the app with one configured resource service
// (notes-service), able to trade client credentials for a service token.
func newServiceClientFixture(t *testing.T, mutate func(c *Config)) *loginFixture {
	t.Helper()
	hash, err := password.Hash(serviceClientSecret)
	if err != nil {
		t.Fatal(err)
	}
	return newLoginFixture(t, func(c *Config) {
		c.Modules.Auth.ServiceClients = []identityauth.ServiceClient{{ID: "notes-service", SecretHash: hash}}
		if mutate != nil {
			mutate(c)
		}
	})
}

// serviceToken trades the configured client's credentials for an access
// token, failing the test unless it answers 200.
func (f *loginFixture) serviceToken(t *testing.T) string {
	t.Helper()
	r := f.post(t, "/v1/auth/token", map[string]any{
		"grant_type": "client_credentials", "client_id": "notes-service", "client_secret": serviceClientSecret,
	})
	token, _ := r.Data["access_token"].(string)
	if r.Status != http.StatusOK || token == "" {
		t.Fatalf("service token = %d %s", r.Status, r.Raw)
	}
	return token
}

// validate checks accessToken against the app's own JWKS, exactly like a
// resource service, and returns its claims.
func (f *loginFixture) validate(t *testing.T, accessToken string) sdkauth.Claims {
	t.Helper()
	v, err := sdkauth.NewRS256(sdkauth.WithJWKSURL(f.srv.URL+"/.well-known/jwks.json"),
		sdkauth.WithExpectedIssuer("identity"), sdkauth.WithExpectedAudience("api"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.Validate(context.Background(), accessToken)
	if err != nil {
		t.Fatalf("access token does not validate against the JWKS: %v", err)
	}
	return claims
}

// TestServiceTokenIntegration checks the TRD 9.4 contract: an unsupported
// grant_type, an unknown client and a wrong secret are all refused, and a
// correct client_credentials request gets a short-lived scope:internal token
// that validates through the JWKS exactly like a user token, with no tenant,
// roles or user claims.
func TestServiceTokenIntegration(t *testing.T) {
	f := newServiceClientFixture(t, nil)

	tests := []struct {
		name   string
		body   map[string]any
		status int
		reason string
	}{
		{
			"unsupported grant_type", map[string]any{
				"grant_type": "password", "client_id": "notes-service", "client_secret": serviceClientSecret,
			}, http.StatusBadRequest, "UNSUPPORTED_GRANT_TYPE",
		},
		{
			"unknown client", map[string]any{
				"grant_type": "client_credentials", "client_id": "ghost-service", "client_secret": serviceClientSecret,
			}, http.StatusUnauthorized, "INVALID_CLIENT",
		},
		{
			"wrong secret", map[string]any{
				"grant_type": "client_credentials", "client_id": "notes-service", "client_secret": "nope",
			}, http.StatusUnauthorized, "INVALID_CLIENT",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := f.post(t, "/v1/auth/token", tt.body)
			if r.Status != tt.status || reason(&r) != tt.reason {
				t.Errorf("= %d %s, want %d %s", r.Status, r.Raw, tt.status, tt.reason)
			}
		})
	}

	token := f.serviceToken(t)
	claims := f.validate(t, token)
	if claims.Subject() != "notes-service" {
		t.Errorf("sub = %q, want notes-service", claims.Subject())
	}
	if scope, _ := claims.Get("scope"); scope != "internal" {
		t.Errorf("scope = %v, want internal", scope)
	}
	for _, claim := range []string{"tid", "sa"} {
		if _, has := claims.Get(claim); has {
			t.Errorf("a service token carries %q, which no user or tenant backs", claim)
		}
	}
	if len(claims.Roles()) != 0 {
		t.Errorf("roles = %v, want none", claims.Roles())
	}

	r := f.post(t, "/v1/auth/token", map[string]any{
		"grant_type": "client_credentials", "client_id": "notes-service", "client_secret": serviceClientSecret,
	})
	if r.Status != http.StatusOK || r.Data["token_type"] != "Bearer" || r.Data["expires_in"] != float64(300) {
		t.Errorf("token response = %v", r.Data)
	}
}

// TestInternalRoutesIntegration checks the three TRD 9.8 endpoints: a service
// token reaches them and gets the documented shape, while no token, an
// ordinary user's token and a service token on a non-internal route are all
// refused.
func TestInternalRoutesIntegration(t *testing.T) {
	f := newServiceClientFixture(t, nil)
	f.register(t)
	userID := f.userID(t, "Bia")
	tenantID := f.text(t, `SELECT id::text FROM tenants WHERE slug = 'default'`)
	svc := f.serviceToken(t)

	t.Run("get user", func(t *testing.T) {
		r := f.get(t, "/v1/internal/users/"+userID, svc)
		if r.Status != http.StatusOK || r.Data["display_name"] != "Bia" || r.Data["status"] != "active" {
			t.Fatalf("= %d %s", r.Status, r.Raw)
		}
		if _, has := r.Data["email"]; has {
			t.Error("internal user response carries an email")
		}
	})

	t.Run("get user not found", func(t *testing.T) {
		r := f.get(t, "/v1/internal/users/"+tenantID, svc) // any other UUID: not a user
		if r.Status != http.StatusNotFound {
			t.Errorf("= %d %s, want 404", r.Status, r.Raw)
		}
	})

	t.Run("get tenant", func(t *testing.T) {
		r := f.get(t, "/v1/internal/tenants/"+tenantID, svc)
		if r.Status != http.StatusOK || r.Data["slug"] != "default" || r.Data["status"] != "active" {
			t.Fatalf("= %d %s", r.Status, r.Raw)
		}
	})

	t.Run("role permission map", func(t *testing.T) {
		r := f.get(t, "/v1/internal/roles/permissions?tenant_id="+tenantID, svc)
		if r.Status != http.StatusOK || r.Data["tenant_id"] != tenantID {
			t.Fatalf("= %d %s", r.Status, r.Raw)
		}
		roles, _ := r.Data["roles"].(map[string]any)
		admin, _ := roles["admin"].([]any)
		member, _ := roles["member"].([]any)
		if len(admin) == 0 || len(member) != 0 {
			t.Errorf("roles = %v, want admin to hold grants and member none", roles)
		}
		if v, ok := r.Data["version"].(float64); !ok || v == 0 {
			t.Errorf("version = %v, want a non-zero fingerprint", r.Data["version"])
		}
	})

	t.Run("no token", func(t *testing.T) {
		r := testkit.Do[map[string]any](t, f.srv, http.MethodGet, "/v1/internal/users/"+userID, nil, nil)
		if r.Status != http.StatusUnauthorized {
			t.Errorf("= %d, want 401", r.Status)
		}
	})

	t.Run("ordinary user token", func(t *testing.T) {
		full := f.token(t, "bia@example.com")
		r := f.get(t, "/v1/internal/users/"+userID, full)
		if r.Status != http.StatusForbidden {
			t.Errorf("= %d %s, want 403", r.Status, r.Raw)
		}
	})

	t.Run("service token outside v1/internal", func(t *testing.T) {
		r := f.get(t, "/v1/me", svc)
		if r.Status != http.StatusForbidden {
			t.Errorf("= %d %s, want 403", r.Status, r.Raw)
		}
	})
}

// TestAuthzSourceIdentityIntegration is the T7.1 acceptance criterion: go-sdk
// authz with source identity, pointed at this app, maps a real user's roles
// through the real role-permission endpoint, fetched with a real service
// token.
func TestAuthzSourceIdentityIntegration(t *testing.T) {
	f := newServiceClientFixture(t, nil)
	f.register(t)
	f.registerAs(t, "kim@example.com", "Kim")
	f.grant(t, "bia@example.com", "admin") // kim keeps the seeded, permission-less member role
	bia := f.validate(t, f.token(t, "bia@example.com"))
	kim := f.validate(t, f.token(t, "kim@example.com"))

	svc := f.serviceToken(t)
	az, err := authz.New(&authz.Config{Source: authz.SourceIdentity, IdentityURL: f.srv.URL, CacheTTL: time.Minute},
		authz.WithServiceToken(func(context.Context) (string, error) { return svc, nil }))
	if err != nil {
		t.Fatalf("authz.New() = %v", err)
	}

	if err := az.Require(sdkauth.ContextWithClaims(context.Background(), bia), "roles:manage"); err != nil {
		t.Errorf("admin Require(roles:manage) = %v, want nil", err)
	}
	if err := az.Require(sdkauth.ContextWithClaims(context.Background(), kim), "roles:manage"); err == nil {
		t.Error("member Require(roles:manage) = nil, want Forbidden")
	}

	// Without a service token the fetch itself is refused: the internal
	// endpoint is not usable by an unauthenticated caller.
	noToken, err := authz.New(&authz.Config{Source: authz.SourceIdentity, IdentityURL: f.srv.URL, CacheTTL: time.Minute})
	if err != nil {
		t.Fatalf("authz.New() = %v", err)
	}
	if err := noToken.Require(sdkauth.ContextWithClaims(context.Background(), bia), "roles:manage"); err == nil {
		t.Error("Require() without a service token = nil, want an error")
	}
}
