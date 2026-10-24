package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/auth/token"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// testModule builds the auth module over generated keys, with no database.
func testModule(t *testing.T, cfg *Config) *Module {
	t.Helper()
	m, err := New(cfg, &Deps{Clock: testkit.NewClock(time.Now())})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	return m
}

// testConfig is a valid auth config pointing at generated keys.
func testConfig(t *testing.T, kids ...string) *Config {
	t.Helper()
	active := "key-a"
	if len(kids) > 0 {
		active = kids[0]
	}
	cfg := Default()
	cfg.Token.SigningKeysDir = testkit.SigningKeys(t, active, kids[min(1, len(kids)):]...)
	return &cfg
}

// TestAccessTokenValidatesThroughJWKS is the acceptance criterion for T2.6: a
// token this service signs must validate in a resource service that only has
// the JWKS endpoint, which is how every resource service checks tokens.
func TestAccessTokenValidatesThroughJWKS(t *testing.T) {
	m := testModule(t, testConfig(t))

	// The JWKS endpoint, served exactly as a resource service sees it.
	srv := httptest.NewServer(sdkauth.JWKSHandler(m.keys.Public))
	defer srv.Close()

	validator, err := sdkauth.NewRS256(sdkauth.WithJWKSURL(srv.URL))
	if err != nil {
		t.Fatalf("NewRS256() = %v", err)
	}

	userID, tenantID := uuid.New(), uuid.New()
	signed, expiry, err := m.Tokens().Access(context.Background(), &token.Subject{
		UserID: userID,
		Roles:  []string{"admin", "member"},
	}, tenantID)
	if err != nil {
		t.Fatalf("Access() = %v", err)
	}
	if expiry.Before(time.Now()) {
		t.Errorf("expiry %v is already past", expiry)
	}

	claims, err := validator.Validate(context.Background(), signed)
	if err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if claims.Subject() != userID.String() {
		t.Errorf("sub = %q, want %q", claims.Subject(), userID)
	}
	if tid, _ := claims.Get(token.ClaimTenant); tid != tenantID.String() {
		t.Errorf("tid = %v, want %q", tid, tenantID)
	}
	if roles := claims.Roles(); len(roles) != 2 {
		t.Errorf("roles = %v, want two", roles)
	}
}

// TestAccessTokenClaims checks each claim in the TRD 6 table, including the
// ones that appear only in some configurations.
func TestAccessTokenClaims(t *testing.T) {
	tests := []struct {
		name    string
		claims  string
		subject token.Subject
		check   func(t *testing.T, c sdkauth.Claims)
	}{
		{
			name:    "roles mode omits perms",
			claims:  token.ClaimsRoles,
			subject: token.Subject{Roles: []string{"member"}, Permissions: []string{"notes:read"}},
			check: func(t *testing.T, c sdkauth.Claims) {
				if _, ok := c.Get(token.ClaimPerms); ok {
					t.Error("perms claim present in roles mode, which should keep tokens small")
				}
			},
		},
		{
			name:    "roles_and_permissions adds perms",
			claims:  token.ClaimsRolesAndPermissions,
			subject: token.Subject{Roles: []string{"member"}, Permissions: []string{"notes:read"}},
			check: func(t *testing.T, c sdkauth.Claims) {
				if _, ok := c.Get(token.ClaimPerms); !ok {
					t.Error("perms claim missing in roles_and_permissions mode")
				}
			},
		},
		{
			name:    "super admin carries sa",
			claims:  token.ClaimsRoles,
			subject: token.Subject{SuperAdmin: true},
			check: func(t *testing.T, c sdkauth.Claims) {
				if sa, ok := c.Get(token.ClaimSuperAdmin); !ok || sa != true {
					t.Errorf("sa = %v, want true", sa)
				}
			},
		},
		{
			name:    "an ordinary user carries no sa",
			claims:  token.ClaimsRoles,
			subject: token.Subject{},
			check: func(t *testing.T, c sdkauth.Claims) {
				if _, ok := c.Get(token.ClaimSuperAdmin); ok {
					t.Error("sa claim present for an ordinary user")
				}
			},
		},
		{
			name:    "a restricted token carries its scope",
			claims:  token.ClaimsRoles,
			subject: token.Subject{Scope: "password_change"},
			check: func(t *testing.T, c sdkauth.Claims) {
				if scope, _ := c.Get(token.ClaimScope); scope != "password_change" {
					t.Errorf("scope = %v, want password_change", scope)
				}
			},
		},
		{
			name:    "every token carries a jti",
			claims:  token.ClaimsRoles,
			subject: token.Subject{},
			check: func(t *testing.T, c sdkauth.Claims) {
				jti, ok := c.Get(token.ClaimTokenID)
				if !ok || jti == "" {
					t.Error("jti missing, so a token cannot be traced in logs")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Token.Claims = tt.claims
			m := testModule(t, cfg)

			srv := httptest.NewServer(sdkauth.JWKSHandler(m.keys.Public))
			defer srv.Close()
			validator, err := sdkauth.NewRS256(sdkauth.WithJWKSURL(srv.URL))
			if err != nil {
				t.Fatalf("NewRS256() = %v", err)
			}

			sub := tt.subject
			sub.UserID = uuid.New()
			signed, _, err := m.Tokens().Access(context.Background(), &sub, uuid.New())
			if err != nil {
				t.Fatalf("Access() = %v", err)
			}
			claims, err := validator.Validate(context.Background(), signed)
			if err != nil {
				t.Fatalf("Validate() = %v", err)
			}
			tt.check(t, claims)
		})
	}
}

// TestJWKSEndpointPublishesEveryKey checks a rotation is visible: the next key
// is published before it signs, so a resource service has it cached in time.
func TestJWKSEndpointPublishesEveryKey(t *testing.T) {
	m := testModule(t, testConfig(t, "key-active", "key-next"))

	rt := newTestRoutes()
	m.Register(rt.routes)

	req := httptest.NewRequest(http.MethodGet, jwksPath, http.NoBody)
	rec := httptest.NewRecorder()
	rt.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", jwksPath, rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Error("no Cache-Control on the key set, so clients cannot cache it")
	}

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("JWKS has %d keys, want the active and the next one", len(set.Keys))
	}
	kids := map[string]bool{}
	for _, k := range set.Keys {
		kid, _ := k["kid"].(string)
		kids[kid] = true
		if k["alg"] != "RS256" || k["use"] != "sig" || k["kty"] != "RSA" {
			t.Errorf("key %q = %v, want an RS256 signing RSA key", kid, k)
		}
	}
	for _, want := range []string{"key-active", "key-next"} {
		if !kids[want] {
			t.Errorf("JWKS is missing %q", want)
		}
	}
}

// TestActiveKeySignsAndIsPublishedFirstOfTheActives checks the token header
// names the active key, which is how a client picks the right one.
func TestTokenHeaderNamesTheActiveKey(t *testing.T) {
	m := testModule(t, testConfig(t, "key-active", "key-next"))
	if got := m.keys.ActiveKID(); got != "key-active" {
		t.Fatalf("ActiveKID() = %q, want key-active", got)
	}

	signed, _, err := m.Tokens().Access(context.Background(),
		&token.Subject{UserID: uuid.New()}, uuid.New())
	if err != nil {
		t.Fatalf("Access() = %v", err)
	}
	if kid := headerKID(t, signed); kid != "key-active" {
		t.Errorf("token header kid = %q, want key-active", kid)
	}
}

// TestNewFailsWithoutKeys checks a missing or unusable key set stops startup
// rather than producing a service that cannot sign.
func TestNewFailsWithoutKeys(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{
			name:  "missing directory",
			setup: func(t *testing.T) string { return t.TempDir() + "/absent" },
		},
		{
			name:  "directory without a manifest",
			setup: func(t *testing.T) string { return t.TempDir() },
		},
		{
			name: "manifest naming a key that is not there",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeFile(t, dir+"/keys.yaml", "active: ghost\n")
				return dir
			},
		},
		{
			name: "manifest with no active key",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeFile(t, dir+"/keys.yaml", "next: [a]\n")
				return dir
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			cfg.Token.SigningKeysDir = tt.setup(t)
			if _, err := New(&cfg, &Deps{}); err == nil {
				t.Fatal("New() = nil, want an error so startup stops")
			}
		})
	}
}
