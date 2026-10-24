package app

import (
	"context"
	"net/http"
	"testing"

	"github.com/biairmal/go-sdk/lib/logger"

	"github.com/biairmal/go-identity/internal/module/tenant"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// TestAuthConfigIsPublic builds the whole app with token validation on and
// checks GET /v1/auth/config answers without a token, while a protected /v1
// path still demands one. It also checks the tenancy mode reaches the
// response through the app's wiring.
func TestAuthConfigIsPublic(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	cfg := validConfig(t)
	cfg.Database = testkit.PostgresConfig(t)
	cfg.Auth.Enabled = true
	cfg.Modules.Tenant.Mode = tenant.ModeMulti
	cfg.Modules.User.SuperAdmin = testSuperAdmin
	a, err := New(context.Background(), &cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := testkit.Server(t, a.Handler())

	type body struct {
		Providers struct {
			Password bool `json:"password"`
			Google   bool `json:"google"`
		} `json:"providers"`
		Registration bool   `json:"registration"`
		Tenancy      string `json:"tenancy"`
	}
	r := testkit.Do[body](t, srv, http.MethodGet, "/v1/auth/config", nil, nil)
	if r.Status != http.StatusOK {
		t.Fatalf("GET /v1/auth/config without a token = %d: %s", r.Status, r.Raw)
	}
	if !r.Data.Providers.Password || r.Data.Providers.Google || !r.Data.Registration || r.Data.Tenancy != "multi" {
		t.Errorf("data = %+v, want password only, registration on, multi tenancy", r.Data)
	}

	if s := testkit.Do[any](t, srv, http.MethodGet, "/v1/me", nil, nil).Status; s != http.StatusUnauthorized {
		t.Errorf("GET /v1/me without a token = %d, want 401 (auth must be active)", s)
	}
	if s := testkit.Do[any](t, srv, http.MethodPost, "/v1/auth/config", nil, nil).Status; s != http.StatusUnauthorized {
		t.Errorf("POST /v1/auth/config without a token = %d, want 401 (only GET is public)", s)
	}
}
