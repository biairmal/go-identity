package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/biairmal/go-sdk/lib/logger"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// switchFixture is a multi-mode app where Bia is an active member of both the
// default tenant and "acme", signed in to the default tenant.
type switchFixture struct {
	*loginFixture
	acme  string // acme tenant ID
	token string // Bia's access token in the default tenant
	rt    string // Bia's refresh token in the default tenant
}

func newSwitchFixture(t *testing.T) *switchFixture {
	t.Helper()
	f := newLoginFixture(t, func(c *Config) { c.Modules.Tenant.Mode = "multi" })
	body := map[string]any{
		"email": "bia@example.com", "password": loginPassword, "display_name": "Bia", "tenant": "default",
	}
	if r := f.post(t, "/v1/auth/register", body); r.Status != http.StatusAccepted {
		t.Fatalf("register = %d %s", r.Status, r.Raw)
	}
	f.exec(t, `INSERT INTO tenants (slug, name) VALUES ('acme', 'Acme')`)
	f.exec(t, `INSERT INTO tenant_members (tenant_id, user_id, status, joined_at)
		SELECT t.id, u.id, 'active', now() FROM tenants t, users u WHERE t.slug = 'acme' AND u.display_name = 'Bia'`)
	acme := f.text(t, `SELECT id::text FROM tenants WHERE slug = 'acme'`)

	r := f.post(t, "/v1/auth/login",
		map[string]any{"email": "bia@example.com", "password": loginPassword, "tenant": "default"})
	token, _ := r.Data["access_token"].(string)
	rt, _ := r.Data["refresh_token"].(string)
	if r.Status != http.StatusOK || token == "" {
		t.Fatalf("login in default = %d %s", r.Status, r.Raw)
	}
	return &switchFixture{loginFixture: f, acme: acme, token: token, rt: rt}
}

// switchTo posts switch-tenant with Bia's default-tenant token.
func (f *switchFixture) switchTo(t *testing.T, tenantID string) testkit.Response[map[string]any] {
	t.Helper()
	return f.do(t, http.MethodPost, "/v1/auth/switch-tenant", f.token, map[string]any{"tenant_id": tenantID}, "")
}

// TestSwitchTenantHappyPath switches to the other tenant and shows both
// refresh families stay valid, each for its own tenant.
func TestSwitchTenantHappyPath(t *testing.T) {
	f := newSwitchFixture(t)
	sw := f.switchTo(t, f.acme)
	tenant, _ := sw.Data["tenant"].(map[string]any)
	rtAcme, _ := sw.Data["refresh_token"].(string)
	if sw.Status != http.StatusOK || tenant["slug"] != "acme" || rtAcme == "" {
		t.Fatalf("switch = %d %s", sw.Status, sw.Raw)
	}
	if rtAcme == f.rt {
		t.Error("switch reused the old refresh family")
	}
	// The new family refreshes into acme.
	status, _, data := f.refresh(t, rtAcme)
	if tn, _ := data["tenant"].(map[string]any); status != http.StatusOK || tn["slug"] != "acme" {
		t.Errorf("refresh of the new family = %d, tenant %v, want 200 acme", status, data["tenant"])
	}
	// The old family still refreshes into the default tenant.
	status, _, data = f.refresh(t, f.rt)
	if tn, _ := data["tenant"].(map[string]any); status != http.StatusOK || tn["slug"] != "default" {
		t.Errorf("refresh of the old family = %d, tenant %v, want 200 default", status, data["tenant"])
	}
}

// TestSwitchTenantErrors covers the three refusals.
func TestSwitchTenantErrors(t *testing.T) {
	f := newSwitchFixture(t)

	// A tenant Bia does not belong to.
	f.exec(t, `INSERT INTO tenants (slug, name) VALUES ('other', 'Other')`)
	other := f.text(t, `SELECT id::text FROM tenants WHERE slug = 'other'`)
	wantReason(t, "not a member", new(f.switchTo(t, other)), http.StatusForbidden, "NOT_A_MEMBER")

	// A disabled membership.
	f.exec(t, `UPDATE tenant_members SET status = 'disabled' WHERE tenant_id = $1
		AND user_id = (SELECT id FROM users WHERE display_name = 'Bia')`, f.acme)
	wantReason(t, "disabled membership", new(f.switchTo(t, f.acme)), http.StatusForbidden, "ACCOUNT_DISABLED")

	// A suspended tenant (restore the membership first).
	f.exec(t, `UPDATE tenant_members SET status = 'active' WHERE tenant_id = $1
		AND user_id = (SELECT id FROM users WHERE display_name = 'Bia')`, f.acme)
	f.exec(t, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, f.acme)
	wantReason(t, "suspended tenant", new(f.switchTo(t, f.acme)), http.StatusForbidden, "TENANT_SUSPENDED")
}

// TestSwitchTenantSuperAdmin lets the super admin switch into a tenant they do
// not belong to, suspended included.
func TestSwitchTenantSuperAdmin(t *testing.T) {
	f := newLoginFixture(t, func(c *Config) { c.Modules.Tenant.Mode = "multi" })
	super := f.superToken(t)
	f.exec(t, `INSERT INTO tenants (slug, name, status) VALUES ('acme', 'Acme', 'suspended')`)
	acme := f.text(t, `SELECT id::text FROM tenants WHERE slug = 'acme'`)
	r := f.do(t, http.MethodPost, "/v1/auth/switch-tenant", super, map[string]any{"tenant_id": acme}, "")
	tenant, _ := r.Data["tenant"].(map[string]any)
	if r.Status != http.StatusOK || tenant["slug"] != "acme" {
		t.Fatalf("super admin switch into a suspended tenant = %d %s, want 200", r.Status, r.Raw)
	}
}

// TestSwitchTenant404InSingleMode hides the route in single mode.
func TestSwitchTenant404InSingleMode(t *testing.T) {
	f := newLoginFixture(t, nil) // single mode
	f.register(t)
	token := f.token(t, "bia@example.com")
	def := f.text(t, `SELECT id::text FROM tenants WHERE slug = 'default'`)
	r := f.do(t, http.MethodPost, "/v1/auth/switch-tenant", token, map[string]any{"tenant_id": def}, "")
	if r.Status != http.StatusNotFound {
		t.Errorf("switch-tenant in single mode = %d %s, want 404", r.Status, r.Raw)
	}
}

// serveApp builds an app against cfg with token validation through its own
// JWKS, and returns the server and a stop func. It shares the test package's
// Postgres, so two apps can run against one database.
func serveApp(t *testing.T, cfg *Config) (srv *httptest.Server, stop func()) {
	t.Helper()
	h := http.NotFoundHandler()
	srv = testkit.Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	cfg.Auth.Local.JWKSURL = srv.URL + "/.well-known/jwks.json"
	a, err := New(context.Background(), cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h = a.Handler()
	return srv, func() { a.close(context.Background()) }
}

// TestSingleToMultiMigrationKeepsUsersAndRoles boots the app in single mode,
// creates a user with the admin role, then reboots in multi mode on the same
// database and shows the user signs in and keeps their role.
func TestSingleToMultiMigrationKeepsUsersAndRoles(t *testing.T) {
	db := testkit.Postgres(t)
	base := validConfig(t)
	base.Database = testkit.PostgresConfig(t)
	base.Auth.Enabled = true
	base.Auth.CacheTTL = 0
	base.Modules.User.SuperAdmin = testSuperAdmin
	base.Modules.Auth.Providers.Password.RequireEmailVerification = false
	base.Modules.Auth.Security.LoginRateLimit = "1000/5m"

	// Phase 1: single mode. Register Bia and give her the admin role.
	single := base
	single.Modules.Tenant.Mode = "single"
	srv1, stop1 := serveApp(t, &single)
	reg := testkit.Do[map[string]any](t, srv1, http.MethodPost, "/v1/auth/register",
		map[string]any{"email": "bia@example.com", "password": loginPassword, "display_name": "Bia"}, nil)
	if reg.Status != http.StatusAccepted {
		t.Fatalf("register = %d %s", reg.Status, reg.Raw)
	}
	if _, err := db.Leader().ExecContext(context.Background(),
		`INSERT INTO user_roles (tenant_id, user_id, role_id)
		 SELECT r.tenant_id, u.id, r.id FROM roles r, users u
		 WHERE r.name = 'admin' AND r.tenant_id IS NOT NULL AND u.display_name = 'Bia'`); err != nil {
		t.Fatalf("grant admin: %v", err)
	}
	stop1()

	// Phase 2: multi mode on the same database.
	multi := base
	multi.Modules.Tenant.Mode = "multi"
	srv2, stop2 := serveApp(t, &multi)
	t.Cleanup(stop2)

	login := testkit.Do[map[string]any](t, srv2, http.MethodPost, "/v1/auth/login",
		map[string]any{"email": "bia@example.com", "password": loginPassword}, nil)
	token, _ := login.Data["access_token"].(string)
	if login.Status != http.StatusOK || token == "" {
		t.Fatalf("login after migration = %d %s", login.Status, login.Raw)
	}
	// The admin role survived: an admin route answers.
	roles := testkit.Do[map[string]any](t, srv2, http.MethodGet, "/v1/admin/roles", nil,
		http.Header{"Authorization": {"Bearer " + token}})
	if roles.Status != http.StatusOK {
		t.Errorf("GET /v1/admin/roles after migration = %d %s, want 200", roles.Status, roles.Raw)
	}
}

// TestSwitchTenantAuditUsesTheSharedActionName writes the action audit/actions.go
// names, so the admin audit filter finds it.
func TestSwitchTenantAuditUsesTheSharedActionName(t *testing.T) {
	f := newSwitchFixture(t)
	if sw := f.switchTo(t, f.acme); sw.Status != http.StatusOK {
		t.Fatalf("switch = %d %s", sw.Status, sw.Raw)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.tenant_switch'`); n != 1 {
		t.Errorf("auth.tenant_switch rows = %d, want 1", n)
	}
}
