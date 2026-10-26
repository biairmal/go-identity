// Package isolation proves no tenant's data crosses to another: every
// tenant-scoped admin route answers 404 (not 403) when one tenant's admin
// targets another tenant's IDs, the list routes show only the caller's
// tenant, and the /me routes act only on the caller. A route-coverage test
// fails if a new admin or me route is added without an isolation case here.
package isolation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/go-chi/chi/v5"

	"github.com/biairmal/go-identity/internal/app"
	"github.com/biairmal/go-identity/internal/module/user"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

const password = "a-good-enough-passw0rd"

// world is two tenants, an admin in each, and the IDs an isolation case
// targets across the tenant boundary.
type world struct {
	srv     *httptest.Server
	handler http.Handler // the app's chi router, for route coverage
	db      *sqlkit.DB

	tokenA string // admin of tenant A (the default tenant)
	tokenB string // admin of tenant B

	userB    string // the admin of B, as seen from A: a non-member
	roleB    string // a role owned by B
	familyB  string // a refresh family of B's admin
	adminBID string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	h := http.NotFoundHandler()
	srv := testkit.Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))

	cfg, err := app.LoadConfig("", filepath.Join("..", "..", "config", "config.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	cfg.Database = testkit.PostgresConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.CacheTTL = 0
	cfg.Auth.Local.JWKSURL = srv.URL + "/.well-known/jwks.json"
	cfg.Modules.Tenant.Mode = "multi"
	cfg.Modules.User.SuperAdmin = user.SuperAdminConfig{Email: "root@example.com", Password: "first-start-password-42"}
	cfg.Modules.Auth.Providers.Password.RequireEmailVerification = false
	cfg.Modules.Auth.Security.LoginRateLimit = "1000/5m"
	cfg.Modules.Auth.Token.SigningKeysDir = testkit.SigningKeys(t, "iso-key")

	a, err := app.New(context.Background(), &cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h = a.Handler()

	w := &world{srv: srv, handler: a.Handler(), db: a.DB()}
	w.setup(t)
	return w
}

// setup builds the two tenants and their admins, and the cross-tenant targets.
func (w *world) setup(t *testing.T) {
	t.Helper()
	// The bootstrapped super admin must change its password on first sign-in;
	// clear that so it can get a full token.
	w.exec(t, `UPDATE users SET must_change_password = false WHERE is_super_admin`)
	super := w.token(t, "root@example.com", "first-start-password-42", "")

	// Tenant A is the default tenant. Register an admin and grant the role.
	w.register(t, "admin-a@example.com", "Admin A", "default")
	w.exec(t, `INSERT INTO user_roles (tenant_id, user_id, role_id)
		SELECT r.tenant_id, u.id, r.id FROM roles r, users u
		WHERE r.name = 'admin' AND r.tenant_id IS NOT NULL AND u.display_name = 'Admin A'`)
	w.tokenA = w.token(t, "admin-a@example.com", password, "default")

	// Tenant B is created by the super admin, which invites its first admin.
	created := w.do(t, http.MethodPost, "/v1/admin/tenants", super,
		map[string]any{"slug": "tenant-b", "name": "Tenant B", "first_admin_email": "admin-b@example.com"})
	if created.Status != http.StatusCreated {
		t.Fatalf("create tenant B = %d %s", created.Status, created.Raw)
	}
	token := w.inviteToken(t, "admin-b@example.com")
	accept := w.do(t, http.MethodPost, "/v1/auth/invite/accept", "",
		map[string]any{"token": token, "password": password})
	if accept.Status != http.StatusOK {
		t.Fatalf("accept invite into B = %d %s", accept.Status, accept.Raw)
	}
	userB, _ := accept.Data["user"].(map[string]any)
	w.adminBID, _ = userB["id"].(string)
	w.userB = w.adminBID
	w.tokenB = w.token(t, "admin-b@example.com", password, "tenant-b")

	// A role owned by B, and a refresh family of B's admin.
	role := w.do(t, http.MethodPost, "/v1/admin/roles", w.tokenB,
		map[string]any{"name": "billing", "permissions": []string{}})
	if role.Status != http.StatusCreated {
		t.Fatalf("create role in B = %d %s", role.Status, role.Raw)
	}
	w.roleB, _ = role.Data["id"].(string)
	w.familyB = w.text(t, `SELECT family_id::text FROM refresh_tokens WHERE user_id = $1 LIMIT 1`, w.adminBID)

	// Guard against a silent empty ID turning a by-ID case into a list hit.
	for name, id := range map[string]string{"userB": w.userB, "roleB": w.roleB, "familyB": w.familyB} {
		if id == "" {
			t.Fatalf("setup produced an empty %s", name)
		}
	}
}

// TestCrossTenantByIDReturns404 checks every tenant-scoped by-ID admin or me
// route: A's admin targeting B's ID is 404 (the resource is not in A's
// tenant), never 403.
func TestCrossTenantByIDReturns404(t *testing.T) {
	w := newWorld(t)
	u := "/v1/admin/users/" + w.userB
	role := "/v1/admin/roles/" + w.roleB
	cases := []struct {
		name, method, path string
		body               any
		ifMatch            string
	}{
		{"get user", http.MethodGet, u, nil, ""},
		{"disable user", http.MethodPost, u + "/disable", nil, ""},
		{"enable user", http.MethodPost, u + "/enable", nil, ""},
		{"remove user", http.MethodDelete, u, nil, ""},
		{"set user roles", http.MethodPut, u + "/roles", map[string]any{"role_ids": []string{}}, ""},
		{"revoke user sessions", http.MethodPost, u + "/revoke-sessions", nil, ""},
		{"get role", http.MethodGet, role, nil, ""},
		{"rename role", http.MethodPatch, role, map[string]any{"name": "x"}, `"1"`},
		{"set role permissions", http.MethodPut, role + "/permissions", map[string]any{"permissions": []string{}}, `"1"`},
		{"delete role", http.MethodDelete, role, nil, ""},
		{"revoke another user's session", http.MethodDelete, "/v1/me/sessions/" + w.familyB, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := w.doIf(t, c.method, c.path, w.tokenA, c.body, c.ifMatch)
			if r.Status != http.StatusNotFound {
				t.Errorf("%s %s = %d %s, want 404", c.method, c.path, r.Status, r.Raw)
			}
		})
	}
}

// TestListRoutesAreTenantScoped checks the admin list routes show only the
// caller's tenant: B's user, role and audit never appear for A.
func TestListRoutesAreTenantScoped(t *testing.T) {
	w := newWorld(t)

	users := w.do(t, http.MethodGet, "/v1/admin/users", w.tokenA, nil)
	if users.Status != http.StatusOK || containsID(items(users.Data), w.userB) {
		t.Errorf("A's user list leaked B's admin: %s", users.Raw)
	}
	roles := w.do(t, http.MethodGet, "/v1/admin/roles", w.tokenA, nil)
	for _, it := range items(roles.Data) {
		if it["id"] == w.roleB || it["name"] == "billing" {
			t.Errorf("A's role list leaked B's role: %s", roles.Raw)
		}
	}
	audit := w.do(t, http.MethodGet, "/v1/admin/audit?actor="+w.adminBID, w.tokenA, nil)
	if audit.Status != http.StatusOK || len(items(audit.Data)) != 0 {
		t.Errorf("A's audit leaked B's actor rows: %d %s", audit.Status, audit.Raw)
	}
}

// TestAdminAndMeRoutesAreCovered collects every /v1/admin and /v1/me route
// from the router and fails if one is not declared here, so a new admin route
// cannot ship without an isolation decision.
func TestAdminAndMeRoutesAreCovered(t *testing.T) {
	w := newWorld(t)
	routes, ok := w.handlerRoutes(t)
	if !ok {
		t.Fatal("handler is not a chi.Routes")
	}
	got := map[string]bool{}
	for _, r := range routes {
		if strings.HasPrefix(r, "GET /v1/admin") || strings.HasPrefix(r, "POST /v1/admin") ||
			strings.HasPrefix(r, "PUT /v1/admin") || strings.HasPrefix(r, "PATCH /v1/admin") ||
			strings.HasPrefix(r, "DELETE /v1/admin") || strings.Contains(r, " /v1/me") {
			got[r] = true
		}
	}
	missing := diff(got, declaredRoutes)
	extra := diff(declaredRoutes, got)
	if len(missing) > 0 {
		t.Errorf("new admin/me route(s) with no isolation decision — add to declaredRoutes:\n  %s",
			strings.Join(missing, "\n  "))
	}
	if len(extra) > 0 {
		t.Errorf("declaredRoutes lists route(s) the router no longer has:\n  %s", strings.Join(extra, "\n  "))
	}
}

// declaredRoutes is every /v1/admin and /v1/me route, each with how its tenant
// isolation is covered above: by-ID 404 cases, tenant-scoped lists, caller-only
// me routes, or super-admin-only (the sa claim, tested in internal/app).
var declaredRoutes = map[string]bool{
	// Tenant-scoped, by ID — TestCrossTenantByIDReturns404.
	"GET /v1/admin/users/{id}":                  true,
	"POST /v1/admin/users/{id}/disable":         true,
	"POST /v1/admin/users/{id}/enable":          true,
	"DELETE /v1/admin/users/{id}":               true,
	"PUT /v1/admin/users/{id}/roles":            true,
	"POST /v1/admin/users/{id}/revoke-sessions": true,
	"GET /v1/admin/roles/{id}":                  true,
	"PATCH /v1/admin/roles/{id}":                true,
	"DELETE /v1/admin/roles/{id}":               true,
	"PUT /v1/admin/roles/{id}/permissions":      true,
	"DELETE /v1/me/sessions/{id}":               true,
	// Tenant-scoped lists and catalog — TestListRoutesAreTenantScoped.
	"GET /v1/admin/users":         true,
	"GET /v1/admin/roles":         true,
	"GET /v1/admin/audit":         true,
	"GET /v1/admin/permissions":   true,
	"POST /v1/admin/roles":        true,
	"POST /v1/admin/users/invite": true,
	// Caller-only me routes.
	"GET /v1/me/":                     true,
	"PATCH /v1/me/":                   true,
	"POST /v1/me/password":            true,
	"GET /v1/me/tenants":              true,
	"DELETE /v1/me/identities/google": true,
	"GET /v1/me/sessions":             true,
	// Super-admin only (the sa claim; a tenant admin gets 403, tested in internal/app).
	"GET /v1/admin/tenants":                true,
	"POST /v1/admin/tenants":               true,
	"GET /v1/admin/tenants/{id}":           true,
	"PATCH /v1/admin/tenants/{id}":         true,
	"GET /v1/admin/role-templates":         true,
	"POST /v1/admin/role-templates":        true,
	"PATCH /v1/admin/role-templates/{id}":  true,
	"DELETE /v1/admin/role-templates/{id}": true,
}

// --- helpers ---

func (w *world) handlerRoutes(t *testing.T) ([]string, bool) {
	t.Helper()
	router, ok := w.srvHandler().(chi.Routes)
	if !ok {
		return nil, false
	}
	var out []string
	_ = chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out = append(out, method+" "+route)
		return nil
	})
	return out, true
}

// srvHandler returns the app's chi router.
func (w *world) srvHandler() http.Handler { return w.handler }

func (w *world) register(t *testing.T, email, name, tenant string) {
	t.Helper()
	body := map[string]any{"email": email, "password": password, "display_name": name}
	if tenant != "" {
		body["tenant"] = tenant
	}
	if r := w.do(t, http.MethodPost, "/v1/auth/register", "", body); r.Status != http.StatusAccepted {
		t.Fatalf("register %s = %d %s", email, r.Status, r.Raw)
	}
}

func (w *world) token(t *testing.T, email, pw, tenant string) string {
	t.Helper()
	body := map[string]any{"email": email, "password": pw}
	if tenant != "" {
		body["tenant"] = tenant
	}
	r := w.do(t, http.MethodPost, "/v1/auth/login", "", body)
	tok, _ := r.Data["access_token"].(string)
	if r.Status != http.StatusOK || tok == "" {
		t.Fatalf("login %s = %d %s", email, r.Status, r.Raw)
	}
	return tok
}

func (w *world) inviteToken(t *testing.T, email string) string {
	t.Helper()
	return w.text(t, `SELECT payload->>'token' FROM outbox WHERE topic = 'mail.send'
		AND payload->>'template' = 'invite' AND payload->>'to' = $1 ORDER BY id DESC LIMIT 1`, email)
}

func (w *world) do(t *testing.T, method, path, token string, body any) testkit.Response[map[string]any] {
	return w.doIf(t, method, path, token, body, "")
}

func (w *world) doIf(
	t *testing.T, method, path, token string, body any, ifMatch string,
) testkit.Response[map[string]any] {
	t.Helper()
	h := http.Header{}
	if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	if ifMatch != "" {
		h.Set("If-Match", ifMatch)
	}
	return testkit.Do[map[string]any](t, w.srv, method, path, body, h)
}

func (w *world) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := w.db.Leader().ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func (w *world) text(t *testing.T, query string, args ...any) string {
	t.Helper()
	var s string
	if err := w.db.Leader().QueryRowContext(context.Background(), query, args...).Scan(&s); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return s
}

func items(data map[string]any) []map[string]any {
	raw, _ := data["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func containsID(items []map[string]any, id string) bool {
	for _, it := range items {
		if it["id"] == id {
			return true
		}
	}
	return false
}

func diff(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
