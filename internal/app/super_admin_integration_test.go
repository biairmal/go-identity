package app

import (
	"net/http"
	"testing"
)

// superFixture is a multi-mode app with the super admin signed in. The super
// admin is bootstrapped into the default tenant on start.
type superFixture struct {
	*loginFixture
	super string // the super admin's access token
}

func newSuperFixture(t *testing.T) *superFixture {
	t.Helper()
	f := newLoginFixture(t, func(c *Config) { c.Modules.Tenant.Mode = "multi" })
	return &superFixture{loginFixture: f, super: f.superToken(t)}
}

// createTenant posts a new tenant and returns the response.
func (f *superFixture) createTenant(t *testing.T, slug, name, firstAdmin string) map[string]any {
	t.Helper()
	r := f.do(t, http.MethodPost, "/v1/admin/tenants", f.super,
		map[string]any{"slug": slug, "name": name, "first_admin_email": firstAdmin}, "")
	if r.Status != http.StatusCreated {
		t.Fatalf("create tenant %s = %d %s", slug, r.Status, r.Raw)
	}
	return r.Data
}

// TestSuperAdminTenantsCRUD creates, lists, reads and updates tenants, and
// proves a new tenant copies the template roles and invites its first admin.
func TestSuperAdminTenantsCRUD(t *testing.T) {
	f := newSuperFixture(t)
	created := f.createTenant(t, "acme", "Acme", "admin@acme.test")
	if created["slug"] != "acme" || created["status"] != "active" || created["version"] != float64(1) {
		t.Fatalf("created tenant = %v", created)
	}
	acme := f.text(t, `SELECT id::text FROM tenants WHERE slug = 'acme'`)

	// Template roles were copied into the new tenant.
	if n := f.count(t, `SELECT count(*) FROM roles WHERE tenant_id = $1`, acme); n != 2 {
		t.Errorf("acme roles = %d, want 2 (admin, member)", n)
	}
	if n := f.count(t, `SELECT count(*) FROM roles WHERE tenant_id = $1 AND name = 'admin'`, acme); n != 1 {
		t.Error("acme has no admin role copied from the template")
	}
	// The first admin was invited: a pending account, an invited membership,
	// and a queued invite mail.
	if n := f.count(t, `SELECT count(*) FROM tenant_members m JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND m.status = 'invited'`, acme); n != 1 {
		t.Error("the first admin was not invited into acme")
	}
	if f.inviteToken(t, "admin@acme.test") == "" {
		t.Error("no invite mail queued for the first admin")
	}

	// List shows acme and the default tenant, with member counts.
	list := f.do(t, http.MethodGet, "/v1/admin/tenants", f.super, nil, "")
	if list.Status != http.StatusOK || len(items(list.Data)) != 2 {
		t.Fatalf("list = %d %s, want 2 tenants", list.Status, list.Raw)
	}
	filtered := f.do(t, http.MethodGet, "/v1/admin/tenants?search=acme", f.super, nil, "")
	if len(items(filtered.Data)) != 1 {
		t.Errorf("search=acme returned %d tenants, want 1", len(items(filtered.Data)))
	}

	// Get one tenant.
	got := f.do(t, http.MethodGet, "/v1/admin/tenants/"+acme, f.super, nil, "")
	if got.Status != http.StatusOK || got.Data["slug"] != "acme" {
		t.Fatalf("get = %d %s", got.Status, got.Raw)
	}

	// Rename, then suspend.
	renamed := f.do(t, http.MethodPatch, "/v1/admin/tenants/"+acme, f.super, map[string]any{"name": "Acme Inc"}, `"1"`)
	if renamed.Status != http.StatusOK || renamed.Data["name"] != "Acme Inc" || renamed.Data["version"] != float64(2) {
		t.Fatalf("rename = %d %s", renamed.Status, renamed.Raw)
	}
	suspended := f.do(t, http.MethodPatch, "/v1/admin/tenants/"+acme, f.super,
		map[string]any{"status": "suspended"}, `"2"`)
	if suspended.Status != http.StatusOK || suspended.Data["status"] != "suspended" {
		t.Fatalf("suspend = %d %s", suspended.Status, suspended.Raw)
	}
	// A stale version is refused.
	if stale := f.do(t, http.MethodPatch, "/v1/admin/tenants/"+acme, f.super,
		map[string]any{"name": "x"}, `"1"`); stale.Status != http.StatusConflict {
		t.Errorf("stale version = %d, want 409", stale.Status)
	}

	// A slug already in use is DUPLICATE.
	dup := f.do(t, http.MethodPost, "/v1/admin/tenants", f.super,
		map[string]any{"slug": "acme", "name": "Other", "first_admin_email": "x@acme.test"}, "")
	wantReason(t, "duplicate slug", new(dup), http.StatusConflict, "DUPLICATE")
}

// TestCreateTenantFirstAdminCanAccept walks the whole onboarding: the invited
// first admin accepts and lands in the new tenant with the admin role.
func TestCreateTenantFirstAdminCanAccept(t *testing.T) {
	f := newSuperFixture(t)
	f.createTenant(t, "acme", "Acme", "admin@acme.test")
	token := f.inviteToken(t, "admin@acme.test")

	accept := f.post(t, "/v1/auth/invite/accept", map[string]any{"token": token, "password": loginPassword})
	tenant, _ := accept.Data["tenant"].(map[string]any)
	if accept.Status != http.StatusOK || tenant["slug"] != "acme" {
		t.Fatalf("accept = %d %s", accept.Status, accept.Raw)
	}
	access, _ := accept.Data["access_token"].(string)
	// The first admin holds roles:manage in the new tenant: an admin route answers.
	if r := f.get(t, "/v1/admin/roles", access); r.Status != http.StatusOK {
		t.Errorf("first admin GET /v1/admin/roles = %d %s, want 200", r.Status, r.Raw)
	}
}

// TestSuperAdminCannotSuspendDefault refuses suspending the default tenant.
func TestSuperAdminCannotSuspendDefault(t *testing.T) {
	f := newSuperFixture(t)
	def := f.text(t, `SELECT id::text FROM tenants WHERE slug = 'default'`)
	version := f.text(t, `SELECT version::text FROM tenants WHERE slug = 'default'`)
	body := map[string]any{"status": "suspended"}
	r := f.do(t, http.MethodPatch, "/v1/admin/tenants/"+def, f.super, body, `"`+version+`"`)
	if r.Status != http.StatusBadRequest {
		t.Errorf("suspend default = %d %s, want 400", r.Status, r.Raw)
	}
}

// TestSuperAdminRoleTemplatesCRUD manages templates and shows a new template
// reaches only tenants created afterwards.
func TestSuperAdminRoleTemplatesCRUD(t *testing.T) {
	f := newSuperFixture(t)
	// The configured roles are seeded as templates on start.
	list := f.callList(t, "/v1/admin/role-templates", f.super)
	if list.Status != http.StatusOK || len(list.Data) != 2 {
		t.Fatalf("list templates = %d %s, want admin and member", list.Status, list.Raw)
	}

	created := f.do(t, http.MethodPost, "/v1/admin/role-templates", f.super,
		map[string]any{"name": "viewer", "description": "read only", "permissions": []string{"users:read"}}, "")
	if created.Status != http.StatusCreated {
		t.Fatalf("create template = %d %s", created.Status, created.Raw)
	}

	// An unknown permission is 400; a duplicate name is 409.
	bad := f.do(t, http.MethodPost, "/v1/admin/role-templates", f.super,
		map[string]any{"name": "x", "permissions": []string{"not:real"}}, "")
	if bad.Status != http.StatusBadRequest {
		t.Errorf("unknown permission = %d, want 400", bad.Status)
	}
	dup := f.do(t, http.MethodPost, "/v1/admin/role-templates", f.super,
		map[string]any{"name": "viewer", "permissions": []string{}}, "")
	wantReason(t, "duplicate template", new(dup), http.StatusConflict, "DUPLICATE")

	// A tenant created now copies viewer too.
	f.createTenant(t, "acme", "Acme", "admin@acme.test")
	acme := f.text(t, `SELECT id::text FROM tenants WHERE slug = 'acme'`)
	if n := f.count(t, `SELECT count(*) FROM roles WHERE tenant_id = $1`, acme); n != 3 {
		t.Errorf("acme roles = %d, want 3 (admin, member, viewer)", n)
	}

	viewerID := created.Data["id"].(string)
	patched := f.do(t, http.MethodPatch, "/v1/admin/role-templates/"+viewerID, f.super,
		map[string]any{"permissions": []string{"users:read", "audit:read"}}, `"1"`)
	if patched.Status != http.StatusOK {
		t.Fatalf("patch template = %d %s", patched.Status, patched.Raw)
	}

	del := f.do(t, http.MethodDelete, "/v1/admin/role-templates/"+viewerID, f.super, nil, "")
	if del.Status != http.StatusNoContent {
		t.Fatalf("delete template = %d %s", del.Status, del.Raw)
	}
	// acme keeps its copied viewer role although the template is gone.
	if n := f.count(t, `SELECT count(*) FROM roles WHERE tenant_id = $1 AND name = 'viewer'`, acme); n != 1 {
		t.Error("deleting the template removed the copied role from acme")
	}
}

// TestSuperAdminRoutes404InSingleMode hides the 9.7 routes in single mode.
func TestSuperAdminRoutes404InSingleMode(t *testing.T) {
	f := newLoginFixture(t, nil) // single mode
	super := f.superToken(t)
	for _, path := range []string{"/v1/admin/tenants", "/v1/admin/role-templates"} {
		if r := f.do(t, http.MethodGet, path, super, nil, ""); r.Status != http.StatusNotFound {
			t.Errorf("single mode GET %s = %d, want 404", path, r.Status)
		}
	}
	body := map[string]any{"slug": "acme", "name": "Acme", "first_admin_email": "a@acme.test"}
	if r := f.do(t, http.MethodPost, "/v1/admin/tenants", super, body, ""); r.Status != http.StatusNotFound {
		t.Errorf("single mode POST /v1/admin/tenants = %d, want 404", r.Status)
	}
}

// TestSuperAdminRoutesRequireSaClaim refuses a tenant admin without the sa claim.
func TestSuperAdminRoutesRequireSaClaim(t *testing.T) {
	f := newMultiAdminFixture(t) // bia is a tenant admin in the default tenant
	if r := f.do(t, http.MethodGet, "/v1/admin/tenants", f.bia, nil, ""); r.Status != http.StatusForbidden {
		t.Errorf("tenant admin GET /v1/admin/tenants = %d %s, want 403", r.Status, r.Raw)
	}
	if r := f.do(t, http.MethodGet, "/v1/admin/role-templates", f.bia, nil, ""); r.Status != http.StatusForbidden {
		t.Errorf("tenant admin GET /v1/admin/role-templates = %d, want 403", r.Status)
	}
}
