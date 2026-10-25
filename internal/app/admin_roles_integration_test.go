package app

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// adminFixture is the app with two ordinary users: bia holds the seeded
// admin role, kim only the default member role.
type adminFixture struct {
	*loginFixture
	bia, kim string // access tokens
}

func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	f := newLoginFixture(t, nil)
	f.register(t)
	f.registerAs(t, "kim@example.com", "Kim")
	f.grant(t, "bia@example.com", "admin")
	return &adminFixture{loginFixture: f, bia: f.token(t, "bia@example.com"), kim: f.token(t, "kim@example.com")}
}

// registerAs signs another user up with loginPassword.
func (f *loginFixture) registerAs(t *testing.T, email, name string) {
	t.Helper()
	body := map[string]any{"email": email, "password": loginPassword, "display_name": name}
	if r := f.post(t, "/v1/auth/register", body); r.Status != http.StatusAccepted {
		t.Fatalf("register %s = %d: %s", email, r.Status, r.Raw)
	}
}

// token signs email in with loginPassword and returns the access token.
func (f *loginFixture) token(t *testing.T, email string) string {
	t.Helper()
	r := f.login(t, email, loginPassword)
	access, _ := r.Data["access_token"].(string)
	if r.Status != http.StatusOK || access == "" {
		t.Fatalf("login %s = %d %s", email, r.Status, r.Raw)
	}
	return access
}

// superToken clears the super admin's forced password change and signs in.
func (f *loginFixture) superToken(t *testing.T) string {
	t.Helper()
	f.exec(t, `UPDATE users SET must_change_password = false WHERE is_super_admin`)
	r := f.login(t, testSuperAdmin.Email, testSuperAdmin.Password)
	access, _ := r.Data["access_token"].(string)
	if r.Status != http.StatusOK || access == "" {
		t.Fatalf("super admin login = %d %s", r.Status, r.Raw)
	}
	return access
}

// userID returns the ID of the user whose display name is name.
func (f *loginFixture) userID(t *testing.T, name string) string {
	t.Helper()
	return f.text(t, `SELECT id::text FROM users WHERE display_name = $1`, name)
}

// grant assigns the named role in the default tenant to the user signed up
// as email; display names in these tests are unique.
func (f *loginFixture) grant(t *testing.T, email, role string) {
	t.Helper()
	name := map[string]string{"bia@example.com": "Bia", "kim@example.com": "Kim"}[email]
	f.exec(t, `INSERT INTO user_roles (tenant_id, user_id, role_id)
		SELECT r.tenant_id, u.id, r.id FROM roles r, users u
		WHERE r.tenant_id IS NOT NULL AND r.name = $1 AND u.display_name = $2`, role, name)
}

// roleID returns the ID of the tenant role called name.
func (f *loginFixture) roleID(t *testing.T, name string) string {
	t.Helper()
	return f.text(t, `SELECT id::text FROM roles WHERE tenant_id IS NOT NULL AND name = $1`, name)
}

func (f *loginFixture) text(t *testing.T, query string, args ...any) string {
	t.Helper()
	var s string
	if err := f.db.Leader().QueryRowContext(context.Background(), query, args...).Scan(&s); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return s
}

// do sends an authenticated admin request; ifMatch may be empty.
func (f *loginFixture) do(
	t *testing.T, method, path, token string, body any, ifMatch string,
) testkit.Response[map[string]any] {
	t.Helper()
	h := http.Header{"Authorization": {"Bearer " + token}}
	if ifMatch != "" {
		h.Set("If-Match", ifMatch)
	}
	return testkit.Do[map[string]any](t, f.srv, method, path, body, h)
}

// createRole creates a role as token and returns its ID.
func (f *adminFixture) createRole(t *testing.T, token, name string, perms ...string) string {
	t.Helper()
	r := f.do(t, http.MethodPost, "/v1/admin/roles", token,
		map[string]any{"name": name, "permissions": perms}, "")
	id, _ := r.Data["id"].(string)
	if r.Status != http.StatusCreated || id == "" {
		t.Fatalf("create role %s = %d %s", name, r.Status, r.Raw)
	}
	return id
}

// setPerms replaces a role's permissions at version 1.
func (f *adminFixture) setPerms(t *testing.T, token, id string, perms ...string) testkit.Response[map[string]any] {
	t.Helper()
	if perms == nil {
		perms = []string{}
	}
	return f.do(t, http.MethodPut, "/v1/admin/roles/"+id+"/permissions", token,
		map[string]any{"permissions": perms}, `"1"`)
}

// wantReason fails unless r has status and meta.reason.
func wantReason(t *testing.T, what string, r *testkit.Response[map[string]any], status int, want string) {
	t.Helper()
	if r.Status != status || reason(r) != want {
		t.Errorf("%s = %d %s, want %d %s", what, r.Status, r.Raw, status, want)
	}
}

// TestAdminRolesAuthorization checks roles:manage against the database: a
// member is refused, and an admin who loses the role or is disabled is
// refused at once although their token still lists it. The super admin needs
// no role.
func TestAdminRolesAuthorization(t *testing.T) {
	f := newAdminFixture(t)
	if r := f.do(t, http.MethodGet, "/v1/admin/roles", f.bia, nil, ""); r.Status != http.StatusOK {
		t.Fatalf("admin GET /v1/admin/roles = %d %s", r.Status, r.Raw)
	}
	if r := f.do(t, http.MethodGet, "/v1/admin/roles", f.kim, nil, ""); r.Status != http.StatusForbidden {
		t.Errorf("member GET /v1/admin/roles = %d, want 403", r.Status)
	}
	if r := f.do(t, http.MethodGet, "/v1/admin/roles", "not-a-token", nil, ""); r.Status != http.StatusUnauthorized {
		t.Errorf("bad token = %d, want 401", r.Status)
	}
	super := f.superToken(t)
	if r := f.callList(t, "/v1/admin/permissions", super); r.Status != http.StatusOK {
		t.Errorf("super admin GET /v1/admin/permissions = %d %s", r.Status, r.Raw)
	}

	f.exec(t, `UPDATE users SET status = 'disabled' WHERE display_name = 'Bia'`)
	if r := f.do(t, http.MethodGet, "/v1/admin/roles", f.bia, nil, ""); r.Status != http.StatusForbidden {
		t.Errorf("disabled admin = %d, want 403", r.Status)
	}
	f.exec(t, `UPDATE users SET status = 'active' WHERE display_name = 'Bia'`)
	f.exec(t, `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`,
		f.userID(t, "Bia"), f.roleID(t, "admin"))
	if r := f.do(t, http.MethodGet, "/v1/admin/roles", f.bia, nil, ""); r.Status != http.StatusForbidden {
		t.Errorf("admin without the role, old token = %d, want 403", r.Status)
	}
}

// TestAdminRolesCRUD walks the endpoints and checks each change is audited
// with before and after.
func TestAdminRolesCRUD(t *testing.T) {
	f := newAdminFixture(t)

	perms := f.callList(t, "/v1/admin/permissions", f.bia)
	if perms.Status != http.StatusOK || len(perms.Data) != 5 {
		t.Fatalf("GET /v1/admin/permissions = %d %s", perms.Status, perms.Raw)
	}
	for _, p := range perms.Data {
		if p["is_system"] != true || p["description"] == "" {
			t.Errorf("identity's own permission %v must be a described system key", p)
		}
	}

	id := f.createRole(t, f.bia, " Support ", "users:read", "users:read")
	r := f.do(t, http.MethodGet, "/v1/admin/roles/"+id, f.bia, nil, "")
	if r.Status != http.StatusOK || r.Data["name"] != "Support" || r.Data["version"] != float64(1) ||
		len(r.Data["permissions"].([]any)) != 1 {
		t.Fatalf("GET role = %d %s", r.Status, r.Raw)
	}
	wantReason(t, "duplicate name", new(f.do(t, http.MethodPost, "/v1/admin/roles", f.bia,
		map[string]any{"name": "SUPPORT"}, "")), http.StatusConflict, "DUPLICATE")

	list := f.do(t, http.MethodGet, "/v1/admin/roles?search=supp&size=1", f.bia, nil, "")
	items, _ := list.Data["items"].([]any)
	if list.Status != http.StatusOK || list.Data["total"] != float64(1) || len(items) != 1 {
		t.Fatalf("GET roles?search = %d %s", list.Status, list.Raw)
	}
	if item := items[0].(map[string]any); item["permission_count"] != float64(1) || item["user_count"] != float64(0) {
		t.Errorf("role summary = %v", item)
	}
	if r := f.do(t, http.MethodGet, "/v1/admin/roles?tenant_id=x", f.bia, nil, ""); r.Status != http.StatusBadRequest {
		t.Errorf("unknown list param = %d, want 400", r.Status)
	}

	patch := map[string]any{"description": "Front line"}
	r = f.do(t, http.MethodPatch, "/v1/admin/roles/"+id, f.bia, patch, "")
	if r.Status != http.StatusPreconditionRequired {
		t.Errorf("PATCH without If-Match = %d, want 428", r.Status)
	}
	wantReason(t, "PATCH stale version", new(f.do(t, http.MethodPatch, "/v1/admin/roles/"+id, f.bia, patch, `"7"`)),
		http.StatusConflict, "VERSION_CONFLICT")
	r = f.do(t, http.MethodPatch, "/v1/admin/roles/"+id, f.bia, patch, `"1"`)
	if r.Status != http.StatusOK || r.Data["description"] != "Front line" || r.Data["name"] != "Support" ||
		r.Data["version"] != float64(2) {
		t.Fatalf("PATCH = %d %s", r.Status, r.Raw)
	}

	r = f.do(t, http.MethodPut, "/v1/admin/roles/"+id+"/permissions", f.bia,
		map[string]any{"permissions": []string{"audit:read", "users:read"}, "version": 2}, "")
	if r.Status != http.StatusOK || r.Data["version"] != float64(3) || len(r.Data["permissions"].([]any)) != 2 {
		t.Fatalf("PUT permissions = %d %s", r.Status, r.Raw)
	}
	if r := f.do(t, http.MethodDelete, "/v1/admin/roles/"+id, f.bia, nil, ""); r.Status != http.StatusNoContent {
		t.Fatalf("DELETE = %d %s", r.Status, r.Raw)
	}
	if r := f.do(t, http.MethodGet, "/v1/admin/roles/"+id, f.bia, nil, ""); r.Status != http.StatusNotFound {
		t.Errorf("GET deleted role = %d, want 404", r.Status)
	}
	if r := f.do(t, http.MethodGet, "/v1/admin/roles/not-a-uuid", f.bia, nil, ""); r.Status != http.StatusNotFound {
		t.Errorf("GET malformed id = %d, want 404", r.Status)
	}

	for action, side := range map[string]string{
		"role.create": "after", "role.update": "before", "role.permissions": "before", "role.delete": "before",
	} {
		if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = $1 AND target_id = $2
			AND actor_id = $3 AND `+side+` IS NOT NULL`, action, id, f.userID(t, "Bia")); n != 1 {
			t.Errorf("audit %s rows = %d, want 1", action, n)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'role.permissions'
		AND before->'permissions' = '["users:read"]' AND after->'permissions' = '["audit:read","users:read"]'`); n != 1 {
		t.Errorf("role.permissions audit does not record before and after")
	}
}

// TestAdminRoleValidation is one row per body rule.
func TestAdminRoleValidation(t *testing.T) {
	f := newAdminFixture(t)
	id := f.createRole(t, f.bia, "Support")
	tests := []struct {
		name, method, path string
		body               map[string]any
	}{
		{"create: blank name", http.MethodPost, "/v1/admin/roles", map[string]any{"name": "  "}},
		{"create: name over 50", http.MethodPost, "/v1/admin/roles", map[string]any{"name": strings.Repeat("é", 51)}},
		{
			"create: description over 200", http.MethodPost, "/v1/admin/roles",
			map[string]any{"name": "ops", "description": strings.Repeat("d", 201)},
		},
		{"create: unknown field", http.MethodPost, "/v1/admin/roles", map[string]any{"name": "ops", "tenant_id": "x"}},
		{
			"create: unknown permission", http.MethodPost, "/v1/admin/roles",
			map[string]any{"name": "ops", "permissions": []string{"notes:read"}},
		},
		{"patch: empty name", http.MethodPatch, "/v1/admin/roles/" + id, map[string]any{"name": " "}},
		{"put: permissions missing", http.MethodPut, "/v1/admin/roles/" + id + "/permissions", map[string]any{}},
		{
			"put: unknown permission", http.MethodPut, "/v1/admin/roles/" + id + "/permissions",
			map[string]any{"permissions": []string{"users:fly"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if r := f.do(t, tt.method, tt.path, f.bia, tt.body, `"1"`); r.Status != http.StatusBadRequest {
				t.Errorf("%s = %d %s, want 400", tt.name, r.Status, r.Raw)
			}
		})
	}
	ok := f.createRole(t, f.bia, strings.Repeat("é", 50))
	if ok == "" {
		t.Error("a 50-rune name must be accepted")
	}
}

// TestAdminRolePermissionNotHeld lets an admin grant only what they hold;
// keys a role already grants may stay.
func TestAdminRolePermissionNotHeld(t *testing.T) {
	f := newAdminFixture(t)
	f.createRole(t, f.bia, "Role admins", "roles:manage", "users:read")
	f.grant(t, "kim@example.com", "Role admins")

	wantReason(t, "create with audit:read", new(f.do(t, http.MethodPost, "/v1/admin/roles", f.kim,
		map[string]any{"name": "Auditors", "permissions": []string{"audit:read"}}, "")),
		http.StatusForbidden, "PERMISSION_NOT_HELD")
	f.createRole(t, f.kim, "Readers", "users:read")

	id := f.createRole(t, f.bia, "Auditors", "audit:read")
	wantReason(t, "add users:manage", new(f.setPerms(t, f.kim, id, "audit:read", "users:manage")),
		http.StatusForbidden, "PERMISSION_NOT_HELD")
	if r := f.setPerms(t, f.kim, id, "audit:read", "users:read"); r.Status != http.StatusOK {
		t.Errorf("keep audit:read, add users:read = %d %s, want 200", r.Status, r.Raw)
	}
}

// TestAdminRoleSelfEscalation refuses changing or deleting a role the caller
// holds that grants roles:manage; renaming it is allowed.
func TestAdminRoleSelfEscalation(t *testing.T) {
	f := newAdminFixture(t)
	admin := f.roleID(t, "admin")
	wantReason(t, "PUT own admin role", new(f.setPerms(t, f.bia, admin, "roles:manage")),
		http.StatusForbidden, "SELF_ESCALATION")
	wantReason(t, "DELETE own admin role", new(f.do(t, http.MethodDelete, "/v1/admin/roles/"+admin+"?force=true",
		f.bia, nil, "")), http.StatusForbidden, "SELF_ESCALATION")
	if r := f.do(t, http.MethodPatch, "/v1/admin/roles/"+admin, f.bia,
		map[string]any{"description": "Everything"}, `"1"`); r.Status != http.StatusOK {
		t.Errorf("PATCH own admin role description = %d %s, want 200", r.Status, r.Raw)
	}
	member := f.roleID(t, "member")
	if r := f.setPerms(t, f.bia, member, "users:read"); r.Status != http.StatusOK {
		t.Errorf("PUT a held role without roles:manage = %d %s, want 200", r.Status, r.Raw)
	}
}

// TestAdminSystemRole refuses every change to an is_system role.
func TestAdminSystemRole(t *testing.T) {
	f := newAdminFixture(t)
	id := f.createRole(t, f.bia, "Locked")
	f.exec(t, `UPDATE roles SET is_system = true WHERE id = $1`, id)
	path := "/v1/admin/roles/" + id
	wantReason(t, "PATCH", new(f.do(t, http.MethodPatch, path, f.bia, map[string]any{"name": "x"}, `"1"`)),
		http.StatusForbidden, "SYSTEM_ROLE")
	wantReason(t, "PUT", new(f.setPerms(t, f.bia, id, "users:read")), http.StatusForbidden, "SYSTEM_ROLE")
	wantReason(t, "DELETE", new(f.do(t, http.MethodDelete, path, f.bia, nil, "")), http.StatusForbidden, "SYSTEM_ROLE")
}

// TestAdminRoleInUse needs ?force=true to delete an assigned role, which then
// removes the assignments in the same transaction.
func TestAdminRoleInUse(t *testing.T) {
	f := newAdminFixture(t)
	id := f.createRole(t, f.bia, "Readers", "users:read")
	f.grant(t, "kim@example.com", "Readers")
	path := "/v1/admin/roles/" + id
	wantReason(t, "DELETE assigned", new(f.do(t, http.MethodDelete, path, f.bia, nil, "")),
		http.StatusConflict, "ROLE_IN_USE")
	if r := f.do(t, http.MethodDelete, path+"?force=true", f.bia, nil, ""); r.Status != http.StatusNoContent {
		t.Fatalf("DELETE ?force=true = %d %s", r.Status, r.Raw)
	}
	if n := f.count(t, `SELECT count(*) FROM user_roles WHERE role_id = $1`, id); n != 0 {
		t.Errorf("assignments after forced delete = %d, want 0", n)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'role.delete'
		AND (before->>'users')::int = 1`); n != 1 {
		t.Errorf("role.delete audit does not record the removed assignments")
	}
}

// TestAdminLastAdmin refuses the change that would leave the tenant with no
// active roles:manage holder, even from the super admin, and leaves the role
// unchanged.
func TestAdminLastAdmin(t *testing.T) {
	f := newAdminFixture(t)
	super := f.superToken(t)
	admin := f.roleID(t, "admin")

	wantReason(t, "drop roles:manage from the only admin role", new(f.setPerms(t, super, admin, "users:read")),
		http.StatusConflict, "LAST_ADMIN")
	if n := f.count(t, `SELECT count(*) FROM role_permissions WHERE role_id = $1`, admin); n != 4 {
		t.Errorf("admin role permissions after refusal = %d, want 4", n)
	}
	wantReason(t, "delete the only admin role", new(f.do(t, http.MethodDelete, "/v1/admin/roles/"+admin+"?force=true",
		super, nil, "")), http.StatusConflict, "LAST_ADMIN")

	f.createRole(t, f.bia, "Managers", "roles:manage")
	f.grant(t, "kim@example.com", "Managers")
	if r := f.setPerms(t, super, admin, "users:read"); r.Status != http.StatusOK {
		t.Errorf("drop roles:manage with another holder = %d %s, want 200", r.Status, r.Raw)
	}
}
