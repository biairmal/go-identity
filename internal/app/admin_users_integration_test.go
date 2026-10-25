package app

import (
	"net/http"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// kimRefresh signs kim in again and returns the refresh token.
func (f *adminFixture) kimRefresh(t *testing.T) string {
	t.Helper()
	r := f.login(t, "kim@example.com", loginPassword)
	rt, _ := r.Data["refresh_token"].(string)
	if r.Status != http.StatusOK || rt == "" {
		t.Fatalf("kim login = %d %s", r.Status, r.Raw)
	}
	return rt
}

// kimPassword returns the stored hash and update time of kim's credentials.
func (f *adminFixture) kimPassword(t *testing.T) string {
	t.Helper()
	return f.text(t, `SELECT c.password_hash || c.updated_at::text FROM credentials c
		JOIN users u ON u.id = c.user_id WHERE u.display_name = 'Kim'`)
}

func (f *adminFixture) superID(t *testing.T) string {
	t.Helper()
	return f.text(t, `SELECT id::text FROM users WHERE is_super_admin`)
}

// items returns the items of a page response.
func items(r map[string]any) []map[string]any {
	raw, _ := r["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		m, _ := it.(map[string]any)
		out = append(out, m)
	}
	return out
}

// TestAdminUsersList filters, searches and pages the tenant's members, and
// refuses a member without users:read.
func TestAdminUsersList(t *testing.T) {
	f := newAdminFixture(t)
	list := func(query string) map[string]any {
		t.Helper()
		r := f.do(t, http.MethodGet, "/v1/admin/users"+query, f.bia, nil, "")
		if r.Status != http.StatusOK {
			t.Fatalf("GET /v1/admin/users%s = %d %s", query, r.Status, r.Raw)
		}
		return r.Data
	}

	all := list("")
	if all["total"] != float64(3) {
		t.Fatalf("members = %v, want bia, kim and the super admin", all["total"])
	}
	for _, it := range items(all) {
		if it["display_name"] != "Kim" {
			continue
		}
		roles, _ := it["roles"].([]any)
		if it["email"] != "kim@example.com" || it["membership_status"] != "active" || it["status"] != "active" ||
			len(roles) != 1 || roles[0].(map[string]any)["name"] != "member" || it["created_at"] == nil {
			t.Errorf("kim = %v", it)
		}
	}

	for query, want := range map[string]float64{
		"?search=KI":                    1, // display name, case-insensitive
		"?search=%20KIM@Example.com%20": 1, // exact email through the blind index
		"?search=kim@":                  0, // a partial email matches nothing
		"?status=disabled":              0,
		"?status=active":                3,
		"?role=" + f.roleID(t, "admin"): 1,
	} {
		if got := list(query)["total"]; got != want {
			t.Errorf("GET /v1/admin/users%s total = %v, want %v", query, got, want)
		}
	}
	page := list("?size=1&page=3&sort=display_name,ASC")
	if its := items(page); len(its) != 1 || its[0]["display_name"] != "Kim" || page["has_prev"] != true {
		t.Errorf("page 3 of 1 by name (the super admin has no name) = %v", page)
	}
	if got := list("?size=500")["size"]; got != float64(100) {
		t.Errorf("size=500 answers size %v, want the 100 maximum", got)
	}
	for _, q := range []string{"?status=gone", "?role=x", "?sort=email,ASC", "?tenant_id=x"} {
		if r := f.do(t, http.MethodGet, "/v1/admin/users"+q, f.bia, nil, ""); r.Status != http.StatusBadRequest {
			t.Errorf("GET /v1/admin/users%s = %d, want 400", q, r.Status)
		}
	}
	if r := f.do(t, http.MethodGet, "/v1/admin/users", f.kim, nil, ""); r.Status != http.StatusForbidden {
		t.Errorf("member GET /v1/admin/users = %d, want 403", r.Status)
	}
}

// TestAdminUserGet returns roles, sign-in methods and version, and 404 for
// anyone outside the tenant.
func TestAdminUserGet(t *testing.T) {
	f := newAdminFixture(t)
	r := f.do(t, http.MethodGet, "/v1/admin/users/"+f.userID(t, "Kim"), f.bia, nil, "")
	providers, _ := r.Data["providers"].(map[string]any)
	if r.Status != http.StatusOK || providers["password"] != true || providers["google"] != false ||
		r.Data["version"] == nil || r.Data["email"] != "kim@example.com" {
		t.Fatalf("GET user = %d %s", r.Status, r.Raw)
	}
	for _, id := range []string{"00000000-0000-0000-0000-000000000001", "not-a-uuid"} {
		if r := f.do(t, http.MethodGet, "/v1/admin/users/"+id, f.bia, nil, ""); r.Status != http.StatusNotFound {
			t.Errorf("GET user %s = %d, want 404", id, r.Status)
		}
	}
}

// TestAdminUserDisableEnable blocks sign-in and revokes sessions, leaves the
// password alone, and audits each change once.
func TestAdminUserDisableEnable(t *testing.T) {
	f := newAdminFixture(t)
	kim := f.userID(t, "Kim")
	rt := f.kimRefresh(t)
	hash := f.kimPassword(t)

	if r := f.do(t, http.MethodPost, "/v1/admin/users/"+kim+"/disable", f.bia, nil, ""); r.Status != http.StatusNoContent {
		t.Fatalf("disable = %d %s", r.Status, r.Raw)
	}
	if status, _, _ := f.refresh(t, rt); status != http.StatusUnauthorized {
		t.Errorf("refresh after disable = %d, want 401", status)
	}
	wantReason(t, "login when disabled", new(f.login(t, "kim@example.com", loginPassword)),
		http.StatusForbidden, "ACCOUNT_DISABLED")
	if r := f.do(t, http.MethodPost, "/v1/admin/users/"+kim+"/disable", f.bia, nil, ""); r.Status != http.StatusNoContent {
		t.Errorf("second disable = %d, want 204", r.Status)
	}
	if r := f.do(t, http.MethodPost, "/v1/admin/users/"+kim+"/enable", f.bia, nil, ""); r.Status != http.StatusNoContent {
		t.Fatalf("enable = %d %s", r.Status, r.Raw)
	}
	f.kimRefresh(t)
	if f.kimPassword(t) != hash {
		t.Error("disable and enable changed the credentials")
	}
	for action, want := range map[string]int{"user.disable": 1, "user.enable": 1} {
		if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = $1 AND target_id = $2
			AND actor_id = $3`, action, kim, f.userID(t, "Bia")); n != want {
			t.Errorf("audit %s = %d, want %d", action, n, want)
		}
	}

	self := "/v1/admin/users/" + f.userID(t, "Bia") + "/disable"
	if r := f.do(t, http.MethodPost, self, f.bia, nil, ""); r.Status != http.StatusForbidden {
		t.Errorf("disable yourself = %d, want 403", r.Status)
	}
	if r := f.do(t, http.MethodPost, "/v1/admin/users/"+kim+"/disable", f.kim, nil, ""); r.Status != http.StatusForbidden {
		t.Errorf("member disables = %d, want 403", r.Status)
	}
}

// TestAdminSuperAdminProtected refuses every change to the super admin's
// status, roles or membership.
func TestAdminSuperAdminProtected(t *testing.T) {
	f := newAdminFixture(t)
	path := "/v1/admin/users/" + f.superID(t)
	for name, r := range map[string]struct{ method, path string }{
		"disable": {http.MethodPost, path + "/disable"},
		"enable":  {http.MethodPost, path + "/enable"},
		"remove":  {http.MethodDelete, path},
	} {
		wantReason(t, name, new(f.do(t, r.method, r.path, f.bia, nil, "")), http.StatusForbidden, "SUPER_ADMIN_PROTECTED")
	}
	wantReason(t, "roles", new(f.do(t, http.MethodPut, path+"/roles", f.bia,
		map[string]any{"role_ids": []string{}}, "")), http.StatusForbidden, "SUPER_ADMIN_PROTECTED")
}

// TestAdminUserRoles replaces a member's roles under the grant and
// self-escalation rules, without touching the password.
func TestAdminUserRoles(t *testing.T) {
	f := newAdminFixture(t)
	f.registerAs(t, "lee@example.com", "Lee")
	kim, lee := f.userID(t, "Kim"), f.userID(t, "Lee")
	set := func(token, id string, roleIDs ...string) testkit.Response[map[string]any] {
		t.Helper()
		if roleIDs == nil {
			roleIDs = []string{}
		}
		return f.do(t, http.MethodPut, "/v1/admin/users/"+id+"/roles", token, map[string]any{"role_ids": roleIDs}, "")
	}
	hash := f.kimPassword(t)

	admin, member := f.roleID(t, "admin"), f.roleID(t, "member")
	r := set(f.bia, kim, admin, admin)
	roles, _ := r.Data["roles"].([]any)
	if r.Status != http.StatusOK || len(roles) != 1 || roles[0].(map[string]any)["name"] != "admin" {
		t.Fatalf("PUT kim roles [admin] = %d %s", r.Status, r.Raw)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'user.roles_assigned' AND target_id = $1
		AND before->'roles' = '["member"]' AND after->'roles' = '["admin"]'`, kim); n != 1 {
		t.Error("user.roles_assigned audit does not record before and after")
	}
	if f.kimPassword(t) != hash {
		t.Error("changing roles changed the credentials")
	}
	wantReason(t, "own roles", new(set(f.bia, f.userID(t, "Bia"), member)), http.StatusForbidden, "SELF_ESCALATION")
	if r := set(f.bia, kim, "00000000-0000-0000-0000-000000000001"); r.Status != http.StatusBadRequest {
		t.Errorf("unknown role = %d, want 400", r.Status)
	}
	if r := set(f.bia, "00000000-0000-0000-0000-000000000001", member); r.Status != http.StatusNotFound {
		t.Errorf("roles of a non-member = %d, want 404", r.Status)
	}

	f.createRole(t, f.bia, "Staff", "users:read", "users:manage")
	if r := set(f.bia, kim, f.roleID(t, "Staff")); r.Status != http.StatusOK {
		t.Fatalf("PUT kim roles [Staff] = %d %s", r.Status, r.Raw)
	}
	wantReason(t, "grant admin without roles:manage", new(set(f.kim, lee, admin)),
		http.StatusForbidden, "PERMISSION_NOT_HELD")
	if r := set(f.kim, lee, member); r.Status != http.StatusOK {
		t.Errorf("grant member = %d %s, want 200", r.Status, r.Raw)
	}
}

// TestAdminUserLastAdmin refuses disabling, removing or stripping the last
// active roles:manage holder, even for the super admin.
func TestAdminUserLastAdmin(t *testing.T) {
	f := newAdminFixture(t)
	super := f.superToken(t)
	bia := f.userID(t, "Bia")
	path := "/v1/admin/users/" + bia
	wantReason(t, "disable", new(f.do(t, http.MethodPost, path+"/disable", super, nil, "")),
		http.StatusConflict, "LAST_ADMIN")
	wantReason(t, "remove", new(f.do(t, http.MethodDelete, path, super, nil, "")), http.StatusConflict, "LAST_ADMIN")
	wantReason(t, "strip roles", new(f.do(t, http.MethodPut, path+"/roles", super,
		map[string]any{"role_ids": []string{}}, "")), http.StatusConflict, "LAST_ADMIN")
	if n := f.count(t, `SELECT count(*) FROM users WHERE id = $1 AND status = 'active'`, bia); n != 1 {
		t.Error("a refused disable changed the status")
	}

	f.grant(t, "kim@example.com", "admin")
	if r := f.do(t, http.MethodPost, path+"/disable", super, nil, ""); r.Status != http.StatusNoContent {
		t.Errorf("disable with another admin = %d %s, want 204", r.Status, r.Raw)
	}
}

// TestAdminUserRemove takes a member out of the tenant with their roles; the
// account stays, and the user is gone from the admin views.
func TestAdminUserRemove(t *testing.T) {
	f := newAdminFixture(t)
	kim := f.userID(t, "Kim")
	if r := f.do(t, http.MethodDelete, "/v1/admin/users/"+kim, f.bia, nil, ""); r.Status != http.StatusNoContent {
		t.Fatalf("remove = %d %s", r.Status, r.Raw)
	}
	if r := f.do(t, http.MethodGet, "/v1/admin/users/"+kim, f.bia, nil, ""); r.Status != http.StatusNotFound {
		t.Errorf("GET removed user = %d, want 404", r.Status)
	}
	if r := f.do(t, http.MethodGet, "/v1/admin/users", f.bia, nil, ""); r.Data["total"] != float64(2) {
		t.Errorf("members after remove = %v, want 2", r.Data["total"])
	}
	if n := f.count(t, `SELECT count(*) FROM user_roles WHERE user_id = $1`, kim); n != 0 {
		t.Errorf("roles after remove = %d, want 0", n)
	}
	if n := f.count(t, `SELECT count(*) FROM tenant_members WHERE user_id = $1 AND status = 'removed'`, kim); n != 1 {
		t.Error("membership not marked removed")
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'member.remove' AND target_id = $1
		AND actor_id = $2`, kim, f.userID(t, "Bia")); n != 1 {
		t.Error("member.remove not audited with the actor")
	}
	if r := f.do(t, http.MethodDelete, "/v1/admin/users/"+kim, f.bia, nil, ""); r.Status != http.StatusNotFound {
		t.Errorf("second remove = %d, want 404", r.Status)
	}
}

// TestAdminRevokeSessions signs a member out of every device in the tenant.
func TestAdminRevokeSessions(t *testing.T) {
	f := newAdminFixture(t)
	kim := f.userID(t, "Kim")
	rt := f.kimRefresh(t)
	revoke := "/v1/admin/users/" + kim + "/revoke-sessions"
	if r := f.do(t, http.MethodPost, revoke, f.bia, nil, ""); r.Status != http.StatusNoContent {
		t.Fatalf("revoke-sessions = %d %s", r.Status, r.Raw)
	}
	if status, _, _ := f.refresh(t, rt); status != http.StatusUnauthorized {
		t.Errorf("refresh after revoke = %d, want 401", status)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log
		WHERE action = 'session.revoke_all' AND target_id = $1`, kim); n != 1 {
		t.Error("session.revoke_all not audited")
	}
	missing := "/v1/admin/users/00000000-0000-0000-0000-000000000001/revoke-sessions"
	if r := f.do(t, http.MethodPost, missing, f.bia, nil, ""); r.Status != http.StatusNotFound {
		t.Errorf("revoke for a non-member = %d, want 404", r.Status)
	}
	if r := f.do(t, http.MethodPost, revoke, f.kim, nil, ""); r.Status != http.StatusForbidden {
		t.Errorf("member revokes = %d, want 403", r.Status)
	}
}
