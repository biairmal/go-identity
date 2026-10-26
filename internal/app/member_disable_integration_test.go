package app

import (
	"net/http"
	"testing"
)

// newMultiAdminFixture is a multi-tenant app where bia administers the default
// tenant and kim belongs to both the default tenant and "acme", where she is
// the only roles:manage holder. Kim holds the admin role in the default
// tenant, so her token there passes the admin authorizer.
func newMultiAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	f := newLoginFixture(t, func(c *Config) { c.Modules.Tenant.Mode = "multi" })
	for _, u := range []struct{ email, name string }{{"bia@example.com", "Bia"}, {"kim@example.com", "Kim"}} {
		body := map[string]any{
			"email": u.email, "password": loginPassword, "display_name": u.name, "tenant": "default",
		}
		if r := f.post(t, "/v1/auth/register", body); r.Status != http.StatusAccepted {
			t.Fatalf("register %s = %d %s", u.email, r.Status, r.Raw)
		}
	}
	f.grant(t, "bia@example.com", "admin")
	f.grant(t, "kim@example.com", "admin")
	f.exec(t, `INSERT INTO tenants (slug, name) VALUES ('acme', 'Acme')`)
	f.exec(t, `INSERT INTO tenant_members (tenant_id, user_id, status, joined_at)
		SELECT t.id, u.id, 'active', now() FROM tenants t, users u WHERE t.slug = 'acme' AND u.display_name = 'Kim'`)
	f.exec(t, `INSERT INTO roles (tenant_id, name) SELECT id, 'owner' FROM tenants WHERE slug = 'acme'`)
	f.exec(t, `INSERT INTO role_permissions (role_id, permission_key)
		SELECT r.id, 'roles:manage' FROM roles r WHERE r.name = 'owner'`)
	f.exec(t, `INSERT INTO user_roles (tenant_id, user_id, role_id)
		SELECT r.tenant_id, u.id, r.id FROM roles r, users u WHERE r.name = 'owner' AND u.display_name = 'Kim'`)
	return &adminFixture{loginFixture: f, bia: f.token(t, "bia@example.com")}
}

// kimIn signs kim into a tenant and returns the response.
func (f *adminFixture) kimIn(t *testing.T, slug string) map[string]any {
	t.Helper()
	r := f.post(t, "/v1/auth/login",
		map[string]any{"email": "kim@example.com", "password": loginPassword, "tenant": slug})
	if r.Status != http.StatusOK {
		t.Fatalf("kim login in %s = %d %s", slug, r.Status, r.Raw)
	}
	return r.Data
}

// TestTenantScopedDisable disables a user in one tenant and checks that the
// other tenant, the account and the admin views behave as TRD 5.2 and 9.6
// describe, and that enabling restores everything.
func TestTenantScopedDisable(t *testing.T) {
	f := newMultiAdminFixture(t)
	kim := f.userID(t, "Kim")
	kimAdmin, _ := f.kimIn(t, "default")["access_token"].(string)
	acme := f.kimIn(t, "acme")
	acmeRefresh, _ := acme["refresh_token"].(string)
	defaultRefresh, _ := f.kimIn(t, "default")["refresh_token"].(string)

	if r := f.do(t, http.MethodPost, "/v1/admin/users/"+kim+"/disable", f.bia, nil, ""); r.Status != http.StatusNoContent {
		t.Fatalf("disable = %d %s", r.Status, r.Raw)
	}

	if status := f.text(t, `SELECT status FROM users WHERE id = $1`, kim); status != "active" {
		t.Errorf("users.status = %s after a tenant disable, want active", status)
	}
	if got := f.text(t, `SELECT tm.status FROM tenant_members tm JOIN tenants t ON t.id = tm.tenant_id
		WHERE t.slug = 'default' AND tm.user_id = $1`, kim); got != "disabled" {
		t.Errorf("membership = %s, want disabled", got)
	}
	// Sessions: gone in the disabling tenant, kept in the other.
	if status, _, _ := f.refresh(t, defaultRefresh); status != http.StatusUnauthorized {
		t.Errorf("refresh of a revoked default session = %d, want 401", status)
	}
	if status, _, _ := f.refresh(t, acmeRefresh); status != http.StatusOK {
		t.Errorf("refresh in the other tenant = %d, want 200", status)
	}
	wantReason(t, "login in the disabling tenant", new(f.post(t, "/v1/auth/login", map[string]any{
		"email": "kim@example.com", "password": loginPassword, "tenant": "default",
	})), http.StatusForbidden, "ACCOUNT_DISABLED")
	f.kimIn(t, "acme")
	if r := f.login(t, "kim@example.com", loginPassword); r.Status != http.StatusOK || r.Data["tenant"] == nil {
		t.Errorf("login without a tenant = %d %s, want a token for the only open tenant", r.Status, r.Raw)
	}
	if r := f.do(t, http.MethodGet, "/v1/admin/users", kimAdmin, nil, ""); r.Status != http.StatusForbidden {
		t.Errorf("admin route with a disabled membership = %d, want 403", r.Status)
	}

	// Admin views.
	detail := f.do(t, http.MethodGet, "/v1/admin/users/"+kim, f.bia, nil, "")
	if detail.Data["membership_status"] != "disabled" || detail.Data["status"] != "active" {
		t.Errorf("detail = %s, want membership_status disabled and status active", detail.Raw)
	}
	for filter, want := range map[string]int{"disabled": 1, "active": 2, "invited": 0} {
		r := f.do(t, http.MethodGet, "/v1/admin/users?membership_status="+filter, f.bia, nil, "")
		if r.Status != http.StatusOK || len(items(r.Data)) != want {
			t.Errorf("membership_status=%s = %d with %d items, want %d", filter, r.Status, len(items(r.Data)), want)
		}
	}
	bogus := f.do(t, http.MethodGet, "/v1/admin/users?membership_status=bogus", f.bia, nil, "")
	if bogus.Status != http.StatusBadRequest {
		t.Errorf("unknown membership_status = %d, want 400", bogus.Status)
	}

	// Enable restores it; a second enable is a no-op.
	for range 2 {
		if r := f.do(t, http.MethodPost, "/v1/admin/users/"+kim+"/enable", f.bia, nil, ""); r.Status != http.StatusNoContent {
			t.Fatalf("enable = %d %s", r.Status, r.Raw)
		}
	}
	f.kimIn(t, "default")
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action IN ('user.disable', 'user.enable')
		AND target_id = $1`, kim); n != 2 {
		t.Errorf("audit rows = %d, want 2", n)
	}
}

// TestRefreshIntoDisabledMembership refuses a refresh whose membership was
// disabled after the session began, and revokes the family.
func TestRefreshIntoDisabledMembership(t *testing.T) {
	f := newMultiAdminFixture(t)
	rt, _ := f.kimIn(t, "default")["refresh_token"].(string)
	f.exec(t, `UPDATE tenant_members SET status = 'disabled'
		WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'default')
		AND user_id = (SELECT id FROM users WHERE display_name = 'Kim')`)
	status, why, _ := f.refresh(t, rt)
	if status != http.StatusForbidden || why != "ACCOUNT_DISABLED" {
		t.Errorf("refresh = %d %v, want 403 ACCOUNT_DISABLED", status, why)
	}
	if status, _, _ := f.refresh(t, rt); status != http.StatusUnauthorized {
		t.Errorf("refresh after the refusal = %d, want 401: the family stays revoked", status)
	}
}

// TestDisableChecksLastAdminInThisTenantOnly lets bia disable kim in the
// default tenant although kim is the only roles:manage holder of acme, but
// refuses disabling yourself and the last admin of this tenant.
func TestDisableChecksLastAdminInThisTenantOnly(t *testing.T) {
	f := newMultiAdminFixture(t)
	super := f.superToken(t)
	kim := f.userID(t, "Kim")

	wantReason(t, "disable yourself", new(f.do(t, http.MethodPost,
		"/v1/admin/users/"+f.userID(t, "Bia")+"/disable", f.bia, nil, "")), http.StatusForbidden, "SELF_ACTION")
	if r := f.do(t, http.MethodPost, "/v1/admin/users/"+kim+"/disable", f.bia, nil, ""); r.Status != http.StatusNoContent {
		t.Errorf("disable the only admin of another tenant = %d %s, want 204", r.Status, r.Raw)
	}
	wantReason(t, "disable the last admin here", new(f.do(t, http.MethodPost,
		"/v1/admin/users/"+f.userID(t, "Bia")+"/disable", super, nil, "")), http.StatusConflict, "LAST_ADMIN")
}

// TestInviteAndDisabledMembership answers ALREADY_MEMBER for an active or
// disabled member without touching a disabled membership, and kills the
// pending invite of a member disabled meanwhile.
func TestInviteAndDisabledMembership(t *testing.T) {
	f := newMultiAdminFixture(t)
	kim := f.userID(t, "Kim")
	wantReason(t, "invite an active member", new(f.invite(t, "kim@example.com")), http.StatusConflict, "ALREADY_MEMBER")

	f.do(t, http.MethodPost, "/v1/admin/users/"+kim+"/disable", f.bia, nil, "")
	wantReason(t, "invite a disabled member", new(f.invite(t, "kim@example.com")), http.StatusConflict, "ALREADY_MEMBER")
	if got := f.text(t, `SELECT tm.status FROM tenant_members tm JOIN tenants t ON t.id = tm.tenant_id
		WHERE t.slug = 'default' AND tm.user_id = $1`, kim); got != "disabled" {
		t.Errorf("membership after a refused invite = %s, want disabled", got)
	}

	f.invite(t, "new@example.com")
	token := f.inviteToken(t, "new@example.com")
	f.exec(t, `UPDATE tenant_members SET status = 'disabled' WHERE user_id =
		(SELECT id FROM users WHERE email_enc IS NOT NULL AND display_name = '' AND NOT is_super_admin
		 ORDER BY created_at DESC LIMIT 1)`)
	wantReason(t, "accept an invite after disable", new(f.accept(t, token, loginPassword)),
		http.StatusBadRequest, "TOKEN_INVALID")
}
