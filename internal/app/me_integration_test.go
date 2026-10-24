package app

import (
	"net/http"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// call sends a request with a bearer token.
func (f *loginFixture) call(t *testing.T, method, path, token string, body any) testkit.Response[map[string]any] {
	t.Helper()
	return testkit.Do[map[string]any](t, f.srv, method, path, body,
		http.Header{"Authorization": {"Bearer " + token}})
}

// callList sends a request with a bearer token and decodes a list payload.
func (f *loginFixture) callList(t *testing.T, path, token string) testkit.Response[[]map[string]any] {
	t.Helper()
	return testkit.Do[[]map[string]any](t, f.srv, http.MethodGet, path, nil,
		http.Header{"Authorization": {"Bearer " + token}})
}

// signInTokens signs the registered user in with loginPassword and returns the access and
// refresh tokens.
func (f *loginFixture) signInTokens(t *testing.T) (access, refresh string) {
	t.Helper()
	r := f.login(t, "bia@example.com", loginPassword)
	access, _ = r.Data["access_token"].(string)
	refresh, _ = r.Data["refresh_token"].(string)
	if r.Status != http.StatusOK || access == "" {
		t.Fatalf("login = %d %s", r.Status, r.Raw)
	}
	return access, refresh
}

// TestMeIntegration reads and renames the caller.
func TestMeIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	access, _ := f.signInTokens(t)

	r := f.call(t, http.MethodGet, "/v1/me", access, nil)
	if r.Status != http.StatusOK {
		t.Fatalf("GET /v1/me = %d %s", r.Status, r.Raw)
	}
	d := r.Data
	tenant, _ := d["tenant"].(map[string]any)
	providers, _ := d["providers"].(map[string]any)
	roles, _ := d["roles"].([]any)
	if d["email"] != "bia@example.com" || d["display_name"] != "Bia" || d["is_super_admin"] != false ||
		tenant["slug"] != "default" || providers["password"] != true || providers["google"] != false ||
		len(roles) == 0 || d["permissions"] == nil || d["email_verified"] == nil {
		t.Errorf("GET /v1/me = %s", r.Raw)
	}

	r = f.call(t, http.MethodPatch, "/v1/me", access, map[string]any{"display_name": "  Bia B  "})
	if r.Status != http.StatusOK || r.Data["display_name"] != "Bia B" {
		t.Fatalf("PATCH /v1/me = %d %s", r.Status, r.Raw)
	}
	if r := f.call(t, http.MethodGet, "/v1/me", access, nil); r.Data["display_name"] != "Bia B" {
		t.Errorf("display_name after PATCH = %v", r.Data["display_name"])
	}
	for name, body := range map[string]any{
		"empty":         map[string]any{"display_name": " "},
		"unknown field": map[string]any{"display_name": "Bia", "email": "x@example.com"},
	} {
		if r := f.call(t, http.MethodPatch, "/v1/me", access, body); r.Status != http.StatusBadRequest {
			t.Errorf("PATCH /v1/me (%s) = %d %s, want 400", name, r.Status, r.Raw)
		}
	}
	if r := f.get(t, "/v1/me", "not-a-token"); r.Status != http.StatusUnauthorized {
		t.Errorf("GET /v1/me with a bad token = %d, want 401", r.Status)
	}
}

// TestMeTenantsIntegration lists the active memberships with tenant status.
func TestMeTenantsIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	access, _ := f.signInTokens(t)
	r := f.callList(t, "/v1/me/tenants", access)
	if r.Status != http.StatusOK || len(r.Data) != 1 {
		t.Fatalf("GET /v1/me/tenants = %d %s", r.Status, r.Raw)
	}
	if got := r.Data[0]; got["slug"] != "default" || got["status"] != "active" || got["id"] == "" {
		t.Errorf("tenant = %v", got)
	}
}

// TestMeSessionsIntegration lists one session per device, marks the caller's
// own, and signs another device out.
func TestMeSessionsIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	access, own := f.signInTokens(t)
	_, other := f.signInTokens(t)

	r := f.callList(t, "/v1/me/sessions", access)
	if r.Status != http.StatusOK || len(r.Data) != 2 {
		t.Fatalf("GET /v1/me/sessions = %d %s", r.Status, r.Raw)
	}
	var otherID string
	current := 0
	for _, s := range r.Data {
		if s["current"] == true {
			current++
		} else {
			otherID, _ = s["id"].(string)
		}
		if s["created_at"] == nil || s["last_used_at"] == nil {
			t.Errorf("session = %v", s)
		}
	}
	if current != 1 || otherID == "" {
		t.Fatalf("sessions = %s, want exactly one current", r.Raw)
	}

	del := f.call(t, http.MethodDelete, "/v1/me/sessions/"+otherID, access, nil)
	if del.Status != http.StatusNoContent {
		t.Fatalf("DELETE the other session = %d %s", del.Status, del.Raw)
	}
	if status, _, _ := f.refresh(t, other); status != http.StatusUnauthorized {
		t.Errorf("refresh on the signed-out device = %d, want 401", status)
	}
	if status, _, _ := f.refresh(t, own); status != http.StatusOK {
		t.Errorf("refresh on the caller's device = %d, want 200", status)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log
		WHERE action = 'auth.logout' AND after->>'via' = 'session_list'`); n != 1 {
		t.Errorf("auth.logout rows from the session list = %d, want 1", n)
	}
	for _, id := range []string{otherID, "8c5f0b9e-0000-4000-8000-000000000000", "not-a-uuid"} {
		if r := f.call(t, http.MethodDelete, "/v1/me/sessions/"+id, access, nil); r.Status != http.StatusNotFound {
			t.Errorf("DELETE /v1/me/sessions/%s = %d, want 404", id, r.Status)
		}
	}
}

// TestChangePasswordIntegration requires the current password, applies the
// policy to the new one, and trades every session for a fresh one.
func TestChangePasswordIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	access, rt1 := f.signInTokens(t)
	_, rt2 := f.signInTokens(t)

	for name, tc := range map[string]struct {
		body   map[string]any
		status int
		reason any
	}{
		"no current": {map[string]any{"new_password": newPassword}, http.StatusBadRequest, nil},
		"wrong current": {
			map[string]any{"current_password": "wrong password!", "new_password": newPassword},
			http.StatusUnauthorized, "INVALID_CREDENTIALS",
		},
		"weak new": {
			map[string]any{"current_password": loginPassword, "new_password": "short"},
			http.StatusBadRequest, "PASSWORD_POLICY",
		},
	} {
		r := f.call(t, http.MethodPost, "/v1/me/password", access, tc.body)
		if r.Status != tc.status || reason(&r) != tc.reason {
			t.Errorf("%s = %d %s, want %d %v", name, r.Status, r.Raw, tc.status, tc.reason)
		}
		if name == "weak new" && r.Error != nil {
			if fields, _ := r.Error.Meta["fields"].(map[string]any); fields["new_password"] == nil {
				t.Errorf("weak new: meta.fields = %v, want new_password", r.Error.Meta["fields"])
			}
		}
	}

	r := f.call(t, http.MethodPost, "/v1/me/password", access,
		map[string]any{"current_password": loginPassword, "new_password": newPassword})
	fresh, _ := r.Data["refresh_token"].(string)
	if r.Status != http.StatusOK || fresh == "" || r.Data["access_token"] == nil {
		t.Fatalf("change password = %d %s", r.Status, r.Raw)
	}
	for _, rt := range []string{rt1, rt2} {
		if status, _, _ := f.refresh(t, rt); status != http.StatusUnauthorized {
			t.Errorf("refresh with a pre-change token = %d, want 401", status)
		}
	}
	if status, _, _ := f.refresh(t, fresh); status != http.StatusOK {
		t.Errorf("refresh with the fresh token = %d, want 200", status)
	}
	if r := f.login(t, "bia@example.com", newPassword); r.Status != http.StatusOK {
		t.Errorf("login with the new password = %d", r.Status)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.password_change'`); n != 1 {
		t.Errorf("auth.password_change rows = %d, want 1", n)
	}
}

// TestChangePasswordRestrictedTokenIntegration: the restricted token from a
// forced change is refused elsewhere, changes the password without the
// current one, and the change clears must_change_password.
func TestChangePasswordRestrictedTokenIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	f.exec(t, `UPDATE users SET must_change_password = true WHERE NOT is_super_admin`)
	r := f.login(t, "bia@example.com", loginPassword)
	restricted, _ := r.Data["access_token"].(string)
	if r.Status != http.StatusOK || r.Data["must_change_password"] != true || r.Data["refresh_token"] != nil {
		t.Fatalf("login = %d %s, want a restricted token", r.Status, r.Raw)
	}
	if r := f.call(t, http.MethodGet, "/v1/me", restricted, nil); r.Status != http.StatusForbidden ||
		reason(&r) != "PASSWORD_CHANGE_REQUIRED" {
		t.Errorf("GET /v1/me with the restricted token = %d %s", r.Status, r.Raw)
	}

	r = f.call(t, http.MethodPost, "/v1/me/password", restricted, map[string]any{"new_password": newPassword})
	if r.Status != http.StatusOK || r.Data["must_change_password"] != false || r.Data["refresh_token"] == nil {
		t.Fatalf("change password with the restricted token = %d %s", r.Status, r.Raw)
	}
	if n := f.count(t, `SELECT count(*) FROM users WHERE must_change_password AND NOT is_super_admin`); n != 0 {
		t.Errorf("must_change_password still set")
	}
	full, _ := r.Data["access_token"].(string)
	if r := f.call(t, http.MethodGet, "/v1/me", full, nil); r.Status != http.StatusOK {
		t.Errorf("GET /v1/me with the new token = %d %s", r.Status, r.Raw)
	}
}

// TestUnlinkGoogleIntegration unlinks Google while a password remains, and
// refuses to remove the last sign-in method.
func TestUnlinkGoogleIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	access, _ := f.signInTokens(t)
	link := `INSERT INTO identities (user_id, provider, provider_subject)
		SELECT id, 'google', 'google-sub-1' FROM users WHERE NOT is_super_admin`
	linked := `SELECT count(*) FROM identities`

	if r := f.call(t, http.MethodDelete, "/v1/me/identities/google", access, nil); r.Status != http.StatusNoContent {
		t.Errorf("unlink with nothing linked = %d %s, want 204", r.Status, r.Raw)
	}

	f.exec(t, link)
	me := f.call(t, http.MethodGet, "/v1/me", access, nil)
	if p, _ := me.Data["providers"].(map[string]any); p["google"] != true || p["password"] != true {
		t.Errorf("providers = %v, want both", me.Data["providers"])
	}
	if r := f.call(t, http.MethodDelete, "/v1/me/identities/google", access, nil); r.Status != http.StatusNoContent {
		t.Fatalf("unlink with a password = %d %s", r.Status, r.Raw)
	}
	if n := f.count(t, linked); n != 0 {
		t.Errorf("identities = %d after unlink, want 0", n)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'identity.unlink'`); n != 1 {
		t.Errorf("identity.unlink rows = %d, want 1", n)
	}

	f.exec(t, link)
	f.exec(t, `DELETE FROM credentials WHERE user_id IN (SELECT id FROM users WHERE NOT is_super_admin)`)
	r := f.call(t, http.MethodDelete, "/v1/me/identities/google", access, nil)
	if r.Status != http.StatusConflict || reason(&r) != "LAST_SIGN_IN_METHOD" {
		t.Errorf("unlink the last method = %d %s, want 409 LAST_SIGN_IN_METHOD", r.Status, r.Raw)
	}
	if n := f.count(t, linked); n != 1 {
		t.Errorf("identities = %d after a refused unlink, want 1", n)
	}
}
