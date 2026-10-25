package app

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// inviteToken returns the token of the newest queued invite mail to email.
func (f *loginFixture) inviteToken(t *testing.T, email string) string {
	t.Helper()
	var raw []byte
	err := f.db.Leader().QueryRowContext(context.Background(),
		`SELECT payload FROM outbox WHERE topic = 'mail.send' AND payload->>'template' = 'invite'
		 AND payload->>'to' = $1 ORDER BY id DESC LIMIT 1`, email).Scan(&raw)
	if err != nil {
		t.Fatalf("no invite mail to %s: %v", email, err)
	}
	var m queuedMail
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.LinkPath != "/invite" || m.Token == "" {
		t.Fatalf("invite mail = %+v", m)
	}
	return m.Token
}

// invite invites email with role IDs as bia.
func (f *adminFixture) invite(t *testing.T, email string, roleIDs ...string) testkit.Response[map[string]any] {
	t.Helper()
	if roleIDs == nil {
		roleIDs = []string{}
	}
	return f.do(t, http.MethodPost, "/v1/admin/users/invite", f.bia,
		map[string]any{"email": email, "role_ids": roleIDs}, "")
}

// accept accepts an invite with the public endpoint.
func (f *adminFixture) accept(t *testing.T, token, pw string) testkit.Response[map[string]any] {
	t.Helper()
	body := map[string]any{"token": token}
	if pw != "" {
		body["password"] = pw
	}
	return f.post(t, "/v1/auth/invite/accept", body)
}

// TestInviteNewAccount creates a pending account without a password, shows
// the invite to the public preview, and on accept sets the password,
// verifies the email, activates the membership, grants the roles and signs
// the user in.
func TestInviteNewAccount(t *testing.T) {
	f := newAdminFixture(t)
	support := f.createRole(t, f.bia, "Support", "users:read")
	if r := f.invite(t, "new@example.com", support); r.Status != http.StatusAccepted || r.Data["status"] != "invited" {
		t.Fatalf("invite = %d %s", r.Status, r.Raw)
	}
	if n := f.count(t, `SELECT count(*) FROM users u JOIN tenant_members tm ON tm.user_id = u.id
		WHERE u.status = 'pending' AND tm.status = 'invited'
		AND NOT EXISTS (SELECT 1 FROM credentials c WHERE c.user_id = u.id)`); n != 1 {
		t.Fatal("invite did not create one pending, invited account without a password")
	}
	token := f.inviteToken(t, "new@example.com")

	p := f.get(t, "/v1/auth/invite/"+token, "")
	tenant, _ := p.Data["tenant"].(map[string]any)
	if p.Status != http.StatusOK || p.Data["email_masked"] != "n**@example.com" || p.Data["has_password"] != false ||
		tenant["name"] == nil {
		t.Fatalf("preview = %d %s", p.Status, p.Raw)
	}
	wantReason(t, "accept without a password", new(f.accept(t, token, "")), http.StatusBadRequest, "PASSWORD_POLICY")
	wantReason(t, "accept with a weak password", new(f.accept(t, token, "password")),
		http.StatusBadRequest, "PASSWORD_POLICY")

	r := f.accept(t, token, loginPassword)
	if r.Status != http.StatusOK || r.Data["access_token"] == nil || r.Data["refresh_token"] == nil {
		t.Fatalf("accept = %d %s", r.Status, r.Raw)
	}
	if n := f.count(t, `SELECT count(*) FROM users u
		JOIN tenant_members tm ON tm.user_id = u.id AND tm.status = 'active'
		JOIN user_roles ur ON ur.user_id = u.id AND ur.role_id = $1
		WHERE u.status = 'active' AND u.email_verified_at IS NOT NULL`, support); n != 1 {
		t.Error("accept did not activate the account and membership and grant the role")
	}
	if r := f.login(t, "new@example.com", loginPassword); r.Status != http.StatusOK {
		t.Errorf("sign in after accept = %d %s", r.Status, r.Raw)
	}
	wantReason(t, "accept twice", new(f.accept(t, token, loginPassword)), http.StatusBadRequest, "TOKEN_INVALID")
	wantReason(t, "preview a spent invite", new(f.get(t, "/v1/auth/invite/"+token, "")),
		http.StatusBadRequest, "TOKEN_INVALID")
	for _, action := range []string{"user.invite", "user.invite_accepted"} {
		if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = $1`, action); n != 1 {
			t.Errorf("audit %s rows = %d, want 1", action, n)
		}
	}
}

// TestInviteExistingAccount adds an invited membership to an account in
// another tenant without touching its password; accepting needs no password
// and ignores one sent anyway.
func TestInviteExistingAccount(t *testing.T) {
	f := newAdminFixture(t)
	kim := f.userID(t, "Kim")
	f.exec(t, `UPDATE tenant_members SET status = 'removed' WHERE user_id = $1`, kim)
	f.exec(t, `DELETE FROM user_roles WHERE user_id = $1`, kim)
	hash := f.text(t, `SELECT password_hash FROM credentials WHERE user_id = $1`, kim)

	if r := f.invite(t, "Kim@Example.com", f.roleID(t, "admin")); r.Status != http.StatusAccepted {
		t.Fatalf("invite = %d %s", r.Status, r.Raw)
	}
	if n := f.count(t, `SELECT count(*) FROM tenant_members WHERE user_id = $1 AND status = 'invited'`, kim); n != 1 {
		t.Error("membership not invited")
	}
	token := f.inviteToken(t, "kim@example.com")
	if p := f.get(t, "/v1/auth/invite/"+token, ""); p.Data["has_password"] != true {
		t.Errorf("preview = %s, want has_password", p.Raw)
	}
	if r := f.accept(t, token, "a different password 99"); r.Status != http.StatusOK {
		t.Fatalf("accept = %d %s", r.Status, r.Raw)
	}
	if got := f.text(t, `SELECT password_hash FROM credentials WHERE user_id = $1`, kim); got != hash {
		t.Error("accepting an invite changed an existing password")
	}
	if n := f.count(t, `SELECT count(*) FROM user_roles WHERE user_id = $1 AND role_id = $2`,
		kim, f.roleID(t, "admin")); n != 1 {
		t.Error("accept did not grant the invited role")
	}
}

// TestInviteRefusals covers the rules on sending and the links that no
// longer work: expired after 7 days, replaced by a re-invite, or for a
// membership removed since.
func TestInviteRefusals(t *testing.T) {
	f := newAdminFixture(t)
	wantReason(t, "invite the super admin", new(f.invite(t, testSuperAdmin.Email)),
		http.StatusForbidden, "SUPER_ADMIN_PROTECTED")
	if r := f.invite(t, "kim@example.com"); r.Status != http.StatusConflict {
		t.Errorf("invite an active member = %d, want 409", r.Status)
	}
	if r := f.invite(t, "x@example.com", "00000000-0000-0000-0000-000000000001"); r.Status != http.StatusBadRequest {
		t.Errorf("invite with an unknown role = %d, want 400", r.Status)
	}
	if r := f.invite(t, "not-an-email"); r.Status != http.StatusBadRequest {
		t.Errorf("invite a malformed address = %d, want 400", r.Status)
	}
	f.createRole(t, f.bia, "Staff", "users:read", "users:manage")
	f.grant(t, "kim@example.com", "Staff")
	f.exec(t, `DELETE FROM user_roles ur USING roles r WHERE ur.role_id = r.id AND r.name = 'member'
		AND ur.user_id = $1`, f.userID(t, "Kim"))
	wantReason(t, "invite with a role the inviter lacks", new(f.do(t, http.MethodPost, "/v1/admin/users/invite",
		f.kim, map[string]any{"email": "y@example.com", "role_ids": []string{f.roleID(t, "admin")}}, "")),
		http.StatusForbidden, "PERMISSION_NOT_HELD")

	f.invite(t, "late@example.com")
	expired := f.inviteToken(t, "late@example.com")
	if n := f.count(t, `SELECT count(*) FROM one_time_tokens WHERE purpose = 'invite'
		AND expires_at - created_at BETWEEN interval '7 days -1 minute' AND interval '7 days 1 minute'`); n != 1 {
		t.Error("invite links do not live 7 days")
	}
	f.exec(t, `UPDATE one_time_tokens SET expires_at = now() - interval '1 second' WHERE purpose = 'invite'`)
	wantReason(t, "accept an expired invite", new(f.accept(t, expired, loginPassword)),
		http.StatusBadRequest, "TOKEN_INVALID")

	f.invite(t, "again@example.com")
	first := f.inviteToken(t, "again@example.com")
	f.invite(t, "again@example.com")
	if second := f.inviteToken(t, "again@example.com"); second == first {
		t.Fatal("re-invite did not send a new link")
	}
	wantReason(t, "accept a replaced invite", new(f.accept(t, first, loginPassword)),
		http.StatusBadRequest, "TOKEN_INVALID")

	f.invite(t, "gone@example.com")
	gone := f.inviteToken(t, "gone@example.com")
	f.exec(t, `UPDATE tenant_members SET status = 'removed' WHERE user_id =
		(SELECT id FROM users WHERE display_name = '' AND NOT is_super_admin ORDER BY created_at DESC LIMIT 1)`)
	wantReason(t, "accept after removal", new(f.accept(t, gone, loginPassword)), http.StatusBadRequest, "TOKEN_INVALID")

	anonymous := f.post(t, "/v1/admin/users/invite", map[string]any{"email": "z@example.com", "role_ids": []string{}})
	if anonymous.Status != http.StatusUnauthorized {
		t.Errorf("invite without a token = %d, want 401", anonymous.Status)
	}
	if r := f.do(t, http.MethodPost, "/v1/admin/users/invite", f.kim,
		map[string]any{"email": "z@example.com", "role_ids": []string{}}, ""); r.Status != http.StatusAccepted {
		t.Errorf("invite by a users:manage holder = %d %s, want 202", r.Status, r.Raw)
	}
}
