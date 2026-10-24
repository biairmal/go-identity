package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// resetToken returns the token of the newest queued reset mail to email.
func (f *loginFixture) resetToken(t *testing.T, email string) string {
	t.Helper()
	var raw []byte
	err := f.db.Leader().QueryRowContext(context.Background(),
		`SELECT payload FROM outbox WHERE topic = 'mail.send' AND payload->>'template' = 'reset_password'
		 AND payload->>'to' = $1 ORDER BY id DESC LIMIT 1`, email).Scan(&raw)
	if err != nil {
		t.Fatalf("no reset mail to %s: %v", email, err)
	}
	var m queuedMail
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.LinkPath != "/reset-password" || m.Token == "" {
		t.Fatalf("reset mail = %+v", m)
	}
	return m.Token
}

func (f *loginFixture) forgot(t *testing.T, email string) testkit.Response[map[string]any] {
	t.Helper()
	r := f.post(t, "/v1/auth/password/forgot", map[string]any{"email": email})
	if r.Status != http.StatusAccepted {
		t.Fatalf("forgot %q = %d %s, want 202", email, r.Status, r.Raw)
	}
	return r
}

func (f *loginFixture) reset(t *testing.T, token, pw string) testkit.Response[map[string]any] {
	t.Helper()
	return f.post(t, "/v1/auth/password/reset", map[string]any{"token": token, "password": pw})
}

// newPassword is the password the reset tests choose.
const newPassword = "a brand new passphrase"

// TestPasswordResetIntegration spends the emailed token: the new password
// works and the old one does not, every refresh family is revoked, the lock
// is cleared, auth.password_reset is audited and the token is single use.
func TestPasswordResetIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	rt1 := f.signIn(t)
	rt2 := f.newSession(t)
	f.exec(t, `UPDATE users SET failed_logins = 10, locked_until = now() + interval '15 minutes',
		must_change_password = true WHERE NOT is_super_admin`)

	f.forgot(t, "Bia@Example.com")
	tok := f.resetToken(t, "bia@example.com")
	if r := f.reset(t, tok, newPassword); r.Status != http.StatusNoContent {
		t.Fatalf("reset = %d %s, want 204", r.Status, r.Raw)
	}

	if n := f.liveTokens(t); n != 0 {
		t.Errorf("live refresh tokens = %d, want 0", n)
	}
	for _, rt := range []string{rt1, rt2} {
		if status, _, _ := f.refresh(t, rt); status != http.StatusUnauthorized {
			t.Errorf("refresh with a pre-reset token = %d, want 401", status)
		}
	}
	if failed, locked, _ := f.userState(t); failed != 0 || locked {
		t.Errorf("failed_logins = %d, locked = %v; want the lock cleared", failed, locked)
	}
	if n := f.count(t, `SELECT count(*) FROM users WHERE must_change_password AND NOT is_super_admin`); n != 0 {
		t.Errorf("must_change_password still set on %d users", n)
	}
	if r := f.login(t, "bia@example.com", loginPassword); r.Status != http.StatusUnauthorized {
		t.Errorf("login with the old password = %d, want 401", r.Status)
	}
	if r := f.login(t, "bia@example.com", newPassword); r.Status != http.StatusOK {
		t.Errorf("login with the new password = %d %s", r.Status, r.Raw)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_id
		WHERE a.action = 'auth.password_reset' AND NOT u.is_super_admin`); n != 1 {
		t.Errorf("auth.password_reset rows = %d, want 1", n)
	}
	if r := f.reset(t, tok, "yet another passphrase"); r.Status != http.StatusBadRequest || reason(&r) != "TOKEN_INVALID" {
		t.Errorf("second reset with the same token = %d %s, want 400 TOKEN_INVALID", r.Status, r.Raw)
	}
}

// TestForgotPasswordIdenticalBody answers 202 with one body for an account,
// an unknown address, a disabled account and a malformed address, and only
// the active account gets a mail.
func TestForgotPasswordIdenticalBody(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	known := f.forgot(t, "bia@example.com")
	for _, email := range []string{"nobody@example.com", "not-an-address"} {
		r := f.forgot(t, email)
		if got, want := withoutTimestamp(t, r.Raw), withoutTimestamp(t, known.Raw); !bytes.Equal(got, want) {
			t.Errorf("forgot %q body = %s, want %s", email, got, want)
		}
	}
	f.exec(t, `UPDATE users SET status = 'disabled' WHERE NOT is_super_admin`)
	f.forgot(t, "bia@example.com")
	if n := f.count(t, `SELECT count(*) FROM outbox WHERE payload->>'template' = 'reset_password'`); n != 1 {
		t.Errorf("reset mails = %d, want 1 (the active account only)", n)
	}
}

// TestPasswordResetRejections: a weak password is PASSWORD_POLICY and leaves
// the token usable; a newer link invalidates the older one; an unknown token
// is TOKEN_INVALID.
func TestPasswordResetRejections(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	f.forgot(t, "bia@example.com")
	old := f.resetToken(t, "bia@example.com")
	f.forgot(t, "bia@example.com")
	tok := f.resetToken(t, "bia@example.com")

	if r := f.reset(t, old, newPassword); r.Status != http.StatusBadRequest || reason(&r) != "TOKEN_INVALID" {
		t.Errorf("reset with the superseded token = %d %s, want 400 TOKEN_INVALID", r.Status, r.Raw)
	}
	if r := f.reset(t, "unknown-token", newPassword); r.Status != http.StatusBadRequest || reason(&r) != "TOKEN_INVALID" {
		t.Errorf("reset with an unknown token = %d %s, want 400 TOKEN_INVALID", r.Status, r.Raw)
	}
	if r := f.reset(t, tok, "short"); r.Status != http.StatusBadRequest || reason(&r) != "PASSWORD_POLICY" {
		t.Errorf("reset with a weak password = %d %s, want 400 PASSWORD_POLICY", r.Status, r.Raw)
	}
	if r := f.reset(t, tok, newPassword); r.Status != http.StatusNoContent {
		t.Errorf("reset after a policy failure = %d %s, want 204", r.Status, r.Raw)
	}
}
