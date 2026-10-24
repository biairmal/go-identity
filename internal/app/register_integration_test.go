package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// registerFixture is the whole app, with token validation on, over a clean
// database, so every request goes through the real router and auth rules.
type registerFixture struct {
	srv *httptest.Server
	db  *sqlkit.DB
}

// newRegisterFixture builds the app after mutate adjusts its config.
func newRegisterFixture(t *testing.T, mutate func(c *Config)) *registerFixture {
	t.Helper()
	cfg := validConfig(t)
	cfg.Database = testkit.PostgresConfig(t)
	cfg.Auth.Enabled = true
	cfg.Modules.User.SuperAdmin = testSuperAdmin
	if mutate != nil {
		mutate(&cfg)
	}
	db := testkit.Postgres(t)
	a, err := New(context.Background(), &cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { a.close(context.Background()) })
	return &registerFixture{srv: testkit.Server(t, a.Handler()), db: db}
}

// registerBody is a valid sign-up for email.
func registerBody(email string) map[string]any {
	return map[string]any{"email": email, "password": "correct horse battery", "display_name": "Bia"}
}

// post sends a JSON body and returns the response.
func (f *registerFixture) post(t *testing.T, path string, body any) testkit.Response[map[string]any] {
	t.Helper()
	return testkit.Do[map[string]any](t, f.srv, http.MethodPost, path, body, nil)
}

// count runs a COUNT(*) query.
func (f *registerFixture) count(t *testing.T, query string) int {
	t.Helper()
	var n int
	if err := f.db.Leader().QueryRowContext(context.Background(), query).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

// queuedMail is one mail.send outbox row's payload.
type queuedMail struct {
	To       string `json:"to"`
	Template string `json:"template"`
	LinkPath string `json:"link_path"`
	Token    string `json:"token"`
}

// mails returns the queued mail, oldest first.
func (f *registerFixture) mails(t *testing.T) []queuedMail {
	t.Helper()
	rows, err := f.db.Leader().QueryContext(context.Background(),
		`SELECT payload FROM outbox WHERE topic = 'mail.send' ORDER BY id`)
	if err != nil {
		t.Fatalf("query outbox: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []queuedMail
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("scan outbox: %v", err)
		}
		var m queuedMail
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("decode outbox payload: %v", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("outbox rows: %v", err)
	}
	return out
}

// userStatus returns the status and whether the email is verified for the
// only non-super-admin user.
func (f *registerFixture) userStatus(t *testing.T) (status string, verified bool) {
	t.Helper()
	err := f.db.Leader().QueryRowContext(context.Background(),
		`SELECT status, email_verified_at IS NOT NULL FROM users WHERE NOT is_super_admin`).Scan(&status, &verified)
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	return status, verified
}

// withoutTimestamp is the response envelope minus its timestamp, the one
// field that legitimately differs between two responses.
func withoutTimestamp(t *testing.T, raw []byte) []byte {
	t.Helper()
	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v: %s", err, raw)
	}
	delete(env, "timestamp")
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// reason returns meta.reason of an error response.
func reason(r *testkit.Response[map[string]any]) any {
	if r.Error == nil {
		return nil
	}
	return r.Error.Meta["reason"]
}

// TestRegisterNewEmail creates a pending user with a verify token, a queued
// verification mail, the default role, a membership and an audit row.
func TestRegisterNewEmail(t *testing.T) {
	f := newRegisterFixture(t, nil)
	r := f.post(t, "/v1/auth/register", registerBody("new@example.com"))
	if r.Status != http.StatusAccepted {
		t.Fatalf("register = %d: %s", r.Status, r.Raw)
	}
	if r.Data["status"] != "accepted" || len(r.Data) != 1 {
		t.Errorf("data = %v, want {status: accepted}", r.Data)
	}
	if status, verified := f.userStatus(t); status != "pending" || verified {
		t.Errorf("user = %s verified=%v, want pending and unverified", status, verified)
	}
	checks := map[string]string{
		"verify token": `SELECT count(*) FROM one_time_tokens
			WHERE purpose = 'verify_email' AND used_at IS NULL AND expires_at > now() + interval '23 hours'`,
		"credentials": `SELECT count(*) FROM credentials c JOIN users u ON u.id = c.user_id WHERE NOT u.is_super_admin`,
		"membership": `SELECT count(*) FROM tenant_members m JOIN users u ON u.id = m.user_id
			WHERE NOT u.is_super_admin AND m.status = 'active'`,
		"member role": `SELECT count(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE r.name = 'member'`,
		"audit":       `SELECT count(*) FROM audit_log WHERE action = 'auth.register'`,
	}
	for name, q := range checks {
		if n := f.count(t, q); n != 1 {
			t.Errorf("%s rows = %d, want 1", name, n)
		}
	}
	mails := f.mails(t)
	if len(mails) != 1 || mails[0].Template != "verify_email" || mails[0].To != "new@example.com" ||
		mails[0].Token == "" || mails[0].LinkPath != "/verify-email" {
		t.Errorf("queued mail = %+v, want one verify_email with a token", mails)
	}
}

// TestRegisterExistingEmail answers exactly as for a new address, creates no
// user and queues the existing-account mail instead.
func TestRegisterExistingEmail(t *testing.T) {
	f := newRegisterFixture(t, nil)
	first := f.post(t, "/v1/auth/register", registerBody("taken@example.com"))
	if first.Status != http.StatusAccepted {
		t.Fatalf("first register = %d: %s", first.Status, first.Raw)
	}
	users := f.count(t, `SELECT count(*) FROM users`)
	tokens := f.count(t, `SELECT count(*) FROM one_time_tokens`)

	for _, email := range []string{" Taken@Example.com ", testSuperAdmin.Email} {
		again := f.post(t, "/v1/auth/register", registerBody(email))
		if again.Status != first.Status {
			t.Errorf("%q: status = %d, want %d", email, again.Status, first.Status)
		}
		if got, want := withoutTimestamp(t, again.Raw), withoutTimestamp(t, first.Raw); !bytes.Equal(got, want) {
			t.Errorf("%q: body = %s, want %s", email, got, want)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM users`); n != users {
		t.Errorf("users = %d, want %d (no new account)", n, users)
	}
	if n := f.count(t, `SELECT count(*) FROM one_time_tokens`); n != tokens {
		t.Errorf("one-time tokens = %d, want %d", n, tokens)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.register'`); n != 1 {
		t.Errorf("auth.register audit rows = %d, want 1", n)
	}
	mails := f.mails(t)
	if len(mails) != 3 {
		t.Fatalf("queued mails = %d, want 3", len(mails))
	}
	for _, m := range mails[1:] {
		if m.Template != "existing_account" || m.Token != "" {
			t.Errorf("mail = %+v, want existing_account without a token", m)
		}
	}
}

// TestVerifyEmail activates the account once; the same token then fails.
func TestVerifyEmail(t *testing.T) {
	f := newRegisterFixture(t, nil)
	if r := f.post(t, "/v1/auth/register", registerBody("verify@example.com")); r.Status != http.StatusAccepted {
		t.Fatalf("register = %d: %s", r.Status, r.Raw)
	}
	token := f.mails(t)[0].Token

	r := f.post(t, "/v1/auth/email/verify", map[string]string{"token": token})
	if r.Status != http.StatusNoContent || len(r.Raw) != 0 {
		t.Fatalf("verify = %d %s, want 204 with no body", r.Status, r.Raw)
	}
	if status, verified := f.userStatus(t); status != "active" || !verified {
		t.Errorf("user = %s verified=%v, want active and verified", status, verified)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.email_verified'`); n != 1 {
		t.Errorf("auth.email_verified audit rows = %d, want 1", n)
	}

	again := f.post(t, "/v1/auth/email/verify", map[string]string{"token": token})
	if again.Status != http.StatusBadRequest || reason(&again) != "TOKEN_INVALID" {
		t.Errorf("second verify = %d %s, want 400 TOKEN_INVALID", again.Status, again.Raw)
	}
}

// TestVerifyEmailBadToken rejects unknown, expired and wrong-purpose tokens
// with TOKEN_INVALID and leaves the account pending.
func TestVerifyEmailBadToken(t *testing.T) {
	f := newRegisterFixture(t, nil)
	if r := f.post(t, "/v1/auth/register", registerBody("bad@example.com")); r.Status != http.StatusAccepted {
		t.Fatalf("register = %d: %s", r.Status, r.Raw)
	}
	token := f.mails(t)[0].Token
	ctx := context.Background()

	tests := []struct {
		name  string
		setup string
		token string
	}{
		{name: "unknown", token: "not-a-real-token"},
		{name: "empty", token: ""},
		{
			name:  "wrong purpose",
			setup: `UPDATE one_time_tokens SET purpose = 'reset_password'`,
			token: token,
		},
		{
			name:  "expired",
			setup: `UPDATE one_time_tokens SET purpose = 'verify_email', expires_at = now() - interval '1 minute'`,
			token: token,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != "" {
				if _, err := f.db.Leader().ExecContext(ctx, tt.setup); err != nil {
					t.Fatalf("setup: %v", err)
				}
			}
			r := f.post(t, "/v1/auth/email/verify", map[string]string{"token": tt.token})
			if r.Status != http.StatusBadRequest || reason(&r) != "TOKEN_INVALID" {
				t.Errorf("verify = %d %s, want 400 TOKEN_INVALID", r.Status, r.Raw)
			}
			if status, verified := f.userStatus(t); status != "pending" || verified {
				t.Errorf("user = %s verified=%v, want still pending", status, verified)
			}
		})
	}
}

// TestResendVerification always answers 202 with one body, and only queues
// a mail, with a fresh token that replaces the old one, for an unverified
// account.
func TestResendVerification(t *testing.T) {
	f := newRegisterFixture(t, nil)
	if r := f.post(t, "/v1/auth/register", registerBody("resend@example.com")); r.Status != http.StatusAccepted {
		t.Fatalf("register = %d: %s", r.Status, r.Raw)
	}
	oldToken := f.mails(t)[0].Token

	unverified := f.post(t, "/v1/auth/email/resend", map[string]string{"email": "Resend@Example.com"})
	if unverified.Status != http.StatusAccepted {
		t.Fatalf("resend = %d: %s", unverified.Status, unverified.Raw)
	}
	mails := f.mails(t)
	if len(mails) != 2 || mails[1].Template != "verify_email" || mails[1].Token == "" || mails[1].Token == oldToken {
		t.Fatalf("mails = %+v, want a second verify_email with a new token", mails)
	}
	if n := f.count(t, `SELECT count(*) FROM one_time_tokens WHERE used_at IS NULL`); n != 1 {
		t.Errorf("unused tokens = %d, want 1 (the old one is invalidated)", n)
	}
	if r := f.post(t, "/v1/auth/email/verify", map[string]string{"token": oldToken}); reason(&r) != "TOKEN_INVALID" {
		t.Errorf("verify with the replaced token = %d %s, want TOKEN_INVALID", r.Status, r.Raw)
	}
	fresh := f.post(t, "/v1/auth/email/verify", map[string]string{"token": mails[1].Token})
	if r := fresh; r.Status != http.StatusNoContent {
		t.Fatalf("verify with the new token = %d %s", r.Status, r.Raw)
	}

	// Verified, unknown and malformed addresses: same answer, nothing sent.
	for _, email := range []string{"resend@example.com", "nobody@example.com", testSuperAdmin.Email, "not-an-email"} {
		r := f.post(t, "/v1/auth/email/resend", map[string]string{"email": email})
		if r.Status != http.StatusAccepted {
			t.Errorf("%q: status = %d, want 202", email, r.Status)
		}
		if got, want := withoutTimestamp(t, r.Raw), withoutTimestamp(t, unverified.Raw); !bytes.Equal(got, want) {
			t.Errorf("%q: body = %s, want %s", email, got, want)
		}
	}
	if n := len(f.mails(t)); n != 2 {
		t.Errorf("queued mails = %d, want still 2", n)
	}
}

// TestRegisterRollsBack fails the registration after the user, credentials
// and membership are written (the default role is missing) and checks none
// of them, and no mail, survive.
func TestRegisterRollsBack(t *testing.T) {
	f := newRegisterFixture(t, nil)
	if _, err := f.db.Leader().ExecContext(context.Background(), `DELETE FROM roles WHERE name = 'member'`); err != nil {
		t.Fatalf("drop role: %v", err)
	}
	// The super admin's bootstrap already wrote audit rows; only new ones count.
	auditBefore := f.count(t, `SELECT count(*) FROM audit_log`)
	r := f.post(t, "/v1/auth/register", registerBody("rollback@example.com"))
	if r.Status == http.StatusAccepted {
		t.Fatalf("register = 202, want a failure when the default role is missing")
	}
	for name, q := range map[string]string{
		"users":       `SELECT count(*) FROM users WHERE NOT is_super_admin`,
		"credentials": `SELECT count(*) FROM credentials c JOIN users u ON u.id = c.user_id WHERE NOT u.is_super_admin`,
		"members":     `SELECT count(*) FROM tenant_members m JOIN users u ON u.id = m.user_id WHERE NOT u.is_super_admin`,
		"tokens":      `SELECT count(*) FROM one_time_tokens`,
		"outbox":      `SELECT count(*) FROM outbox`,
	} {
		if n := f.count(t, q); n != 0 {
			t.Errorf("%s rows = %d, want 0 after the rollback", name, n)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log`); n != auditBefore {
		t.Errorf("audit rows = %d, want %d (none from the failed registration)", n, auditBefore)
	}
}

// TestRegisterRejected covers the requests register refuses before writing
// anything.
func TestRegisterRejected(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(c *Config)
		body       map[string]any
		wantStatus int
		wantReason string
		wantField  string
	}{
		{
			name:       "registration disabled",
			mutate:     func(c *Config) { c.Modules.Auth.Registration.Enabled = false },
			body:       registerBody("closed@example.com"),
			wantStatus: http.StatusForbidden, wantReason: "REGISTRATION_CLOSED",
		},
		{
			name: "password provider disabled",
			mutate: func(c *Config) {
				c.Modules.Auth.Providers.Password.Enabled = false
				c.Modules.Auth.Providers.Google.Enabled = true
				c.Modules.Auth.Providers.Google.ClientID = "id"
				c.Modules.Auth.Providers.Google.ClientSecret = "secret"
			},
			body:       registerBody("nopassword@example.com"),
			wantStatus: http.StatusNotFound, wantReason: "PROVIDER_DISABLED",
		},
		{
			name:       "short password",
			body:       map[string]any{"email": "weak@example.com", "password": "short", "display_name": "Bia"},
			wantStatus: http.StatusBadRequest, wantReason: "PASSWORD_POLICY", wantField: "password",
		},
		{
			name:       "common password",
			body:       map[string]any{"email": "weak@example.com", "password": "1234567890", "display_name": "Bia"},
			wantStatus: http.StatusBadRequest, wantReason: "PASSWORD_POLICY", wantField: "password",
		},
		{
			name:       "bad email",
			body:       map[string]any{"email": "nope", "password": "correct horse battery", "display_name": "Bia"},
			wantStatus: http.StatusBadRequest, wantField: "email",
		},
		{
			name:       "missing display name",
			body:       map[string]any{"email": "a@example.com", "password": "correct horse battery"},
			wantStatus: http.StatusBadRequest, wantField: "display_name",
		},
		{
			name:       "unknown field",
			body:       map[string]any{"email": "a@example.com", "password": "x", "display_name": "B", "role": "admin"},
			wantStatus: http.StatusBadRequest, wantField: "role",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRegisterFixture(t, tt.mutate)
			r := f.post(t, "/v1/auth/register", tt.body)
			if r.Status != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", r.Status, tt.wantStatus, r.Raw)
			}
			if tt.wantReason != "" && reason(&r) != tt.wantReason {
				t.Errorf("reason = %v, want %s", reason(&r), tt.wantReason)
			}
			if tt.wantField != "" {
				fields, _ := r.Error.Meta["fields"].(map[string]any)
				if _, ok := fields[tt.wantField]; !ok {
					t.Errorf("meta.fields = %v, want an entry for %s", r.Error.Meta["fields"], tt.wantField)
				}
			}
			if n := f.count(t, `SELECT count(*) FROM users WHERE NOT is_super_admin`); n != 0 {
				t.Errorf("users = %d, want 0", n)
			}
			if n := f.count(t, `SELECT count(*) FROM outbox`); n != 0 {
				t.Errorf("outbox rows = %d, want 0", n)
			}
		})
	}
}

// TestRegisterMultiTenant joins the named tenant and refuses an unknown one.
func TestRegisterMultiTenant(t *testing.T) {
	f := newRegisterFixture(t, func(c *Config) { c.Modules.Tenant.Mode = "multi" })

	missing := f.post(t, "/v1/auth/register", registerBody("multi@example.com"))
	if missing.Status != http.StatusBadRequest {
		t.Errorf("no tenant = %d, want 400: %s", missing.Status, missing.Raw)
	}
	body := registerBody("multi@example.com")
	body["tenant"] = "no-such-tenant"
	if r := f.post(t, "/v1/auth/register", body); r.Status != http.StatusNotFound {
		t.Errorf("unknown tenant = %d, want 404: %s", r.Status, r.Raw)
	}
	body["tenant"] = "default"
	if r := f.post(t, "/v1/auth/register", body); r.Status != http.StatusAccepted {
		t.Fatalf("default tenant = %d: %s", r.Status, r.Raw)
	}
	if n := f.count(t, `SELECT count(*) FROM tenant_members m JOIN tenants t ON t.id = m.tenant_id
		JOIN users u ON u.id = m.user_id WHERE t.slug = 'default' AND NOT u.is_super_admin`); n != 1 {
		t.Errorf("memberships in the named tenant = %d, want 1", n)
	}
}
