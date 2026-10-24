package app

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// loginFixture is the whole app with token validation on. The app validates
// its own tokens through its JWKS endpoint, exactly like a resource service,
// so a token can be checked against a protected route end to end.
type loginFixture struct {
	srv *httptest.Server
	db  *sqlkit.DB
}

// newLoginFixture builds the app after mutate adjusts its config. Sign-up
// needs no verification by default, so registered accounts can sign in.
func newLoginFixture(t *testing.T, mutate func(c *Config)) *loginFixture {
	t.Helper()
	h := http.NotFoundHandler()
	srv := testkit.Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))

	cfg := validConfig(t)
	cfg.Database = testkit.PostgresConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Local.JWKSURL = srv.URL + "/.well-known/jwks.json"
	cfg.Auth.CacheTTL = 0
	cfg.Modules.User.SuperAdmin = testSuperAdmin
	cfg.Modules.Auth.Providers.Password.RequireEmailVerification = false
	cfg.Modules.Auth.Security.LoginRateLimit = "1000/5m"
	if mutate != nil {
		mutate(&cfg)
	}
	db := testkit.Postgres(t)
	a, err := New(context.Background(), &cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { a.close(context.Background()) })
	h = a.Handler()
	return &loginFixture{srv: srv, db: db}
}

func (f *loginFixture) post(t *testing.T, path string, body any) testkit.Response[map[string]any] {
	t.Helper()
	return testkit.Do[map[string]any](t, f.srv, http.MethodPost, path, body, nil)
}

// register signs bia@example.com up with loginPassword and fails the test
// otherwise.
func (f *loginFixture) register(t *testing.T) {
	t.Helper()
	const email = "bia@example.com"
	body := map[string]any{"email": email, "password": loginPassword, "display_name": "Bia"}
	if r := f.post(t, "/v1/auth/register", body); r.Status != http.StatusAccepted {
		t.Fatalf("register %s = %d: %s", email, r.Status, r.Raw)
	}
}

func (f *loginFixture) login(t *testing.T, email, pw string) testkit.Response[map[string]any] {
	t.Helper()
	return f.post(t, "/v1/auth/login", map[string]any{"email": email, "password": pw})
}

func (f *loginFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.db.Leader().ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func (f *loginFixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.db.Leader().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

// userState is the lockout and sign-in columns of the only ordinary user.
func (f *loginFixture) userState(t *testing.T) (failed int, locked, signedIn bool) {
	t.Helper()
	err := f.db.Leader().QueryRowContext(context.Background(),
		`SELECT failed_logins, locked_until IS NOT NULL, last_sign_in_at IS NOT NULL
		 FROM users WHERE NOT is_super_admin`).Scan(&failed, &locked, &signedIn)
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	return failed, locked, signedIn
}

// get calls path with a bearer token.
func (f *loginFixture) get(t *testing.T, path, token string) testkit.Response[map[string]any] {
	t.Helper()
	return testkit.Do[map[string]any](t, f.srv, http.MethodGet, path, nil,
		http.Header{"Authorization": {"Bearer " + token}})
}

// loginPassword is the password of every account the tests register.
const loginPassword = "correct horse battery"

// TestLoginLockoutIntegration locks the account on the tenth failure, so the
// eleventh attempt is refused even with the right password, and keeps the
// counter and the audit rows although every failure answered 401.
func TestLoginLockoutIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	for i := 1; i <= 10; i++ {
		r := f.login(t, "bia@example.com", "wrong password!")
		if r.Status != http.StatusUnauthorized || reason(&r) != "INVALID_CREDENTIALS" {
			t.Fatalf("attempt %d = %d %s, want 401 INVALID_CREDENTIALS", i, r.Status, r.Raw)
		}
		failed, locked, _ := f.userState(t)
		if failed != i || locked != (i == 10) {
			t.Fatalf("after attempt %d: failed_logins = %d, locked = %v", i, failed, locked)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.login_failed' AND actor_id IS NULL`); n != 10 {
		t.Errorf("auth.login_failed rows = %d, want 10", n)
	}
	for _, pw := range []string{"wrong password!", loginPassword} {
		r := f.login(t, "bia@example.com", pw)
		if r.Status != http.StatusUnauthorized || reason(&r) != "ACCOUNT_LOCKED" {
			t.Fatalf("11th attempt (%q) = %d %s, want 401 ACCOUNT_LOCKED", pw, r.Status, r.Raw)
		}
		if ra := r.Header.Get("Retry-After"); ra == "" || ra == "0" {
			t.Errorf("Retry-After = %q, want the remaining lock", ra)
		}
	}

	// The lock expires: move it into the past, as lockout_duration passing would.
	f.exec(t, `UPDATE users SET locked_until = now() - interval '1 second' WHERE NOT is_super_admin`)
	if r := f.login(t, "bia@example.com", loginPassword); r.Status != http.StatusOK {
		t.Fatalf("login after the lock expired = %d %s", r.Status, r.Raw)
	}
	if failed, locked, signedIn := f.userState(t); failed != 0 || locked || !signedIn {
		t.Errorf("after success failed = %d locked = %v signed in = %v", failed, locked, signedIn)
	}
}

// TestLoginUnknownEmailIdenticalBody answers an unknown address exactly like a
// wrong password.
func TestLoginUnknownEmailIdenticalBody(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	wrong := f.login(t, "bia@example.com", "wrong password!")
	unknown := f.login(t, "nobody@example.com", "wrong password!")
	if wrong.Status != http.StatusUnauthorized || unknown.Status != wrong.Status {
		t.Fatalf("statuses = %d and %d, want 401", wrong.Status, unknown.Status)
	}
	if got, want := withoutTimestamp(t, unknown.Raw), withoutTimestamp(t, wrong.Raw); !bytes.Equal(got, want) {
		t.Errorf("unknown body = %s, wrong password body = %s", got, want)
	}
}

// TestLoginSuccessIntegration returns tokens that validate against the JWKS,
// starts a session family with the device, stamps last_sign_in_at, resets
// the counter and audits auth.login without the email.
func TestLoginSuccessIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	f.login(t, "bia@example.com", "wrong password!")

	req := map[string]any{"email": "Bia@Example.com", "password": loginPassword}
	r := testkit.Do[map[string]any](t, f.srv, http.MethodPost, "/v1/auth/login", req,
		http.Header{"User-Agent": {"login-test/1.0"}})
	if r.Status != http.StatusOK {
		t.Fatalf("login = %d %s", r.Status, r.Raw)
	}
	d := r.Data
	if d["token_type"] != "Bearer" || d["expires_in"] != float64(900) || d["must_change_password"] != false ||
		d["refresh_token"] == nil || d["refresh_expires_in"] != float64(2592000) {
		t.Errorf("token response = %v", d)
	}
	user, _ := d["user"].(map[string]any)
	tenant, _ := d["tenant"].(map[string]any)
	if user["email"] != "bia@example.com" || user["display_name"] != "Bia" || tenant["slug"] != "default" {
		t.Errorf("user = %v, tenant = %v", user, tenant)
	}

	v, err := sdkauth.NewRS256(sdkauth.WithJWKSURL(f.srv.URL+"/.well-known/jwks.json"),
		sdkauth.WithExpectedIssuer("identity"), sdkauth.WithExpectedAudience("api"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.Validate(context.Background(), d["access_token"].(string))
	if err != nil {
		t.Fatalf("access token does not validate against the JWKS: %v", err)
	}
	if claims.Subject() != user["id"] || claims.Raw()["tid"] != tenant["id"] {
		t.Errorf("claims = %v", claims.Raw())
	}
	if roles := claims.Roles(); len(roles) != 1 || roles[0] != "member" {
		t.Errorf("roles = %v, want [member]", roles)
	}
	if _, has := claims.Get("scope"); has {
		t.Error("a full token carries a scope")
	}

	if n := f.count(t, `SELECT count(*) FROM refresh_tokens
		WHERE user_agent = 'login-test/1.0' AND ip IS NOT NULL AND revoked_at IS NULL`); n != 1 {
		t.Errorf("session rows = %d, want 1 with the device", n)
	}
	if failed, _, signedIn := f.userState(t); failed != 0 || !signedIn {
		t.Errorf("failed_logins = %d, last_sign_in_at set = %v", failed, signedIn)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND actor_id::text = $1`,
		user["id"]); n != 1 {
		t.Errorf("auth.login rows = %d, want 1", n)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log
		WHERE action LIKE 'auth.login%' AND (coalesce(after::text, '') ILIKE '%example.com%'
			OR coalesce(before::text, '') ILIKE '%example.com%' OR target_id ILIKE '%example.com%')`); n != 0 {
		t.Errorf("%d sign-in audit rows hold the email", n)
	}
}

// TestLoginRehashesOldParameters stores a hash written with weaker
// parameters and checks a sign-in replaces it with a current one.
func TestLoginRehashesOldParameters(t *testing.T) {
	f := newLoginFixture(t, nil)
	f.register(t)
	weak, err := password.HashWith(loginPassword,
		password.Params{Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32})
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE credentials SET password_hash = $1
		WHERE user_id = (SELECT id FROM users WHERE NOT is_super_admin)`, weak)
	if r := f.login(t, "bia@example.com", loginPassword); r.Status != http.StatusOK {
		t.Fatalf("login = %d %s", r.Status, r.Raw)
	}
	var stored string
	if err := f.db.Leader().QueryRowContext(context.Background(),
		`SELECT c.password_hash FROM credentials c JOIN users u ON u.id = c.user_id WHERE NOT u.is_super_admin`,
	).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == weak || password.NeedsRehash(stored) {
		t.Errorf("hash = %s, want a rehash with current parameters", stored)
	}
	if match, _, err := password.Verify(loginPassword, stored); err != nil || !match {
		t.Errorf("rehash does not verify: %v %v", match, err)
	}
}

// TestLoginMustChangePasswordIntegration signs the bootstrapped super admin
// in with a restricted token and no refresh token, and checks every other
// authenticated route rejects that token while a full token passes.
func TestLoginMustChangePasswordIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	r := f.login(t, testSuperAdmin.Email, testSuperAdmin.Password)
	if r.Status != http.StatusOK {
		t.Fatalf("login = %d %s", r.Status, r.Raw)
	}
	if _, has := r.Data["refresh_token"]; has || r.Data["must_change_password"] != true ||
		r.Data["expires_in"] != float64(600) {
		t.Errorf("restricted response = %v", r.Data)
	}
	if n := f.count(t, `SELECT count(*) FROM refresh_tokens`); n != 0 {
		t.Errorf("refresh tokens = %d, want none", n)
	}
	restricted := r.Data["access_token"].(string)

	// Auth runs before routing, so an unmounted path still shows the verdict:
	// a token the middleware accepts reaches the router (404).
	for _, path := range []string{"/v1/me", "/v1/admin/users"} {
		got := f.get(t, path, restricted)
		if got.Status != http.StatusForbidden || reason(&got) != "PASSWORD_CHANGE_REQUIRED" {
			t.Errorf("GET %s with a restricted token = %d %s, want 403 PASSWORD_CHANGE_REQUIRED", path, got.Status, got.Raw)
		}
	}
	pw := testkit.Do[map[string]any](t, f.srv, http.MethodPost, "/v1/me/password", map[string]any{}, http.Header{
		"Authorization": {"Bearer " + restricted},
	})
	if pw.Status == http.StatusForbidden || pw.Status == http.StatusUnauthorized {
		t.Errorf("POST /v1/me/password with a restricted token = %d %s, want it to pass auth", pw.Status, pw.Raw)
	}

	f.register(t)
	full := f.login(t, "bia@example.com", loginPassword)
	if got := f.get(t, "/v1/me", full.Data["access_token"].(string)); got.Status != http.StatusNotFound {
		t.Errorf("GET /v1/me with a full token = %d %s, want 404 (passes auth)", got.Status, got.Raw)
	}
	if got := f.get(t, "/v1/me", "not-a-token"); got.Status != http.StatusUnauthorized {
		t.Errorf("GET /v1/me with a bad token = %d, want 401", got.Status)
	}
}

// TestLoginRateLimitIntegration answers 429 with Retry-After once the
// per-IP budget is spent, and limits register the same way.
func TestLoginRateLimitIntegration(t *testing.T) {
	f := newLoginFixture(t, func(c *Config) { c.Modules.Auth.Security.LoginRateLimit = "3/5m" })
	for i := 1; i <= 3; i++ {
		if r := f.login(t, "nobody@example.com", "wrong password!"); r.Status != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d %s", i, r.Status, r.Raw)
		}
	}
	r := f.login(t, "other@example.com", "wrong password!")
	if r.Status != http.StatusTooManyRequests || reason(&r) != "RATE_LIMITED" {
		t.Fatalf("4th attempt = %d %s, want 429 RATE_LIMITED", r.Status, r.Raw)
	}
	if r.Header.Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}

	for i := 1; i <= 3; i++ {
		body := map[string]any{
			"email":    "new" + strings.Repeat("x", i) + "@example.com",
			"password": loginPassword, "display_name": "Bia",
		}
		if got := f.post(t, "/v1/auth/register", body); got.Status != http.StatusAccepted {
			t.Fatalf("register %d = %d %s", i, got.Status, got.Raw)
		}
	}
	body := map[string]any{"email": "late@example.com", "password": loginPassword, "display_name": "Bia"}
	if got := f.post(t, "/v1/auth/register", body); got.Status != http.StatusTooManyRequests ||
		got.Header.Get("Retry-After") == "" {
		t.Errorf("4th register = %d %s, want 429 with Retry-After", got.Status, got.Raw)
	}
	got := f.post(t, "/v1/auth/email/resend", map[string]any{"email": "a@example.com"})
	if got.Status != http.StatusAccepted {
		t.Errorf("resend has its own budget: %d %s", got.Status, got.Raw)
	}
}

// TestLoginRateLimitByEmail limits one address across IPs: the per-email key
// is spent even though each request comes from another forwarded address.
func TestLoginRateLimitByEmail(t *testing.T) {
	f := newLoginFixture(t, func(c *Config) {
		c.Modules.Auth.Security.LoginRateLimit = "2/5m"
		c.HTTP.TrustProxy = true
	})
	for i, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		r := testkit.Do[map[string]any](t, f.srv, http.MethodPost, "/v1/auth/login",
			map[string]any{"email": "target@example.com", "password": "wrong password!"},
			http.Header{"X-Forwarded-For": {ip}})
		want := http.StatusUnauthorized
		if i == 2 {
			want = http.StatusTooManyRequests
		}
		if r.Status != want {
			t.Errorf("attempt from %s = %d %s, want %d", ip, r.Status, r.Raw, want)
		}
	}
}

// TestLoginTenantRequiredIntegration lists the tenants of a multi-mode user
// who belongs to several and named none, signs in to the named one, and
// issues no tokens for the choice.
func TestLoginTenantRequiredIntegration(t *testing.T) {
	f := newLoginFixture(t, func(c *Config) { c.Modules.Tenant.Mode = "multi" })
	body := map[string]any{
		"email": "bia@example.com", "password": loginPassword, "display_name": "Bia", "tenant": "default",
	}
	if r := f.post(t, "/v1/auth/register", body); r.Status != http.StatusAccepted {
		t.Fatalf("register = %d %s", r.Status, r.Raw)
	}
	f.exec(t, `INSERT INTO tenants (slug, name) VALUES ('acme', 'Acme')`)
	f.exec(t, `INSERT INTO tenant_members (tenant_id, user_id, status, joined_at)
		SELECT t.id, u.id, 'active', now() FROM tenants t, users u WHERE t.slug = 'acme' AND NOT u.is_super_admin`)

	r := f.login(t, "bia@example.com", loginPassword)
	if r.Status != http.StatusOK || r.Data["tenant_required"] != true {
		t.Fatalf("login = %d %s, want 200 tenant_required", r.Status, r.Raw)
	}
	tenants, _ := r.Data["tenants"].([]any)
	if len(tenants) != 2 || r.Data["access_token"] != nil {
		t.Errorf("choice = %v, want two tenants and no token", r.Data)
	}
	if n := f.count(t, `SELECT count(*) FROM refresh_tokens`); n != 0 {
		t.Errorf("refresh tokens = %d after a tenant choice", n)
	}

	r = f.post(t, "/v1/auth/login",
		map[string]any{"email": "bia@example.com", "password": loginPassword, "tenant": "acme"})
	tenant, _ := r.Data["tenant"].(map[string]any)
	if r.Status != http.StatusOK || tenant["slug"] != "acme" || r.Data["refresh_token"] == nil {
		t.Errorf("login with tenant = %d %s", r.Status, r.Raw)
	}
}

// TestLoginRouteIsPublicPOSTOnly makes POST /v1/auth/login public while other
// methods on the path still need a token.
func TestLoginRouteIsPublicPOSTOnly(t *testing.T) {
	f := newLoginFixture(t, nil)
	if r := f.login(t, "nobody@example.com", "whatever pass"); r.Status != http.StatusUnauthorized ||
		reason(&r) != "INVALID_CREDENTIALS" {
		t.Errorf("POST = %d %s, want 401 INVALID_CREDENTIALS", r.Status, r.Raw)
	}
	r := testkit.Do[map[string]any](t, f.srv, http.MethodGet, "/v1/auth/login", nil, nil)
	if r.Status != http.StatusUnauthorized || reason(&r) != nil {
		t.Errorf("GET without a token = %d %s, want the auth middleware's 401", r.Status, r.Raw)
	}
}
