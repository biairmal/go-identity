package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
)

// signIn registers bia@example.com and signs in, returning the refresh token.
func (f *loginFixture) signIn(t *testing.T) string {
	t.Helper()
	f.register(t)
	return f.newSession(t)
}

// newSession signs the registered user in again: one more device, one more
// family.
func (f *loginFixture) newSession(t *testing.T) string {
	t.Helper()
	r := f.login(t, "bia@example.com", loginPassword)
	rt, ok := r.Data["refresh_token"].(string)
	if r.Status != http.StatusOK || !ok {
		t.Fatalf("login = %d %s", r.Status, r.Raw)
	}
	return rt
}

func (f *loginFixture) refresh(t *testing.T, rt string) (status int, reasonValue any, data map[string]any) {
	t.Helper()
	r := f.post(t, "/v1/auth/refresh", map[string]any{"refresh_token": rt})
	return r.Status, reason(&r), r.Data
}

// liveTokens counts the unrevoked refresh tokens of the ordinary user.
func (f *loginFixture) liveTokens(t *testing.T) int {
	t.Helper()
	return f.count(t, `SELECT count(*) FROM refresh_tokens r JOIN users u ON u.id = r.user_id
		WHERE NOT u.is_super_admin AND r.revoked_at IS NULL`)
}

// families counts the distinct families of the ordinary user, all, and
// those with a live token.
func (f *loginFixture) families(t *testing.T) (all, live int) {
	t.Helper()
	all = f.count(t, `SELECT count(DISTINCT family_id) FROM refresh_tokens`)
	live = f.count(t, `SELECT count(DISTINCT family_id) FROM refresh_tokens WHERE revoked_at IS NULL`)
	return all, live
}

// roles validates an access token against the app's JWKS and returns its
// roles.
func (f *loginFixture) roles(t *testing.T, accessToken string) []string {
	t.Helper()
	v, err := sdkauth.NewRS256(sdkauth.WithJWKSURL(f.srv.URL+"/.well-known/jwks.json"),
		sdkauth.WithExpectedIssuer("identity"), sdkauth.WithExpectedAudience("api"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.Validate(context.Background(), accessToken)
	if err != nil {
		t.Fatalf("access token does not validate: %v", err)
	}
	return claims.Roles()
}

// TestRefreshShowsNewRolesIntegration rotates the token and signs the access
// token with the roles the user holds now, so an admin's role change shows
// at the next refresh.
func TestRefreshShowsNewRolesIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	rt := f.signIn(t)

	f.exec(t, `INSERT INTO user_roles (tenant_id, user_id, role_id)
		SELECT r.tenant_id, u.id, r.id FROM roles r, users u
		WHERE r.name = 'admin' AND r.tenant_id IS NOT NULL AND NOT u.is_super_admin`)

	status, _, d := f.refresh(t, rt)
	if status != http.StatusOK {
		t.Fatalf("refresh = %d %v", status, d)
	}
	next, _ := d["refresh_token"].(string)
	if next == "" || next == rt || d["refresh_expires_in"] != float64(2592000) || d["token_type"] != "Bearer" {
		t.Errorf("token response = %v", d)
	}
	got := f.roles(t, d["access_token"].(string))
	if len(got) != 2 || !contains(got, "admin") || !contains(got, "member") {
		t.Errorf("roles after the change = %v, want admin and member", got)
	}
	if all, live := f.families(t); all != 1 || live != 1 {
		t.Errorf("families = %d (live %d), want the one family kept", all, live)
	}
	if status, _, d := f.refresh(t, next); status != http.StatusOK {
		t.Errorf("refresh with the rotated-to token = %d %v", status, d)
	}
}

// TestRefreshFailuresIntegration covers the refusals and checks the family's
// state after each 401 or 403 is the one APP_FLOW 7 commits.
func TestRefreshFailuresIntegration(t *testing.T) {
	tests := []struct {
		name string
		// prepare changes the database after sign-in and returns the token
		// to present.
		prepare    func(t *testing.T, f *loginFixture, rt string) string
		status     int
		reason     string
		liveAfter  int
		reuseAudit int
	}{
		{
			"unknown token", func(*testing.T, *loginFixture, string) string { return "not-a-token" },
			http.StatusUnauthorized, "INVALID_CREDENTIALS", 1, 0,
		},
		{"sliding expiry passed", func(t *testing.T, f *loginFixture, rt string) string {
			f.exec(t, `UPDATE refresh_tokens SET expires_at = now() - interval '1 second'`)
			return rt
		}, http.StatusUnauthorized, "REFRESH_EXPIRED", 1, 0},
		{"absolute expiry passed", func(t *testing.T, f *loginFixture, rt string) string {
			f.exec(t, `UPDATE refresh_tokens SET absolute_expires_at = now() - interval '1 second'`)
			return rt
		}, http.StatusUnauthorized, "REFRESH_EXPIRED", 1, 0},
		{"disabled user", func(t *testing.T, f *loginFixture, rt string) string {
			f.exec(t, `UPDATE users SET status = 'disabled' WHERE NOT is_super_admin`)
			return rt
		}, http.StatusForbidden, "ACCOUNT_DISABLED", 0, 0},
		{"forced password change", func(t *testing.T, f *loginFixture, rt string) string {
			f.exec(t, `UPDATE users SET must_change_password = true WHERE NOT is_super_admin`)
			return rt
		}, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", 0, 0},
		{"reused after the grace", func(t *testing.T, f *loginFixture, rt string) string {
			if status, _, d := f.refresh(t, rt); status != http.StatusOK {
				t.Fatalf("first refresh = %d %v", status, d)
			}
			f.exec(t, `UPDATE refresh_tokens SET rotated_at = now() - interval '1 minute' WHERE rotated_at IS NOT NULL`)
			return rt
		}, http.StatusUnauthorized, "REFRESH_REUSED", 0, 1},
		{"family signed out", func(t *testing.T, f *loginFixture, rt string) string {
			if r := f.post(t, "/v1/auth/logout", map[string]any{"refresh_token": rt}); r.Status != http.StatusNoContent {
				t.Fatalf("logout = %d %s", r.Status, r.Raw)
			}
			return rt
		}, http.StatusUnauthorized, "REFRESH_REUSED", 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newLoginFixture(t, nil)
			rt := tt.prepare(t, f, f.signIn(t))
			status, got, d := f.refresh(t, rt)
			if status != tt.status || got != tt.reason {
				t.Fatalf("refresh = %d %v (%v), want %d %s", status, got, d, tt.status, tt.reason)
			}
			if d["access_token"] != nil {
				t.Error("a refused refresh returned a token")
			}
			if n := f.liveTokens(t); n != tt.liveAfter {
				t.Errorf("live tokens after the refusal = %d, want %d", n, tt.liveAfter)
			}
			n := f.count(t, `SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_id
				WHERE a.action = 'auth.refresh_reuse' AND NOT u.is_super_admin`)
			if n != tt.reuseAudit {
				t.Errorf("auth.refresh_reuse rows = %d, want %d", n, tt.reuseAudit)
			}
		})
	}
}

// TestRefreshReuseRevokesTheWholeFamilyIntegration replays a rotated token
// after the grace: the token the legitimate client holds now dies with it,
// and only that family, not the user's other sessions.
func TestRefreshReuseRevokesTheWholeFamilyIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	stolen := f.signIn(t)
	other := f.newSession(t)
	_, _, d := f.refresh(t, stolen)
	current, _ := d["refresh_token"].(string)
	if current == "" {
		t.Fatalf("refresh = %v", d)
	}
	f.exec(t, `UPDATE refresh_tokens SET rotated_at = now() - interval '1 minute' WHERE rotated_at IS NOT NULL`)

	if status, got, _ := f.refresh(t, stolen); status != http.StatusUnauthorized || got != "REFRESH_REUSED" {
		t.Fatalf("replay = %d %v, want 401 REFRESH_REUSED", status, got)
	}
	if status, got, _ := f.refresh(t, current); status != http.StatusUnauthorized || got != "REFRESH_REUSED" {
		t.Errorf("the family's newest token after the replay = %d %v, want 401 REFRESH_REUSED", status, got)
	}
	if status, _, d := f.refresh(t, other); status != http.StatusOK {
		t.Errorf("another device's family = %d %v, want it untouched", status, d)
	}
}

// TestRefreshConcurrentInsideTheGraceIntegration presents one token from two
// goroutines at once, as two pods would: both get a token, distinct, in the
// same family, and nothing is revoked.
func TestRefreshConcurrentInsideTheGraceIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	rt := f.signIn(t)
	body, err := json.Marshal(map[string]any{"refresh_token": rt})
	if err != nil {
		t.Fatal(err)
	}

	const n = 2
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		tokens  = make([]string, n)
		failure = make([]error, n)
	)
	for i := range n {
		wg.Go(func() {
			<-start
			tokens[i], failure[i] = refreshRaw(f.srv.Client(), f.srv.URL, body)
		})
	}
	close(start)
	wg.Wait()

	for i, err := range failure {
		if err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
	}
	if tokens[0] == tokens[1] || tokens[0] == rt || tokens[1] == rt {
		t.Errorf("tokens = %v, want two new distinct ones", tokens)
	}
	if all, live := f.families(t); all != 1 || live != 1 {
		t.Errorf("families = %d (live %d), want the one family", all, live)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.refresh_reuse'`); n != 0 {
		t.Errorf("a race inside the grace was audited as reuse %d times", n)
	}
	for _, tok := range tokens {
		if status, _, d := f.refresh(t, tok); status != http.StatusOK {
			t.Errorf("refresh with a sibling = %d %v", status, d)
		}
	}
}

// refreshRaw calls POST /v1/auth/refresh without testing.T, so it can run in
// a goroutine, and returns the new refresh token.
func refreshRaw(c *http.Client, base string, body []byte) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		base+"/v1/auth/refresh", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var env struct {
		Data struct {
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK || env.Data.RefreshToken == "" {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	return env.Data.RefreshToken, nil
}

// TestLogoutIntegration revokes only the presented family and audits it; an
// unknown or dead token is answered 204 without an audit row.
func TestLogoutIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	rt := f.signIn(t)
	other := f.newSession(t)

	for _, tok := range []string{rt, rt, "not-a-token"} {
		if r := f.post(t, "/v1/auth/logout", map[string]any{"refresh_token": tok}); r.Status != http.StatusNoContent ||
			len(bytes.TrimSpace(r.Raw)) != 0 {
			t.Fatalf("logout = %d %s, want 204 with no body", r.Status, r.Raw)
		}
	}
	if all, live := f.families(t); all != 2 || live != 1 {
		t.Errorf("families = %d (live %d), want one of two revoked", all, live)
	}
	if status, _, d := f.refresh(t, other); status != http.StatusOK {
		t.Errorf("the other device = %d %v, want it still signed in", status, d)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log a JOIN users u ON u.id = a.actor_id
		WHERE a.action = 'auth.logout' AND NOT u.is_super_admin AND a.target_id = u.id::text`); n != 1 {
		t.Errorf("auth.logout rows = %d, want 1 (repeats and unknown tokens are not audited)", n)
	}
	if r := f.post(t, "/v1/auth/logout", map[string]any{}); r.Status != http.StatusBadRequest {
		t.Errorf("logout without a token = %d, want 400", r.Status)
	}
}

// TestLogoutAllIntegration revokes every family of the user and audits it
// once. A dead token signs no one out: 204, the live sessions stay.
func TestLogoutAllIntegration(t *testing.T) {
	f := newLoginFixture(t, nil)
	rt := f.signIn(t)
	f.newSession(t)
	dead := f.newSession(t)
	if r := f.post(t, "/v1/auth/logout", map[string]any{"refresh_token": dead}); r.Status != http.StatusNoContent {
		t.Fatalf("logout = %d", r.Status)
	}

	for _, tok := range []string{dead, "not-a-token"} {
		if r := f.post(t, "/v1/auth/logout-all", map[string]any{"refresh_token": tok}); r.Status != http.StatusNoContent {
			t.Fatalf("logout-all with a dead token = %d %s", r.Status, r.Raw)
		}
	}
	if _, live := f.families(t); live != 2 {
		t.Fatalf("live families after logout-all with a dead token = %d, want 2", live)
	}

	if r := f.post(t, "/v1/auth/logout-all", map[string]any{"refresh_token": rt}); r.Status != http.StatusNoContent {
		t.Fatalf("logout-all = %d %s", r.Status, r.Raw)
	}
	if all, live := f.families(t); all != 3 || live != 0 {
		t.Errorf("families = %d (live %d), want all revoked", all, live)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.logout_all'`); n != 1 {
		t.Errorf("auth.logout_all rows = %d, want 1", n)
	}
	if status, got, _ := f.refresh(t, rt); status != http.StatusUnauthorized || got != "REFRESH_REUSED" {
		t.Errorf("refresh after logout-all = %d %v, want 401 REFRESH_REUSED", status, got)
	}
}

// TestRefreshRoutesArePublicPOSTOnly makes the three routes public for POST
// only; another method on the same path still needs a bearer token.
func TestRefreshRoutesArePublicPOSTOnly(t *testing.T) {
	f := newLoginFixture(t, nil)
	for _, path := range []string{"/v1/auth/refresh", "/v1/auth/logout", "/v1/auth/logout-all"} {
		r := f.post(t, path, map[string]any{"refresh_token": "not-a-token"})
		if r.Status == http.StatusUnauthorized && reason(&r) == nil {
			t.Errorf("POST %s = the auth middleware's 401, want it public", path)
		}
		if got := f.get(t, path, "not-a-token"); got.Status != http.StatusUnauthorized || reason(&got) != nil {
			t.Errorf("GET %s with a bad token = %d %s, want the middleware's 401", path, got.Status, got.Raw)
		}
	}
}

// TestRefreshRateLimitIntegration answers 429 once the per-IP refresh budget
// is spent, with its own budget apart from login's.
func TestRefreshRateLimitIntegration(t *testing.T) {
	f := newLoginFixture(t, func(c *Config) { c.Modules.Auth.Security.RefreshRateLimit = "2/5m" })
	for i := 1; i <= 2; i++ {
		if status, got, _ := f.refresh(t, "not-a-token"); status != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d %v", i, status, got)
		}
	}
	r := f.post(t, "/v1/auth/refresh", map[string]any{"refresh_token": "not-a-token"})
	if r.Status != http.StatusTooManyRequests || reason(&r) != "RATE_LIMITED" || r.Header.Get("Retry-After") == "" {
		t.Errorf("3rd refresh = %d %s, want 429 RATE_LIMITED with Retry-After", r.Status, r.Raw)
	}
	if got := f.login(t, "nobody@example.com", "wrong password!"); got.Status != http.StatusUnauthorized {
		t.Errorf("login has its own budget: %d %s", got.Status, got.Raw)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
