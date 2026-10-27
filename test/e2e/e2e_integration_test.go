package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/biairmal/go-identity/internal/app"
	"github.com/biairmal/go-identity/internal/platform/testkit"
	"github.com/biairmal/go-identity/test/e2e/sampleresource"
)

// TestNotesWithEachProvider runs the resource-service checks under the three
// provider configs (TRD 12): a token from identity, validated through its
// JWKS, drives the sample service's permission and owner checks; a user whose
// roles are taken away loses access at the next token.
func TestNotesWithEachProvider(t *testing.T) {
	tests := []struct {
		name             string
		password, google bool
	}{
		{"password only", true, false},
		{"google only", false, true},
		{"both", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			google := testkit.NewOIDC(t, googleClientID, googleClientSecret)
			cfg := identityConfig(t, func(c *app.Config) {
				c.Modules.Auth.Providers.Password.Enabled = tc.password
				g := &c.Modules.Auth.Providers.Google
				g.Enabled, g.ClientID, g.ClientSecret, g.IssuerURL = tc.google, googleClientID, googleClientSecret,
					google.URL
			})
			idp, db := startIdentity(t, cfg)
			notes := startSample(t, idp.URL)

			// With both providers on, users alternate between them.
			signIn := func(i int, email string) session {
				if !tc.password || (tc.google && i%2 == 1) {
					return googleSignIn(t, idp, google, email)
				}
				return passwordSignIn(t, idp, email, "")
			}
			owner := signIn(0, "owner@example.com")
			other := signIn(1, "other@example.com")
			admin := signIn(2, "admin@example.com")
			grantRole(t, db, admin.userID, "admin", "default")
			admin = refresh(t, idp, admin)

			checkNotes(t, notes, owner, other, admin)

			exec(t, db, `DELETE FROM user_roles WHERE user_id = $1`, other.userID)
			other = refresh(t, idp, other)
			r := call(t, notes, http.MethodPost, "/notes", other.access, map[string]any{"text": "x"})
			if r.Status != http.StatusForbidden {
				t.Errorf("write without roles = %d %s, want 403", r.Status, r.Raw)
			}
		})
	}
}

// checkNotes covers the sample service's checks: authentication, the owner
// scope of notes:read and the tenant-wide scope of notes:read:any.
func checkNotes(t *testing.T, notes *httptest.Server, owner, other, admin session) {
	t.Helper()
	created := call(t, notes, http.MethodPost, "/notes", owner.access, map[string]any{"text": "owner's note"})
	id, _ := created.Data["id"].(string)
	if created.Status != http.StatusCreated || created.Data["owner_id"] != owner.userID || id == "" {
		t.Fatalf("create note = %d %s", created.Status, created.Raw)
	}

	cases := []struct {
		name   string
		token  string
		status int // of GET /notes/{id}
		listed int // notes in GET /notes
	}{
		{"owner", owner.access, http.StatusOK, 1},
		{"another member", other.access, http.StatusNotFound, 0},
		{"admin with notes:read:any", admin.access, http.StatusOK, 1},
	}
	for _, c := range cases {
		if r := call(t, notes, http.MethodGet, "/notes/"+id, c.token, nil); r.Status != c.status {
			t.Errorf("%s: GET /notes/%s = %d %s, want %d", c.name, id, r.Status, r.Raw, c.status)
		}
		if got := listNotes(t, notes, c.token); len(got) != c.listed {
			t.Errorf("%s: GET /notes = %v, want %d notes", c.name, got, c.listed)
		}
	}

	for name, token := range map[string]string{"no token": "", "garbage token": "not-a-jwt"} {
		if r := call(t, notes, http.MethodGet, "/notes", token, nil); r.Status != http.StatusUnauthorized {
			t.Errorf("%s: GET /notes = %d, want 401", name, r.Status)
		}
	}
}

func listNotes(t *testing.T, notes *httptest.Server, token string) []sampleresource.Note {
	t.Helper()
	r := testkit.Do[[]sampleresource.Note](t, notes, http.MethodGet, "/notes", nil,
		http.Header{"Authorization": {"Bearer " + token}})
	if r.Status != http.StatusOK {
		t.Fatalf("GET /notes = %d %s", r.Status, r.Raw)
	}
	return r.Data
}

// TestTenantIsolationInTheResourceService runs identity in multi mode with
// two tenants: an admin holding notes:read:any in tenant B can neither read
// nor list tenant A's note in the sample service, and the other way round.
func TestTenantIsolationInTheResourceService(t *testing.T) {
	cfg := identityConfig(t, func(c *app.Config) { c.Modules.Tenant.Mode = "multi" })
	idp, db := startIdentity(t, cfg)
	notes := startSample(t, idp.URL)

	// Tenant A is the default tenant; tenant B is created by the super admin,
	// whose invite makes B's first admin.
	adminA := passwordSignIn(t, idp, "admin-a@example.com", "default")
	grantRole(t, db, adminA.userID, "admin", "default")
	adminA = refresh(t, idp, adminA)

	exec(t, db, `UPDATE users SET must_change_password = false WHERE is_super_admin`)
	super := login(t, idp, superEmail, superPassword, "")
	r := call(t, idp, http.MethodPost, "/v1/admin/tenants", super.access,
		map[string]any{"slug": "tenant-b", "name": "Tenant B", "first_admin_email": "admin-b@example.com"})
	if r.Status != http.StatusCreated {
		t.Fatalf("create tenant B = %d %s", r.Status, r.Raw)
	}
	invite := text(t, db, `SELECT payload->>'token' FROM outbox WHERE payload->>'template' = 'invite'
		AND payload->>'to' = 'admin-b@example.com' ORDER BY id DESC LIMIT 1`)
	accept := call(t, idp, http.MethodPost, "/v1/auth/invite/accept", "",
		map[string]any{"token": invite, "password": userPassword})
	if accept.Status != http.StatusOK {
		t.Fatalf("accept invite = %d %s", accept.Status, accept.Raw)
	}
	adminB := login(t, idp, "admin-b@example.com", userPassword, "tenant-b")

	a := call(t, notes, http.MethodPost, "/notes", adminA.access, map[string]any{"text": "A's note"})
	b := call(t, notes, http.MethodPost, "/notes", adminB.access, map[string]any{"text": "B's note"})
	if a.Status != http.StatusCreated || b.Status != http.StatusCreated {
		t.Fatalf("create notes = %d %s / %d %s", a.Status, a.Raw, b.Status, b.Raw)
	}
	for _, c := range []struct {
		name           string
		token, foreign string
		own            any
	}{
		{"B reads A", adminB.access, a.Data["id"].(string), b.Data["id"]},
		{"A reads B", adminA.access, b.Data["id"].(string), a.Data["id"]},
	} {
		if r := call(t, notes, http.MethodGet, "/notes/"+c.foreign, c.token, nil); r.Status != http.StatusNotFound {
			t.Errorf("%s: GET = %d %s, want 404", c.name, r.Status, r.Raw)
		}
		if got := listNotes(t, notes, c.token); len(got) != 1 || got[0].ID != c.own {
			t.Errorf("%s: list = %v, want only the caller's tenant's note", c.name, got)
		}
	}
}

// TestKeyRotationUnderLoad rotates the signing key while users refresh
// through a balancer and call the sample service with each new token (TRD 6
// rotation, TRD 12): replica A signs with k1 and publishes k2 as next; B and
// C sign with k2 and keep k1 as retiring; A is then taken out. No call may
// fail, and a sample service started after the rotation still accepts a k1
// token.
func TestKeyRotationUnderLoad(t *testing.T) {
	before := testkit.SigningKeys(t, "k1", "k2")
	cfg := identityConfig(t, func(c *app.Config) { c.Modules.Auth.Token.SigningKeysDir = before })
	replicaA, _ := startIdentity(t, cfg)
	lb := newBalancer(t, replicaA)
	notes := startSample(t, lb.srv.URL)

	const workers = 6
	sessions := make([]session, workers)
	for i := range sessions {
		sessions[i] = passwordSignIn(t, lb.srv, fmt.Sprintf("load%d@example.com", i), "")
	}
	k1Token := sessions[0].access

	var (
		stop     atomic.Bool
		mu       sync.Mutex
		kids     = map[string]int{}
		failures []string
		wg       sync.WaitGroup
	)
	for _, s := range sessions {
		wg.Go(func() {
			rt := s.refresh
			for !stop.Load() {
				var kid string
				var err error
				rt, kid, err = loadStep(lb.srv.URL, notes.URL, rt)
				mu.Lock()
				if err != nil {
					failures = append(failures, err.Error())
				} else {
					kids[kid]++
				}
				mu.Unlock()
				if err != nil {
					return
				}
			}
		})
	}

	time.Sleep(300 * time.Millisecond)
	rotatedCfg := *cfg
	rotatedCfg.Modules.Auth.Token.SigningKeysDir = rotate(t, before)
	replicaB, _ := startIdentity(t, &rotatedCfg)
	lb.set(t, replicaA, replicaB)
	time.Sleep(300 * time.Millisecond)
	replicaC, _ := startIdentity(t, &rotatedCfg)
	lb.set(t, replicaB, replicaC)
	time.Sleep(300 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	if len(failures) > 0 {
		t.Fatalf("%d calls failed during the rotation, first: %s", len(failures), failures[0])
	}
	if kids["k1"] == 0 || kids["k2"] == 0 {
		t.Fatalf("tokens by kid = %v, want both keys to have signed under load", kids)
	}

	t.Logf("tokens by kid: %v", kids)

	// A service whose first JWKS fetch comes after the rotation still accepts
	// a k1 token, because k1 stays published as retiring.
	listNotes(t, startSample(t, lb.srv.URL), k1Token)
}

// rotate copies the keys in dir into a new directory whose manifest makes k2
// the signing key and keeps k1 published as retiring.
func rotate(t *testing.T, dir string) string {
	t.Helper()
	out := t.TempDir()
	for _, kid := range []string{"k1", "k2"} {
		b, err := os.ReadFile(filepath.Join(dir, kid+".pem"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, kid+".pem"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := "active: k2\nretiring:\n  - k1\n"
	if err := os.WriteFile(filepath.Join(out, "keys.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

// loadStep refreshes through identity and calls the sample service with the
// new access token. It returns the next refresh token and the kid that signed
// the access token. It never touches t: it runs on worker goroutines.
func loadStep(identityURL, notesURL, refreshToken string) (next, kid string, err error) {
	ctx := context.Background()
	body, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, identityURL+"/v1/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	var env struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	err = json.NewDecoder(resp.Body).Decode(&env)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("refresh = %d: %w", resp.StatusCode, err)
	}

	header, _ := base64.RawURLEncoding.DecodeString(strings.Split(env.Data.AccessToken, ".")[0])
	var h struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(header, &h); err != nil {
		return "", "", err
	}

	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, notesURL+"/notes", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+env.Data.AccessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("GET /notes with a %s token = %d", h.KID, resp.StatusCode)
	}
	return env.Data.RefreshToken, h.KID, nil
}

// TestLoginLimitsAcrossReplicas runs two identity replicas on one Redis
// (TRD 12): the lockout and the login rate limit count attempts from both, so
// alternating replicas gains an attacker nothing. With in-memory limits each
// replica would allow the full budget.
func TestLoginLimitsAcrossReplicas(t *testing.T) {
	const limit = 6
	redisAddr := startRedis(t)
	cfg := identityConfig(t, func(c *app.Config) {
		c.Redis.Address = redisAddr
		c.Modules.Auth.Security.LoginRateLimit = fmt.Sprintf("%d/5m", limit)
		c.Modules.Auth.Security.LockoutAfterFailures = 3
	})
	a, _ := startIdentity(t, cfg)
	b, _ := startIdentity(t, cfg)
	replicas := []*httptest.Server{a, b}
	if r := call(t, a, http.MethodPost, "/v1/auth/register", "", map[string]any{
		"email": "bia@example.com", "password": userPassword, "display_name": "Bia",
	}); r.Status != http.StatusAccepted {
		t.Fatalf("register = %d %s", r.Status, r.Raw)
	}

	attempt := func(i int, pw string) testkit.Response[map[string]any] {
		return call(t, replicas[i%2], http.MethodPost, "/v1/auth/login", "",
			map[string]any{"email": "bia@example.com", "password": pw})
	}
	for i := range 3 {
		if r := attempt(i, "wrong password!"); r.Status != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d %s", i+1, r.Status, r.Raw)
		}
	}
	for i := 3; i < limit; i++ {
		r := attempt(i, userPassword)
		if r.Status != http.StatusUnauthorized || r.Error == nil || !strings.Contains(string(r.Raw), "ACCOUNT_LOCKED") {
			t.Fatalf("attempt %d with the right password = %d %s, want 401 ACCOUNT_LOCKED", i+1, r.Status, r.Raw)
		}
	}
	for i := limit; i < limit+2; i++ {
		if r := attempt(i, userPassword); r.Status != http.StatusTooManyRequests {
			t.Errorf("attempt %d = %d %s, want 429 from either replica", i+1, r.Status, r.Raw)
		}
	}
}
