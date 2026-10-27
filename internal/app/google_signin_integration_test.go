package app

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// googleFixture is the app with Google sign-in on, pointed at a fake OIDC
// provider on a local port: no request ever leaves the machine.
type googleFixture struct {
	*loginFixture
	idp *testkit.OIDC
}

// Credentials the app and the fake provider share.
const (
	googleClientID     = "identity-client"
	googleClientSecret = "identity-secret"
	frontendCallback   = "http://localhost:3000/auth/callback"
)

// newGoogleFixture builds the app with Google on, after mutate adjusts it.
func newGoogleFixture(t *testing.T, mutate func(c *Config)) *googleFixture {
	t.Helper()
	idp := testkit.NewOIDC(t, googleClientID, googleClientSecret)
	f := newLoginFixture(t, func(c *Config) {
		g := &c.Modules.Auth.Providers.Google
		g.Enabled, g.ClientID, g.ClientSecret, g.IssuerURL = true, googleClientID, googleClientSecret, idp.URL
		if mutate != nil {
			mutate(c)
		}
	})
	return &googleFixture{loginFixture: f, idp: idp}
}

// noFollow hands back each redirect instead of following it.
var noFollow = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// hop GETs target, with a bearer token unless token is empty, and returns
// the Location of its 302.
func hop(t *testing.T, target, token string) *url.URL {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("build GET %s: %v", target, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET %s = %d, want 302: %s", target, resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location of %s: %v", target, err)
	}
	return loc
}

// flow runs startPath → provider → callback as u and returns the query the
// app sent the browser back to the frontend with, and the callback URL.
func (f *googleFixture) flow(
	t *testing.T, u testkit.OIDCUser, startPath, token string,
) (back url.Values, callback string) {
	t.Helper()
	f.idp.SignInAs(u)
	toProvider := hop(t, f.srv.URL+startPath, token)
	if !strings.HasPrefix(toProvider.String(), f.idp.URL+"/authorize?") {
		t.Fatalf("start redirected to %s, want the provider", toProvider)
	}
	if q := toProvider.Query(); q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
		t.Fatalf("authorize URL lacks PKCE or nonce: %s", toProvider)
	}
	cb := hop(t, toProvider.String(), "")
	toFrontend := hop(t, cb.String(), "")
	if !strings.HasPrefix(toFrontend.String(), frontendCallback+"?") {
		t.Fatalf("callback redirected to %s, want %s", toFrontend, frontendCallback)
	}
	return toFrontend.Query(), cb.String()
}

// signIn runs the sign-in flow as u.
func (f *googleFixture) signIn(t *testing.T, u testkit.OIDCUser) url.Values {
	t.Helper()
	q, _ := f.flow(t, u, "/v1/auth/google/start?redirect_to="+url.QueryEscape(frontendCallback), "")
	return q
}

// exchangeUser spends a callback code and returns the signed-in user's ID.
func (f *googleFixture) exchangeUser(t *testing.T, q url.Values) string {
	t.Helper()
	if q.Get("code") == "" {
		t.Fatalf("callback returned %v, want a code", q)
	}
	r := f.post(t, "/v1/auth/exchange", map[string]any{"code": q.Get("code")})
	user, _ := r.Data["user"].(map[string]any)
	id, _ := user["id"].(string)
	refresh, _ := r.Data["refresh_token"].(string)
	if r.Status != http.StatusOK || id == "" || refresh == "" {
		t.Fatalf("exchange = %d %s", r.Status, r.Raw)
	}
	return id
}

// ana is a Google account no user is linked to yet.
var ana = testkit.OIDCUser{Subject: "google-ana", Email: "ana@example.com", EmailVerified: true, Name: "Ana"}

// TestGoogleNewUserIntegration signs a new address up through Google: an
// active, verified user without a password, a member with the default role,
// a linked identity. The state and the exchange code are single use.
func TestGoogleNewUserIntegration(t *testing.T) {
	f := newGoogleFixture(t, nil)
	q, callback := f.flow(t, ana, "/v1/auth/google/start?redirect_to="+url.QueryEscape(frontendCallback), "")
	id := f.exchangeUser(t, q)

	if got := f.text(t, `SELECT display_name || ' ' || status || ' ' || (email_verified_at IS NOT NULL)::text
		FROM users WHERE id = $1`, id); got != "Ana active true" {
		t.Errorf("user = %q, want an active, verified Ana", got)
	}
	checks := []struct {
		what  string
		query string
		want  int
	}{
		{"credentials", `SELECT count(*) FROM credentials WHERE user_id = $1`, 0},
		{"identities", `SELECT count(*) FROM identities WHERE user_id = $1 AND provider = 'google'
			AND provider_subject = 'google-ana' AND email_at_link IS NOT NULL`, 1},
		{"memberships", `SELECT count(*) FROM tenant_members WHERE user_id = $1 AND status = 'active'`, 1},
		{"member role", `SELECT count(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id
			WHERE ur.user_id = $1 AND r.name = 'member'`, 1},
		{"register audit", `SELECT count(*) FROM audit_log WHERE action = 'auth.register'
			AND target_id = $1::text AND after->>'method' = 'google'`, 1},
		{"login audit", `SELECT count(*) FROM audit_log WHERE action = 'auth.login'
			AND target_id = $1::text AND after->>'method' = 'google'`, 1},
		{"signed in", `SELECT count(*) FROM users WHERE id = $1 AND last_sign_in_at IS NOT NULL`, 1},
	}
	for _, c := range checks {
		if n := f.count(t, c.query, id); n != c.want {
			t.Errorf("%s = %d, want %d", c.what, n, c.want)
		}
	}

	r := f.maybeAuthed(t, http.MethodGet, strings.TrimPrefix(callback, f.srv.URL), "", nil)
	wantReason(t, "replayed callback", &r, http.StatusBadRequest, "OAUTH_STATE_INVALID")
	r = f.post(t, "/v1/auth/exchange", map[string]any{"code": q.Get("code")})
	wantReason(t, "second exchange", &r, http.StatusBadRequest, "TOKEN_INVALID")
}

// TestGoogleLinkedUserIntegration signs a linked Google account in as its
// user again, even after Google reports another address.
func TestGoogleLinkedUserIntegration(t *testing.T) {
	f := newGoogleFixture(t, nil)
	first := f.exchangeUser(t, f.signIn(t, ana))
	moved := ana
	moved.Email = "ana@elsewhere.example"
	if again := f.exchangeUser(t, f.signIn(t, moved)); again != first {
		t.Errorf("second sign-in = user %s, want %s", again, first)
	}
	if n := f.count(t, `SELECT count(*) FROM users WHERE NOT is_super_admin`); n != 1 {
		t.Errorf("users = %d, want 1", n)
	}
}

// TestGoogleAutoLinkIntegration links Google to the password account with
// the same verified address, and refuses with DUPLICATE when auto-link is
// off.
func TestGoogleAutoLinkIntegration(t *testing.T) {
	bia := testkit.OIDCUser{Subject: "google-bia", Email: "bia@example.com", EmailVerified: true, Name: "B"}
	t.Run("on", func(t *testing.T) {
		f := newGoogleFixture(t, nil)
		f.register(t)
		id := f.userID(t, "Bia")
		if got := f.exchangeUser(t, f.signIn(t, bia)); got != id {
			t.Fatalf("Google sign-in = user %s, want the password account %s", got, id)
		}
		if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'identity.link' AND target_id = $1`, id); n != 1 {
			t.Errorf("identity.link audit rows = %d, want 1", n)
		}
		if f.login(t, "bia@example.com", loginPassword).Status != http.StatusOK {
			t.Error("the password still signs in after linking")
		}
	})
	t.Run("off", func(t *testing.T) {
		f := newGoogleFixture(t, func(c *Config) { c.Modules.Auth.Providers.Google.AutoLinkVerifiedEmail = false })
		f.register(t)
		if q := f.signIn(t, bia); q.Get("error") != "DUPLICATE" || q.Get("code") != "" {
			t.Errorf("callback = %v, want error=DUPLICATE", q)
		}
		if n := f.count(t, `SELECT count(*) FROM identities`); n != 0 {
			t.Errorf("identities = %d, want 0", n)
		}
	})
}

// TestGoogleRefusalsByRedirectIntegration answers each refusal with
// redirect_to?error=<reason>, creating nobody.
func TestGoogleRefusalsByRedirectIntegration(t *testing.T) {
	clientOnly := func(c *Config) { c.Modules.Auth.Providers.Google.AllowedDomains = []string{"client.com"} }
	staff := testkit.OIDCUser{Subject: "google-staff", Email: "lee@Client.com", EmailVerified: true}
	unverified := ana
	unverified.EmailVerified = false
	tests := []struct {
		name   string
		mutate func(c *Config)
		user   testkit.OIDCUser
		want   string // error reason, or "" for a code
	}{
		{"unverified email", nil, unverified, "OAUTH_EMAIL_UNVERIFIED"},
		{"domain not allowed", clientOnly, ana, "OAUTH_DOMAIN_NOT_ALLOWED"},
		{"allowed domain", clientOnly, staff, ""},
		{
			"registration closed", func(c *Config) { c.Modules.Auth.Registration.Enabled = false }, ana,
			"REGISTRATION_CLOSED",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newGoogleFixture(t, tt.mutate)
			q := f.signIn(t, tt.user)
			if tt.want == "" {
				f.exchangeUser(t, q)
				return
			}
			if q.Get("error") != tt.want || q.Get("code") != "" {
				t.Errorf("callback = %v, want error=%s", q, tt.want)
			}
			if n := f.count(t, `SELECT count(*) FROM users WHERE NOT is_super_admin`); n != 0 {
				t.Errorf("users = %d, want 0", n)
			}
		})
	}
}

// TestGoogleLinkIntegration links Google to the signed-in user from
// link/start; the account then signs in with Google, and nobody else can
// link it.
func TestGoogleLinkIntegration(t *testing.T) {
	f := newGoogleFixture(t, nil)
	f.register(t)
	f.registerAs(t, "kim@example.com", "Kim")
	start := "/v1/auth/google/link/start?redirect_to=" + url.QueryEscape(frontendCallback)
	googleBia := testkit.OIDCUser{Subject: "google-bia", Email: "bia.personal@example.com", EmailVerified: true}

	if q, _ := f.flow(t, googleBia, start, f.token(t, "bia@example.com")); q.Get("linked") != "1" {
		t.Fatalf("link callback = %v, want linked=1", q)
	}
	me := f.get(t, "/v1/me", f.token(t, "bia@example.com"))
	if providers, _ := me.Data["providers"].(map[string]any); providers["google"] != true {
		t.Errorf("GET /v1/me providers = %v, want google: true", me.Data["providers"])
	}
	if got := f.exchangeUser(t, f.signIn(t, googleBia)); got != f.userID(t, "Bia") {
		t.Errorf("Google sign-in = user %s, want Bia", got)
	}
	if q, _ := f.flow(t, googleBia, start, f.token(t, "kim@example.com")); q.Get("error") != "DUPLICATE" {
		t.Errorf("linking Bia's Google to Kim = %v, want error=DUPLICATE", q)
	}
}
