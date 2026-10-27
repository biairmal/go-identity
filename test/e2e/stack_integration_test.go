// Package e2e runs identity next to a resource service (sampleresource) the
// way they are deployed: separate HTTP servers that talk only over HTTP, on a
// real Postgres and, where a test needs it, a real Redis. Identity replicas
// share the database, the signing keys and Redis, behind a round-robin
// balancer. test/e2e/README.md maps every TRD 12 acceptance item to a test.
package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/biairmal/go-identity/internal/app"
	identityauth "github.com/biairmal/go-identity/internal/module/auth"
	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/module/rbac"
	"github.com/biairmal/go-identity/internal/module/user"
	"github.com/biairmal/go-identity/internal/platform/testkit"
	"github.com/biairmal/go-identity/test/e2e/sampleresource"
)

const (
	userPassword  = "a-good-enough-passw0rd"
	superEmail    = "root@example.com"
	superPassword = "first-start-password-42"

	// The sample service's client credentials in identity.
	sampleClientID     = "sample-resource"
	sampleClientSecret = "correct horse battery staple"

	googleClientID     = "identity-client"
	googleClientSecret = "identity-secret"
	frontendCallback   = "http://localhost:3000/auth/callback"
)

// identityConfig is identity's config for the suite: auth on, the sample
// service as a service client, and the notes permissions in the catalog
// (admin gets notes:read:any, member reads and writes its own notes). It
// empties the database. mutate runs last.
func identityConfig(t *testing.T, mutate func(c *app.Config)) *app.Config {
	t.Helper()
	cfg, err := app.LoadConfig("", filepath.Join("..", "..", "config", "config.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	cfg.Database = testkit.PostgresConfig(t)
	cfg.Database.Pool.MaxOpenConns = 8 // several replicas share one test Postgres
	cfg.Auth.Enabled = true
	cfg.Auth.CacheTTL = 0
	cfg.Modules.User.SuperAdmin = user.SuperAdminConfig{Email: superEmail, Password: superPassword}
	cfg.Modules.Auth.Providers.Password.RequireEmailVerification = false
	cfg.Modules.Auth.Security.LoginRateLimit = "100000/5m"
	cfg.Modules.Auth.Security.RefreshRateLimit = "100000/5m"
	cfg.Modules.Auth.Token.SigningKeysDir = testkit.SigningKeys(t, "k1")

	hash, err := password.Hash(sampleClientSecret)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Modules.Auth.ServiceClients = []identityauth.ServiceClient{{ID: sampleClientID, SecretHash: hash}}

	rb := &cfg.Modules.RBAC
	rb.Permissions = append(rb.Permissions,
		rbac.Permission{Key: sampleresource.PermRead, Description: "Read own notes"},
		rbac.Permission{Key: sampleresource.PermReadAny, Description: "Read every note in the tenant"},
		rbac.Permission{Key: sampleresource.PermWrite, Description: "Write notes"},
	)
	rb.Roles["admin"] = append(rb.Roles["admin"], sampleresource.PermRead, sampleresource.PermReadAny,
		sampleresource.PermWrite)
	rb.Roles["member"] = []string{sampleresource.PermRead, sampleresource.PermWrite}

	if mutate != nil {
		mutate(&cfg)
	}
	return &cfg
}

// startIdentity starts one identity replica on its own port and returns it
// with its database handle. Replicas built from one config share the
// database, the signing keys and Redis.
func startIdentity(t *testing.T, cfg *app.Config) (*httptest.Server, *sqlkit.DB) {
	t.Helper()
	var h atomic.Pointer[http.Handler]
	srv := testkit.Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := h.Load(); p != nil {
			(*p).ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	c := *cfg
	c.Auth.Local.JWKSURL = srv.URL + "/.well-known/jwks.json"
	c.Modules.Auth.PublicURL = srv.URL
	a, err := app.New(context.Background(), &c, logger.NewNoOp())
	if err != nil {
		t.Fatalf("start identity: %v", err)
	}
	t.Cleanup(func() { _ = a.DB().Close() })
	handler := a.Handler()
	h.Store(&handler)
	return srv, a.DB()
}

// balancer round-robins requests over identity replicas, like a Service in
// front of the pods. Replacing the set is a rolling deploy.
type balancer struct {
	srv      *httptest.Server
	backends atomic.Pointer[[]*url.URL]
	next     atomic.Uint64
}

func newBalancer(t *testing.T, replicas ...*httptest.Server) *balancer {
	t.Helper()
	b := &balancer{}
	b.set(t, replicas...)
	b.srv = testkit.Server(t, &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		set := *b.backends.Load()
		pr.SetURL(set[b.next.Add(1)%uint64(len(set))])
	}})
	return b
}

func (b *balancer) set(t *testing.T, replicas ...*httptest.Server) {
	t.Helper()
	set := make([]*url.URL, 0, len(replicas))
	for _, r := range replicas {
		u, err := url.Parse(r.URL)
		if err != nil {
			t.Fatal(err)
		}
		set = append(set, u)
	}
	b.backends.Store(&set)
}

// startSample starts the sample resource service against identity's URL.
func startSample(t *testing.T, identityURL string) *httptest.Server {
	t.Helper()
	h, err := sampleresource.New(sampleresource.Config{
		IdentityURL: identityURL, ClientID: sampleClientID, ClientSecret: sampleClientSecret,
	})
	if err != nil {
		t.Fatalf("start sample service: %v", err)
	}
	return testkit.Server(t, h)
}

// startRedis runs a Redis container for this test and returns its address.
func startRedis(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.Run(ctx, "redis:7-alpine",
		testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithWaitStrategy(wait.ForLog("Ready to accept connections")))
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatalf("start redis: %v", err)
	}
	addr, err := c.PortEndpoint(ctx, "6379/tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

// session is a signed-in user.
type session struct {
	userID  string
	access  string
	refresh string
}

// tokens reads a TRD 9.3 token response.
func tokens(t *testing.T, r *testkit.Response[map[string]any]) session {
	t.Helper()
	u, _ := r.Data["user"].(map[string]any)
	s := session{}
	s.userID, _ = u["id"].(string)
	s.access, _ = r.Data["access_token"].(string)
	s.refresh, _ = r.Data["refresh_token"].(string)
	if r.Status != http.StatusOK || s.userID == "" || s.access == "" || s.refresh == "" {
		t.Fatalf("sign-in = %d %s", r.Status, r.Raw)
	}
	return s
}

func call(t *testing.T, srv *httptest.Server, method, path, token string, body any) testkit.Response[map[string]any] {
	t.Helper()
	h := http.Header{}
	if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	return testkit.Do[map[string]any](t, srv, method, path, body, h)
}

// passwordSignIn registers email (into tenant, when not empty) and signs in.
func passwordSignIn(t *testing.T, idp *httptest.Server, email, tenant string) session {
	t.Helper()
	body := map[string]any{"email": email, "password": userPassword, "display_name": strings.Split(email, "@")[0]}
	if tenant != "" {
		body["tenant"] = tenant
	}
	if r := call(t, idp, http.MethodPost, "/v1/auth/register", "", body); r.Status != http.StatusAccepted {
		t.Fatalf("register %s = %d %s", email, r.Status, r.Raw)
	}
	return login(t, idp, email, userPassword, tenant)
}

func login(t *testing.T, idp *httptest.Server, email, pw, tenant string) session {
	t.Helper()
	body := map[string]any{"email": email, "password": pw}
	if tenant != "" {
		body["tenant"] = tenant
	}
	r := call(t, idp, http.MethodPost, "/v1/auth/login", "", body)
	return tokens(t, &r)
}

// refresh rotates s and returns the new session, whose access token carries
// the roles s.userID holds now.
func refresh(t *testing.T, idp *httptest.Server, s session) session {
	t.Helper()
	r := call(t, idp, http.MethodPost, "/v1/auth/refresh", "", map[string]any{"refresh_token": s.refresh})
	return tokens(t, &r)
}

// googleSignIn runs the browser flow against the fake provider as email and
// spends the callback code: start → provider → callback → frontend.
func googleSignIn(t *testing.T, idp *httptest.Server, google *testkit.OIDC, email string) session {
	t.Helper()
	google.SignInAs(testkit.OIDCUser{Subject: "google-" + email, Email: email, EmailVerified: true, Name: email})
	loc := hop(t, idp.URL+"/v1/auth/google/start?redirect_to="+url.QueryEscape(frontendCallback))
	loc = hop(t, hop(t, loc))
	back, err := url.Parse(loc)
	if err != nil || !strings.HasPrefix(loc, frontendCallback+"?") || back.Query().Get("code") == "" {
		t.Fatalf("Google flow ended at %s, want the frontend with a code", loc)
	}
	r := call(t, idp, http.MethodPost, "/v1/auth/exchange", "", map[string]any{"code": back.Query().Get("code")})
	return tokens(t, &r)
}

var noFollow = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// hop GETs target and returns the Location of its 302.
func hop(t *testing.T, target string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET %s = %d, want 302", target, resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

// grantRole gives userID the named role of the tenant with tenantSlug, as an
// admin would.
func grantRole(t *testing.T, db *sqlkit.DB, userID, role, tenantSlug string) {
	t.Helper()
	exec(t, db, `INSERT INTO user_roles (tenant_id, user_id, role_id)
		SELECT r.tenant_id, $1, r.id FROM roles r JOIN tenants tn ON tn.id = r.tenant_id
		WHERE r.name = $2 AND tn.slug = $3`, userID, role, tenantSlug)
}

func exec(t *testing.T, db *sqlkit.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Leader().ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func text(t *testing.T, db *sqlkit.DB, query string, args ...any) string {
	t.Helper()
	var s string
	if err := db.Leader().QueryRowContext(context.Background(), query, args...).Scan(&s); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return s
}
