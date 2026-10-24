package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit/handler"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/auth/keys"
	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/module/auth/token"
	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// testPassword is the password every fake account is created with.
const testPassword = "correct horse battery"

// fakeUser is one account plus its password hash and counters.
type fakeUser struct {
	account  Account
	hash     string
	failed   int
	signedIn *time.Time
}

// fakeUsers is an in-memory Users port. committed counts what the fake
// transaction committed, so tests can tell a write that survived the error.
type fakeUsers struct {
	byEmail map[string]*fakeUser
}

func (f *fakeUsers) find(id uuid.UUID) *fakeUser {
	for _, u := range f.byEmail {
		if u.account.ID == id {
			return u
		}
	}
	return nil
}

func (f *fakeUsers) FindByEmail(_ context.Context, email string) (*Account, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return nil, errorz.NotFound()
	}
	a := u.account
	return &a, nil
}

func (f *fakeUsers) Get(_ context.Context, id uuid.UUID) (*Account, error) {
	if u := f.find(id); u != nil {
		a := u.account
		return &a, nil
	}
	return nil, errorz.NotFound()
}

func (f *fakeUsers) Create(context.Context, *NewAccount) (uuid.UUID, error) {
	return uuid.Nil, errors.New("not used")
}

func (f *fakeUsers) VerifyEmail(context.Context, uuid.UUID, time.Time) error { return nil }

func (f *fakeUsers) PasswordHash(_ context.Context, id uuid.UUID) (string, error) {
	u := f.find(id)
	if u == nil || u.hash == "" {
		return "", errorz.NotFound()
	}
	return u.hash, nil
}

func (f *fakeUsers) UpdatePasswordHash(_ context.Context, id uuid.UUID, hash string) error {
	f.find(id).hash = hash
	return nil
}

func (f *fakeUsers) RecordFailedLogin(_ context.Context, id uuid.UUID) (int, error) {
	u := f.find(id)
	u.failed++
	return u.failed, nil
}

func (f *fakeUsers) Lock(_ context.Context, id uuid.UUID, until time.Time) error {
	f.find(id).account.LockedUntil = &until
	return nil
}

func (f *fakeUsers) ClearFailedLogins(_ context.Context, id uuid.UUID) error {
	u := f.find(id)
	u.failed, u.account.LockedUntil = 0, nil
	return nil
}

func (f *fakeUsers) RecordSignIn(_ context.Context, id uuid.UUID, at time.Time) error {
	u := f.find(id)
	u.failed, u.account.LockedUntil, u.signedIn = 0, nil, &at
	return nil
}

func (f *fakeUsers) EmailKey(email string) string { return "key-of-" + email }

// fakeTenants serves a default tenant and per-user memberships.
type fakeTenants struct {
	def         TenantInfo
	memberships map[uuid.UUID][]Membership
}

func (f *fakeTenants) DefaultTenantID(context.Context) (uuid.UUID, error) { return f.def.ID, nil }

func (f *fakeTenants) BySlug(context.Context, string) (uuid.UUID, bool, error) {
	return uuid.Nil, false, errors.New("not used")
}

func (f *fakeTenants) AddActiveMember(context.Context, uuid.UUID, uuid.UUID) error { return nil }

func (f *fakeTenants) Tenant(_ context.Context, id uuid.UUID) (*TenantInfo, error) {
	if id == f.def.ID {
		t := f.def
		return &t, nil
	}
	return nil, errorz.NotFound()
}

func (f *fakeTenants) Memberships(_ context.Context, userID uuid.UUID) ([]Membership, error) {
	return append([]Membership(nil), f.memberships[userID]...), nil
}

// fakeRoles grants every user the member role.
type fakeRoles struct{}

func (fakeRoles) Assign(context.Context, uuid.UUID, uuid.UUID, []string) error { return nil }

func (fakeRoles) RoleNames(context.Context, uuid.UUID, uuid.UUID) ([]string, error) {
	return []string{"member"}, nil
}

func (fakeRoles) Permissions(context.Context, uuid.UUID, uuid.UUID) ([]string, error) {
	return []string{"notes:read"}, nil
}

// fakeSessions records issued families.
type fakeSessions struct{ issued []Device }

func (f *fakeSessions) Issue(_ context.Context, _, _ uuid.UUID, d Device) (*IssuedSession, error) {
	f.issued = append(f.issued, d)
	return &IssuedSession{Raw: "raw-refresh", FamilyID: uuid.New(), ExpiresAt: time.Now().Add(time.Hour)}, nil
}

// fakeAudit records events.
type fakeAudit struct{ events []AuditEvent }

func (f *fakeAudit) Write(_ context.Context, e *AuditEvent) error {
	f.events = append(f.events, *e)
	return nil
}

func (f *fakeAudit) count(action string) int {
	n := 0
	for _, e := range f.events {
		if e.Action == action {
			n++
		}
	}
	return n
}

// fakeLimiter denies keys listed in deny.
type fakeLimiter struct {
	keys []string
	deny map[string]bool
}

func (f *fakeLimiter) Check(_ context.Context, key string) error {
	f.keys = append(f.keys, key)
	if f.deny[key] {
		return apierr.WithRetryAfter(apierr.ReasonRateLimited, 30*time.Second)
	}
	return nil
}

// loginFixture is a Logins over fakes, with a fake clock.
type loginFixture struct {
	logins   *Logins
	users    *fakeUsers
	tenants  *fakeTenants
	sessions *fakeSessions
	audit    *fakeAudit
	limiter  *fakeLimiter
	clock    *testkit.Clock
	set      *keys.Set
}

// weakParams make the fake accounts cheap to verify. They are below
// DefaultParams, so every successful sign-in also exercises the rehash.
var weakParams = password.Params{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func newLoginFixture(t *testing.T, tenancy string) *loginFixture {
	t.Helper()
	cfg := Default()
	cfg.Security.LockoutAfterFailures = 3
	cfg.Security.LockoutDuration = 15 * time.Minute
	set, err := keys.Load(testkit.SigningKeys(t, "unit-key"))
	if err != nil {
		t.Fatal(err)
	}
	clk := testkit.NewClock(time.Now())
	builder, err := token.NewBuilder(token.Config{
		Issuer: cfg.Token.Issuer, Audience: cfg.Token.Audience, AccessTTL: cfg.Token.AccessTTL, Claims: cfg.Token.Claims,
	}, set, clk)
	if err != nil {
		t.Fatal(err)
	}
	f := &loginFixture{
		users:    &fakeUsers{byEmail: map[string]*fakeUser{}},
		tenants:  &fakeTenants{def: TenantInfo{ID: uuid.New(), Slug: "default", Name: "Default", Active: true}},
		sessions: &fakeSessions{},
		audit:    &fakeAudit{},
		limiter:  &fakeLimiter{deny: map[string]bool{}},
		clock:    clk,
		set:      set,
	}
	f.tenants.memberships = map[uuid.UUID][]Membership{}
	f.logins = &Logins{
		cfg: &cfg, tenancy: tenancy, v: validator.New(validator.Config{FieldNameTag: "json"}),
		tx:    func(ctx context.Context, fn func(ctx context.Context) error) error { return fn(ctx) },
		users: f.users, tenants: f.tenants, roles: fakeRoles{}, sessions: f.sessions,
		audit: f.audit, limiter: f.limiter, tokens: builder, clock: clk, log: logger.NewNoOp(),
		dummyHash: func() string {
			h, _ := password.HashWith("dummy", weakParams)
			return h
		},
	}
	return f
}

// addUser creates an account with testPassword.
func (f *loginFixture) addUser(t *testing.T, email string, mutate func(a *Account)) *fakeUser {
	t.Helper()
	hash, err := password.HashWith(testPassword, weakParams)
	if err != nil {
		t.Fatal(err)
	}
	u := &fakeUser{account: Account{ID: uuid.New(), Email: email, DisplayName: "Bia", Status: StatusActive}, hash: hash}
	if mutate != nil {
		mutate(&u.account)
	}
	f.users.byEmail[email] = u
	return u
}

func (f *loginFixture) login(email, pw string) (any, error) {
	return f.logins.Login(context.Background(), &LoginRequest{Email: email, Password: pw},
		Device{UserAgent: "test-agent", IP: "192.0.2.1"})
}

func wantReason(t *testing.T, err error, want apierr.Reason) {
	t.Helper()
	if got := apierr.ReasonOf(err); got != want {
		t.Fatalf("err = %v (reason %q), want %s", err, got, want)
	}
}

// TestLoginLockout locks the account on the failure that reaches the limit:
// the next attempt, even with the right password, is ACCOUNT_LOCKED with a
// retry hint, and the lock lifts after lockout_duration.
func TestLoginLockout(t *testing.T) {
	f := newLoginFixture(t, "single")
	u := f.addUser(t, "bia@example.com", nil)
	for i := range 3 {
		_, err := f.login("bia@example.com", "wrong password!")
		wantReason(t, err, apierr.ReasonInvalidCredentials)
		if u.failed != i+1 {
			t.Fatalf("failed = %d after %d attempts", u.failed, i+1)
		}
	}
	if u.account.LockedUntil == nil || !u.account.LockedUntil.Equal(f.clock.Now().Add(15*time.Minute)) {
		t.Fatalf("locked_until = %v, want now + 15m", u.account.LockedUntil)
	}
	_, err := f.login("bia@example.com", testPassword)
	wantReason(t, err, apierr.ReasonAccountLocked)
	if handler.StatusCodeFromError(err) != http.StatusUnauthorized {
		t.Errorf("locked status = %d, want 401", handler.StatusCodeFromError(err))
	}
	if s, ok := apierr.RetryAfterOf(err); !ok || s != 900 {
		t.Errorf("retry_after = %d, want 900", s)
	}
	if n := f.audit.count(ActionLoginFailed); n != 3 {
		t.Errorf("login_failed events = %d, want 3 (a locked attempt is not a guess)", n)
	}

	f.clock.Advance(15*time.Minute + time.Second)
	if _, err := f.login("bia@example.com", testPassword); err != nil {
		t.Fatalf("login after the lock expired = %v", err)
	}
	if u.failed != 0 || u.account.LockedUntil != nil {
		t.Errorf("after success failed = %d, locked = %v; want reset", u.failed, u.account.LockedUntil)
	}
}

// TestLoginExpiredLockRestartsCount makes a wrong password after an expired
// lock count from one, so a single miss does not re-lock the account.
func TestLoginExpiredLockRestartsCount(t *testing.T) {
	f := newLoginFixture(t, "single")
	past := f.clock.Now().Add(-time.Minute)
	u := f.addUser(t, "bia@example.com", func(a *Account) { a.LockedUntil = &past })
	u.failed = 3
	_, err := f.login("bia@example.com", "wrong password!")
	wantReason(t, err, apierr.ReasonInvalidCredentials)
	if u.failed != 1 || u.account.LockedUntil != nil {
		t.Errorf("failed = %d, locked = %v; want 1 and unlocked", u.failed, u.account.LockedUntil)
	}
}

// TestLoginUnknownEmailMatchesWrongPassword returns the same error for both,
// and audits only the attempt against a real account (without the email).
func TestLoginUnknownEmailMatchesWrongPassword(t *testing.T) {
	f := newLoginFixture(t, "single")
	u := f.addUser(t, "bia@example.com", nil)
	_, unknown := f.login("nobody@example.com", testPassword)
	_, wrong := f.login("bia@example.com", "wrong password!")
	wantReason(t, unknown, apierr.ReasonInvalidCredentials)
	wantReason(t, wrong, apierr.ReasonInvalidCredentials)
	if unknown.Error() != wrong.Error() {
		t.Errorf("unknown = %q, wrong = %q; want identical", unknown, wrong)
	}
	if len(f.audit.events) != 1 || f.audit.events[0].TargetID != u.account.ID.String() ||
		f.audit.events[0].ActorID != uuid.Nil {
		t.Errorf("events = %+v, want one login_failed for the user with no actor", f.audit.events)
	}
}

// TestLoginStatusOnlyAfterPassword reveals pending and disabled accounts only
// to a caller with the right password.
func TestLoginStatusOnlyAfterPassword(t *testing.T) {
	tests := []struct {
		status string
		want   apierr.Reason
	}{
		{StatusPending, apierr.ReasonEmailNotVerified},
		{StatusDisabled, apierr.ReasonAccountDisabled},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			f := newLoginFixture(t, "single")
			f.addUser(t, "bia@example.com", func(a *Account) { a.Status = tt.status })
			_, err := f.login("bia@example.com", "wrong password!")
			wantReason(t, err, apierr.ReasonInvalidCredentials)
			_, err = f.login("bia@example.com", testPassword)
			wantReason(t, err, tt.want)
			if len(f.sessions.issued) != 0 {
				t.Error("a session was issued")
			}
		})
	}
}

// TestLoginSuccess issues a full token, a session with the device, resets
// the counter, rehashes the weak hash and audits auth.login.
func TestLoginSuccess(t *testing.T) {
	f := newLoginFixture(t, "single")
	u := f.addUser(t, "bia@example.com", nil)
	u.failed = 2
	out, err := f.login(" bia@example.com ", testPassword)
	if err != nil {
		t.Fatalf("Login = %v", err)
	}
	resp, ok := out.(*TokenResponse)
	if !ok {
		t.Fatalf("response = %T", out)
	}
	if resp.RefreshToken != "raw-refresh" || resp.TokenType != "Bearer" || resp.ExpiresIn != 900 ||
		resp.MustChangePassword || resp.Tenant.Slug != "default" || resp.User.Email != "bia@example.com" {
		t.Errorf("response = %+v", resp)
	}
	claims := validate(t, f.set, resp.AccessToken)
	if claims["tid"] != f.tenants.def.ID.String() || claims["sub"] != u.account.ID.String() {
		t.Errorf("claims = %v", claims)
	}
	if _, has := claims["scope"]; has {
		t.Error("full token carries a scope")
	}
	if len(f.sessions.issued) != 1 || f.sessions.issued[0] != (Device{UserAgent: "test-agent", IP: "192.0.2.1"}) {
		t.Errorf("sessions = %+v", f.sessions.issued)
	}
	if u.failed != 0 || u.signedIn == nil {
		t.Errorf("failed = %d, signed in = %v", u.failed, u.signedIn)
	}
	if password.NeedsRehash(u.hash) {
		t.Error("weak hash was not rehashed")
	}
	if f.audit.count(ActionLogin) != 1 {
		t.Errorf("events = %+v, want one auth.login", f.audit.events)
	}
}

// TestLoginMustChangePassword gets a ten-minute token scoped to the password
// change and no session.
func TestLoginMustChangePassword(t *testing.T) {
	f := newLoginFixture(t, "single")
	f.addUser(t, "root@example.com", func(a *Account) { a.MustChangePassword, a.IsSuperAdmin = true, true })
	out, err := f.login("root@example.com", testPassword)
	if err != nil {
		t.Fatalf("Login = %v", err)
	}
	resp := out.(*TokenResponse)
	if resp.RefreshToken != "" || resp.RefreshExpiresIn != 0 || !resp.MustChangePassword || resp.ExpiresIn != 600 {
		t.Errorf("response = %+v", resp)
	}
	claims := validate(t, f.set, resp.AccessToken)
	if claims["scope"] != token.ScopePasswordChange {
		t.Errorf("scope = %v", claims["scope"])
	}
	if _, has := claims["roles"]; has {
		t.Errorf("restricted token carries roles: %v", claims["roles"])
	}
	if len(f.sessions.issued) != 0 {
		t.Error("a session was issued for a restricted token")
	}
}

// TestLoginRateLimitedByIPAndEmailKey checks both keys and never passes the
// plain address to the limiter.
func TestLoginRateLimitedByIPAndEmailKey(t *testing.T) {
	f := newLoginFixture(t, "single")
	f.addUser(t, "bia@example.com", nil)
	f.limiter.deny["login:email:key-of-bia@example.com"] = true
	_, err := f.login("bia@example.com", testPassword)
	wantReason(t, err, apierr.ReasonRateLimited)
	want := []string{"login:ip:192.0.2.1", "login:email:key-of-bia@example.com"}
	if len(f.limiter.keys) != 2 || f.limiter.keys[0] != want[0] || f.limiter.keys[1] != want[1] {
		t.Errorf("keys = %v, want %v", f.limiter.keys, want)
	}
	f.limiter.deny = map[string]bool{"login:ip:192.0.2.1": true}
	_, err = f.login("bia@example.com", testPassword)
	wantReason(t, err, apierr.ReasonRateLimited)
	if f.audit.count(ActionLoginFailed) != 0 {
		t.Error("a rate-limited attempt counted as a failure")
	}
}

// TestLoginTenantResolution covers the multi-mode rules of APP_FLOW 5.
func TestLoginTenantResolution(t *testing.T) {
	acme := TenantInfo{ID: uuid.New(), Slug: "acme", Name: "Acme", Active: true}
	beta := TenantInfo{ID: uuid.New(), Slug: "beta", Name: "Beta", Active: true}
	gone := TenantInfo{ID: uuid.New(), Slug: "gone", Name: "Gone", Active: false}
	tests := []struct {
		name        string
		memberships []Membership
		slug        string
		wantTenant  string        // slug of the token's tenant
		wantChoice  []string      // slugs offered
		wantReason  apierr.Reason // error
	}{
		{"one tenant", []Membership{{acme, true}}, "", "acme", nil, ""},
		{"several, none named", []Membership{{acme, true}, {beta, true}}, "", "", []string{"acme", "beta"}, ""},
		{"several, one named", []Membership{{acme, true}, {beta, true}}, "beta", "beta", nil, ""},
		{"inactive membership ignored", []Membership{{acme, true}, {beta, false}}, "", "acme", nil, ""},
		{"named but not a member", []Membership{{acme, true}}, "beta", "", nil, apierr.ReasonInvalidCredentials},
		{"no tenant", nil, "", "", nil, apierr.ReasonInvalidCredentials},
		{"suspended tenant", []Membership{{gone, true}}, "", "", nil, apierr.ReasonTenantSuspended},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newLoginFixture(t, "multi")
			u := f.addUser(t, "bia@example.com", nil)
			f.tenants.memberships[u.account.ID] = tt.memberships
			out, err := f.logins.Login(context.Background(),
				&LoginRequest{Email: "bia@example.com", Password: testPassword, Tenant: tt.slug}, Device{})
			if tt.wantReason != "" {
				wantReason(t, err, tt.wantReason)
				return
			}
			if err != nil {
				t.Fatalf("Login = %v", err)
			}
			switch resp := out.(type) {
			case *TokenResponse:
				if resp.Tenant.Slug != tt.wantTenant {
					t.Errorf("tenant = %s, want %s", resp.Tenant.Slug, tt.wantTenant)
				}
			case *TenantChoiceResponse:
				var got []string
				for _, c := range resp.Tenants {
					got = append(got, c.Slug)
				}
				if !resp.TenantRequired || len(got) != len(tt.wantChoice) || got[0] != tt.wantChoice[0] {
					t.Errorf("choice = %+v, want %v", resp, tt.wantChoice)
				}
				if len(f.sessions.issued) != 0 || f.audit.count(ActionLogin) != 0 {
					t.Error("a tenant choice signed the user in")
				}
			default:
				t.Fatalf("response = %T", out)
			}
		})
	}
}

// TestLoginSuperAdminIntoSuspendedTenant lets the super admin in.
func TestLoginSuperAdminIntoSuspendedTenant(t *testing.T) {
	f := newLoginFixture(t, "single")
	f.tenants.def.Active = false
	f.addUser(t, "root@example.com", func(a *Account) { a.IsSuperAdmin = true })
	if _, err := f.login("root@example.com", testPassword); err != nil {
		t.Errorf("super admin login = %v", err)
	}
	f.addUser(t, "bia@example.com", nil)
	_, err := f.login("bia@example.com", testPassword)
	wantReason(t, err, apierr.ReasonTenantSuspended)
}

// TestLoginWithoutPasswordCredentials treats an account with no password
// like an unknown address.
func TestLoginWithoutPasswordCredentials(t *testing.T) {
	f := newLoginFixture(t, "single")
	u := f.addUser(t, "bia@example.com", nil)
	u.hash = ""
	_, err := f.login("bia@example.com", testPassword)
	wantReason(t, err, apierr.ReasonInvalidCredentials)
	if u.failed != 0 {
		t.Error("an account with no password counted a failure")
	}
}

// TestLoginValidationAndProvider rejects a bad body and a disabled provider.
func TestLoginValidationAndProvider(t *testing.T) {
	f := newLoginFixture(t, "single")
	_, err := f.login("not-an-email", testPassword)
	if handler.StatusCodeFromError(err) != http.StatusBadRequest {
		t.Errorf("bad email = %v, want 400", err)
	}
	f.logins.cfg.Providers.Password.Enabled = false
	_, err = f.login("bia@example.com", testPassword)
	wantReason(t, err, apierr.ReasonProviderDisabled)
}

func TestTruncateUserAgent(t *testing.T) {
	long := string(make([]byte, 600))
	if got := truncateUserAgent(long); len(got) != maxUserAgent {
		t.Errorf("len = %d, want %d", len(got), maxUserAgent)
	}
	multi := string(make([]byte, 511)) + "é"
	if got := truncateUserAgent(multi); len(got) != 511 {
		t.Errorf("len = %d, want 511 (cut before the split rune)", len(got))
	}
	if got := truncateUserAgent("short"); got != "short" {
		t.Errorf("got %q", got)
	}
}

// validate checks signed through the JWKS endpoint, as a resource service
// would, and returns its raw claims.
func validate(t *testing.T, set *keys.Set, signed string) map[string]any {
	t.Helper()
	srv := httptest.NewServer(sdkauth.JWKSHandler(set.Public))
	defer srv.Close()
	v, err := sdkauth.NewRS256(sdkauth.WithJWKSURL(srv.URL),
		sdkauth.WithExpectedIssuer("identity"), sdkauth.WithExpectedAudience("api"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.Validate(context.Background(), signed)
	if err != nil {
		t.Fatalf("validate access token: %v", err)
	}
	return claims.Raw()
}
