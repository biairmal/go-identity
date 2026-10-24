package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit/handler"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/apierr"
)

func (f *fakeSessions) Rotate(context.Context, string, Device) (*IssuedSession, error) {
	if f.rotateErr != nil {
		return nil, f.rotateErr
	}
	return f.rotated, nil
}

func (f *fakeSessions) Lookup(_ context.Context, raw string) (*SessionToken, error) {
	if t, ok := f.tokens[raw]; ok {
		c := *t
		return &c, nil
	}
	return nil, errorz.NotFound()
}

func (f *fakeSessions) RevokeFamily(_ context.Context, id uuid.UUID) error {
	f.revokedFamily = append(f.revokedFamily, id)
	return nil
}

func (f *fakeSessions) RevokeAllForUser(_ context.Context, id uuid.UUID) error {
	f.revokedUser = append(f.revokedUser, id)
	return nil
}

// refreshFixture is a Refreshes over the login fakes, sharing their clock
// and keys, with one active member of the default tenant.
type refreshFixture struct {
	*loginFixture
	refreshes *Refreshes
	user      *fakeUser
	family    uuid.UUID
}

func newRefreshFixture(t *testing.T) *refreshFixture {
	t.Helper()
	lf := newLoginFixture(t, "single")
	f := &refreshFixture{loginFixture: lf, family: uuid.New()}
	f.user = f.addUser(t, "bia@example.com", nil)
	f.tenants.memberships[f.user.account.ID] = []Membership{{Tenant: f.tenants.def, Active: true}}
	f.sessions.rotated = &IssuedSession{
		Raw: "next-refresh", FamilyID: f.family, UserID: f.user.account.ID, TenantID: f.tenants.def.ID,
		ExpiresAt: f.clock.Now().Add(720 * time.Hour),
	}
	f.sessions.tokens = map[string]*SessionToken{}
	f.refreshes = &Refreshes{
		tx: lf.logins.tx, v: validator.New(validator.Config{FieldNameTag: "json"}),
		users: f.users, tenants: f.tenants, sessions: f.sessions, audit: f.audit, limiter: f.limiter,
		issue: lf.logins.issue, clock: f.clock, log: logger.NewNoOp(),
	}
	return f
}

func (f *refreshFixture) refresh() (*TokenResponse, error) {
	return f.refreshes.Refresh(context.Background(), &RefreshRequest{RefreshToken: "old-refresh"},
		Device{UserAgent: "test-agent", IP: "192.0.2.1"})
}

// payload decodes a JWT's claims without verifying it.
func payload(t *testing.T, signed string) map[string]any {
	t.Helper()
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// TestRefreshIssuesRotatedToken returns the next refresh token and a full
// access token with the user's current roles.
func TestRefreshIssuesRotatedToken(t *testing.T) {
	f := newRefreshFixture(t)
	resp, err := f.refresh()
	if err != nil {
		t.Fatalf("Refresh = %v", err)
	}
	if resp.RefreshToken != "next-refresh" || resp.RefreshExpiresIn != 2592000 || resp.ExpiresIn != 900 {
		t.Errorf("response = %+v", resp)
	}
	claims := payload(t, resp.AccessToken)
	if claims["sub"] != f.user.account.ID.String() || claims["tid"] != f.tenants.def.ID.String() {
		t.Errorf("claims = %v", claims)
	}
	if roles, _ := claims["roles"].([]any); len(roles) != 1 || roles[0] != "member" {
		t.Errorf("roles = %v", claims["roles"])
	}
	if len(f.sessions.revokedFamily) != 0 {
		t.Errorf("a good refresh revoked %v", f.sessions.revokedFamily)
	}
	if got := f.limiter.keys; len(got) != 1 || got[0] != "refresh:ip:192.0.2.1" {
		t.Errorf("limiter keys = %v", got)
	}
}

// TestRefreshRotationFailures maps each session outcome to its reason; a
// replay is audited against the owner and carries no token.
func TestRefreshRotationFailures(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		want      apierr.Reason
		wantAudit int
	}{
		{"unknown token", errorz.NotFound(), apierr.ReasonInvalidCredentials, 0},
		{"expired", ErrRefreshExpired, apierr.ReasonRefreshExpired, 0},
		{"reused after the grace", ErrRefreshReused, apierr.ReasonRefreshReused, 1},
		{"family already revoked", ErrRefreshRevoked, apierr.ReasonRefreshReused, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRefreshFixture(t)
			f.sessions.rotateErr = tt.err
			f.sessions.tokens["old-refresh"] = &SessionToken{
				FamilyID: f.family, UserID: f.user.account.ID, TenantID: f.tenants.def.ID,
			}
			_, err := f.refresh()
			wantReason(t, err, tt.want)
			if handler.StatusCodeFromError(err) != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", handler.StatusCodeFromError(err))
			}
			if n := f.audit.count(ActionRefreshReuse); n != tt.wantAudit {
				t.Fatalf("refresh_reuse events = %d, want %d", n, tt.wantAudit)
			}
			if tt.wantAudit == 1 {
				e := f.audit.events[0]
				if e.ActorID != f.user.account.ID || strings.Contains(toJSON(t, e), "old-refresh") {
					t.Errorf("audit event = %+v", e)
				}
			}
		})
	}
}

// TestRefreshInternalErrorPassesThrough keeps a database failure a 500.
func TestRefreshInternalErrorPassesThrough(t *testing.T) {
	f := newRefreshFixture(t)
	f.sessions.rotateErr = errorz.Internal()
	_, err := f.refresh()
	if handler.StatusCodeFromError(err) != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", handler.StatusCodeFromError(err))
	}
}

// TestRefreshRechecksTheAccount refuses an account or tenant that may no
// longer act, and revokes the family that was just rotated.
func TestRefreshRechecksTheAccount(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(f *refreshFixture)
		want   apierr.Reason
		status int
	}{
		{
			"disabled user", func(f *refreshFixture) { f.user.account.Status = StatusDisabled },
			apierr.ReasonAccountDisabled, http.StatusForbidden,
		},
		{
			"forced password change", func(f *refreshFixture) { f.user.account.MustChangePassword = true },
			apierr.ReasonPasswordChangeRequired, http.StatusForbidden,
		},
		{
			"suspended tenant", func(f *refreshFixture) { f.tenants.def.Active = false },
			apierr.ReasonTenantSuspended, http.StatusForbidden,
		},
		{"membership removed", func(f *refreshFixture) {
			f.tenants.memberships[f.user.account.ID][0].Active = false
		}, apierr.ReasonInvalidCredentials, http.StatusUnauthorized},
		{
			"no membership", func(f *refreshFixture) { delete(f.tenants.memberships, f.user.account.ID) },
			apierr.ReasonInvalidCredentials, http.StatusUnauthorized,
		},
		{
			"user deleted", func(f *refreshFixture) { delete(f.users.byEmail, "bia@example.com") },
			apierr.ReasonInvalidCredentials, http.StatusUnauthorized,
		},
		{
			"tenant deleted", func(f *refreshFixture) { f.sessions.rotated.TenantID = uuid.New() },
			apierr.ReasonInvalidCredentials, http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRefreshFixture(t)
			tt.mutate(f)
			_, err := f.refresh()
			wantReason(t, err, tt.want)
			if handler.StatusCodeFromError(err) != tt.status {
				t.Errorf("status = %d, want %d", handler.StatusCodeFromError(err), tt.status)
			}
			if len(f.sessions.revokedFamily) != 1 || f.sessions.revokedFamily[0] != f.family {
				t.Errorf("revoked families = %v, want [%s]", f.sessions.revokedFamily, f.family)
			}
		})
	}
}

// TestRefreshSuperAdminInSuspendedTenant lets the super admin keep acting in
// a suspended tenant, as sign-in does.
func TestRefreshSuperAdminInSuspendedTenant(t *testing.T) {
	f := newRefreshFixture(t)
	f.user.account.IsSuperAdmin = true
	f.tenants.def.Active = false
	delete(f.tenants.memberships, f.user.account.ID)
	resp, err := f.refresh()
	if err != nil {
		t.Fatalf("Refresh = %v", err)
	}
	if payload(t, resp.AccessToken)["sa"] != true {
		t.Error("super admin token without sa")
	}
}

// TestRefreshRateLimitedAndValidated checks the limit before anything else
// and requires a token.
func TestRefreshRateLimitedAndValidated(t *testing.T) {
	f := newRefreshFixture(t)
	f.limiter.deny["refresh:ip:192.0.2.1"] = true
	_, err := f.refresh()
	wantReason(t, err, apierr.ReasonRateLimited)

	f.limiter.deny = map[string]bool{}
	_, err = f.refreshes.Refresh(context.Background(), &RefreshRequest{}, Device{})
	if handler.StatusCodeFromError(err) != http.StatusBadRequest {
		t.Errorf("empty token = %v, want 400", err)
	}
}

// TestLogout revokes a live token's family and audits it; any dead or
// unknown token is a silent no-op.
func TestLogout(t *testing.T) {
	tests := []struct {
		name    string
		token   *SessionToken
		revoked bool
	}{
		{"live", &SessionToken{Exchangeable: true}, true},
		{"unknown", nil, false},
		{"revoked", &SessionToken{Revoked: true}, false},
		{"rotated, expired or past the grace", &SessionToken{}, false},
	}
	for _, tt := range tests {
		for _, all := range []bool{false, true} {
			t.Run(tt.name, func(t *testing.T) {
				f := newRefreshFixture(t)
				if tt.token != nil {
					tok := *tt.token
					tok.FamilyID, tok.UserID, tok.TenantID = f.family, f.user.account.ID, f.tenants.def.ID
					f.sessions.tokens["old-refresh"] = &tok
				}
				in := &RefreshRequest{RefreshToken: "old-refresh"}
				var err error
				action := ActionLogout
				if all {
					action = ActionLogoutAll
					err = f.refreshes.LogoutAll(context.Background(), in)
				} else {
					err = f.refreshes.Logout(context.Background(), in)
				}
				if err != nil {
					t.Fatalf("logout = %v", err)
				}
				gotRevoked := len(f.sessions.revokedFamily)+len(f.sessions.revokedUser) > 0
				if gotRevoked != tt.revoked || f.audit.count(action) != boolInt(tt.revoked) {
					t.Fatalf("revoked = %v (families %v users %v), %s events = %d",
						gotRevoked, f.sessions.revokedFamily, f.sessions.revokedUser, action, f.audit.count(action))
				}
				if tt.revoked && all && f.sessions.revokedUser[0] != f.user.account.ID {
					t.Errorf("logout-all revoked user %v", f.sessions.revokedUser)
				}
				if tt.revoked && !all && f.sessions.revokedFamily[0] != f.family {
					t.Errorf("logout revoked family %v", f.sessions.revokedFamily)
				}
			})
		}
	}
}

// TestLogoutRequiresAToken is a validation error, not a silent 204.
func TestLogoutRequiresAToken(t *testing.T) {
	f := newRefreshFixture(t)
	err := f.refreshes.Logout(context.Background(), &RefreshRequest{})
	if handler.StatusCodeFromError(err) != http.StatusBadRequest {
		t.Errorf("Logout without a token = %v, want 400", err)
	}
	f.sessions.tokens = nil
	if err := f.refreshes.LogoutAll(context.Background(), &RefreshRequest{RefreshToken: "x"}); err != nil {
		t.Errorf("LogoutAll(unknown) = %v", err)
	}
}

// TestLogoutLookupFailure surfaces a database failure.
func TestLogoutLookupFailure(t *testing.T) {
	f := newRefreshFixture(t)
	f.refreshes.sessions = failingLookup{f.sessions}
	err := f.refreshes.Logout(context.Background(), &RefreshRequest{RefreshToken: "x"})
	if !errors.Is(err, errLookup) {
		t.Errorf("Logout = %v, want the lookup error", err)
	}
}

var errLookup = errors.New("lookup failed")

type failingLookup struct{ *fakeSessions }

func (failingLookup) Lookup(context.Context, string) (*SessionToken, error) { return nil, errLookup }

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func toJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
