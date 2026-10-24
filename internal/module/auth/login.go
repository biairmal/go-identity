package auth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/module/auth/token"
	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/clock"
)

// restrictedTokenTTL is the lifetime of the password-change token a forced
// password change gets instead of a session (TRD 9.3).
const restrictedTokenTTL = 10 * time.Minute

// maxUserAgent caps the user agent stored with a session; the header is
// client-controlled.
const maxUserAgent = 512

// Rate-limit key prefixes. The email part of a key is always the keyed blind
// index, never the address.
const (
	limitLoginIP      = "login:ip:"
	limitLoginEmail   = "login:email:"
	limitRegisterIP   = "register:ip:"
	limitRegisterMail = "register:email:"
	limitResendIP     = "resend:ip:"
	limitResendMail   = "resend:email:"
)

// txFunc runs fn in one database transaction.
type txFunc func(ctx context.Context, fn func(ctx context.Context) error) error

// Logins runs password sign-in: rate limits, lockout, the password check,
// tenant resolution and issuing tokens.
type Logins struct {
	cfg      *Config
	tenancy  string
	tx       txFunc
	v        validator.Validator
	users    Users
	tenants  Tenants
	roles    Roles
	sessions Sessions
	audit    AuditWriter
	limiter  Limiter
	tokens   *token.Builder
	clock    clock.Clock
	log      logger.Logger
	// dummyHash is verified against when the address has no account or no
	// password, so those answers take as long as a wrong password.
	dummyHash func() string
}

// newDummyHash returns a lazily computed hash of a random password, made once
// per process with the current parameters.
func newDummyHash() func() string {
	return sync.OnceValue(func() string {
		h, err := password.Hash(uuid.NewString())
		if err != nil {
			// Hash only fails when the system random source does; the
			// fallback still costs a full verification of nothing.
			return ""
		}
		return h
	})
}

// signIn is a verified account on its way to a token response.
type signIn struct {
	account *Account
	tenant  *TenantInfo
	rehash  string
	device  Device
}

// Login signs a user in with email and password. It returns a TokenResponse,
// or a TenantChoiceResponse in multi mode when the user must pick a tenant.
//
// An unknown address and a wrong password give the same error, and both run
// one argon2 verification, so neither the body nor the timing tells them
// apart. Whether an account is locked, unverified or disabled is only
// revealed to a caller who got the password right, except the lock, which
// TRD 9.2 reports as ACCOUNT_LOCKED.
func (s *Logins) Login(ctx context.Context, in *LoginRequest, d Device) (any, error) {
	if !s.cfg.Providers.Password.Enabled {
		return nil, apierr.New(apierr.ReasonProviderDisabled)
	}
	if err := s.limit(ctx, limitLoginIP, d.IP); err != nil {
		return nil, err
	}
	in.Email = strings.TrimSpace(in.Email)
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	if err := s.limit(ctx, limitLoginEmail, s.users.EmailKey(in.Email)); err != nil {
		return nil, err
	}
	a, needsRehash, err := s.authenticate(ctx, in)
	if err != nil {
		return nil, err
	}
	tenant, choice, err := s.resolveTenant(ctx, a, in.Tenant)
	if err != nil || choice != nil {
		return choice, err
	}
	si := &signIn{account: a, tenant: tenant, device: d}
	if needsRehash {
		if si.rehash, err = password.Hash(in.Password); err != nil {
			return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: rehash password")
		}
	}
	return s.complete(ctx, si)
}

// limit checks one rate-limit key; an empty value (no client IP) is skipped.
func (s *Logins) limit(ctx context.Context, prefix, value string) error {
	if s.limiter == nil || value == "" {
		return nil
	}
	return s.limiter.Check(ctx, prefix+value)
}

// authenticate finds the account and checks the lock, the password and the
// status, recording a failed attempt. needsRehash reports a correct password
// stored with weaker parameters.
func (s *Logins) authenticate(ctx context.Context, in *LoginRequest) (a *Account, needsRehash bool, err error) {
	a, err = s.users.FindByEmail(ctx, in.Email)
	if errors.Is(err, errorz.ErrNotFound) {
		s.verifyDummy(in.Password)
		return nil, false, apierr.New(apierr.ReasonInvalidCredentials)
	}
	if err != nil {
		return nil, false, err
	}
	now := s.clock.Now()
	if a.LockedUntil != nil && a.LockedUntil.After(now) {
		return nil, false, apierr.WithRetryAfter(apierr.ReasonAccountLocked, a.LockedUntil.Sub(now))
	}
	hash, err := s.users.PasswordHash(ctx, a.ID)
	if errors.Is(err, errorz.ErrNotFound) {
		// A Google-only account has no password to guess.
		s.verifyDummy(in.Password)
		return nil, false, apierr.New(apierr.ReasonInvalidCredentials)
	}
	if err != nil {
		return nil, false, err
	}
	match, needsRehash, err := password.Verify(in.Password, hash)
	if err != nil {
		return nil, false, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: verify password")
	}
	if !match {
		return nil, false, s.recordFailure(ctx, a, now)
	}
	return a, needsRehash, checkStatus(a)
}

// verifyDummy spends the time of a real verification.
func (s *Logins) verifyDummy(plain string) {
	if _, _, err := password.Verify(plain, s.dummyHash()); err != nil {
		s.log.Error("auth: dummy hash unusable, sign-in timing is uneven", logger.F("error", err.Error()))
	}
}

// checkStatus refuses an account that may not sign in yet or any more.
func checkStatus(a *Account) error {
	switch a.Status {
	case StatusActive:
		return nil
	case StatusPending:
		return apierr.New(apierr.ReasonEmailNotVerified)
	default:
		return apierr.New(apierr.ReasonAccountDisabled)
	}
}

// recordFailure counts the failed attempt, locks the account once it reaches
// the limit and audits it, in a transaction of its own that commits before
// the caller answers 401, so the failure survives the error. A lock that
// has already expired is cleared first, so counting starts again from one.
func (s *Logins) recordFailure(ctx context.Context, a *Account, now time.Time) error {
	sec := s.cfg.Security
	err := s.tx(ctx, func(ctx context.Context) error {
		if a.LockedUntil != nil {
			if err := s.users.ClearFailedLogins(ctx, a.ID); err != nil {
				return err
			}
		}
		n, err := s.users.RecordFailedLogin(ctx, a.ID)
		if err != nil {
			return err
		}
		locked := n >= sec.LockoutAfterFailures
		if locked {
			if err := s.users.Lock(ctx, a.ID, now.Add(sec.LockoutDuration)); err != nil {
				return err
			}
			s.log.WarnWithContext(ctx, "account locked after failed sign-ins",
				logger.F("user_id", a.ID.String()))
		}
		return s.audit.Write(ctx, &AuditEvent{
			Action: ActionLoginFailed, TargetType: TargetUser, TargetID: a.ID.String(),
			After: map[string]any{"failed_logins": n, "locked": locked},
		})
	})
	if err != nil {
		return err
	}
	return apierr.New(apierr.ReasonInvalidCredentials)
}

// resolveTenant picks the tenant the token is for (APP_FLOW 5): the default
// tenant in single mode; in multi mode the named one, the only one, or a
// choice when the user belongs to several and named none. A tenant the user
// cannot act in is INVALID_CREDENTIALS, so the answer does not say which part
// of the sign-in failed.
func (s *Logins) resolveTenant(
	ctx context.Context, a *Account, slug string,
) (*TenantInfo, *TenantChoiceResponse, error) {
	t, choice, err := s.pickTenant(ctx, a.ID, strings.TrimSpace(slug))
	if err != nil || choice != nil {
		return nil, choice, err
	}
	if !t.Active && !a.IsSuperAdmin {
		return nil, nil, apierr.New(apierr.ReasonTenantSuspended)
	}
	return t, nil, nil
}

// pickTenant applies the tenancy mode's selection rule.
func (s *Logins) pickTenant(
	ctx context.Context, userID uuid.UUID, slug string,
) (*TenantInfo, *TenantChoiceResponse, error) {
	if s.tenancy != tenancyMulti {
		id, err := s.tenants.DefaultTenantID(ctx)
		if err != nil {
			return nil, nil, err
		}
		t, err := s.tenants.Tenant(ctx, id)
		return t, nil, err
	}
	all, err := s.tenants.Memberships(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	active := slices.DeleteFunc(all, func(m Membership) bool { return !m.Active })
	if slug != "" {
		i := slices.IndexFunc(active, func(m Membership) bool { return m.Tenant.Slug == slug })
		if i < 0 {
			return nil, nil, apierr.New(apierr.ReasonInvalidCredentials)
		}
		return &active[i].Tenant, nil, nil
	}
	switch len(active) {
	case 0:
		return nil, nil, apierr.New(apierr.ReasonInvalidCredentials)
	case 1:
		return &active[0].Tenant, nil, nil
	}
	choice := &TenantChoiceResponse{TenantRequired: true, Tenants: make([]TenantSummaryResponse, 0, len(active))}
	for _, m := range active {
		choice.Tenants = append(choice.Tenants, tenantSummary(&m.Tenant))
	}
	return nil, choice, nil
}

// complete records the sign-in and builds the token response in one
// transaction: the rehash, the counter reset and sign-in time, the session
// and the audit row land together or not at all. A forced password change
// gets a restricted token and no session.
func (s *Logins) complete(ctx context.Context, si *signIn) (*TokenResponse, error) {
	var resp *TokenResponse
	err := s.tx(ctx, func(ctx context.Context) error {
		a := si.account
		if si.rehash != "" {
			if err := s.users.UpdatePasswordHash(ctx, a.ID, si.rehash); err != nil {
				return err
			}
		}
		if err := s.users.RecordSignIn(ctx, a.ID, s.clock.Now()); err != nil {
			return err
		}
		var err error
		if a.MustChangePassword {
			resp, err = s.restrictedResponse(ctx, si)
		} else {
			resp, err = s.sessionResponse(ctx, si)
		}
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, &AuditEvent{
			TenantID: si.tenant.ID, ActorID: a.ID, Action: ActionLogin,
			TargetType: TargetUser, TargetID: a.ID.String(),
			After: map[string]any{"method": "password", "restricted": a.MustChangePassword, "rehashed": si.rehash != ""},
		})
	})
	if err != nil {
		return nil, err
	}
	s.log.InfoWithContext(ctx, "user signed in", logger.F("user_id", si.account.ID.String()))
	return resp, nil
}

// restrictedResponse is the token response of a forced password change: a
// short-lived token scoped to the password change, no refresh token.
func (s *Logins) restrictedResponse(ctx context.Context, si *signIn) (*TokenResponse, error) {
	signed, expiry, err := s.tokens.Access(ctx, &token.Subject{
		UserID: si.account.ID, Scope: token.ScopePasswordChange, TTL: restrictedTokenTTL,
	}, si.tenant.ID)
	if err != nil {
		return nil, err
	}
	return s.response(si, signed, expiry), nil
}

// sessionResponse starts a refresh-token family and signs a full access token
// with the user's roles in the tenant.
func (s *Logins) sessionResponse(ctx context.Context, si *signIn) (*TokenResponse, error) {
	a := si.account
	sub := &token.Subject{UserID: a.ID, SuperAdmin: a.IsSuperAdmin}
	var err error
	if sub.Roles, err = s.roles.RoleNames(ctx, si.tenant.ID, a.ID); err != nil {
		return nil, err
	}
	if s.cfg.Token.Claims == ClaimsRolesAndPermissions {
		if sub.Permissions, err = s.roles.Permissions(ctx, si.tenant.ID, a.ID); err != nil {
			return nil, err
		}
	}
	issued, err := s.sessions.Issue(ctx, a.ID, si.tenant.ID, si.device)
	if err != nil {
		return nil, err
	}
	signed, expiry, err := s.tokens.Access(ctx, sub, si.tenant.ID)
	if err != nil {
		return nil, err
	}
	resp := s.response(si, signed, expiry)
	resp.RefreshToken = issued.Raw
	resp.RefreshExpiresIn = seconds(issued.ExpiresAt.Sub(s.clock.Now()))
	return resp, nil
}

// response fills the fields every token response shares.
func (s *Logins) response(si *signIn, accessToken string, expiry time.Time) *TokenResponse {
	a := si.account
	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   tokenTypeBearer,
		ExpiresIn:   seconds(expiry.Sub(s.clock.Now())),
		User: UserSummaryResponse{
			ID: a.ID.String(), DisplayName: a.DisplayName, Email: a.Email,
		},
		Tenant:             tenantSummary(si.tenant),
		MustChangePassword: a.MustChangePassword,
	}
}

// tenantSummary is the response view of a tenant.
func tenantSummary(t *TenantInfo) TenantSummaryResponse {
	return TenantSummaryResponse{ID: t.ID.String(), Slug: t.Slug, Name: t.Name}
}

// seconds rounds a duration to whole seconds for expires_in fields.
func seconds(d time.Duration) int {
	return int(d.Round(time.Second) / time.Second)
}

// truncateUserAgent caps a client-supplied user agent at maxUserAgent bytes,
// on a rune boundary.
func truncateUserAgent(ua string) string {
	if len(ua) <= maxUserAgent {
		return ua
	}
	cut := maxUserAgent
	for cut > 0 && !utf8.RuneStart(ua[cut]) {
		cut--
	}
	return ua[:cut]
}
