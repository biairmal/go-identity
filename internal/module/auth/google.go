package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/auth/onetime"
	"github.com/biairmal/go-identity/internal/module/auth/provider"
	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/clock"
)

// oauthStateTTL is how long a started provider sign-in may take (TRD 5.2).
const oauthStateTTL = 10 * time.Minute

// exchangeCodeTTL is the lifetime of the code the callback hands the frontend
// (TRD 9.4).
const exchangeCodeTTL = 60 * time.Second

// maxDisplayName is the longest display name an account may have.
const maxDisplayName = 100

// methodGoogle is the sign-in method recorded in audit rows.
const methodGoogle = "google"

// errTenantRequired is a multi-mode sign-in that names no tenant while the
// user has several, or none yet to join. A redirect cannot carry a tenant
// list, so the frontend restarts the flow with a tenant.
var errTenantRequired = errors.New("auth: tenant required")

// EmailEncrypter encrypts an address for identities.email_at_link with the
// cipher users.email_enc uses. internal/app wires it over the email cipher.
type EmailEncrypter interface {
	Encrypt(plain string) ([]byte, error)
}

// GoogleSignIns runs Google sign-in and linking (APP_FLOW 6): the redirect to
// Google, the callback that turns Google's answer into a one-time exchange
// code or a linked identity, and the exchange of that code for tokens.
type GoogleSignIns struct {
	cfg        *Config
	tenancy    string
	provider   provider.Provider
	states     *StateRepository
	identities *IdentityRepository
	tx         txFunc
	users      Users
	tenants    Tenants
	roles      Roles
	audit      AuditWriter
	cipher     EmailEncrypter
	tokens     *onetime.Service
	logins     *Logins
	clock      clock.Clock
	log        logger.Logger
}

// enabled refuses every Google route while the provider is off.
func (s *GoogleSignIns) enabled() error {
	if !s.cfg.Providers.Google.Enabled {
		return apierr.New(apierr.ReasonProviderDisabled)
	}
	return nil
}

// Start stores a new state and returns the Google URL to send the browser
// to. linkUser is the signed-in user when the flow links Google to them.
func (s *GoogleSignIns) Start(ctx context.Context, redirectTo, tenantSlug string, linkUser *uuid.UUID) (string, error) {
	if err := s.enabled(); err != nil {
		return "", err
	}
	if !s.cfg.AllowsRedirect(redirectTo) {
		return "", badQuery("redirect_to", "must be one of the configured frontend URLs")
	}
	if len(tenantSlug) > maxSlug {
		return "", badQuery("tenant", "must be at most 63 characters")
	}
	state, nonce, verifier := randomToken(), randomToken(), randomToken()
	target, err := s.provider.AuthCodeURL(ctx, state, nonce, verifier)
	if err != nil {
		return "", errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: google unavailable")
	}
	err = s.states.Insert(ctx, state, &OAuthState{
		CodeVerifier: verifier, Nonce: nonce, RedirectTo: redirectTo, TenantSlug: tenantSlug,
		LinkUserID: linkUser, ExpiresAt: s.clock.Now().Add(oauthStateTTL),
	})
	if err != nil {
		return "", err
	}
	return target, nil
}

// maxSlug is the longest tenant slug.
const maxSlug = 63

// LinkStart is Start for the signed-in caller: the callback links Google to
// them. The caller's tenant is kept for the audit row.
func (s *GoogleSignIns) LinkStart(ctx context.Context, redirectTo string) (string, error) {
	if err := s.enabled(); err != nil {
		return "", err
	}
	userID, tenantID, err := caller(ctx)
	if err != nil {
		return "", err
	}
	t, err := s.tenants.Tenant(ctx, tenantID)
	if err != nil {
		return "", err
	}
	return s.Start(ctx, redirectTo, t.Slug, &userID)
}

// Callback consumes the state named by q and returns where to send the
// browser: redirect_to with code=<exchange code>, linked=1 or
// error=<reason>. A missing, expired or reused state cannot name a
// redirect_to, so it is a 400 OAUTH_STATE_INVALID instead.
func (s *GoogleSignIns) Callback(ctx context.Context, q url.Values) (string, error) {
	if err := s.enabled(); err != nil {
		return "", err
	}
	st, err := s.states.Take(ctx, q.Get("state"), s.clock.Now())
	if err != nil {
		return "", err
	}
	if st == nil {
		return "", apierr.New(apierr.ReasonOAuthStateInvalid)
	}
	key, value, err := s.finish(ctx, st, q)
	if err != nil {
		return "", err
	}
	return withQuery(st.RedirectTo, key, value)
}

// finish runs the part of the callback that answers by redirect. It returns
// the query parameter to add to redirect_to; err is left for failures that
// have no reason to show, which answer 500.
func (s *GoogleSignIns) finish(ctx context.Context, st *OAuthState, q url.Values) (key, value string, err error) {
	if q.Get("error") != "" || q.Get("code") == "" {
		// The user declined consent, or Google sent no code.
		return "error", string(apierr.ReasonInvalidCredentials), nil
	}
	c, err := s.provider.Exchange(ctx, q.Get("code"), st.CodeVerifier, st.Nonce)
	if err != nil {
		s.log.WarnWithContext(ctx, "google sign-in rejected", logger.F("error", err.Error()))
		return "error", string(apierr.ReasonInvalidCredentials), nil
	}
	if st.LinkUserID != nil {
		err = s.link(ctx, *st.LinkUserID, st.TenantSlug, c)
		key, value = "linked", "1"
	} else {
		key = "code"
		value, err = s.signIn(ctx, st.TenantSlug, c)
	}
	if errors.Is(err, errTenantRequired) {
		return "error", string(apierr.ReasonTenantRequired), nil
	}
	if reason := apierr.ReasonOf(err); reason != "" {
		return "error", string(reason), nil
	}
	return key, value, err
}

// checkClaims refuses an address Google has not verified, or one outside
// allowed_domains.
func (s *GoogleSignIns) checkClaims(c *provider.Claims) error {
	if !c.EmailVerified || c.Email == "" {
		return apierr.New(apierr.ReasonOAuthEmailUnverified)
	}
	allowed := s.cfg.Providers.Google.AllowedDomains
	if len(allowed) == 0 {
		return nil
	}
	domain := c.Email[strings.LastIndex(c.Email, "@")+1:]
	if !slices.ContainsFunc(allowed, func(d string) bool { return strings.EqualFold(d, domain) }) {
		return apierr.New(apierr.ReasonOAuthDomainNotAllowed)
	}
	return nil
}

// link attaches the Google account to userID. Linking the same account again
// succeeds; one linked to someone else is DUPLICATE.
func (s *GoogleSignIns) link(ctx context.Context, userID uuid.UUID, tenantSlug string, c *provider.Claims) error {
	if err := s.checkClaims(c); err != nil {
		return err
	}
	return s.tx(ctx, func(ctx context.Context) error {
		owner, err := s.identities.UserBySubject(ctx, ProviderGoogle, c.Subject)
		switch {
		case err == nil && owner == userID:
			return nil
		case err == nil:
			return apierr.New(apierr.ReasonDuplicate)
		case !errors.Is(err, errorz.ErrNotFound):
			return err
		}
		tenantID, _, err := s.tenants.BySlug(ctx, tenantSlug)
		if err != nil {
			return err
		}
		return s.linkIdentity(ctx, userID, tenantID, c)
	})
}

// linkIdentity stores the identity and audits identity.link.
func (s *GoogleSignIns) linkIdentity(ctx context.Context, userID, tenantID uuid.UUID, c *provider.Claims) error {
	var enc []byte
	if s.cipher != nil {
		var err error
		if enc, err = s.cipher.Encrypt(c.Email); err != nil {
			return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: encrypt email")
		}
	}
	err := s.identities.Link(ctx, userID, ProviderGoogle, c.Subject, enc)
	if errors.Is(err, errorz.ErrConflict) {
		return apierr.New(apierr.ReasonDuplicate)
	}
	if err != nil {
		return err
	}
	return s.audit.Write(ctx, &AuditEvent{
		TenantID: tenantID, ActorID: userID, Action: ActionIdentityLink,
		TargetType: TargetUser, TargetID: userID.String(),
		After: map[string]any{"provider": ProviderGoogle},
	})
}

// signIn finds or creates the user behind the Google account and returns a
// one-time exchange code for a token in the resolved tenant, all in one
// transaction.
func (s *GoogleSignIns) signIn(ctx context.Context, tenantSlug string, c *provider.Claims) (string, error) {
	if err := s.checkClaims(c); err != nil {
		return "", err
	}
	var code string
	err := s.tx(ctx, func(ctx context.Context) error {
		a, linked, err := s.account(ctx, tenantSlug, c)
		if err != nil {
			return err
		}
		if err := checkStatus(a); err != nil {
			return err
		}
		tenant, choice, err := s.logins.resolveTenant(ctx, a, tenantSlug)
		if err != nil {
			return err
		}
		if choice != nil {
			return errTenantRequired
		}
		if !linked {
			if err := s.linkIdentity(ctx, a.ID, tenant.ID, c); err != nil {
				return err
			}
		}
		issued, err := s.tokens.Create(ctx, a.ID, onetime.PurposeOAuthExchange, exchangeCodeTTL,
			onetime.Options{TenantID: &tenant.ID})
		if err != nil {
			return err
		}
		code = issued.Raw
		return nil
	})
	return code, err
}

// account is the user the Google account signs in as (APP_FLOW 6): the
// linked one; else, with auto_link_verified_email, the user with the same
// address, whose email Google has now verified; else a new user when
// registration is open. linked reports whether the identity exists already.
func (s *GoogleSignIns) account(
	ctx context.Context, tenantSlug string, c *provider.Claims,
) (a *Account, linked bool, err error) {
	userID, err := s.identities.UserBySubject(ctx, ProviderGoogle, c.Subject)
	if err == nil {
		a, err = s.users.Get(ctx, userID)
		return a, true, err
	}
	if !errors.Is(err, errorz.ErrNotFound) {
		return nil, false, err
	}
	a, err = s.users.FindByEmail(ctx, c.Email)
	switch {
	case errors.Is(err, errorz.ErrNotFound):
		a, err = s.create(ctx, tenantSlug, c)
		return a, false, err
	case err != nil:
		return nil, false, err
	}
	if !s.cfg.Providers.Google.AutoLinkVerifiedEmail {
		return nil, false, apierr.New(apierr.ReasonDuplicate)
	}
	if !a.EmailVerified && a.Status != StatusDisabled {
		if err := s.users.VerifyEmail(ctx, a.ID, s.clock.Now()); err != nil {
			return nil, false, err
		}
		a.EmailVerified = true
		if a.Status == StatusPending {
			a.Status = StatusActive
		}
	}
	return a, false, nil
}

// create signs a new user up from the Google account: active and verified,
// with no password, a membership and the default roles.
func (s *GoogleSignIns) create(ctx context.Context, tenantSlug string, c *provider.Claims) (*Account, error) {
	if !s.cfg.Registration.Enabled {
		return nil, apierr.New(apierr.ReasonRegistrationClosed)
	}
	tenantID, err := s.signUpTenant(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	userID, err := s.users.Create(ctx, &NewAccount{
		Email: c.Email, DisplayName: displayName(c), Status: StatusActive,
	})
	if errors.Is(err, errorz.ErrConflict) {
		return nil, apierr.New(apierr.ReasonDuplicate)
	}
	if err != nil {
		return nil, err
	}
	if err := s.users.VerifyEmail(ctx, userID, s.clock.Now()); err != nil {
		return nil, err
	}
	if err := s.tenants.AddActiveMember(ctx, tenantID, userID); err != nil {
		return nil, err
	}
	if err := s.roles.Assign(ctx, tenantID, userID, s.cfg.Registration.DefaultRoles); err != nil {
		return nil, err
	}
	err = s.audit.Write(ctx, &AuditEvent{
		TenantID: tenantID, ActorID: userID, Action: ActionRegister,
		TargetType: TargetUser, TargetID: userID.String(),
		After: map[string]any{"status": StatusActive, "roles": s.cfg.Registration.DefaultRoles, "method": methodGoogle},
	})
	if err != nil {
		return nil, err
	}
	s.log.InfoWithContext(ctx, "user registered", logger.F("user_id", userID.String()))
	return s.users.Get(ctx, userID)
}

// signUpTenant is the tenant a new Google user joins: the default one in
// single mode, the named, active one in multi mode.
func (s *GoogleSignIns) signUpTenant(ctx context.Context, slug string) (uuid.UUID, error) {
	if s.tenancy != tenancyMulti {
		return s.tenants.DefaultTenantID(ctx)
	}
	if slug == "" {
		return uuid.Nil, errTenantRequired
	}
	id, active, err := s.tenants.BySlug(ctx, slug)
	if err != nil {
		return uuid.Nil, err
	}
	if !active {
		return uuid.Nil, apierr.New(apierr.ReasonTenantSuspended)
	}
	return id, nil
}

// Exchange spends a callback's code and signs the user in, re-checking the
// account and the tenant: either may have changed since the callback.
func (s *GoogleSignIns) Exchange(ctx context.Context, in *ExchangeRequest, d Device) (*TokenResponse, error) {
	if err := s.enabled(); err != nil {
		return nil, err
	}
	if err := s.logins.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	var resp *TokenResponse
	err := s.tx(ctx, func(ctx context.Context) error {
		t, err := s.tokens.Consume(ctx, in.Code, onetime.PurposeOAuthExchange)
		if errors.Is(err, onetime.ErrInvalid) || errors.Is(err, onetime.ErrExpired) || t != nil && t.TenantID == nil {
			return apierr.New(apierr.ReasonTokenInvalid)
		}
		if err != nil {
			return err
		}
		a, err := s.users.Get(ctx, t.UserID)
		if err != nil {
			return err
		}
		if err := checkStatus(a); err != nil {
			return err
		}
		named, err := s.tenants.Tenant(ctx, *t.TenantID)
		if err != nil {
			return err
		}
		tenant, _, err := s.logins.resolveTenant(ctx, a, named.Slug)
		if err != nil {
			return err
		}
		resp, err = s.logins.record(ctx, &signIn{account: a, tenant: tenant, device: d, method: methodGoogle})
		return err
	})
	if err != nil {
		return nil, err
	}
	s.log.InfoWithContext(ctx, "user signed in", logger.F("user_id", resp.User.ID))
	return resp, nil
}

// displayName is the new account's name: Google's, else the address's local
// part, cut to maxDisplayName runes.
func displayName(c *provider.Claims) string {
	name := strings.TrimSpace(c.Name)
	if name == "" {
		name, _, _ = strings.Cut(c.Email, "@")
	}
	if utf8.RuneCountInString(name) > maxDisplayName {
		name = string([]rune(name)[:maxDisplayName])
	}
	return name
}

// withQuery adds key=value to the query of raw, an allow-listed redirect_to.
func withQuery(raw, key, value string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: parse redirect_to")
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// randomToken is 256 random bits, base64url encoded: a state, a nonce or a
// PKCE verifier (43 characters, within RFC 7636's 43-128).
func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails: crypto/rand aborts the process instead
	return base64.RawURLEncoding.EncodeToString(b)
}

// badQuery is a 400 naming one query parameter.
func badQuery(field, msg string) error {
	return errorz.BadRequest().WithMessage(field+": "+msg).
		WithMeta(apierr.MetaFields, map[string]string{field: msg})
}
