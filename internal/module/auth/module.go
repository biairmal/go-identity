package auth

import (
	"context"
	"net/http"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/httpkit/middleware"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/auth/keys"
	"github.com/biairmal/go-identity/internal/module/auth/onetime"
	"github.com/biairmal/go-identity/internal/module/auth/token"
	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/httpx"
	"github.com/biairmal/go-identity/internal/platform/mail"
)

// Module is the auth feature boundary: the sign-in flows and the only issuer
// of tokens.
type Module struct {
	cfg     Config
	keys    *keys.Set
	tokens  *token.Builder
	keyRepo *KeyRepository
	onetime *onetime.Service
	log     logger.Logger
	// registrations runs sign-up and email verification.
	registrations *Registrations
	// logins runs password sign-in.
	logins *Logins
	// refreshes runs refresh, logout and logout-all.
	refreshes *Refreshes
	// profiles serves the caller's own account under /v1/me.
	profiles *Profiles
	// resets runs forgot-password and reset-password.
	resets *PasswordResets
	// invites runs invite, preview and accept.
	invites *Invites
	// switches runs switch-tenant.
	switches *Switches
	// az guards the admin invite route.
	az authz.Authorizer
	// limiter rate-limits the public sign-in and sign-up routes; nil
	// allows everything.
	limiter Limiter
	// authConfig is the public view of cfg served at /v1/auth/config.
	authConfig AuthConfigResponse
}

// Deps are what auth needs from internal/app.
type Deps struct {
	DB    *sqlkit.DB
	Log   logger.Logger
	Clock clock.Clock
	// Tenancy is the tenancy mode ("single" or "multi"), owned by the
	// tenant module and passed through by internal/app.
	Tenancy string
	// V validates request bodies; nil builds one that names fields by
	// their JSON key.
	V validator.Validator
	// Outbox queues mail in the caller's transaction.
	Outbox mail.Enqueuer
	// Users, Tenants, Roles, Sessions and Audit are ports over the other
	// modules, wired by internal/app.
	Users    Users
	Tenants  Tenants
	Roles    Roles
	Sessions Sessions
	Audit    AuditWriter
	// Limiter rate-limits sign-in and sign-up by IP and by email key, with
	// the modules.auth.security.login_rate_limit budget. nil disables it.
	Limiter Limiter
	// RefreshLimiter rate-limits refresh by IP with the
	// modules.auth.security.refresh_rate_limit budget. nil disables it.
	RefreshLimiter Limiter
	// Authz guards POST /v1/admin/users/invite. It may be nil when the
	// routes are not registered.
	Authz authz.Authorizer
}

// New loads the signing keys and builds the token builder. It fails when the
// keys are missing or too weak, so a service that cannot sign never starts.
func New(cfg *Config, deps *Deps) (*Module, error) {
	log := deps.Log
	if log == nil {
		log = logger.NewNoOp()
	}
	set, err := keys.Load(cfg.Token.SigningKeysDir)
	if err != nil {
		return nil, err
	}
	builder, err := token.NewBuilder(token.Config{
		Issuer:    cfg.Token.Issuer,
		Audience:  cfg.Token.Audience,
		AccessTTL: cfg.Token.AccessTTL,
		Claims:    cfg.Token.Claims,
	}, set, deps.Clock)
	if err != nil {
		return nil, err
	}
	clk := deps.Clock
	if clk == nil {
		clk = clock.System{}
	}
	v := deps.V
	if v == nil {
		v = validator.New(validator.Config{FieldNameTag: "json"})
	}
	tokRepo := onetime.NewRepository(deps.DB)
	tokens := onetime.NewService(tokRepo, clk)
	m := &Module{
		cfg: *cfg, keys: set, tokens: builder,
		keyRepo:    NewKeyRepository(deps.DB),
		onetime:    tokens,
		log:        log,
		authConfig: newAuthConfigResponse(cfg, deps.Tenancy),
	}
	m.registrations = &Registrations{
		cfg: &m.cfg, tenancy: deps.Tenancy, db: deps.DB, v: v,
		users: deps.Users, tenants: deps.Tenants, roles: deps.Roles, audit: deps.Audit,
		outbox: deps.Outbox, tokens: tokens, tokRepo: tokRepo, clock: clk, log: log,
	}
	m.resets = &PasswordResets{
		cfg: &m.cfg, db: deps.DB, v: v, users: deps.Users, sessions: deps.Sessions, audit: deps.Audit,
		outbox: deps.Outbox, tokens: tokens, tokRepo: tokRepo, log: log,
	}
	m.limiter = deps.Limiter
	m.az = deps.Authz
	tx := func(ctx context.Context, fn func(ctx context.Context) error) error {
		return database.WithTx(ctx, deps.DB, fn)
	}
	issue := &tokenIssuer{cfg: &m.cfg, roles: deps.Roles, tokens: builder, clock: clk}
	m.invites = &Invites{
		cfg: &m.cfg, db: deps.DB, v: v, users: deps.Users, tenants: deps.Tenants, roles: deps.Roles,
		sessions: deps.Sessions, audit: deps.Audit, outbox: deps.Outbox, tokens: tokens, tokRepo: tokRepo,
		issue: issue, clock: clk, log: log,
	}
	m.logins = &Logins{
		cfg: &m.cfg, tenancy: deps.Tenancy, v: v, tx: tx,
		users: deps.Users, tenants: deps.Tenants, sessions: deps.Sessions,
		audit: deps.Audit, limiter: deps.Limiter, issue: issue, clock: clk, log: log,
		dummyHash: newDummyHash(),
	}
	m.profiles = &Profiles{
		cfg: &m.cfg, tx: tx, v: v, users: deps.Users, tenants: deps.Tenants, roles: deps.Roles,
		sessions: deps.Sessions, audit: deps.Audit, identities: NewIdentityRepository(deps.DB),
		issue: issue, log: log,
	}
	m.refreshes = &Refreshes{
		tx: tx, v: v, users: deps.Users, tenants: deps.Tenants, sessions: deps.Sessions,
		audit: deps.Audit, limiter: deps.RefreshLimiter, issue: issue, clock: clk, log: log,
	}
	m.switches = &Switches{
		tenancy: deps.Tenancy, tx: tx, v: v, users: deps.Users, tenants: deps.Tenants,
		sessions: deps.Sessions, audit: deps.Audit, issue: issue, log: log,
	}
	return m, nil
}

// Tokens is the access-token builder, used by the sign-in flows.
func (m *Module) Tokens() *token.Builder { return m.tokens }

// OneTime issues and consumes the single-use tokens the email flows put in
// their links.
func (m *Module) OneTime() *onetime.Service { return m.onetime }

// InviteToTenant invites email into tenantID as its admin, granting roleIDs,
// recording invitedBy as the inviter. internal/app calls it through the
// tenant onboarding adapter, inside the tenant-creation transaction.
func (m *Module) InviteToTenant(
	ctx context.Context, tenantID, invitedBy uuid.UUID, email string, roleIDs []uuid.UUID,
) error {
	return m.invites.InviteToTenant(ctx, tenantID, invitedBy, email, roleIDs)
}

// SyncKeys records the loaded keys and their statuses, so an operator can see
// which keys this deployment publishes. internal/app calls it at startup.
func (m *Module) SyncKeys(ctx context.Context) error {
	return m.keyRepo.Sync(ctx, m.keys.Public(), m.keys.Statuses())
}

// Register mounts the JWKS endpoint outside /v1, where resource services and
// go-sdk's JWKS client expect it, and the public sign-in endpoints on /v1.
func (m *Module) Register(rt *httpx.Routes) {
	rt.Root.Method(http.MethodGet, jwksPath, sdkauth.JWKSHandler(m.keys.Public))
	rt.API.Get(authConfigPath, httpx.Handle(m.getAuthConfig))
	rt.API.Post(loginPath, httpx.Handle(m.login))
	rt.API.Post(switchTenantPath, httpx.Handle(m.switchTenant))
	rt.API.Post(refreshPath, httpx.Handle(m.refresh))
	rt.API.Post(logoutPath, httpx.Handle(m.logout))
	rt.API.Post(logoutAllPath, httpx.Handle(m.logoutAll))
	rt.API.Post(registerPath, httpx.Handle(m.register))
	rt.API.Post(verifyEmailPath, httpx.Handle(m.verifyEmail))
	rt.API.Post(resendVerifyPath, httpx.Handle(m.resendVerification))
	rt.API.Post(forgotPasswordPath, httpx.Handle(m.forgotPassword))
	rt.API.Post(resetPasswordPath, httpx.Handle(m.resetPassword))
	rt.API.Get(invitePreviewPath, httpx.Handle(m.previewInvite))
	rt.API.Post(inviteAcceptPath, httpx.Handle(m.acceptInvite))
	rt.Admin.With(middleware.RequirePermission(m.az, permUsersManage)).Post(adminInvitePath, httpx.Handle(m.inviteUser))
	rt.Me.Get(mePath, httpx.Handle(m.getMe))
	rt.Me.Patch(mePath, httpx.Handle(m.updateMe))
	rt.Me.Post(mePasswordPath, httpx.Handle(m.changePassword))
	rt.Me.Get(meTenantsPath, httpx.Handle(m.myTenants))
	rt.Me.Delete(meGoogleIdentity, httpx.Handle(m.unlinkGoogle))
}

// jwksPath is the well-known location of the public key set.
const jwksPath = "/.well-known/jwks.json"
