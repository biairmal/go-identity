package auth

import (
	"context"
	"net/http"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/validator"

	"github.com/biairmal/go-identity/internal/module/auth/keys"
	"github.com/biairmal/go-identity/internal/module/auth/onetime"
	"github.com/biairmal/go-identity/internal/module/auth/token"
	"github.com/biairmal/go-identity/internal/platform/clock"
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
	// Users, Tenants, Roles and Audit are ports over the other modules,
	// wired by internal/app. The sign-up flows need all four.
	Users   Users
	Tenants Tenants
	Roles   Roles
	Audit   AuditWriter
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
	return m, nil
}

// Tokens is the access-token builder, used by the sign-in flows.
func (m *Module) Tokens() *token.Builder { return m.tokens }

// OneTime issues and consumes the single-use tokens the email flows put in
// their links.
func (m *Module) OneTime() *onetime.Service { return m.onetime }

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
	rt.API.Post(registerPath, httpx.Handle(m.register))
	rt.API.Post(verifyEmailPath, httpx.Handle(m.verifyEmail))
	rt.API.Post(resendVerifyPath, httpx.Handle(m.resendVerification))
}

// jwksPath is the well-known location of the public key set.
const jwksPath = "/.well-known/jwks.json"
