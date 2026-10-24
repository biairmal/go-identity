package auth

import (
	"context"
	"net/http"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/module/auth/keys"
	"github.com/biairmal/go-identity/internal/module/auth/onetime"
	"github.com/biairmal/go-identity/internal/module/auth/token"
	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// Module is the auth feature boundary: the sign-in flows and the only issuer
// of tokens. This milestone builds the signing keys, the access-token builder
// and the JWKS endpoint; the flows arrive in Milestone 3.
type Module struct {
	cfg     Config
	keys    *keys.Set
	tokens  *token.Builder
	keyRepo *KeyRepository
	onetime *onetime.Service
	log     logger.Logger
}

// Deps are what auth needs from internal/app.
type Deps struct {
	DB    *sqlkit.DB
	Log   logger.Logger
	Clock clock.Clock
}

// New loads the signing keys and builds the token builder. It fails when the
// keys are missing or too weak, so a service that cannot sign never starts.
func New(cfg *Config, deps Deps) (*Module, error) {
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
	return &Module{
		cfg: *cfg, keys: set, tokens: builder,
		keyRepo: NewKeyRepository(deps.DB),
		onetime: onetime.NewService(onetime.NewRepository(deps.DB), deps.Clock),
		log:     log,
	}, nil
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
// go-sdk's JWKS client expect it.
func (m *Module) Register(rt *httpx.Routes) {
	rt.Root.Method(http.MethodGet, jwksPath, sdkauth.JWKSHandler(m.keys.Public))
}

// jwksPath is the well-known location of the public key set.
const jwksPath = "/.well-known/jwks.json"
