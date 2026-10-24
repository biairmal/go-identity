package user

import (
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// Module is the user feature boundary.
type Module struct {
	svc *Service
}

// Deps are what user needs from internal/app. EmailCipher is a port, wired
// over go-sdk crypto by an adapter, so the module never depends on a
// particular cipher.
type Deps struct {
	DB          *sqlkit.DB
	Log         logger.Logger
	EmailCipher EmailCipher
}

// New builds the module from its config block and dependencies.
func New(cfg Config, deps Deps) *Module {
	repo := NewRepository(deps.DB, deps.EmailCipher)
	return &Module{svc: NewService(cfg, repo, NewCredentialsRepository(deps.DB), deps.Log)}
}

// Service exposes the user rules to internal/app, which adapts them to the
// ports other modules declare.
func (m *Module) Service() *Service { return m.svc }

// Register mounts the module's routes. The admin user endpoints arrive with
// the admin API, so there is nothing to mount yet.
func (m *Module) Register(*httpx.Routes) {}
