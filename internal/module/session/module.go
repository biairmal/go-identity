package session

import (
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// Module is the session feature boundary.
type Module struct {
	svc *Service
}

// Deps are what session needs from internal/app.
type Deps struct {
	DB    *sqlkit.DB
	Log   logger.Logger
	Clock clock.Clock
}

// New builds the module from its config block and dependencies.
func New(cfg Config, deps Deps) *Module {
	return &Module{svc: NewService(cfg, NewRepository(deps.DB), deps.DB, deps.Clock, deps.Log)}
}

// Service exposes the session rules to internal/app, which adapts them to the
// ports other modules declare.
func (m *Module) Service() *Service { return m.svc }

// Register mounts the module's routes. The session list and revoke endpoints
// arrive with T3.9 and T5.2.
func (m *Module) Register(*httpx.Routes) {}
