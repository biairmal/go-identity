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
	// Audit records sign-outs from the session list. It may be nil when
	// the routes are not registered (the CLI).
	Audit AuditWriter
}

// New builds the module from its config block and dependencies.
func New(cfg Config, deps Deps) *Module {
	svc := NewService(cfg, NewRepository(deps.DB), deps.DB, deps.Clock, deps.Log)
	svc.audit = deps.Audit
	return &Module{svc: svc}
}

// Service exposes the session rules to internal/app, which adapts them to the
// ports other modules declare.
func (m *Module) Service() *Service { return m.svc }

// Register mounts the caller's session list and sign-out of one device. The
// admin revoke endpoint arrives with T5.2.
func (m *Module) Register(rt *httpx.Routes) {
	rt.Me.Get("/sessions", httpx.Handle(m.listMine))
	rt.Me.Delete("/sessions/{id}", httpx.Handle(m.revokeMine))
}
