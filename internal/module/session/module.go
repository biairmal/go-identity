package session

import (
	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/httpkit/middleware"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// Module is the session feature boundary.
type Module struct {
	svc *Service
	az  authz.Authorizer
}

// Deps are what session needs from internal/app.
type Deps struct {
	DB    *sqlkit.DB
	Log   logger.Logger
	Clock clock.Clock
	// Audit, Members and Authz serve the routes. They may be nil when the
	// routes are not registered (the CLI).
	Audit   AuditWriter
	Members Members
	Authz   authz.Authorizer
}

// New builds the module from its config block and dependencies.
func New(cfg Config, deps *Deps) *Module {
	svc := NewService(cfg, NewRepository(deps.DB), deps.DB, deps.Clock, deps.Log)
	svc.audit = deps.Audit
	svc.members = deps.Members
	return &Module{svc: svc, az: deps.Authz}
}

// Service exposes the session rules to internal/app, which adapts them to the
// ports other modules declare.
func (m *Module) Service() *Service { return m.svc }

// Register mounts the caller's session list and sign-out of one device, and
// the admin revoke of a user's sessions behind users:manage.
func (m *Module) Register(rt *httpx.Routes) {
	rt.Me.Get("/sessions", httpx.Handle(m.listMine))
	rt.Me.Delete("/sessions/{id}", httpx.Handle(m.revokeMine))
	rt.Admin.With(middleware.RequirePermission(m.az, "users:manage")).
		Post("/users/{id}/revoke-sessions", httpx.Handle(m.revokeForUser))
}
