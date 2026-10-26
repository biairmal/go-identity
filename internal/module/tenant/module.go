package tenant

import (
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/validator"

	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// Module is the tenant feature boundary.
type Module struct {
	svc *Service
}

// Deps are what tenant needs from internal/app. Audit is a port, wired to the
// audit module by an adapter.
type Deps struct {
	DB    *sqlkit.DB
	Log   logger.Logger
	V     validator.Validator
	Audit AuditWriter
}

// New builds the module from its config block and dependencies.
func New(cfg Config, deps Deps) *Module {
	svc := NewService(cfg, NewRepository(deps.DB), deps.Audit, deps.Log)
	svc.v = deps.V
	return &Module{svc: svc}
}

// Service exposes the tenant rules to internal/app, which adapts them to the
// ports other modules declare.
func (m *Module) Service() *Service { return m.svc }

// Register mounts the super-admin tenant endpoints (9.7). They live in the
// Super group, so they require the sa claim and answer 404 in single mode.
func (m *Module) Register(rt *httpx.Routes) {
	rt.Super.Get("/tenants", httpx.Handle(m.listTenants))
	rt.Super.Post("/tenants", httpx.Handle(m.createTenant))
	rt.Super.Get("/tenants/{id}", httpx.Handle(m.getTenant))
	rt.Super.Patch("/tenants/{id}", httpx.Handle(m.updateTenant))
}
