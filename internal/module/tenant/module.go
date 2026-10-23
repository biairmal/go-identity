package tenant

import (
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

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
	Audit AuditWriter
}

// New builds the module from its config block and dependencies.
func New(cfg Config, deps Deps) *Module {
	return &Module{svc: NewService(cfg, NewRepository(deps.DB), deps.Audit, deps.Log)}
}

// Service exposes the tenant rules to internal/app, which adapts them to the
// ports other modules declare.
func (m *Module) Service() *Service { return m.svc }

// Register mounts the module's routes. The admin tenant endpoints arrive with
// T6.1, and they return 404 in single mode.
func (m *Module) Register(*httpx.Routes) {}
