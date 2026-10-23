package rbac

import (
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// Module is the RBAC feature boundary.
type Module struct {
	svc *Service
}

// Deps are what rbac needs from internal/app. Audit is a port, wired to the
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

// Service exposes the RBAC rules to internal/app, which adapts them to the
// ports other modules declare and calls the startup steps.
func (m *Module) Service() *Service { return m.svc }

// Register mounts the module's routes. The admin role endpoints arrive with
// T5.1 and the internal role map with T7.1.
func (m *Module) Register(*httpx.Routes) {}
