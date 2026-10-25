package rbac

import (
	"github.com/biairmal/go-sdk/lib/httpkit/middleware"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/validator"

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
	V     validator.Validator
	Audit AuditWriter
}

// New builds the module from its config block and dependencies.
func New(cfg Config, deps Deps) *Module {
	svc := NewService(cfg, NewRepository(deps.DB), deps.Audit, deps.Log)
	svc.v = deps.V
	return &Module{svc: svc}
}

// Service exposes the RBAC rules to internal/app, which adapts them to the
// ports other modules declare and calls the startup steps.
func (m *Module) Service() *Service { return m.svc }

// Authorizer is the database-backed permission check for identity's admin
// routes; internal/app hands it to the other modules that serve them.
func (m *Module) Authorizer() *Authorizer { return m.svc.az }

// Register mounts the admin role and permission endpoints, behind
// roles:manage, and user role assignment, behind users:manage. The internal
// role map arrives with T7.1.
func (m *Module) Register(rt *httpx.Routes) {
	rt.Admin.With(middleware.RequirePermission(m.svc.az, PermUsersManage)).
		Put("/users/{id}/roles", httpx.Handle(m.setUserRoles))
	g := rt.Admin.With(middleware.RequirePermission(m.svc.az, PermRolesManage))
	g.Get("/permissions", httpx.Handle(m.listPermissions))
	g.Get("/roles", httpx.Handle(m.listRoles))
	g.Post("/roles", httpx.Handle(m.createRole))
	g.Get("/roles/{id}", httpx.Handle(m.getRole))
	g.Patch("/roles/{id}", httpx.Handle(m.updateRole))
	g.Delete("/roles/{id}", httpx.Handle(m.deleteRole))
	g.Put("/roles/{id}/permissions", httpx.Handle(m.setPermissions))
}
