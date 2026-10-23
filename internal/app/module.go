package app

import (
	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/validator"

	"github.com/biairmal/go-identity/internal/module/audit"
	"github.com/biairmal/go-identity/internal/module/rbac"
	"github.com/biairmal/go-identity/internal/module/tenant"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// Deps are the shared dependencies handed to every module's New.
type Deps struct {
	DB     *sqlkit.DB
	Log    logger.Logger
	V      validator.Validator
	Authz  authz.Authorizer
	Outbox *database.Outbox
}

// Module is a feature boundary. internal/app only sees this: it builds each
// module with New(cfg, deps) and mounts its routes. Modules never import each
// other; when one needs another's data it declares a port and app wires an
// adapter.
type Module interface {
	Register(rt *httpx.Routes)
}

// services are the module services internal/app itself needs, for the startup
// steps that span modules: ensuring the default tenant now, and later seeding
// roles and the super admin.
type services struct {
	tenant *tenant.Service
	rbac   *rbac.Service
}

// buildModules constructs every module and returns them together with the
// services internal/app needs afterwards. Adding a module adds one entry
// here. The order is the one modules are registered in, not a dependency
// order: modules never depend on each other directly, only through ports.
func buildModules(cfg *Config, deps Deps) ([]Module, *services) {
	auditModule := audit.New(audit.Deps{DB: deps.DB, Log: deps.Log})

	tenantModule := tenant.New(cfg.Modules.Tenant, tenant.Deps{
		DB:    deps.DB,
		Log:   deps.Log,
		Audit: tenantAudit{w: auditModule.Writer()},
	})

	rbacModule := rbac.New(cfg.Modules.RBAC, rbac.Deps{
		DB:    deps.DB,
		Log:   deps.Log,
		Audit: rbacAudit{w: auditModule.Writer()},
	})

	modules := []Module{auditModule, tenantModule, rbacModule}
	return modules, &services{
		tenant: tenantModule.Service(),
		rbac:   rbacModule.Service(),
	}
}
