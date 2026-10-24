package app

import (
	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/validator"

	"github.com/biairmal/go-identity/internal/module/audit"
	identityauth "github.com/biairmal/go-identity/internal/module/auth"
	"github.com/biairmal/go-identity/internal/module/rbac"
	"github.com/biairmal/go-identity/internal/module/session"
	"github.com/biairmal/go-identity/internal/module/tenant"
	"github.com/biairmal/go-identity/internal/module/user"
	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/httpx"
	"github.com/biairmal/go-identity/internal/platform/ratelimit"
)

// Deps are the shared dependencies handed to every module's New.
type Deps struct {
	DB     *sqlkit.DB
	Log    logger.Logger
	V      validator.Validator
	Authz  authz.Authorizer
	Outbox *database.Outbox
	// Limiter rate-limits the public sign-in and sign-up routes; nil turns
	// rate limiting off.
	Limiter *ratelimit.Limiter
}

// Module is a feature boundary. internal/app only sees this: it builds each
// module with New(cfg, deps) and mounts its routes. Modules never import each
// other; when one needs another's data it declares a port and app wires an
// adapter.
type Module interface {
	Register(rt *httpx.Routes)
}

// services are the module services internal/app itself needs, for the startup
// steps that span modules (the default tenant, role seeding, the super admin)
// and for the super admin CLI.
type services struct {
	tenant      *tenant.Service
	rbac        *rbac.Service
	auth        *identityauth.Module
	session     *session.Service
	user        *user.Service
	superAdmins *user.SuperAdmins
}

// buildModules constructs every module and returns them together with the
// services internal/app needs afterwards. Adding a module adds one entry
// here. The order is the one modules are registered in, not a dependency
// order: modules never depend on each other directly, only through ports.
func buildModules(cfg *Config, deps Deps) ([]Module, *services, error) {
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

	sessionModule := session.New(cfg.Modules.Session, session.Deps{
		DB:    deps.DB,
		Log:   deps.Log,
		Clock: clock.System{},
	})

	userModule, err := newUserModule(cfg, deps, auditModule, tenantModule.Service(), sessionModule.Service())
	if err != nil {
		return nil, nil, err
	}

	// auth loads the signing keys, so a service that cannot sign a token
	// does not start.
	authDeps := &identityauth.Deps{
		DB:       deps.DB,
		Log:      deps.Log,
		Clock:    clock.System{},
		Tenancy:  cfg.Modules.Tenant.Mode,
		V:        deps.V,
		Outbox:   deps.Outbox,
		Users:    authUsers{svc: userModule.Service()},
		Tenants:  tenantMemberships{svc: tenantModule.Service()},
		Roles:    authRoles{svc: rbacModule.Service()},
		Sessions: authSessions{svc: sessionModule.Service()},
		Audit:    authAudit{w: auditModule.Writer()},
	}
	if deps.Limiter != nil {
		// Assigned only when set, so the interface never holds a nil pointer.
		authDeps.Limiter = deps.Limiter
	}
	authModule, err := identityauth.New(&cfg.Modules.Auth, authDeps)
	if err != nil {
		return nil, nil, err
	}

	modules := []Module{auditModule, tenantModule, rbacModule, authModule, sessionModule, userModule}
	return modules, &services{
		tenant:      tenantModule.Service(),
		rbac:        rbacModule.Service(),
		auth:        authModule,
		session:     sessionModule.Service(),
		user:        userModule.Service(),
		superAdmins: userModule.SuperAdmins(),
	}, nil
}
