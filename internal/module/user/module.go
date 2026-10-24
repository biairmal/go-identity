package user

import (
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// Module is the user feature boundary.
type Module struct {
	svc    *Service
	admins *SuperAdmins
}

// Deps are what user needs from internal/app. EmailCipher, Passwords,
// Memberships, Sessions and Audit are ports, wired over other modules and
// go-sdk by adapters, so the module never depends on them directly.
type Deps struct {
	DB          *sqlkit.DB
	Log         logger.Logger
	Clock       clock.Clock
	EmailCipher EmailCipher
	Passwords   Passwords
	Memberships Memberships
	Sessions    Sessions
	Audit       AuditWriter
}

// New builds the module from its config block and dependencies.
func New(cfg Config, deps *Deps) *Module {
	repo := NewRepository(deps.DB, deps.EmailCipher)
	creds := NewCredentialsRepository(deps.DB)
	return &Module{
		svc: NewService(cfg, repo, creds, deps.Log),
		admins: NewSuperAdmins(cfg.SuperAdmin, deps.DB, repo, creds, &SuperAdminDeps{
			Passwords:   deps.Passwords,
			Memberships: deps.Memberships,
			Sessions:    deps.Sessions,
			Audit:       deps.Audit,
			Clock:       deps.Clock,
			Log:         deps.Log,
		}),
	}
}

// Service exposes the user rules to internal/app, which adapts them to the
// ports other modules declare.
func (m *Module) Service() *Service { return m.svc }

// SuperAdmins exposes the super admin bootstrap, reset and transfer to the
// startup path and the CLI.
func (m *Module) SuperAdmins() *SuperAdmins { return m.admins }

// Register mounts the module's routes. The admin user endpoints arrive with
// the admin API, so there is nothing to mount yet.
func (m *Module) Register(*httpx.Routes) {}
