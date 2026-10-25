// Package audit writes the append-only change history. Every role,
// permission, membership, tenant-status and sign-in event is recorded with
// before and after state, inside the same transaction as the change it
// describes, so a change and its audit row can never diverge.
package audit

import (
	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/httpkit/middleware"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// Module is the audit feature boundary. It owns the writer other modules
// reach through a port, and the admin read endpoint.
type Module struct {
	writer *Writer
	repo   *Repository
	az     authz.Authorizer
}

// Deps are what audit needs from internal/app. Authz guards the read
// endpoint; it may be nil when the routes are not registered (the CLI).
type Deps struct {
	DB    *sqlkit.DB
	Log   logger.Logger
	Authz authz.Authorizer
}

// New builds the module. The audit module has no configuration.
func New(deps Deps) *Module {
	repo := NewRepository(deps.DB)
	return &Module{writer: NewWriter(repo, deps.Log), repo: repo, az: deps.Authz}
}

// Writer is the audit writer other modules use, wired as an adapter in
// internal/app.
func (m *Module) Writer() *Writer { return m.writer }

// Register mounts GET /v1/admin/audit behind audit:read.
func (m *Module) Register(rt *httpx.Routes) {
	rt.Admin.With(middleware.RequirePermission(m.az, permAuditRead)).Get("/audit", httpx.Handle(m.listAudit))
}
