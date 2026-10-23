// Package audit writes the append-only change history. Every role,
// permission, membership, tenant-status and sign-in event is recorded with
// before and after state, inside the same transaction as the change it
// describes, so a change and its audit row can never diverge.
package audit

import (
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// Module is the audit feature boundary. It owns the writer other modules
// reach through a port, and later the admin read endpoint.
type Module struct {
	writer *Writer
}

// Deps are what audit needs from internal/app.
type Deps struct {
	DB  *sqlkit.DB
	Log logger.Logger
}

// New builds the module. The audit module has no configuration.
func New(deps Deps) *Module {
	return &Module{writer: NewWriter(NewRepository(deps.DB), deps.Log)}
}

// Writer is the audit writer other modules use, wired as an adapter in
// internal/app.
func (m *Module) Writer() *Writer { return m.writer }

// Register mounts the module's routes. The admin read endpoint arrives with
// T5.4; until then audit only writes.
func (m *Module) Register(*httpx.Routes) {}
