package app

import (
	"net/http"

	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/validator"
)

// Deps are the shared dependencies handed to every module's New.
type Deps struct {
	DB    *sqlkit.DB
	Log   logger.Logger
	V     validator.Validator
	Authz authz.Authorizer
}

// Module is a feature boundary. internal/app only sees this: it builds each
// module with New(cfg, deps) and mounts its routes. Modules never import each
// other; when one needs another's data it declares a port and app wires an
// adapter.
type Module interface {
	Register(mux *http.ServeMux)
}

// buildModules constructs every module. Adding a module adds one entry here.
func buildModules(_ *Config, _ Deps) ([]Module, error) {
	return nil, nil
}
