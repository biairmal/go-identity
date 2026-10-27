// Package identity lets a host application mount identity's HTTP routes into
// its own chi router and run it as part of one binary (TRD 1.1 "mounted"
// mode), instead of running identity as its own process.
package identity

import (
	"context"
	"io/fs"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/go-chi/chi/v5"

	"github.com/biairmal/go-identity/internal/app"
	"github.com/biairmal/go-identity/internal/platform/mail"
	"github.com/biairmal/go-identity/migrations"
)

// Config is identity's configuration (TRD 4), the same type cmd/server loads
// from config/config.yaml and .env.
type Config = app.Config

// Mailer sends the mail identity queues on sign-up, password reset and
// invites (verification links, one-time tokens). See internal/platform/mail
// for Message and the development logging stub.
type Mailer = mail.Mailer

// Deps are the dependencies a host supplies to mount identity.
type Deps struct {
	// DB is the host's database connection, already migrated (see
	// Migrations). Register never closes it: the host owns its lifecycle.
	DB *sqlkit.DB
	// Log is identity's logger.
	Log logger.Logger
	// Config is identity's full configuration.
	Config Config
	// Mailer is reserved for the host's own delivery of identity's queued
	// mail; identity has no exported worker yet, so Register does not read
	// it (T7.4 tracks exposing the dispatcher to mounted hosts).
	Mailer Mailer
}

// Register builds identity against the host's own database connection and
// mounts its routes onto r: the operational endpoints, /v1 and its groups,
// and every module. The host migrates the database first (see Migrations)
// and keeps running its own process around r; Register only wires HTTP
// handlers, it starts neither a listener nor identity's background worker.
//
// Register adds middleware to r, which chi refuses once a route is already
// defined on it, so call Register before adding the host's own routes to r
// (a fresh chi.NewRouter(), or the host's own top-level router).
func Register(r chi.Router, deps Deps) error { //nolint:gocritic // Deps by value, matching the plan's published API
	_, err := app.Register(context.Background(), r, &deps.Config, deps.Log, deps.DB)
	return err
}

// Migrations is identity's embedded SQL migration set, for a host that runs
// it with its own migration tool before calling Register.
func Migrations() fs.FS { return migrations.FS }
