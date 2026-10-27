// Command monolith is a worked example of mounting identity into a host's
// own chi app (TRD 1.1 "mounted" mode, IMPLEMENTATION_PLAN T7.2): one binary
// serves identity's routes (GET /healthz, POST /v1/auth/login, ...) and the
// host's own route (GET /host/ping) side by side, on one router.
//
// Run it against the repo's local stack:
//
//	make up
//	SIGNING_KEYS_DIR=../../keys go run . serve
//
// A host outside this repo cannot reuse internal/app.LoadConfig or
// internal/platform/database the way this example does (they are
// unexported); it builds identity.Config and runs identity.Migrations()
// itself, however its own config and migration tooling work. Only
// identity.Config, identity.Deps, identity.Register and identity.Migrations
// are the public surface this example demonstrates.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/go-chi/chi/v5"

	identity "github.com/biairmal/go-identity"
	"github.com/biairmal/go-identity/internal/app"
	"github.com/biairmal/go-identity/internal/platform/database"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	cfg, err := app.LoadConfig("../../.env", "../../config/config.yaml")
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := app.NewLogger(&cfg)

	db, err := sqlkit.New(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			log.Error("database close", logger.F("error", cerr.Error()))
		}
	}()

	// Run identity's migrations before Register, which refuses to serve a
	// stale schema (the same guard the standalone server uses).
	migrator, err := database.NewMigrator(db.Leader(), identity.Migrations())
	if err != nil {
		return fmt.Errorf("build migrator: %w", err)
	}
	if _, err := migrator.Up(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	r := chi.NewRouter()

	// Register uses r.Use internally, which chi refuses once a route is
	// already defined on r, so it runs before the host adds its own routes.
	if err := identity.Register(r, identity.Deps{DB: db, Log: log, Config: cfg}); err != nil {
		return fmt.Errorf("mount identity: %w", err)
	}
	r.Get("/host/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	log.Info("monolith example listening", logger.F("addr", cfg.HTTP.Addr))
	return http.ListenAndServe(cfg.HTTP.Addr, r) //nolint:gosec // example binary, not the deployed service
}
