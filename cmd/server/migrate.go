package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/app"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/migrations"
)

// migrationsDir is where `migrate create` writes new files.
const migrationsDir = "migrations"

// migrate runs `server migrate up|down|status` against the leader.
func migrate(ctx context.Context, cfg *app.Config, log logger.Logger, args []string) (err error) {
	if len(args) == 0 {
		return errors.New("usage: server migrate up|down|status|create <name>")
	}
	db, err := sqlkit.New(ctx, &cfg.Database)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	m, err := database.NewMigrator(db.Leader(), migrations.FS)
	if err != nil {
		return err
	}

	switch args[0] {
	case "up":
		results, err := m.Up(ctx)
		for _, r := range results {
			logResult(log, "migrated up", r.Source.Version, r.Source.Path)
		}
		if err == nil && len(results) == 0 {
			log.Info("no pending migrations")
		}
		return err
	case "down":
		r, err := m.Down(ctx)
		if r != nil {
			logResult(log, "migrated down", r.Source.Version, r.Source.Path)
		}
		return err
	case "status":
		statuses, err := m.Status(ctx)
		for _, s := range statuses {
			log.Info(string(s.State), logger.F("version", s.Source.Version), logger.F("file", s.Source.Path))
		}
		return err
	default:
		return fmt.Errorf("unknown migrate command %q (want up, down, status or create)", args[0])
	}
}

// migrateCreate runs `server migrate create <name>`.
func migrateCreate(args []string) error {
	if len(args) != 1 || args[0] == "" {
		return errors.New("usage: server migrate create <name>")
	}
	return database.Create(migrationsDir, args[0])
}
