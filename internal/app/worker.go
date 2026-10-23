package app

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"golang.org/x/sync/errgroup"

	"github.com/biairmal/go-identity/internal/platform/cleanup"
	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/database"
)

// senders maps outbox topics to their Sender. Modules that enqueue a topic
// add its sender here.
func senders(_ *Config, _ logger.Logger) map[string]database.Sender {
	return map[string]database.Sender{}
}

// RunWorker runs the background jobs (the outbox dispatcher and the cleanup
// job) until SIGINT, SIGTERM or ctx is done.
func RunWorker(ctx context.Context, cfg *Config, log logger.Logger) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := sqlkit.New(ctx, &cfg.Database)
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Error("database close", logger.F("error", err.Error()))
		}
	}()
	if err := checkSchema(ctx, db); err != nil {
		return err
	}

	log.Info("worker started")

	// The dispatcher and the cleanup job are independent, so they run
	// side by side; the first to fail stops the worker.
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return database.NewDispatcher(db, senders(cfg, log), log).Run(ctx)
	})
	group.Go(func() error {
		return cleanup.New(db, clock.System{}, log).Run(ctx, cleanup.DefaultInterval)
	})
	err = group.Wait()

	log.Info("worker stopped")
	return err
}
