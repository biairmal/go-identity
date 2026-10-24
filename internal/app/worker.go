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
	"github.com/biairmal/go-identity/internal/platform/mail"
)

// senders maps outbox topics to their Sender. Modules that enqueue a topic
// add its sender here.
//
// Until a real mailer lands, mail is delivered by the development logging
// mailer, which refuses to be built in production: a worker there would print
// one-time tokens to its logs instead of emailing them, so it must fail
// loudly rather than start.
func senders(cfg *Config, log logger.Logger, db *sqlkit.DB) (map[string]database.Sender, error) {
	mailer, err := mail.NewLogging(log, cfg.Service.Environment, cfg.Modules.Auth.EmailBaseURL())
	if err != nil {
		return nil, err
	}
	return map[string]database.Sender{
		mail.Topic: mail.NewSender(mailer, db),
	}, nil
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
	topics, err := senders(cfg, log, db)
	if err != nil {
		return err
	}

	log.Info("worker started")

	// The dispatcher and the cleanup job are independent, so they run
	// side by side; the first to fail stops the worker.
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return database.NewDispatcher(db, topics, log).Run(ctx)
	})
	group.Go(func() error {
		return cleanup.New(db, clock.System{}, log).Run(ctx, cleanup.DefaultInterval)
	})
	err = group.Wait()

	log.Info("worker stopped")
	return err
}
