// Command server runs go-identity: serve (default) | worker | migrate.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/biairmal/go-identity/internal/app"
)

// Config locations, relative to the working directory.
const (
	envFile    = ".env"
	configFile = "config/config.yaml"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	cfg, err := app.LoadConfig(envFile, configFile)
	if err != nil {
		return err
	}
	log := app.NewLogger(&cfg)
	ctx := context.Background()

	switch cmd {
	case "serve":
		a, err := app.New(ctx, &cfg, log)
		if err != nil {
			return err
		}
		return a.Serve(ctx)
	case "worker":
		return runWorker(ctx)
	case "migrate":
		return fmt.Errorf("migrate %v: not implemented", args)
	default:
		return fmt.Errorf("unknown command %q (want serve, worker or migrate)", cmd)
	}
}

// runWorker blocks until SIGINT or SIGTERM. Background jobs attach here.
func runWorker(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return nil
}
