// Command server runs go-identity: serve (default) | worker | migrate.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/biairmal/go-sdk/lib/logger"

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
	if cmd == "migrate" && len(args) > 0 && args[0] == "create" {
		return migrateCreate(args[1:]) // needs no config or database
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
		return app.RunWorker(ctx, &cfg, log)
	case "migrate":
		return migrate(ctx, &cfg, log, args)
	default:
		return fmt.Errorf("unknown command %q (want serve, worker or migrate)", cmd)
	}
}

// logResult is the shape shared by every migrate output line.
func logResult(log logger.Logger, msg string, version int64, path string) {
	log.Info(msg, logger.F("version", version), logger.F("file", path))
}
