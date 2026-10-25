// Command server runs go-identity: serve (default) | worker | migrate | superadmin.
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

// General API info for swag (make swagger-generate).
//
//	@title			go-identity API
//	@version		1.0
//	@description	Sign-in service and the only issuer of tokens: password sign-in, sessions and profiles.
//	@BasePath		/
//
//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				"Bearer" followed by a space and the access token from POST /v1/auth/login.

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
	case "superadmin":
		return superAdmin(ctx, liveSuperAdminOps(&cfg, log), args, os.Stdout)
	default:
		return fmt.Errorf("unknown command %q (want serve, worker, migrate or superadmin)", cmd)
	}
}

// logResult is the shape shared by every migrate output line.
func logResult(log logger.Logger, msg string, version int64, path string) {
	log.Info(msg, logger.F("version", version), logger.F("file", path))
}
