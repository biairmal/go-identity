package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/app"
)

// superAdminUsage is printed for a missing or unknown superadmin command.
const superAdminUsage = "usage: server superadmin reset --email <email> | transfer --to <email>"

// superAdminOps are the operations the superadmin command runs. They are
// injected so the argument handling and the output can be tested without a
// database.
type superAdminOps struct {
	reset    func(ctx context.Context, email string) (string, error)
	transfer func(ctx context.Context, email string) (uuid.UUID, error)
}

// liveSuperAdminOps runs the operations against the configured database.
func liveSuperAdminOps(cfg *app.Config, log logger.Logger) superAdminOps {
	return superAdminOps{
		reset: func(ctx context.Context, email string) (string, error) {
			return app.SuperAdminReset(ctx, cfg, log, email)
		},
		transfer: func(ctx context.Context, email string) (uuid.UUID, error) {
			return app.SuperAdminTransfer(ctx, cfg, log, email)
		},
	}
}

// superAdmin runs `server superadmin reset|transfer`. The temporary password
// of a reset goes to out (stdout) exactly once and never to the logger.
func superAdmin(ctx context.Context, ops superAdminOps, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(superAdminUsage)
	}
	switch args[0] {
	case "reset":
		email, err := emailFlag("reset", "email", args[1:])
		if err != nil {
			return err
		}
		temp, err := ops.reset(ctx, email)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out,
			"Super admin password reset. Temporary password (shown once, change it at the next sign-in):\n%s\n",
			temp)
		return err
	case "transfer":
		email, err := emailFlag("transfer", "to", args[1:])
		if err != nil {
			return err
		}
		id, err := ops.transfer(ctx, email)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Super admin transferred to user %s.\n", id)
		return err
	default:
		return fmt.Errorf("unknown superadmin command %q; %s", args[0], superAdminUsage)
	}
}

// emailFlag parses the one required email flag of a superadmin command.
func emailFlag(cmd, name string, args []string) (string, error) {
	fs := flag.NewFlagSet("superadmin "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	email := fs.String(name, "", "email address")
	if err := fs.Parse(args); err != nil {
		return "", fmt.Errorf("%w; %s", err, superAdminUsage)
	}
	if fs.NArg() > 0 {
		return "", fmt.Errorf("unexpected argument %q; %s", fs.Arg(0), superAdminUsage)
	}
	if strings.TrimSpace(*email) == "" {
		return "", fmt.Errorf("--%s is required; %s", name, superAdminUsage)
	}
	return *email, nil
}
