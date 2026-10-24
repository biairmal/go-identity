package app

import (
	"context"
	"errors"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/audit"
	"github.com/biairmal/go-identity/internal/module/session"
	"github.com/biairmal/go-identity/internal/module/tenant"
	"github.com/biairmal/go-identity/internal/module/user"
	"github.com/biairmal/go-identity/internal/platform/clock"
)

// newUserModule builds the user module with its ports wired over the audit,
// tenant and session modules. The email cipher is built here, not inside
// user: the module declares the port and app owns the go-sdk crypto adapter
// behind it.
func newUserModule(
	cfg *Config, deps *Deps, auditModule *audit.Module, tenants *tenant.Service, sessions *session.Service,
) (*user.Module, error) {
	cipher, err := newEmailCipher(cfg, deps.Log)
	if err != nil {
		return nil, err
	}
	return user.New(cfg.Modules.User, &user.Deps{
		DB:          deps.DB,
		Log:         deps.Log,
		Clock:       clock.System{},
		EmailCipher: cipher,
		Passwords:   userPasswords{},
		Memberships: tenantMemberships{svc: tenants},
		Sessions:    sessions,
		Audit:       userAudit{w: auditModule.Writer()},
	}), nil
}

// SuperAdminReset gives the super admin with this email a new temporary
// password, forces a change at the next sign-in and revokes its sessions. It
// returns the temporary password for the caller to show once; it is never
// logged. It is the `server superadmin reset` command.
func SuperAdminReset(ctx context.Context, cfg *Config, log logger.Logger, email string) (string, error) {
	var temp string
	err := withSuperAdmins(ctx, cfg, log, func(ctx context.Context, s *user.SuperAdmins) error {
		var err error
		temp, err = s.Reset(ctx, email)
		return err
	})
	return temp, err
}

// SuperAdminTransfer moves the super admin flag to the active account with
// this email and returns its ID. It is the `server superadmin transfer`
// command.
func SuperAdminTransfer(ctx context.Context, cfg *Config, log logger.Logger, email string) (uuid.UUID, error) {
	var id uuid.UUID
	err := withSuperAdmins(ctx, cfg, log, func(ctx context.Context, s *user.SuperAdmins) error {
		var err error
		id, err = s.Transfer(ctx, email)
		return err
	})
	return id, err
}

// withSuperAdmins opens the database, checks the schema and runs fn with the
// super admin operations. It builds only the modules those need, so the CLI
// does not require the signing keys a server does.
func withSuperAdmins(
	ctx context.Context, cfg *Config, log logger.Logger, fn func(context.Context, *user.SuperAdmins) error,
) (err error) {
	db, err := sqlkit.New(ctx, &cfg.Database)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	if err := checkSchema(ctx, db); err != nil {
		return err
	}
	s, err := superAdminsOver(cfg, db, log)
	if err != nil {
		return err
	}
	return fn(ctx, s)
}

// superAdminsOver builds the super admin operations over an open database.
func superAdminsOver(cfg *Config, db *sqlkit.DB, log logger.Logger) (*user.SuperAdmins, error) {
	deps := &Deps{DB: db, Log: log}
	auditModule := audit.New(audit.Deps{DB: db, Log: log})
	tenants := tenant.New(cfg.Modules.Tenant, tenant.Deps{
		DB: db, Log: log, Audit: tenantAudit{w: auditModule.Writer()},
	}).Service()
	sessions := session.New(cfg.Modules.Session, session.Deps{DB: db, Log: log, Clock: clock.System{}}).Service()
	m, err := newUserModule(cfg, deps, auditModule, tenants, sessions)
	if err != nil {
		return nil, err
	}
	return m.SuperAdmins(), nil
}
