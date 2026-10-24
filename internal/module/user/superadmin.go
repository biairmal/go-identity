package user

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/database"
)

// superAdminLock is the advisory lock key every super admin change takes, so
// two pods booting together, or a CLI command racing a boot, run one at a
// time. The value is arbitrary but fixed: every process must agree on it.
const superAdminLock int64 = 0x5375706572416431 // "SuperAd1"

// Errors the super admin operations return. They are plain sentinels: the
// callers are the startup path and the CLI, which print them, not the API.
var (
	// ErrSuperAdminNotConfigured reports a first start without the
	// credentials to create the super admin.
	ErrSuperAdminNotConfigured = errors.New(
		"user: no super admin exists; set modules.user.super_admin.email and password " +
			"(SUPER_ADMIN_EMAIL and SUPER_ADMIN_PASSWORD) for the first start")
	// ErrSuperAdminEmailTaken reports a first start whose configured email
	// already belongs to an ordinary account. Promoting it would hand the
	// super admin to whoever registered that address first.
	ErrSuperAdminEmailTaken = errors.New(
		"user: modules.user.super_admin.email belongs to an existing account; " +
			"use `server superadmin transfer --to <email>` to promote it")
	// ErrNotSuperAdmin reports a reset aimed at an account that is not the
	// super admin.
	ErrNotSuperAdmin = errors.New("user: that account is not the super admin")
	// ErrNoSuperAdmin reports a transfer before any super admin exists.
	ErrNoSuperAdmin = errors.New("user: no super admin exists yet; start the server once to create it")
	// ErrAlreadySuperAdmin reports a transfer to the current holder.
	ErrAlreadySuperAdmin = errors.New("user: that account is already the super admin")
	// ErrTransferInactive reports a transfer to an account that cannot sign
	// in.
	ErrTransferInactive = errors.New("user: the new super admin must be an active account")
)

// SuperAdminDeps are the ports the super admin operations need.
type SuperAdminDeps struct {
	Passwords   Passwords
	Memberships Memberships
	Sessions    Sessions
	Audit       AuditWriter
	Clock       clock.Clock
	Log         logger.Logger
}

// SuperAdmins creates, resets and transfers the one super admin. Every
// operation runs in one transaction under an advisory lock, so it is atomic
// and safe to run from several processes at once.
type SuperAdmins struct {
	cfg   SuperAdminConfig
	db    *sqlkit.DB
	repo  *Repository
	creds *CredentialsRepository
	deps  SuperAdminDeps
}

// NewSuperAdmins returns the super admin operations. Clock and Log may be
// nil; the other ports are required.
func NewSuperAdmins(
	cfg SuperAdminConfig, db *sqlkit.DB, repo *Repository, creds *CredentialsRepository, deps *SuperAdminDeps,
) *SuperAdmins {
	d := *deps
	if d.Clock == nil {
		d.Clock = clock.System{}
	}
	if d.Log == nil {
		d.Log = logger.NewNoOp()
	}
	return &SuperAdmins{cfg: cfg, db: db, repo: repo, creds: creds, deps: d}
}

// Bootstrap creates the super admin from the configured credentials when none
// exists, and does nothing otherwise. It runs on every start: it joins the
// caller's transaction when there is one, and the advisory lock makes a
// second pod wait for the first and then find its work done.
//
// The account is created active, verified and with a forced password change,
// as an active member of the default tenant with no roles: its permissions
// come from the flag, not from role rows.
func (s *SuperAdmins) Bootstrap(ctx context.Context) error {
	return database.InTx(ctx, s.db, func(ctx context.Context) error {
		if err := database.LockXact(ctx, superAdminLock); err != nil {
			return err
		}
		exists, err := s.repo.SuperAdminExists(ctx)
		if err != nil || exists {
			return err
		}
		return s.create(ctx)
	})
}

// create inserts the configured super admin. The caller holds the lock.
func (s *SuperAdmins) create(ctx context.Context) error {
	if !s.cfg.Configured() {
		return ErrSuperAdminNotConfigured
	}
	if err := s.deps.Passwords.Validate(s.cfg.Password); err != nil {
		return fmt.Errorf("user: modules.user.super_admin.password breaks the password policy: %w", err)
	}
	if _, err := s.repo.FindByEmail(ctx, s.cfg.Email); err == nil {
		return ErrSuperAdminEmailTaken
	} else if !errors.Is(err, errorz.ErrNotFound) {
		return err
	}
	hash, err := s.deps.Passwords.Hash(s.cfg.Password)
	if err != nil {
		return fmt.Errorf("user: hash super admin password: %w", err)
	}
	now := s.deps.Clock.Now()
	u, err := s.repo.Create(ctx, &CreateParams{
		Email: s.cfg.Email, Status: StatusActive, EmailVerifiedAt: &now,
		IsSuperAdmin: true, MustChangePassword: true,
	})
	if err != nil {
		return err
	}
	if err := s.creds.Set(ctx, u.ID, hash); err != nil {
		return err
	}
	if err := s.joinDefaultTenant(ctx, u.ID); err != nil {
		return err
	}
	s.deps.Log.InfoWithContext(ctx, "super admin created", logger.F("user_id", u.ID.String()))
	return s.deps.Audit.Write(ctx, &AuditEvent{
		Action: ActionSuperAdminCreate, TargetType: TargetUser, TargetID: u.ID.String(),
		After: map[string]any{
			"status": u.Status, "is_super_admin": true, "must_change_password": true,
		},
	})
}

// Reset gives the super admin a new random temporary password, forces a
// change at the next sign-in, clears any lockout and revokes every session,
// all in one transaction. It returns the temporary password, which the
// caller shows once and never logs.
func (s *SuperAdmins) Reset(ctx context.Context, email string) (string, error) {
	temp := rand.Text()
	hash, err := s.deps.Passwords.Hash(temp)
	if err != nil {
		return "", fmt.Errorf("user: hash temporary password: %w", err)
	}
	err = database.WithTx(ctx, s.db, func(ctx context.Context) error {
		if err := database.LockXact(ctx, superAdminLock); err != nil {
			return err
		}
		u, err := s.repo.FindByEmail(ctx, email)
		if errors.Is(err, errorz.ErrNotFound) {
			return ErrNotSuperAdmin
		}
		if err != nil {
			return err
		}
		if !u.IsSuperAdmin {
			return ErrNotSuperAdmin
		}
		return s.reset(ctx, u, hash)
	})
	if err != nil {
		return "", err
	}
	return temp, nil
}

// reset writes the new credentials and revokes the sessions of u.
func (s *SuperAdmins) reset(ctx context.Context, u *User, hash string) error {
	if err := s.creds.Set(ctx, u.ID, hash); err != nil {
		return err
	}
	if err := s.repo.SetMustChangePassword(ctx, u.ID, true); err != nil {
		return err
	}
	if err := s.repo.ResetFailedLogins(ctx, u.ID); err != nil {
		return err
	}
	if err := s.deps.Sessions.RevokeAllForUser(ctx, u.ID); err != nil {
		return err
	}
	return s.deps.Audit.Write(ctx, &AuditEvent{
		Action: ActionSuperAdminReset, TargetType: TargetUser, TargetID: u.ID.String(),
		Before: map[string]any{"must_change_password": u.MustChangePassword, "locked": u.LockedUntil != nil},
		After:  map[string]any{"must_change_password": true, "locked": false, "sessions_revoked": true},
	})
}

// Transfer moves the super admin flag to the active account with this email,
// in one transaction: the old holder loses the flag and its sessions, the new
// one gains it and an active membership in the default tenant. It returns the
// new super admin's ID.
func (s *SuperAdmins) Transfer(ctx context.Context, toEmail string) (uuid.UUID, error) {
	var to *User
	err := database.WithTx(ctx, s.db, func(ctx context.Context) error {
		if err := database.LockXact(ctx, superAdminLock); err != nil {
			return err
		}
		from, err := s.repo.SuperAdmin(ctx)
		if errors.Is(err, errorz.ErrNotFound) {
			return ErrNoSuperAdmin
		}
		if err != nil {
			return err
		}
		if to, err = s.repo.FindByEmail(ctx, toEmail); err != nil {
			return err
		}
		switch {
		case to.ID == from.ID:
			return ErrAlreadySuperAdmin
		case !to.Active():
			return ErrTransferInactive
		}
		return s.transfer(ctx, from, to)
	})
	if err != nil {
		return uuid.Nil, err
	}
	return to.ID, nil
}

// transfer moves the flag from one account to the other. The old holder's
// flag is cleared first, because the partial unique index allows only one.
func (s *SuperAdmins) transfer(ctx context.Context, from, to *User) error {
	if err := s.repo.SetSuperAdmin(ctx, from.ID, false); err != nil {
		return err
	}
	if err := s.repo.SetSuperAdmin(ctx, to.ID, true); err != nil {
		return err
	}
	if err := s.joinDefaultTenant(ctx, to.ID); err != nil {
		return err
	}
	// The old holder's tokens carry the super admin claim until they
	// expire; revoking its sessions stops it from refreshing into more.
	if err := s.deps.Sessions.RevokeAllForUser(ctx, from.ID); err != nil {
		return err
	}
	return s.deps.Audit.Write(ctx, &AuditEvent{
		Action: ActionSuperAdminTransfer, TargetType: TargetUser, TargetID: to.ID.String(),
		Before: map[string]any{"super_admin_id": from.ID.String()},
		After:  map[string]any{"super_admin_id": to.ID.String()},
	})
}

// joinDefaultTenant makes the user an active member of the default tenant.
func (s *SuperAdmins) joinDefaultTenant(ctx context.Context, userID uuid.UUID) error {
	tenantID, err := s.deps.Memberships.DefaultTenantID(ctx)
	if err != nil {
		return err
	}
	return s.deps.Memberships.AddActiveMember(ctx, tenantID, userID)
}
