package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/validator"

	"github.com/biairmal/go-identity/internal/module/auth/onetime"
	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/module/auth/templates"
	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/mail"
)

// resetPasswordTTL is how long a reset link stays valid (APP_FLOW 8).
const resetPasswordTTL = 30 * time.Minute

// Rate-limit key prefixes of the reset endpoints, on the login budget
// (TRD 10 "Brute force").
const (
	limitForgotIP    = "forgot:ip:"
	limitForgotEmail = "forgot:email:"
	limitResetIP     = "reset:ip:"
)

// PasswordResets runs forgot-password and reset-password (APP_FLOW 8).
type PasswordResets struct {
	cfg      *Config
	db       *sqlkit.DB
	v        validator.Validator
	users    Users
	sessions Sessions
	audit    AuditWriter
	outbox   mail.Enqueuer
	tokens   *onetime.Service
	tokRepo  *onetime.Repository
	log      logger.Logger
}

// Forgot queues a reset link when the address belongs to an account that is
// not disabled, and does nothing otherwise. Earlier unused links stop
// working. The caller answers 202 either way, so the response does not reveal
// whether the address exists.
func (s *PasswordResets) Forgot(ctx context.Context, email string) error {
	if !s.cfg.Providers.Password.Enabled {
		return apierr.New(apierr.ReasonProviderDisabled)
	}
	email = strings.TrimSpace(email)
	if s.v.ValidateVar(email, "required,email,max=254") != nil {
		return nil
	}
	return database.WithTx(ctx, s.db, func(ctx context.Context) error {
		a, err := s.users.FindByEmail(ctx, email)
		if errors.Is(err, errorz.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if a.Status == StatusDisabled {
			return nil
		}
		if err := s.tokRepo.DeleteUnusedForUser(ctx, a.ID, onetime.PurposeResetPassword); err != nil {
			return err
		}
		issued, err := s.tokens.Create(ctx, a.ID, onetime.PurposeResetPassword, resetPasswordTTL, onetime.Options{})
		if err != nil {
			return err
		}
		return mail.Queue(ctx, s.outbox, templates.ResetPasswordMessage(a.Email, issued.Raw,
			map[string]string{"DisplayName": a.DisplayName}))
	})
}

// Reset spends a reset token and sets the new password. In one transaction
// it stores the hash, clears a forced change and any lockout, drops the
// user's other reset links, revokes every refresh family and audits
// auth.password_reset. The password is checked and hashed first, so a
// rejected password leaves the token usable and no transaction waits on
// argon2.
func (s *PasswordResets) Reset(ctx context.Context, in *ResetPasswordRequest) error {
	if !s.cfg.Providers.Password.Enabled {
		return apierr.New(apierr.ReasonProviderDisabled)
	}
	if err := s.v.ValidateStruct(in); err != nil {
		return err
	}
	if err := checkPassword(in.Password, s.cfg.Providers.Password.MinLength); err != nil {
		return err
	}
	hash, err := password.Hash(in.Password)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: hash password")
	}
	return database.WithTx(ctx, s.db, func(ctx context.Context) error {
		t, err := s.tokens.Consume(ctx, in.Token, onetime.PurposeResetPassword)
		if errors.Is(err, onetime.ErrInvalid) || errors.Is(err, onetime.ErrExpired) {
			return apierr.New(apierr.ReasonTokenInvalid)
		}
		if err != nil {
			return err
		}
		if err := s.users.SetPassword(ctx, t.UserID, hash); err != nil {
			return err
		}
		if err := s.users.ClearFailedLogins(ctx, t.UserID); err != nil {
			return err
		}
		if err := s.tokRepo.DeleteUnusedForUser(ctx, t.UserID, onetime.PurposeResetPassword); err != nil {
			return err
		}
		if err := s.sessions.RevokeAllForUser(ctx, t.UserID); err != nil {
			return err
		}
		s.log.InfoWithContext(ctx, "password reset", logger.F("user_id", t.UserID.String()))
		return s.audit.Write(ctx, &AuditEvent{
			ActorID: t.UserID, Action: ActionPasswordReset,
			TargetType: TargetUser, TargetID: t.UserID.String(),
		})
	})
}
