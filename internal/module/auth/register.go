package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/auth/onetime"
	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/module/auth/templates"
	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/mail"
)

// verifyEmailTTL is how long a verification link stays valid (APP_FLOW 3).
const verifyEmailTTL = 24 * time.Hour

// tenancyMulti is the tenancy mode in which a sign-up names its tenant.
const tenancyMulti = "multi"

// errEmailTaken marks a registration that lost the race for an address to a
// concurrent one; the caller answers it like any existing address.
var errEmailTaken = errors.New("auth: email already registered")

// Registrations runs sign-up, email verification and resending the
// verification link. Every write of one request shares one transaction, so a
// failure part-way leaves no account, token, audit row or queued mail behind.
type Registrations struct {
	cfg     *Config
	tenancy string
	db      *sqlkit.DB
	v       validator.Validator
	users   Users
	tenants Tenants
	roles   Roles
	audit   AuditWriter
	outbox  mail.Enqueuer
	tokens  *onetime.Service
	tokRepo *onetime.Repository
	clock   clock.Clock
	log     logger.Logger
}

// Register signs a user up. It answers the same way whether or not the
// address already has an account: a new address gets a pending account and a
// verification mail, an existing one gets an "you already have an account"
// mail and nothing else changes. Both paths hash the password, so the
// response time does not tell them apart either.
//
// The switches are checked before the body, so a closed registration says so
// whatever was sent.
func (s *Registrations) Register(ctx context.Context, in *RegisterRequest) error {
	if !s.cfg.Registration.Enabled {
		return apierr.New(apierr.ReasonRegistrationClosed)
	}
	if !s.cfg.Providers.Password.Enabled {
		return apierr.New(apierr.ReasonProviderDisabled)
	}
	in.Email = strings.TrimSpace(in.Email)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if err := s.v.ValidateStruct(in); err != nil {
		return err
	}
	if err := checkPassword(in.Password, s.cfg.Providers.Password.MinLength); err != nil {
		return err
	}
	tenantID, err := s.signUpTenant(ctx, in.Tenant)
	if err != nil {
		return err
	}
	hash, err := password.Hash(in.Password)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: hash password")
	}
	err = database.WithTx(ctx, s.db, func(ctx context.Context) error {
		existing, err := s.users.FindByEmail(ctx, in.Email)
		switch {
		case err == nil:
			return s.queueExistingAccount(ctx, existing.Email)
		case !errors.Is(err, errorz.ErrNotFound):
			return err
		}
		return s.createAccount(ctx, in, tenantID, hash)
	})
	if errors.Is(err, errEmailTaken) {
		// The insert aborted the transaction, so the mail goes in a new one.
		return database.WithTx(ctx, s.db, func(ctx context.Context) error {
			return s.queueExistingAccount(ctx, in.Email)
		})
	}
	return err
}

// checkPassword maps a policy failure onto PASSWORD_POLICY with a message for
// the password field. minLength is the configured minimum, which may be
// stricter than the policy's own floor.
func checkPassword(plain string, minLength int) error {
	err := password.Validate(plain)
	if err == nil && utf8.RuneCountInString(plain) < minLength {
		err = password.ErrTooShort
	}
	if err == nil {
		return nil
	}
	var msg string
	switch {
	case errors.Is(err, password.ErrTooShort):
		msg = fmt.Sprintf("must be at least %d characters", max(minLength, password.MinRunes))
	case errors.Is(err, password.ErrTooLong):
		msg = fmt.Sprintf("must be at most %d characters", password.MaxRunes)
	case errors.Is(err, password.ErrTooCommon):
		msg = "is too common"
	default:
		msg = "is not valid UTF-8"
	}
	return apierr.WithFields(apierr.ReasonPasswordPolicy, map[string]string{"password": msg})
}

// signUpTenant is the tenant a sign-up joins: the default tenant in single
// mode, the named one in multi mode.
func (s *Registrations) signUpTenant(ctx context.Context, slug string) (uuid.UUID, error) {
	if s.tenancy != tenancyMulti {
		return s.tenants.DefaultTenantID(ctx)
	}
	if strings.TrimSpace(slug) == "" {
		return uuid.Nil, errorz.BadRequest().WithMessage("tenant: required").
			WithMeta(apierr.MetaFields, map[string]string{"tenant": "required in multi-tenant mode"})
	}
	id, active, err := s.tenants.BySlug(ctx, slug)
	if err != nil {
		return uuid.Nil, err
	}
	if !active {
		return uuid.Nil, apierr.New(apierr.ReasonTenantSuspended)
	}
	return id, nil
}

// createAccount writes the new account and everything that comes with it.
// It runs inside the registration transaction.
func (s *Registrations) createAccount(ctx context.Context, in *RegisterRequest, tenantID uuid.UUID, hash string) error {
	verify := s.cfg.Providers.Password.RequireEmailVerification
	status := StatusActive
	if verify {
		status = StatusPending
	}
	userID, err := s.users.Create(ctx, &NewAccount{
		Email: in.Email, DisplayName: in.DisplayName, Status: status, PasswordHash: hash,
	})
	if errors.Is(err, errorz.ErrConflict) {
		return errEmailTaken
	}
	if err != nil {
		return err
	}
	if err := s.tenants.AddActiveMember(ctx, tenantID, userID); err != nil {
		return err
	}
	if err := s.roles.Assign(ctx, tenantID, userID, s.cfg.Registration.DefaultRoles); err != nil {
		return err
	}
	if verify {
		if err := s.queueVerification(ctx, userID, in.Email, in.DisplayName); err != nil {
			return err
		}
	}
	s.log.InfoWithContext(ctx, "user registered", logger.F("user_id", userID.String()))
	return s.audit.Write(ctx, &AuditEvent{
		TenantID: tenantID, ActorID: userID, Action: ActionRegister,
		TargetType: TargetUser, TargetID: userID.String(),
		After: map[string]any{"status": status, "roles": s.cfg.Registration.DefaultRoles},
	})
}

// queueVerification issues a verification token and queues the mail that
// carries it, in the caller's transaction.
func (s *Registrations) queueVerification(ctx context.Context, userID uuid.UUID, email, name string) error {
	issued, err := s.tokens.Create(ctx, userID, onetime.PurposeVerifyEmail, verifyEmailTTL, onetime.Options{})
	if err != nil {
		return err
	}
	return mail.Queue(ctx, s.outbox, templates.VerifyEmailMessage(email, issued.Raw,
		map[string]string{"DisplayName": name}))
}

// queueExistingAccount queues the mail an address with an account receives
// instead of a second registration.
func (s *Registrations) queueExistingAccount(ctx context.Context, email string) error {
	return mail.Queue(ctx, s.outbox, templates.ExistingAccountMessage(email, nil))
}

// VerifyEmail spends a verification token, stamps the email as confirmed and
// activates a pending account, in one transaction. Every kind of bad token,
// expired included, is TOKEN_INVALID (TRD 9.2).
func (s *Registrations) VerifyEmail(ctx context.Context, raw string) error {
	return database.WithTx(ctx, s.db, func(ctx context.Context) error {
		t, err := s.tokens.Consume(ctx, raw, onetime.PurposeVerifyEmail)
		if errors.Is(err, onetime.ErrInvalid) || errors.Is(err, onetime.ErrExpired) {
			return apierr.New(apierr.ReasonTokenInvalid)
		}
		if err != nil {
			return err
		}
		before, err := s.users.Get(ctx, t.UserID)
		if err != nil {
			return err
		}
		if err := s.users.VerifyEmail(ctx, t.UserID, s.clock.Now()); err != nil {
			return err
		}
		after := before.Status
		if after == StatusPending {
			after = StatusActive
		}
		return s.audit.Write(ctx, &AuditEvent{
			ActorID: t.UserID, Action: ActionEmailVerified,
			TargetType: TargetUser, TargetID: t.UserID.String(),
			Before: map[string]any{"status": before.Status, "email_verified": before.EmailVerified},
			After:  map[string]any{"status": after, "email_verified": true},
		})
	})
}

// ResendVerification issues a fresh verification link when the address
// belongs to an unverified, not disabled account, and does nothing
// otherwise. Earlier unused links stop working. The caller answers 202 either
// way, so the response does not reveal whether the address exists.
func (s *Registrations) ResendVerification(ctx context.Context, email string) error {
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
		if a.EmailVerified || a.Status == StatusDisabled {
			return nil
		}
		if err := s.tokRepo.DeleteUnusedForUser(ctx, a.ID, onetime.PurposeVerifyEmail); err != nil {
			return err
		}
		return s.queueVerification(ctx, a.ID, a.Email, a.DisplayName)
	})
}
