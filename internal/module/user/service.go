package user

import (
	"context"
	"time"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/database"
)

// Service holds the user rules. It knows nothing about HTTP, and it only ever
// sees plain emails: the repository encrypts and decrypts around the database.
type Service struct {
	cfg   Config
	repo  *Repository
	creds *CredentialsRepository
	log   logger.Logger
}

// NewService returns a Service. log may be nil.
func NewService(cfg Config, repo *Repository, creds *CredentialsRepository, log logger.Logger) *Service {
	if log == nil {
		log = logger.NewNoOp()
	}
	return &Service{cfg: cfg, repo: repo, creds: creds, log: log}
}

// Create stores a user and, when passwordHash is not empty, its credentials
// in one transaction, so an account never exists without the password it was
// created with.
func (s *Service) Create(ctx context.Context, p *CreateParams, passwordHash string) (*User, error) {
	var u *User
	err := database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		var err error
		if u, err = s.repo.Create(ctx, p); err != nil {
			return err
		}
		if passwordHash == "" {
			return nil
		}
		return s.creds.Set(ctx, u.ID, passwordHash)
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// Get returns one user.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*User, error) {
	return s.repo.Get(ctx, id)
}

// FindByEmail returns the user with this address, whatever its spelling.
func (s *Service) FindByEmail(ctx context.Context, email string) (*User, error) {
	return s.repo.FindByEmail(ctx, email)
}

// SetStatus moves a user between pending, active and disabled.
func (s *Service) SetStatus(ctx context.Context, id uuid.UUID, version int, status string) error {
	return s.repo.UpdateStatus(ctx, id, version, status)
}

// SetDisplayName renames a user.
func (s *Service) SetDisplayName(ctx context.Context, id uuid.UUID, version int, name string) error {
	return s.repo.UpdateDisplayName(ctx, id, version, name)
}

// RecordFailedLogin counts one failed attempt and returns the new total.
func (s *Service) RecordFailedLogin(ctx context.Context, id uuid.UUID) (int, error) {
	return s.repo.IncrementFailedLogins(ctx, id)
}

// Lock blocks sign-in until the given time; a nil time clears the lock.
func (s *Service) Lock(ctx context.Context, id uuid.UUID, until *time.Time) error {
	return s.repo.Lock(ctx, id, until)
}

// RecordSignIn clears the failure counter and the lock and stamps the
// sign-in time, which is what a successful authentication leaves behind.
func (s *Service) RecordSignIn(ctx context.Context, id uuid.UUID, at time.Time) error {
	return database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		if err := s.repo.ResetFailedLogins(ctx, id); err != nil {
			return err
		}
		return s.repo.MarkSignedIn(ctx, id, at)
	})
}

// VerifyEmail stamps the email as confirmed and activates a pending account.
func (s *Service) VerifyEmail(ctx context.Context, u *User, at time.Time) error {
	return database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		if err := s.repo.MarkEmailVerified(ctx, u.ID, at); err != nil {
			return err
		}
		if u.Status != StatusPending {
			return nil
		}
		return s.repo.UpdateStatus(ctx, u.ID, u.Version, StatusActive)
	})
}

// SetPassword replaces a user's password hash and clears the forced change,
// because choosing a password is how that requirement is satisfied.
func (s *Service) SetPassword(ctx context.Context, id uuid.UUID, hash string) error {
	return database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		if err := s.creds.Set(ctx, id, hash); err != nil {
			return err
		}
		return s.repo.SetMustChangePassword(ctx, id, false)
	})
}

// RequirePasswordChange forces the next sign-in to choose a new password,
// used by the super admin reset and by an admin-set temporary password.
func (s *Service) RequirePasswordChange(ctx context.Context, id uuid.UUID) error {
	return s.repo.SetMustChangePassword(ctx, id, true)
}

// Credentials returns a user's password hash, or errorz.NotFound when the
// account has none.
func (s *Service) Credentials(ctx context.Context, id uuid.UUID) (*Credentials, error) {
	return s.creds.Get(ctx, id)
}

// SuperAdminExists reports whether the single super admin has been created.
func (s *Service) SuperAdminExists(ctx context.Context) (bool, error) {
	return s.repo.SuperAdminExists(ctx)
}
