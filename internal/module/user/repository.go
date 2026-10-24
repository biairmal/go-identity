package user

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/biairmal/go-identity/internal/platform/database"
)

// Repository reads and writes users. It is the only place the encrypted email
// exists: a write encrypts just before the statement and a read decrypts just
// after the scan, so every caller above it works with the plain address.
//
// Every update names its own columns, so a field the caller never loaded is
// never overwritten. Users are global rows (membership lives in
// tenant_members), so there is no tenant_id in these predicates.
type Repository struct {
	db     *sqlkit.DB
	cipher EmailCipher
}

// NewRepository returns a Repository over db that encrypts emails with cipher.
func NewRepository(db *sqlkit.DB, cipher EmailCipher) *Repository {
	return &Repository{db: db, cipher: cipher}
}

// userColumns is the select list for a User. email_hash is never selected:
// nothing above the repository can use a blind index.
const userColumns = `id, email_enc, display_name, status, email_verified_at, is_super_admin,
	must_change_password, failed_logins, locked_until, last_sign_in_at, version, created_at, updated_at`

// uniqueViolation is the Postgres error class of a broken unique constraint.
const uniqueViolation = "23505"

// CreateParams is the user to create. Only these columns are written;
// everything else takes its database default, so a new account starts pending
// with no lock, no failed logins and an unverified email unless stated
// otherwise.
type CreateParams struct {
	Email              string
	DisplayName        string
	Status             string
	EmailVerifiedAt    *time.Time
	IsSuperAdmin       bool
	MustChangePassword bool
}

// Create inserts a user and returns the stored row. The email is normalized
// before it is encrypted and indexed, so the address decides identity rather
// than its spelling. A second user with the same address is a conflict, raised
// by the unique index on the blind index rather than by a read-then-write
// check that two concurrent registrations could both pass.
func (r *Repository) Create(ctx context.Context, n *CreateParams) (*User, error) {
	normalized := NormalizeEmail(n.Email)
	enc, hash, err := r.encrypt(normalized)
	if err != nil {
		return nil, err
	}
	status := n.Status
	if status == "" {
		status = StatusPending
	}
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`INSERT INTO users
			(email_enc, email_hash, display_name, status, email_verified_at,
			 is_super_admin, must_change_password)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING `+userColumns,
		enc, hash, n.DisplayName, status, n.EmailVerifiedAt, n.IsSuperAdmin, n.MustChangePassword)
	u, err := r.scan(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return nil, errorz.Conflict().WithMessage("user: already exists")
		}
		return nil, err
	}
	return u, nil
}

// Get returns one user by ID, or errorz.NotFound.
func (r *Repository) Get(ctx context.Context, id uuid.UUID) (*User, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1`, id)
	return r.scan(row)
}

// FindByEmail returns the user with this address, or errorz.NotFound. The
// lookup goes through the blind index of the normalized email, so it is an
// exact match that ignores surrounding space and letter case.
func (r *Repository) FindByEmail(ctx context.Context, email string) (*User, error) {
	hash := r.cipher.BlindIndex(NormalizeEmail(email))
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE email_hash = $1`, hash)
	return r.scan(row)
}

// UpdateStatus moves a user between pending, active and disabled, checking
// the version so a concurrent edit is reported rather than silently lost.
func (r *Repository) UpdateStatus(ctx context.Context, id uuid.UUID, version int, status string) error {
	return r.execChecked(ctx, id,
		`UPDATE users SET status = $3, version = version + 1, updated_at = now()
		 WHERE id = $1 AND version = $2`, id, version, status)
}

// UpdateDisplayName changes only the display name, checking the version. It
// writes no other column, so it cannot disturb the sign-in state or the
// password.
func (r *Repository) UpdateDisplayName(ctx context.Context, id uuid.UUID, version int, name string) error {
	return r.execChecked(ctx, id,
		`UPDATE users SET display_name = $3, version = version + 1, updated_at = now()
		 WHERE id = $1 AND version = $2`, id, version, name)
}

// MarkEmailVerified stamps the verification time, leaving it alone when it is
// already set so a second verification does not move it.
func (r *Repository) MarkEmailVerified(ctx context.Context, id uuid.UUID, at time.Time) error {
	return r.exec(ctx,
		`UPDATE users SET email_verified_at = coalesce(email_verified_at, $2), updated_at = now()
		 WHERE id = $1`, id, at)
}

// IncrementFailedLogins counts one failed sign-in and returns the new total,
// so the caller can decide whether the account has reached its lockout
// threshold. The read-modify-write happens in the database, which keeps the
// count right when attempts arrive on several pods at once.
func (r *Repository) IncrementFailedLogins(ctx context.Context, id uuid.UUID) (int, error) {
	var n int
	err := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`UPDATE users SET failed_logins = failed_logins + 1, updated_at = now()
		 WHERE id = $1 RETURNING failed_logins`, id).Scan(&n)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, errorz.NotFound().WithMessage("user: not found")
		}
		return 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: increment failed logins")
	}
	return n, nil
}

// ResetFailedLogins clears the counter and any lock, which is what a
// successful sign-in does: the account is no longer suspect, so leaving a
// lock behind would keep punishing someone who just proved who they are.
func (r *Repository) ResetFailedLogins(ctx context.Context, id uuid.UUID) error {
	return r.exec(ctx,
		`UPDATE users SET failed_logins = 0, locked_until = NULL, updated_at = now()
		 WHERE id = $1`, id)
}

// Lock blocks sign-in until the given time. A nil time clears the lock.
func (r *Repository) Lock(ctx context.Context, id uuid.UUID, until *time.Time) error {
	return r.exec(ctx,
		`UPDATE users SET locked_until = $2, updated_at = now() WHERE id = $1`, id, until)
}

// SetMustChangePassword turns the forced password change on or off. It is set
// for a seeded or reset account and cleared once the user has chosen a
// password.
func (r *Repository) SetMustChangePassword(ctx context.Context, id uuid.UUID, must bool) error {
	return r.exec(ctx,
		`UPDATE users SET must_change_password = $2, updated_at = now() WHERE id = $1`, id, must)
}

// MarkSignedIn stamps the last successful sign-in.
func (r *Repository) MarkSignedIn(ctx context.Context, id uuid.UUID, at time.Time) error {
	return r.exec(ctx,
		`UPDATE users SET last_sign_in_at = $2, updated_at = now() WHERE id = $1`, id, at)
}

// SuperAdminExists reports whether the single super admin has been created,
// which the startup bootstrap asks before seeding one.
func (r *Repository) SuperAdminExists(ctx context.Context) (bool, error) {
	var exists bool
	err := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE is_super_admin)`).Scan(&exists)
	if err != nil {
		return false, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: super admin exists")
	}
	return exists, nil
}

// SuperAdmin returns the current super admin, or errorz.NotFound before the
// first start has created one.
func (r *Repository) SuperAdmin(ctx context.Context) (*User, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE is_super_admin`)
	return r.scan(row)
}

// SetSuperAdmin sets or clears the super admin flag. The partial unique index
// allows one flagged row at a time, so a transfer clears the old holder before
// it flags the new one.
func (r *Repository) SetSuperAdmin(ctx context.Context, id uuid.UUID, on bool) error {
	return r.exec(ctx,
		`UPDATE users SET is_super_admin = $2, version = version + 1, updated_at = now()
		 WHERE id = $1`, id, on)
}

// encrypt returns the ciphertext and the blind index of an already-normalized
// email.
func (r *Repository) encrypt(normalized string) (enc, hash []byte, err error) {
	enc, err = r.cipher.Encrypt(normalized)
	if err != nil {
		return nil, nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: encrypt email")
	}
	return enc, r.cipher.BlindIndex(normalized), nil
}

// scan reads one user row and decrypts its email, mapping no rows to
// errorz.NotFound.
func (r *Repository) scan(row *sql.Row) (*User, error) {
	var (
		u   User
		enc []byte
	)
	err := row.Scan(&u.ID, &enc, &u.DisplayName, &u.Status, &u.EmailVerifiedAt, &u.IsSuperAdmin,
		&u.MustChangePassword, &u.FailedLogins, &u.LockedUntil, &u.LastSignInAt, &u.Version,
		&u.CreatedAt, &u.UpdatedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, errorz.NotFound().WithMessage("user: not found")
	case err != nil:
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: scan")
	}
	if u.Email, err = r.cipher.Decrypt(enc); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: decrypt email")
	}
	return &u, nil
}

// exec runs an update that matches on the ID alone, turning no affected rows
// into a not-found error.
func (r *Repository) exec(ctx context.Context, query string, args ...any) error {
	res, err := database.Leader(ctx, r.db).ExecContext(ctx, query, args...)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: update")
	}
	n, err := res.RowsAffected()
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: rows affected")
	}
	if n == 0 {
		return errorz.NotFound().WithMessage("user: not found")
	}
	return nil
}

// execChecked runs a version-checked update, distinguishing a stale version
// (a conflict) from a missing row (not found).
func (r *Repository) execChecked(
	ctx context.Context, id uuid.UUID, query string, args ...any,
) error {
	res, err := database.Leader(ctx, r.db).ExecContext(ctx, query, args...)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: update")
	}
	n, err := res.RowsAffected()
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: rows affected")
	}
	if n > 0 {
		return nil
	}
	if _, err := r.Get(ctx, id); err != nil {
		return err // not found
	}
	return errorz.Conflict().WithMessage("user: version conflict")
}

// CredentialsRepository stores password hashes. It lives beside the user
// repository because the two are written together, but in its own type so a
// user read can never pull a hash along by accident.
type CredentialsRepository struct {
	db *sqlkit.DB
}

// NewCredentialsRepository returns a CredentialsRepository over db.
func NewCredentialsRepository(db *sqlkit.DB) *CredentialsRepository {
	return &CredentialsRepository{db: db}
}

// Set stores or replaces a user's password hash. It writes only the hash and
// its timestamp, so it never touches the user row.
func (r *CredentialsRepository) Set(ctx context.Context, userID uuid.UUID, hash string) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`INSERT INTO credentials (user_id, password_hash) VALUES ($1, $2)
		 ON CONFLICT (user_id) DO UPDATE SET password_hash = $2, updated_at = now()`,
		userID, hash)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: set credentials")
	}
	return nil
}

// Get returns a user's credentials, or errorz.NotFound when the account has
// no password (an invite that was never accepted, or a Google-only sign-in).
func (r *CredentialsRepository) Get(ctx context.Context, userID uuid.UUID) (*Credentials, error) {
	var c Credentials
	err := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT user_id, password_hash, updated_at FROM credentials WHERE user_id = $1`, userID).
		Scan(&c.UserID, &c.PasswordHash, &c.UpdatedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, errorz.NotFound().WithMessage("user: no credentials")
	case err != nil:
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: scan credentials")
	}
	return &c, nil
}

// Delete removes a user's password, used when an account moves to
// external-only sign-in.
func (r *CredentialsRepository) Delete(ctx context.Context, userID uuid.UUID) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`DELETE FROM credentials WHERE user_id = $1`, userID)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: delete credentials")
	}
	return nil
}
