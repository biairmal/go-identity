package auth

import (
	"context"
	"database/sql"
	"errors"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/biairmal/go-identity/internal/platform/database"
)

// ProviderGoogle is the identities.provider value of a linked Google account.
const ProviderGoogle = "google"

// IdentityRepository reads, links and removes the external sign-in identities
// of a user.
type IdentityRepository struct {
	db *sqlkit.DB
}

// NewIdentityRepository returns an IdentityRepository over db.
func NewIdentityRepository(db *sqlkit.DB) *IdentityRepository { return &IdentityRepository{db: db} }

// Linked reports whether the user has an identity with this provider.
func (r *IdentityRepository) Linked(ctx context.Context, userID uuid.UUID, provider string) (bool, error) {
	var linked bool
	err := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM identities WHERE user_id = $1 AND provider = $2)`,
		userID, provider).Scan(&linked)
	if err != nil {
		return false, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: read identities")
	}
	return linked, nil
}

// UserBySubject returns the user the provider account is linked to, or an
// errorz.NotFound error.
func (r *IdentityRepository) UserBySubject(ctx context.Context, provider, subject string) (uuid.UUID, error) {
	var id uuid.UUID
	err := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT user_id FROM identities WHERE provider = $1 AND provider_subject = $2`,
		provider, subject).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, errorz.NotFound()
	}
	if err != nil {
		return uuid.Nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: read identity")
	}
	return id, nil
}

// Link attaches the provider account to the user, keeping the encrypted
// address it had. A provider account linked already, to anyone, is an
// errorz.Conflict error.
func (r *IdentityRepository) Link(
	ctx context.Context, userID uuid.UUID, provider, subject string, emailEnc []byte,
) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`INSERT INTO identities (user_id, provider, provider_subject, email_at_link) VALUES ($1, $2, $3, $4)`,
		userID, provider, subject, emailEnc)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return errorz.Conflict().WithMessage("auth: identity already linked")
	}
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: link identity")
	}
	return nil
}

// uniqueViolation is Postgres's unique_violation SQLSTATE.
const uniqueViolation = "23505"

// Unlink removes the user's identities with this provider.
func (r *IdentityRepository) Unlink(ctx context.Context, userID uuid.UUID, provider string) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`DELETE FROM identities WHERE user_id = $1 AND provider = $2`, userID, provider)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: unlink identity")
	}
	return nil
}
