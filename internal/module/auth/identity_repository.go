package auth

import (
	"context"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/database"
)

// ProviderGoogle is the identities.provider value of a linked Google account.
const ProviderGoogle = "google"

// IdentityRepository reads and removes the external sign-in identities linked
// to a user. Linking arrives with Google sign-in (T4.1).
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

// Unlink removes the user's identities with this provider.
func (r *IdentityRepository) Unlink(ctx context.Context, userID uuid.UUID, provider string) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`DELETE FROM identities WHERE user_id = $1 AND provider = $2`, userID, provider)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: unlink identity")
	}
	return nil
}
