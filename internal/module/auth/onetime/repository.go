package onetime

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/database"
)

// tokenColumns is the select list for a Token; the raw value is never stored,
// so it cannot be selected.
//
//nolint:gosec // G101 matches the column names; there is no secret here.
const tokenColumns = `id, user_id, tenant_id, purpose, payload, expires_at, used_at, created_at`

// Repository stores one-time tokens. Writes go through the context
// transaction when there is one, so a token is created with the change that
// needs it.
type Repository struct {
	db *sqlkit.DB
}

// NewRepository returns a Repository over db.
func NewRepository(db *sqlkit.DB) *Repository { return &Repository{db: db} }

// Insert stores one token row with its hash.
func (r *Repository) Insert(ctx context.Context, t *Token, hash []byte) error {
	payload := t.Payload
	if len(payload) == 0 {
		payload = []byte(`{}`)
	}
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`INSERT INTO one_time_tokens
			(id, user_id, tenant_id, purpose, token_hash, payload, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		t.ID, t.UserID, t.TenantID, t.Purpose, hash, payload, t.ExpiresAt, t.CreatedAt)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("onetime: insert token")
	}
	return nil
}

// FindByHash returns the token with this hash, or nil when there is none. An
// absent token is not an error: the caller answers the same way for an
// unknown and a spent token.
func (r *Repository) FindByHash(ctx context.Context, hash []byte) (*Token, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT `+tokenColumns+` FROM one_time_tokens WHERE token_hash = $1`, hash)
	var t Token
	err := row.Scan(&t.ID, &t.UserID, &t.TenantID, &t.Purpose, &t.Payload,
		&t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("onetime: find token")
	}
	return &t, nil
}

// MarkUsed stamps a token as spent and reports whether it was this call that
// spent it. The condition on used_at makes the update the single point where
// two concurrent consumers are decided, without needing a row lock.
func (r *Repository) MarkUsed(ctx context.Context, id uuid.UUID, at time.Time) (bool, error) {
	res, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`UPDATE one_time_tokens SET used_at = $2 WHERE id = $1 AND used_at IS NULL`, id, at)
	if err != nil {
		return false, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("onetime: mark used")
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("onetime: rows affected")
	}
	return n == 1, nil
}

// DeleteUnusedForUser drops a user's live tokens of one purpose, so issuing a
// new verification or reset link invalidates the previous one.
func (r *Repository) DeleteUnusedForUser(ctx context.Context, userID uuid.UUID, purpose string) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`DELETE FROM one_time_tokens WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL`,
		userID, purpose)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("onetime: delete unused tokens")
	}
	return nil
}

// DeleteUnusedForUserInTenant deletes a user's unused tokens of one purpose
// scoped to one tenant, so a new invite replaces the previous one without
// touching invites to other tenants.
func (r *Repository) DeleteUnusedForUserInTenant(
	ctx context.Context, userID, tenantID uuid.UUID, purpose string,
) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`DELETE FROM one_time_tokens
		 WHERE user_id = $1 AND tenant_id = $2 AND purpose = $3 AND used_at IS NULL`,
		userID, tenantID, purpose)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("onetime: delete unused tokens")
	}
	return nil
}
