package session

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

// Repository stores refresh-token families. Rotation runs on the leader
// inside a transaction with a row lock, because two requests racing to
// exchange the same token must be serialized, not merged.
type Repository struct {
	db *sqlkit.DB
}

// NewRepository returns a Repository over db.
func NewRepository(db *sqlkit.DB) *Repository { return &Repository{db: db} }

// tokenColumns is the select list for a Token.
//
//nolint:gosec // G101 matches the column names; there is no secret here.
const tokenColumns = `id, family_id, user_id, tenant_id, issued_at, expires_at,
	absolute_expires_at, rotated_at, revoked_at, user_agent, host(ip)`

// Insert stores one token row.
func (r *Repository) Insert(ctx context.Context, t *Token, hash []byte) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`INSERT INTO refresh_tokens
			(id, family_id, user_id, tenant_id, token_hash, issued_at, expires_at,
			 absolute_expires_at, user_agent, ip)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		t.ID, t.FamilyID, t.UserID, t.TenantID, hash, t.IssuedAt, t.ExpiresAt,
		t.AbsoluteExpiresAt, t.UserAgent, t.IP)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: insert token")
	}
	return nil
}

// LockByHash reads one token for update, so a concurrent rotation of the same
// token waits here instead of both proceeding.
func (r *Repository) LockByHash(ctx context.Context, hash []byte) (*Token, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT `+tokenColumns+` FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`, hash)
	return scanToken(row)
}

// MarkRotated stamps a token as exchanged at the given time.
func (r *Repository) MarkRotated(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`UPDATE refresh_tokens SET rotated_at = $2 WHERE id = $1 AND rotated_at IS NULL`, id, at)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: mark rotated")
	}
	return nil
}

// RevokeFamily revokes every token of one family that is not revoked yet. It
// returns how many were revoked, which tells a reuse from a no-op.
func (r *Repository) RevokeFamily(ctx context.Context, familyID uuid.UUID, at time.Time) (int64, error) {
	res, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL`,
		familyID, at)
	if err != nil {
		return 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: revoke family")
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: rows affected")
	}
	return n, nil
}

// RevokeAllForUser revokes every live token of one user, across tenants. It
// backs logout-all, a password reset and an account being disabled.
func (r *Repository) RevokeAllForUser(ctx context.Context, userID uuid.UUID, at time.Time) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`,
		userID, at)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: revoke user tokens")
	}
	return nil
}

// ListForUser returns the live sessions of one user, newest first, for the
// session list and for revoking one device.
func (r *Repository) ListForUser(ctx context.Context, userID uuid.UUID, now time.Time) ([]Token, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT `+tokenColumns+`
		 FROM refresh_tokens
		 WHERE user_id = $1 AND revoked_at IS NULL AND rotated_at IS NULL AND expires_at > $2
		 ORDER BY issued_at DESC`, userID, now)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: list")
	}
	defer func() { _ = rows.Close() }()
	var out []Token
	for rows.Next() {
		t, err := scanTokenRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	if err := rows.Err(); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: list rows")
	}
	return out, nil
}

// FamilyOf returns the family a session belongs to, so revoking one session
// revokes the chain it is part of rather than just that row.
func (r *Repository) FamilyOf(ctx context.Context, userID, id uuid.UUID) (uuid.UUID, error) {
	var familyID uuid.UUID
	err := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT family_id FROM refresh_tokens WHERE id = $1 AND user_id = $2`, id, userID).Scan(&familyID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, errorz.NotFound().WithMessage("session: not found")
		}
		return uuid.Nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: family of")
	}
	return familyID, nil
}

// scanToken reads one token row, mapping no rows to errorz.NotFound.
func scanToken(row *sql.Row) (*Token, error) {
	var t Token
	err := row.Scan(&t.ID, &t.FamilyID, &t.UserID, &t.TenantID, &t.IssuedAt, &t.ExpiresAt,
		&t.AbsoluteExpiresAt, &t.RotatedAt, &t.RevokedAt, &t.UserAgent, &t.IP)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errorz.NotFound().WithMessage("session: token not found")
		}
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: scan token")
	}
	return &t, nil
}

// scanTokenRow reads one token from a multi-row result.
func scanTokenRow(rows *sql.Rows) (*Token, error) {
	var t Token
	err := rows.Scan(&t.ID, &t.FamilyID, &t.UserID, &t.TenantID, &t.IssuedAt, &t.ExpiresAt,
		&t.AbsoluteExpiresAt, &t.RotatedAt, &t.RevokedAt, &t.UserAgent, &t.IP)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: scan token")
	}
	return &t, nil
}
