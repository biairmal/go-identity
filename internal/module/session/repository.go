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

// ByHash reads one token without locking it, for sign-out, which only needs
// to know whose token it is.
func (r *Repository) ByHash(ctx context.Context, hash []byte) (*Token, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT `+tokenColumns+` FROM refresh_tokens WHERE token_hash = $1`, hash)
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

// RevokeAllForUserInTenant revokes every live token of one user in one
// tenant and returns how many it revoked.
func (r *Repository) RevokeAllForUserInTenant(
	ctx context.Context, userID, tenantID uuid.UUID, at time.Time,
) (int64, error) {
	return r.revoke(ctx, "session: revoke tenant tokens",
		`UPDATE refresh_tokens SET revoked_at = $3
		 WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`, userID, tenantID, at)
}

// ListSessions returns the live sessions of one user, one per family, most
// recently used first. A family's live token is its newest, so its issue
// time is when the device last refreshed; the family began with its oldest.
func (r *Repository) ListSessions(ctx context.Context, userID uuid.UUID, now time.Time) ([]Session, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT t.family_id,
		        (SELECT min(f.issued_at) FROM refresh_tokens f WHERE f.family_id = t.family_id),
		        t.issued_at, t.user_agent, host(t.ip)
		 FROM refresh_tokens t
		 WHERE t.user_id = $1 AND t.revoked_at IS NULL AND t.rotated_at IS NULL
		   AND t.expires_at > $2 AND t.absolute_expires_at > $2
		 ORDER BY t.issued_at DESC`, userID, now)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: list")
	}
	defer func() { _ = rows.Close() }()
	var out []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.FamilyID, &s.CreatedAt, &s.LastUsedAt, &s.UserAgent, &s.IP); err != nil {
			return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: scan session")
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: list rows")
	}
	return out, nil
}

// RevokeUserFamily revokes a family only if it belongs to userID and still
// has a live token. It reports how many tokens it revoked, so zero means not
// found as far as that user can tell.
func (r *Repository) RevokeUserFamily(ctx context.Context, userID, familyID uuid.UUID, at time.Time) (int64, error) {
	return r.revoke(ctx, "session: revoke user family",
		`UPDATE refresh_tokens SET revoked_at = $3
		 WHERE family_id = $1 AND user_id = $2 AND revoked_at IS NULL`, familyID, userID, at)
}

// revoke runs a revoking update and returns how many tokens it revoked.
func (r *Repository) revoke(ctx context.Context, what, query string, args ...any) (int64, error) {
	res, err := database.Leader(ctx, r.db).ExecContext(ctx, query, args...)
	if err != nil {
		return 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage(what)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage(what)
	}
	return n, nil
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
