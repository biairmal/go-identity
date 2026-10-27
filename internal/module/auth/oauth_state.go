package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/auth/onetime"
	"github.com/biairmal/go-identity/internal/platform/database"
)

// OAuthState is one in-flight provider sign-in, keyed by the hash of the
// state parameter that travels through the browser.
type OAuthState struct {
	CodeVerifier string
	Nonce        string
	RedirectTo   string
	TenantSlug   string
	// LinkUserID is set when the flow links the provider to a signed-in
	// user instead of signing someone in.
	LinkUserID *uuid.UUID
	ExpiresAt  time.Time
}

// StateRepository stores oauth_states rows. The raw state is never stored.
type StateRepository struct {
	db *sqlkit.DB
}

// NewStateRepository returns a StateRepository over db.
func NewStateRepository(db *sqlkit.DB) *StateRepository { return &StateRepository{db: db} }

// Insert stores s under the hash of raw.
func (r *StateRepository) Insert(ctx context.Context, raw string, s *OAuthState) error {
	var slug *string
	if s.TenantSlug != "" {
		slug = &s.TenantSlug
	}
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`INSERT INTO oauth_states (state_hash, code_verifier, nonce, redirect_to, tenant_slug, link_user_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		onetime.Hash(raw), s.CodeVerifier, s.Nonce, s.RedirectTo, slug, s.LinkUserID, s.ExpiresAt)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: store oauth state")
	}
	return nil
}

// Take deletes the state behind raw and returns it when it had not expired
// at now, or nil. Deleting on read makes a state single use, even when two
// callbacks race.
func (r *StateRepository) Take(ctx context.Context, raw string, now time.Time) (*OAuthState, error) {
	var (
		s    OAuthState
		slug sql.NullString
	)
	err := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`DELETE FROM oauth_states WHERE state_hash = $1
		 RETURNING code_verifier, nonce, redirect_to, tenant_slug, link_user_id, expires_at`,
		onetime.Hash(raw)).Scan(&s.CodeVerifier, &s.Nonce, &s.RedirectTo, &slug, &s.LinkUserID, &s.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: take oauth state")
	}
	if !now.Before(s.ExpiresAt) {
		return nil, nil
	}
	s.TenantSlug = slug.String
	return &s, nil
}
