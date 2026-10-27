package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// TestStateRepositoryIntegration stores a state and takes it back: once, only
// before it expires, and never by its hash or by a wrong value.
func TestStateRepositoryIntegration(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	repo := NewStateRepository(db)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

	var userID uuid.UUID
	err := db.Leader().QueryRowContext(ctx,
		`INSERT INTO users (email_enc, email_hash) VALUES ('enc', 'hash') RETURNING id`).Scan(&userID)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	put := func(raw string, s OAuthState) {
		t.Helper()
		s.ExpiresAt = now.Add(oauthStateTTL)
		if err := repo.Insert(ctx, raw, &s); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}
	put("plain", OAuthState{CodeVerifier: "v", Nonce: "n", RedirectTo: "http://fe/cb", TenantSlug: "acme"})
	put("link", OAuthState{CodeVerifier: "v", Nonce: "n", RedirectTo: "http://fe/cb", LinkUserID: &userID})
	put("late", OAuthState{CodeVerifier: "v", Nonce: "n", RedirectTo: "http://fe/cb"})

	var stored int
	if err := db.Leader().QueryRowContext(ctx,
		`SELECT count(*) FROM oauth_states WHERE state_hash = 'plain'::bytea`).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("raw state stored: %d, %v", stored, err)
	}

	got, err := repo.Take(ctx, "plain", now)
	if err != nil || got == nil || got.TenantSlug != "acme" || got.LinkUserID != nil || got.CodeVerifier != "v" {
		t.Fatalf("Take(plain) = %+v, %v", got, err)
	}
	if again, err := repo.Take(ctx, "plain", now); again != nil || err != nil {
		t.Errorf("second Take(plain) = %+v, %v; want nil: a state is single use", again, err)
	}
	if got, err := repo.Take(ctx, "link", now); err != nil || got == nil || got.LinkUserID == nil ||
		*got.LinkUserID != userID || got.TenantSlug != "" {
		t.Errorf("Take(link) = %+v, %v", got, err)
	}
	if got, err := repo.Take(ctx, "late", now.Add(oauthStateTTL)); got != nil || err != nil {
		t.Errorf("Take(late) after expiry = %+v, %v; want nil", got, err)
	}
	if got, err := repo.Take(ctx, "tampered", now); got != nil || err != nil {
		t.Errorf("Take(tampered) = %+v, %v; want nil", got, err)
	}
}
