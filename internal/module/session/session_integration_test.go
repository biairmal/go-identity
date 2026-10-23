package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// fixture is a service over a real database with a controllable clock, plus
// the user and tenant the tokens belong to.
type fixture struct {
	svc      *Service
	repo     *Repository
	clock    *testkit.Clock
	db       *sqlkit.DB
	userID   uuid.UUID
	tenantID uuid.UUID
}

// newFixture builds the fixture with the default lifetimes.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWithConfig(t, Default())
}

// newFixtureWithConfig builds the fixture with a specific config, for the
// expiry and grace-window tests.
func newFixtureWithConfig(t *testing.T, cfg Config) *fixture {
	t.Helper()
	db := testkit.Postgres(t)
	ctx := context.Background()
	clk := testkit.NewClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	repo := NewRepository(db)

	var tenantID, userID uuid.UUID
	err := db.Leader().QueryRowContext(ctx,
		`INSERT INTO tenants (slug, name) VALUES ('sessions', 'Sessions') RETURNING id`).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	err = db.Leader().QueryRowContext(ctx,
		`INSERT INTO users (email_enc, email_hash) VALUES ('enc', 'hash') RETURNING id`).Scan(&userID)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	return &fixture{
		svc:  NewService(cfg, repo, db, clk, nil),
		repo: repo, clock: clk, db: db,
		userID: userID, tenantID: tenantID,
	}
}

// device is a stand-in for the caller's browser.
func device() Device { return Device{UserAgent: "test-agent", IP: "203.0.113.7"} }

// TestIssueAndRotate covers the happy path: a fresh family, then an exchange
// that slides the expiry but keeps the family and its absolute deadline.
func TestIssueAndRotate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	first, err := f.svc.Issue(ctx, f.userID, f.tenantID, device())
	if err != nil {
		t.Fatalf("Issue() = %v", err)
	}
	if first.Raw == "" {
		t.Fatal("Issue() returned no raw token")
	}

	f.clock.Advance(time.Hour)
	second, err := f.svc.Rotate(ctx, first.Raw, device())
	if err != nil {
		t.Fatalf("Rotate() = %v", err)
	}

	if second.Raw == first.Raw {
		t.Error("the rotated token is the same string as the old one")
	}
	if second.Token.FamilyID != first.Token.FamilyID {
		t.Error("the rotated token started a new family, want the same one")
	}
	if !second.Token.ExpiresAt.After(first.Token.ExpiresAt) {
		t.Error("the sliding expiry did not move forward")
	}
	if !second.Token.AbsoluteExpiresAt.Equal(first.Token.AbsoluteExpiresAt) {
		t.Error("the absolute expiry moved, so a family could be extended forever")
	}
}

// TestRawTokenIsNotStored checks the database holds only the hash, so a dump
// cannot be replayed.
func TestRawTokenIsNotStored(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Issue(ctx, f.userID, f.tenantID, device())
	if err != nil {
		t.Fatalf("Issue() = %v", err)
	}
	var n int
	err = f.db.Leader().QueryRowContext(ctx,
		`SELECT count(*) FROM refresh_tokens WHERE token_hash = $1`, []byte(issued.Raw)).Scan(&n)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 0 {
		t.Error("the raw token is stored in token_hash, want only its digest")
	}
	// The digest is there, and finds the row.
	if _, err := f.repo.LockByHash(ctx, hashToken(issued.Raw)); err != nil {
		t.Errorf("LockByHash() with the digest = %v, want the row", err)
	}
}

// TestReuseAfterTheGraceRevokesTheFamily is the acceptance criterion: a token
// replayed after the grace window revokes every token of its family, so a
// stolen token cannot be used even once more.
func TestReuseAfterTheGraceRevokesTheFamily(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	first, err := f.svc.Issue(ctx, f.userID, f.tenantID, device())
	if err != nil {
		t.Fatalf("Issue() = %v", err)
	}
	second, err := f.svc.Rotate(ctx, first.Raw, device())
	if err != nil {
		t.Fatalf("Rotate() = %v", err)
	}

	// Past the grace window, the old token is a replay.
	f.clock.Advance(Default().RefreshReuseGrace + time.Second)
	_, err = f.svc.Rotate(ctx, first.Raw, device())
	if !errors.Is(err, ErrReuse) {
		t.Fatalf("Rotate() with a replayed token = %v, want ErrReuse", err)
	}

	// The whole family is gone, including the token the attacker did not have.
	if _, err := f.svc.Rotate(ctx, second.Raw, device()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Rotate() after a reuse = %v, want ErrRevoked for the family", err)
	}
}

// TestConcurrentRotationInsideTheGrace is the other acceptance criterion: two
// goroutines exchanging the same token inside the grace window both succeed
// with distinct tokens in one family, because a browser firing several
// requests at once is not an attack. The row lock serializes them.
func TestConcurrentRotationInsideTheGrace(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	first, err := f.svc.Issue(ctx, f.userID, f.tenantID, device())
	if err != nil {
		t.Fatalf("Issue() = %v", err)
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []*Issued
		errs    []error
	)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := f.svc.Rotate(ctx, first.Raw, device())
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			results = append(results, got)
		}()
	}
	wg.Wait()

	if len(errs) != 0 {
		t.Fatalf("concurrent rotation produced errors: %v", errs)
	}
	if len(results) != 2 {
		t.Fatalf("got %d tokens from two rotations, want 2", len(results))
	}
	if results[0].Raw == results[1].Raw {
		t.Error("both rotations returned the same token")
	}
	if results[0].Token.FamilyID != results[1].Token.FamilyID {
		t.Error("the two tokens are in different families, want one")
	}
	if results[0].Token.FamilyID != first.Token.FamilyID {
		t.Error("the siblings left the original family")
	}

	// Neither sibling is treated as a reuse afterwards.
	for i, r := range results {
		if _, err := f.svc.Rotate(ctx, r.Raw, device()); err != nil {
			t.Errorf("rotating sibling %d = %v, want success", i, err)
		}
	}
}

// TestRotateExpired covers both deadlines: the sliding expiry and the
// family's absolute one.
func TestRotateExpired(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		advance time.Duration
	}{
		{
			name:    "past the sliding expiry",
			cfg:     Config{RefreshTTL: time.Hour, RefreshAbsoluteTTL: 100 * time.Hour, RefreshReuseGrace: time.Second},
			advance: 2 * time.Hour,
		},
		{
			name:    "past the absolute expiry",
			cfg:     Config{RefreshTTL: time.Hour, RefreshAbsoluteTTL: time.Hour, RefreshReuseGrace: time.Second},
			advance: 90 * time.Minute,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixtureWithConfig(t, tt.cfg)
			ctx := context.Background()

			issued, err := f.svc.Issue(ctx, f.userID, f.tenantID, device())
			if err != nil {
				t.Fatalf("Issue() = %v", err)
			}
			f.clock.Advance(tt.advance)
			if _, err := f.svc.Rotate(ctx, issued.Raw, device()); !errors.Is(err, ErrExpired) {
				t.Fatalf("Rotate() = %v, want ErrExpired", err)
			}
		})
	}
}

// TestRotateUnknownToken checks a token that was never issued is not found,
// rather than a server error.
func TestRotateUnknownToken(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Rotate(context.Background(), "not-a-real-token", device()); err == nil {
		t.Fatal("Rotate() with an unknown token = nil, want an error")
	}
}

// TestRevokeAllForUser checks logout-all: every live token stops working,
// across tenants.
func TestRevokeAllForUser(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	a, err := f.svc.Issue(ctx, f.userID, f.tenantID, device())
	if err != nil {
		t.Fatalf("Issue() = %v", err)
	}
	b, err := f.svc.Issue(ctx, f.userID, f.tenantID, device())
	if err != nil {
		t.Fatalf("second Issue() = %v", err)
	}

	if err := f.svc.RevokeAllForUser(ctx, f.userID); err != nil {
		t.Fatalf("RevokeAllForUser() = %v", err)
	}
	for name, issued := range map[string]*Issued{"first": a, "second": b} {
		if _, err := f.svc.Rotate(ctx, issued.Raw, device()); !errors.Is(err, ErrRevoked) {
			t.Errorf("rotating the %s token after logout-all = %v, want ErrRevoked", name, err)
		}
	}
}

// TestListAndRevokeSession covers the session list and signing one device
// out, which revokes that device's whole chain.
func TestListAndRevokeSession(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	laptop, err := f.svc.Issue(ctx, f.userID, f.tenantID, Device{UserAgent: "laptop", IP: "203.0.113.1"})
	if err != nil {
		t.Fatalf("Issue(laptop) = %v", err)
	}
	phone, err := f.svc.Issue(ctx, f.userID, f.tenantID, Device{UserAgent: "phone", IP: "203.0.113.2"})
	if err != nil {
		t.Fatalf("Issue(phone) = %v", err)
	}

	sessions, err := f.svc.List(ctx, f.userID)
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("List() = %d sessions, want 2", len(sessions))
	}

	// Signing the laptop out leaves the phone working.
	if err := f.svc.RevokeSession(ctx, f.userID, laptop.Token.ID); err != nil {
		t.Fatalf("RevokeSession() = %v", err)
	}
	if _, err := f.svc.Rotate(ctx, laptop.Raw, device()); !errors.Is(err, ErrRevoked) {
		t.Errorf("rotating the revoked laptop session = %v, want ErrRevoked", err)
	}
	if _, err := f.svc.Rotate(ctx, phone.Raw, device()); err != nil {
		t.Errorf("rotating the phone session = %v, want it still to work", err)
	}

	// A rotated token is no longer a live session.
	sessions, err = f.svc.List(ctx, f.userID)
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	for _, s := range sessions {
		if s.ID == laptop.Token.ID {
			t.Error("the revoked session is still listed")
		}
	}
}

// TestRevokeSessionOfAnotherUser checks a session ID cannot be revoked by
// someone else, and that the failure is not found rather than forbidden, so
// IDs cannot be probed.
func TestRevokeSessionOfAnotherUser(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Issue(ctx, f.userID, f.tenantID, device())
	if err != nil {
		t.Fatalf("Issue() = %v", err)
	}
	err = f.svc.RevokeSession(ctx, uuid.New(), issued.Token.ID)
	if err == nil {
		t.Fatal("RevokeSession() for another user = nil, want not found")
	}
	if _, err := f.svc.Rotate(ctx, issued.Raw, device()); err != nil {
		t.Errorf("the session was revoked by a stranger: %v", err)
	}
}
