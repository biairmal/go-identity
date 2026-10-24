package onetime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// fixture is a service over a real database with a controllable clock, plus
// the user and tenant its tokens belong to.
type fixture struct {
	svc      *Service
	repo     *Repository
	clock    *testkit.Clock
	db       *sqlkit.DB
	userID   uuid.UUID
	tenantID uuid.UUID
}

// newFixture builds the fixture and the rows the foreign keys need.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := testkit.Postgres(t)
	ctx := context.Background()
	clk := testkit.NewClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	repo := NewRepository(db)

	var tenantID, userID uuid.UUID
	err := db.Leader().QueryRowContext(ctx,
		`INSERT INTO tenants (slug, name) VALUES ('onetime', 'One Time') RETURNING id`).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	err = db.Leader().QueryRowContext(ctx,
		`INSERT INTO users (email_enc, email_hash) VALUES ('enc', 'hash') RETURNING id`).Scan(&userID)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	return &fixture{
		svc: NewService(repo, clk), repo: repo, clock: clk, db: db,
		userID: userID, tenantID: tenantID,
	}
}

// TestCreateAndConsume covers the happy path: the raw value is returned once,
// only its hash is stored, and consuming it returns the row.
func TestCreateAndConsume(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Create(ctx, f.userID, PurposeVerifyEmail, time.Hour, Options{})
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if issued.Raw == "" {
		t.Fatal("Create() returned no raw token")
	}
	if f.rawTokenIsStored(t, issued.Raw) {
		t.Error("the raw token is stored in the database")
	}

	got, err := f.svc.Consume(ctx, issued.Raw, PurposeVerifyEmail)
	if err != nil {
		t.Fatalf("Consume() = %v", err)
	}
	if got.ID != issued.Token.ID || got.UserID != f.userID {
		t.Errorf("Consume() returned %+v, want the issued token", got)
	}
	if got.UsedAt == nil {
		t.Error("Consume() did not stamp used_at")
	}
}

// TestConsumeRejections is the acceptance list: twice, wrong purpose, expired,
// and an unknown token.
func TestConsumeRejections(t *testing.T) {
	tests := []struct {
		name string
		// prepare issues a token and returns the raw value to present
		// and the purpose to present it for.
		prepare func(t *testing.T, f *fixture) (raw, purpose string)
		wantErr error
	}{
		{
			name: "a second consume fails",
			prepare: func(t *testing.T, f *fixture) (string, string) {
				t.Helper()
				issued := f.create(t, PurposeVerifyEmail)
				if _, err := f.svc.Consume(context.Background(), issued.Raw, PurposeVerifyEmail); err != nil {
					t.Fatalf("first Consume() = %v", err)
				}
				return issued.Raw, PurposeVerifyEmail
			},
			wantErr: ErrInvalid,
		},
		{
			name: "the wrong purpose fails",
			prepare: func(t *testing.T, f *fixture) (string, string) {
				t.Helper()
				return f.create(t, PurposeResetPassword).Raw, PurposeVerifyEmail
			},
			wantErr: ErrInvalid,
		},
		{
			name: "an unknown token fails",
			prepare: func(t *testing.T, _ *fixture) (string, string) {
				t.Helper()
				return "not-a-token", PurposeVerifyEmail
			},
			wantErr: ErrInvalid,
		},
		{
			name: "an expired token fails",
			prepare: func(t *testing.T, f *fixture) (string, string) {
				t.Helper()
				issued := f.create(t, PurposeVerifyEmail)
				f.clock.Advance(time.Hour + time.Second)
				return issued.Raw, PurposeVerifyEmail
			},
			wantErr: ErrExpired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			raw, purpose := tt.prepare(t, f)
			_, err := f.svc.Consume(context.Background(), raw, purpose)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Consume() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestConsumeAtTheExpiryInstantSucceeds pins the boundary: the token is valid
// up to and including its expiry, and invalid after it.
func TestConsumeAtTheExpiryInstantSucceeds(t *testing.T) {
	f := newFixture(t)
	issued := f.create(t, PurposeResetPassword)
	f.clock.Advance(time.Hour)
	if _, err := f.svc.Consume(context.Background(), issued.Raw, PurposeResetPassword); err != nil {
		t.Fatalf("Consume() at the expiry instant = %v, want success", err)
	}
}

// TestConcurrentConsumeSpendsTheTokenOnce checks the single-use rule holds
// under a race, which is the case the conditional update exists for.
func TestConcurrentConsumeSpendsTheTokenOnce(t *testing.T) {
	f := newFixture(t)
	issued := f.create(t, PurposeInvite)

	var (
		mu        sync.Mutex
		successes int
		wg        sync.WaitGroup
	)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.svc.Consume(context.Background(), issued.Raw, PurposeInvite); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("%d of 4 concurrent consumers succeeded, want exactly 1", successes)
	}
}

// TestCreateJoinsTheCallersTransaction checks a token created beside a change
// that then fails leaves no row, so a rolled-back registration cannot leave a
// usable verification link.
func TestCreateJoinsTheCallersTransaction(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	failure := errors.New("the change failed")

	var raw string
	err := database.WithTx(ctx, f.db, func(ctx context.Context) error {
		issued, err := f.svc.Create(ctx, f.userID, PurposeVerifyEmail, time.Hour, Options{})
		if err != nil {
			return err
		}
		raw = issued.Raw
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("WithTx = %v, want the rollback error", err)
	}
	if _, err := f.svc.Consume(ctx, raw, PurposeVerifyEmail); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Consume() of a rolled-back token = %v, want ErrInvalid", err)
	}
}

// TestCreateWithTenantAndPayload checks the optional parts round trip, which
// invites need to know which tenant they are for.
func TestCreateWithTenantAndPayload(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Create(ctx, f.userID, PurposeInvite, time.Hour, Options{
		TenantID: &f.tenantID,
		Payload:  []byte(`{"role_ids":["admin"]}`),
	})
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	got, err := f.svc.Consume(ctx, issued.Raw, PurposeInvite)
	if err != nil {
		t.Fatalf("Consume() = %v", err)
	}
	if got.TenantID == nil || *got.TenantID != f.tenantID {
		t.Errorf("TenantID = %v, want %v", got.TenantID, f.tenantID)
	}
	if string(got.Payload) != `{"role_ids": ["admin"]}` && string(got.Payload) != `{"role_ids":["admin"]}` {
		t.Errorf("Payload = %s, want the stored JSON", got.Payload)
	}
}

// TestDeleteUnusedForUser checks re-issuing a link invalidates the previous
// one without touching tokens of another purpose or an already-spent one.
func TestDeleteUnusedForUser(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	first := f.create(t, PurposeVerifyEmail)
	other := f.create(t, PurposeResetPassword)

	if err := f.repo.DeleteUnusedForUser(ctx, f.userID, PurposeVerifyEmail); err != nil {
		t.Fatalf("DeleteUnusedForUser() = %v", err)
	}
	if _, err := f.svc.Consume(ctx, first.Raw, PurposeVerifyEmail); !errors.Is(err, ErrInvalid) {
		t.Fatalf("the superseded token still works: %v", err)
	}
	if _, err := f.svc.Consume(ctx, other.Raw, PurposeResetPassword); err != nil {
		t.Fatalf("a token of another purpose was deleted: %v", err)
	}
}

// defaultTTL is the lifetime the fixture issues tokens with.
const defaultTTL = time.Hour

// create issues a token and fails the test when it cannot.
func (f *fixture) create(t *testing.T, purpose string) *Issued {
	t.Helper()
	issued, err := f.svc.Create(context.Background(), f.userID, purpose, defaultTTL, Options{})
	if err != nil {
		t.Fatalf("Create(%q) = %v", purpose, err)
	}
	return issued
}

// rawTokenIsStored reports whether the raw value appears in the stored row,
// which it must not.
func (f *fixture) rawTokenIsStored(t *testing.T, raw string) bool {
	t.Helper()
	var n int
	err := f.db.Leader().QueryRowContext(context.Background(),
		`SELECT count(*) FROM one_time_tokens
		 WHERE token_hash = $1::bytea OR payload::text LIKE '%' || $2 || '%'`,
		[]byte(raw), raw).Scan(&n)
	if err != nil {
		t.Fatalf("rawTokenIsStored: %v", err)
	}
	return n > 0
}
