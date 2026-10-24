package user

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/biairmal/go-sdk/lib/crypto"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// testCipher is the real go-sdk cipher behind the module's port, built with
// throwaway keys. Using the real primitive rather than a fake is what makes
// "the row never holds the plain email" evidence instead of an assumption.
type testCipher struct{ enc *crypto.Encryptor }

func (c testCipher) Encrypt(plain string) ([]byte, error) {
	s, err := c.enc.Encrypt([]byte(plain))
	return []byte(s), err
}

func (c testCipher) Decrypt(ciphertext []byte) (string, error) {
	plain, err := c.enc.Decrypt(string(ciphertext))
	return string(plain), err
}

func (c testCipher) BlindIndex(normalized string) []byte {
	return []byte(c.enc.BlindIndex(normalized))
}

// newTestCipher builds a cipher with fixed test keys.
func newTestCipher(t *testing.T) EmailCipher {
	t.Helper()
	key := func(fill byte, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = fill
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	enc, err := crypto.New(crypto.Config{EncryptionKey: key(0x11, 32), BlindIndexKey: key(0x22, 32)})
	if err != nil {
		t.Fatalf("build test cipher: %v", err)
	}
	return testCipher{enc: enc}
}

// newRepos returns the two repositories over a clean migrated database.
func newRepos(t *testing.T) (*sqlkit.DB, *Repository, *CredentialsRepository) {
	t.Helper()
	db := testkit.Postgres(t)
	return db, NewRepository(db, newTestCipher(t)), NewCredentialsRepository(db)
}

// createUser inserts an active user with the given email.
func createUser(ctx context.Context, t *testing.T, repo *Repository, email string) *User {
	t.Helper()
	u, err := repo.Create(ctx, &CreateParams{Email: email, DisplayName: "Bia", Status: StatusActive})
	if err != nil {
		t.Fatalf("Create(%q) = %v", email, err)
	}
	return u
}

// TestFindByEmailIgnoresSpacingAndCase is the acceptance criterion: the blind
// index is taken over the normalized address, so a user created as
// bia@example.com is found by " Bia@Example.com ".
func TestFindByEmailIgnoresSpacingAndCase(t *testing.T) {
	ctx := context.Background()
	_, repo, _ := newRepos(t)
	created := createUser(ctx, t, repo, "bia@example.com")

	lookups := []string{
		" Bia@Example.com ",
		"BIA@EXAMPLE.COM",
		"bia@example.com",
		"\tbia@Example.com\n",
	}
	for _, in := range lookups {
		t.Run(strings.TrimSpace(in), func(t *testing.T) {
			got, err := repo.FindByEmail(ctx, in)
			if err != nil {
				t.Fatalf("FindByEmail(%q) = %v", in, err)
			}
			if got.ID != created.ID {
				t.Errorf("FindByEmail(%q) = %v, want %v", in, got.ID, created.ID)
			}
			if got.Email != "bia@example.com" {
				t.Errorf("email read back = %q, want the normalized address", got.Email)
			}
		})
	}

	if _, err := repo.FindByEmail(ctx, "someone.else@example.com"); !errors.Is(err, errorz.ErrNotFound) {
		t.Fatalf("FindByEmail() for a stranger = %v, want not found", err)
	}
}

// TestCreateNormalizesTheStoredEmail checks the normalization happens on the
// write path too: an address typed with spaces and capitals is stored and
// returned canonical, and re-registering its other spelling is a conflict.
func TestCreateNormalizesTheStoredEmail(t *testing.T) {
	ctx := context.Background()
	_, repo, _ := newRepos(t)

	u := createUser(ctx, t, repo, "  Bia@Example.COM ")
	if u.Email != "bia@example.com" {
		t.Errorf("stored email = %q, want bia@example.com", u.Email)
	}

	_, err := repo.Create(ctx, &CreateParams{Email: "bia@example.com", Status: StatusActive})
	if !errors.Is(err, errorz.ErrConflict) {
		t.Fatalf("Create() with the same address = %v, want a conflict", err)
	}
}

// TestTheRowNeverHoldsThePlainEmail reads the raw bytea columns and asserts
// the address appears in neither of them, which is the whole point of the
// encrypted column plus blind index.
func TestTheRowNeverHoldsThePlainEmail(t *testing.T) {
	ctx := context.Background()
	db, repo, _ := newRepos(t)
	const email = "bia@example.com"
	u := createUser(ctx, t, repo, email)

	var enc, hash []byte
	err := db.Leader().QueryRowContext(ctx,
		`SELECT email_enc, email_hash FROM users WHERE id = $1`, u.ID).Scan(&enc, &hash)
	if err != nil {
		t.Fatalf("read raw columns: %v", err)
	}
	for name, col := range map[string][]byte{"email_enc": enc, "email_hash": hash} {
		if bytes.Contains(col, []byte(email)) {
			t.Errorf("%s contains the plain email", name)
		}
		if bytes.Contains(bytes.ToLower(col), []byte("example.com")) {
			t.Errorf("%s contains the email domain in clear", name)
		}
		if len(col) == 0 {
			t.Errorf("%s is empty", name)
		}
	}
	if bytes.Equal(enc, hash) {
		t.Error("email_enc and email_hash are identical; the blind index must be a separate value")
	}

	// The ciphertext is randomly nonced, so the same address encrypts
	// differently each time; only the blind index is stable.
	second := createUser(ctx, t, repo, "other@example.com")
	var otherEnc []byte
	if err := db.Leader().QueryRowContext(ctx,
		`SELECT email_enc FROM users WHERE id = $1`, second.ID).Scan(&otherEnc); err != nil {
		t.Fatalf("read second ciphertext: %v", err)
	}
	if bytes.Equal(enc, otherEnc) {
		t.Error("two users share one ciphertext, which means the cipher is deterministic")
	}
}

// TestStatusAndNameUpdatesLeaveCredentialsAlone is a regression test: a
// full-row update once wiped the password hash when an admin only changed a
// user's status or display name. Every write here names its own columns, so
// the credentials row must be untouched.
func TestStatusAndNameUpdatesLeaveCredentialsAlone(t *testing.T) {
	ctx := context.Background()
	_, repo, creds := newRepos(t)
	u := createUser(ctx, t, repo, "bia@example.com")

	const hash = "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHlzYWx0$aGFzaGVkcGFzc3dvcmQ"
	if err := creds.Set(ctx, u.ID, hash); err != nil {
		t.Fatalf("Set() credentials = %v", err)
	}
	before, err := creds.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get() credentials = %v", err)
	}

	if err := repo.UpdateStatus(ctx, u.ID, u.Version, StatusDisabled); err != nil {
		t.Fatalf("UpdateStatus() = %v", err)
	}
	if err := repo.UpdateDisplayName(ctx, u.ID, u.Version+1, "Bia Renamed"); err != nil {
		t.Fatalf("UpdateDisplayName() = %v", err)
	}
	if err := repo.SetMustChangePassword(ctx, u.ID, true); err != nil {
		t.Fatalf("SetMustChangePassword() = %v", err)
	}
	if err := repo.Lock(ctx, u.ID, timePtr(time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("Lock() = %v", err)
	}

	after, err := creds.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get() credentials after the updates = %v", err)
	}
	if after.PasswordHash != hash {
		t.Errorf("password hash = %q after unrelated updates, want it unchanged", after.PasswordHash)
	}
	if !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Errorf("credentials updated_at moved from %v to %v; the row must not be rewritten",
			before.UpdatedAt, after.UpdatedAt)
	}

	// The user row did change, and each update wrote only its own column.
	got, err := repo.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if got.Status != StatusDisabled || got.DisplayName != "Bia Renamed" || !got.MustChangePassword {
		t.Errorf("user = %+v, want disabled, renamed and must-change-password", got)
	}
	if got.Email != "bia@example.com" {
		t.Errorf("email = %q after the updates, want it unchanged", got.Email)
	}
}

// TestUpdateStatusChecksTheVersion covers the optimistic lock on users: a
// stale version is a conflict, and a missing user is not found.
func TestUpdateStatusChecksTheVersion(t *testing.T) {
	ctx := context.Background()
	_, repo, _ := newRepos(t)
	u := createUser(ctx, t, repo, "bia@example.com")

	if err := repo.UpdateStatus(ctx, u.ID, u.Version, StatusDisabled); err != nil {
		t.Fatalf("UpdateStatus() = %v", err)
	}
	err := repo.UpdateStatus(ctx, u.ID, u.Version, StatusActive)
	if !errors.Is(err, errorz.ErrConflict) {
		t.Fatalf("UpdateStatus() with a stale version = %v, want a conflict", err)
	}
	err = repo.UpdateStatus(ctx, uuid.New(), 1, StatusActive)
	if !errors.Is(err, errorz.ErrNotFound) {
		t.Fatalf("UpdateStatus() on a missing user = %v, want not found", err)
	}
}

// TestLockoutCounters covers the sign-in counters: failures accumulate, a
// lock is set and read back, and a reset clears both.
func TestLockoutCounters(t *testing.T) {
	ctx := context.Background()
	_, repo, _ := newRepos(t)
	u := createUser(ctx, t, repo, "bia@example.com")
	now := time.Now().UTC()

	for want := 1; want <= 3; want++ {
		got, err := repo.IncrementFailedLogins(ctx, u.ID)
		if err != nil {
			t.Fatalf("IncrementFailedLogins() = %v", err)
		}
		if got != want {
			t.Fatalf("IncrementFailedLogins() = %d, want %d", got, want)
		}
	}

	until := now.Add(15 * time.Minute)
	if err := repo.Lock(ctx, u.ID, &until); err != nil {
		t.Fatalf("Lock() = %v", err)
	}
	locked, err := repo.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if !locked.Locked(now) || locked.FailedLogins != 3 {
		t.Fatalf("user = %+v, want locked with 3 failures", locked)
	}
	if locked.Locked(until.Add(time.Second)) {
		t.Error("the lock must expire at locked_until")
	}

	if err := repo.ResetFailedLogins(ctx, u.ID); err != nil {
		t.Fatalf("ResetFailedLogins() = %v", err)
	}
	reset, err := repo.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get() after reset = %v", err)
	}
	if reset.FailedLogins != 0 || reset.LockedUntil != nil {
		t.Errorf("user = %+v, want no failures and no lock", reset)
	}

	// A missing user is not found rather than a silent no-op.
	if _, err := repo.IncrementFailedLogins(ctx, uuid.New()); !errors.Is(err, errorz.ErrNotFound) {
		t.Errorf("IncrementFailedLogins() on a missing user = %v, want not found", err)
	}
	if err := repo.ResetFailedLogins(ctx, uuid.New()); !errors.Is(err, errorz.ErrNotFound) {
		t.Errorf("ResetFailedLogins() on a missing user = %v, want not found", err)
	}
	if err := repo.Lock(ctx, uuid.New(), &until); !errors.Is(err, errorz.ErrNotFound) {
		t.Errorf("Lock() on a missing user = %v, want not found", err)
	}
	if err := repo.SetMustChangePassword(ctx, uuid.New(), true); !errors.Is(err, errorz.ErrNotFound) {
		t.Errorf("SetMustChangePassword() on a missing user = %v, want not found", err)
	}
}

// TestCreateDefaultsAndSuperAdmin checks the columns Create leaves to the
// database, and the super admin probe the startup bootstrap uses.
func TestCreateDefaultsAndSuperAdmin(t *testing.T) {
	ctx := context.Background()
	_, repo, _ := newRepos(t)

	exists, err := repo.SuperAdminExists(ctx)
	if err != nil {
		t.Fatalf("SuperAdminExists() = %v", err)
	}
	if exists {
		t.Fatal("SuperAdminExists() = true on an empty database")
	}

	plain, err := repo.Create(ctx, &CreateParams{Email: "pending@example.com"})
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if plain.Status != StatusPending || plain.EmailVerified() || plain.IsSuperAdmin ||
		plain.MustChangePassword || plain.FailedLogins != 0 || plain.LockedUntil != nil {
		t.Errorf("new user = %+v, want a pending, unverified, unlocked account", plain)
	}
	if plain.Version != 1 {
		t.Errorf("new user version = %d, want 1", plain.Version)
	}

	verified := time.Now().UTC().Truncate(time.Millisecond)
	admin, err := repo.Create(ctx, &CreateParams{
		Email: "root@example.com", Status: StatusActive, EmailVerifiedAt: &verified,
		IsSuperAdmin: true, MustChangePassword: true,
	})
	if err != nil {
		t.Fatalf("Create() super admin = %v", err)
	}
	if !admin.IsSuperAdmin || !admin.MustChangePassword || !admin.EmailVerified() {
		t.Errorf("super admin = %+v, want the flags set", admin)
	}
	exists, err = repo.SuperAdminExists(ctx)
	if err != nil {
		t.Fatalf("SuperAdminExists() = %v", err)
	}
	if !exists {
		t.Error("SuperAdminExists() = false after creating one")
	}
}

// TestServiceCreateIsAtomic checks the service writes the user and its
// credentials in one transaction, so neither can exist without the other.
func TestServiceCreateIsAtomic(t *testing.T) {
	ctx := context.Background()
	db, repo, creds := newRepos(t)
	svc := NewService(Default(), repo, creds, nil)
	const hash = "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHlzYWx0$aGFzaA"

	u, err := svc.Create(ctx, &CreateParams{Email: " Bia@Example.com ", Status: StatusActive}, hash)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	stored, err := svc.Credentials(ctx, u.ID)
	if err != nil {
		t.Fatalf("Credentials() = %v", err)
	}
	if stored.PasswordHash != hash {
		t.Errorf("password hash = %q, want the one passed in", stored.PasswordHash)
	}

	// The second create collides on the blind index, so nothing is left
	// behind: not a user row, and not a credentials row.
	if _, err := svc.Create(ctx, &CreateParams{Email: "bia@example.com"}, "other-hash"); err == nil {
		t.Fatal("Create() with a duplicate address = nil, want a conflict")
	}
	if n := countRows(ctx, t, db, "users"); n != 1 {
		t.Errorf("%d users after the failed create, want 1", n)
	}
	if n := countRows(ctx, t, db, "credentials"); n != 1 {
		t.Errorf("%d credentials after the failed create, want 1", n)
	}
	if stored.PasswordHash != hash {
		t.Error("the failed create changed the existing password")
	}
}

// TestServiceSignInAndVerify covers the two service flows that write several
// columns at once: verifying an email activates a pending account, and a
// successful sign-in clears the failure state.
func TestServiceSignInAndVerify(t *testing.T) {
	ctx := context.Background()
	_, repo, creds := newRepos(t)
	svc := NewService(Default(), repo, creds, nil)
	at := time.Now().UTC().Truncate(time.Millisecond)

	u, err := svc.Create(ctx, &CreateParams{Email: "bia@example.com"}, "hash")
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if err := svc.VerifyEmail(ctx, u, at); err != nil {
		t.Fatalf("VerifyEmail() = %v", err)
	}
	verified, err := svc.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if !verified.EmailVerified() || !verified.Active() {
		t.Fatalf("user = %+v, want verified and active", verified)
	}

	if _, err := svc.RecordFailedLogin(ctx, u.ID); err != nil {
		t.Fatalf("RecordFailedLogin() = %v", err)
	}
	if err := svc.Lock(ctx, u.ID, timePtr(at.Add(time.Hour))); err != nil {
		t.Fatalf("Lock() = %v", err)
	}
	if err := svc.RecordSignIn(ctx, u.ID, at); err != nil {
		t.Fatalf("RecordSignIn() = %v", err)
	}
	after, err := svc.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get() after sign-in = %v", err)
	}
	if after.FailedLogins != 0 || after.LockedUntil != nil || after.LastSignInAt == nil {
		t.Errorf("user = %+v, want a clean sign-in state with a stamp", after)
	}

	// Setting a password clears the forced change in the same transaction.
	if err := svc.RequirePasswordChange(ctx, u.ID); err != nil {
		t.Fatalf("RequirePasswordChange() = %v", err)
	}
	if err := svc.SetPassword(ctx, u.ID, "new-hash"); err != nil {
		t.Fatalf("SetPassword() = %v", err)
	}
	final, err := svc.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get() after SetPassword = %v", err)
	}
	if final.MustChangePassword {
		t.Error("must_change_password still set after the user chose a password")
	}
	stored, err := svc.Credentials(ctx, u.ID)
	if err != nil {
		t.Fatalf("Credentials() = %v", err)
	}
	if stored.PasswordHash != "new-hash" {
		t.Errorf("password hash = %q, want new-hash", stored.PasswordHash)
	}
}

// TestCredentialsAbsence checks an account without a password reports not
// found rather than an empty hash, which a verify step could accept.
func TestCredentialsAbsence(t *testing.T) {
	ctx := context.Background()
	_, repo, creds := newRepos(t)
	u := createUser(ctx, t, repo, "google-only@example.com")

	if _, err := creds.Get(ctx, u.ID); !errors.Is(err, errorz.ErrNotFound) {
		t.Fatalf("Get() without credentials = %v, want not found", err)
	}
	if err := creds.Set(ctx, u.ID, "hash"); err != nil {
		t.Fatalf("Set() = %v", err)
	}
	if err := creds.Delete(ctx, u.ID); err != nil {
		t.Fatalf("Delete() = %v", err)
	}
	if _, err := creds.Get(ctx, u.ID); !errors.Is(err, errorz.ErrNotFound) {
		t.Fatalf("Get() after Delete = %v, want not found", err)
	}
}

// countRows returns how many rows a table holds.
func countRows(ctx context.Context, t *testing.T, db *sqlkit.DB, table string) int {
	t.Helper()
	var n int
	if err := db.Leader().QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// timePtr returns a pointer to t, for the nullable timestamp columns.
func timePtr(t time.Time) *time.Time { return &t }
