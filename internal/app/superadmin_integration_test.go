package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/audit"
	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/module/session"
	"github.com/biairmal/go-identity/internal/module/tenant"
	"github.com/biairmal/go-identity/internal/module/user"
	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// testSuperAdmin is the super admin every test app starts with. The password
// passes the policy, as the bootstrap requires.
var testSuperAdmin = user.SuperAdminConfig{
	Email:    "Root@Example.com",
	Password: "first-start-password-42",
}

// superAdminFixture is a migrated database with the config the app was built
// from, so a test can start the app again without the test kit truncating.
type superAdminFixture struct {
	cfg Config
	db  *sqlkit.DB
}

// newSuperAdminFixture builds a config over a clean database.
func newSuperAdminFixture(t *testing.T) *superAdminFixture {
	t.Helper()
	cfg := validConfig(t)
	cfg.Database = testkit.PostgresConfig(t)
	cfg.Modules.User.SuperAdmin = testSuperAdmin
	return &superAdminFixture{cfg: cfg, db: testkit.Postgres(t)}
}

// start runs one service start (New, which runs the bootstrap) and closes it.
func (f *superAdminFixture) start(t *testing.T) error {
	t.Helper()
	ctx := context.Background()
	a, err := New(ctx, &f.cfg, logger.NewNoOp())
	if err != nil {
		return err
	}
	a.close(ctx)
	return nil
}

// admins returns the super admin operations over the fixture database.
func (f *superAdminFixture) admins(t *testing.T) *user.SuperAdmins {
	t.Helper()
	s, err := superAdminsOver(&f.cfg, f.db, logger.NewNoOp())
	if err != nil {
		t.Fatalf("superAdminsOver: %v", err)
	}
	return s
}

// users returns the user module's service over the fixture database.
func (f *superAdminFixture) users(t *testing.T) *user.Service {
	t.Helper()
	cipher, err := newEmailCipher(&f.cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("newEmailCipher: %v", err)
	}
	return user.New(f.cfg.Modules.User, &user.Deps{DB: f.db, EmailCipher: cipher}).Service()
}

// sessions returns the session service over the fixture database.
func (f *superAdminFixture) sessions() *session.Service {
	return session.New(f.cfg.Modules.Session, session.Deps{DB: f.db, Clock: clock.System{}}).Service()
}

// superAdmin returns the one flagged user.
func (f *superAdminFixture) superAdmin(ctx context.Context, t *testing.T) *user.User {
	t.Helper()
	var id uuid.UUID
	if err := f.db.Leader().QueryRowContext(ctx,
		`SELECT id FROM users WHERE is_super_admin`).Scan(&id); err != nil {
		t.Fatalf("read super admin: %v", err)
	}
	u, err := f.users(t).Get(ctx, id)
	if err != nil {
		t.Fatalf("Get(super admin): %v", err)
	}
	return u
}

// snapshot renders every row the bootstrap touches, so two states can be
// compared for equality.
func (f *superAdminFixture) snapshot(ctx context.Context, t *testing.T) string {
	t.Helper()
	queries := []string{
		`SELECT id, status, is_super_admin, must_change_password, email_verified_at IS NOT NULL,
		        version, updated_at FROM users ORDER BY id`,
		`SELECT user_id, password_hash, updated_at FROM credentials ORDER BY user_id`,
		`SELECT tenant_id, user_id, status, joined_at FROM tenant_members ORDER BY tenant_id, user_id`,
		`SELECT user_id, role_id FROM user_roles ORDER BY user_id, role_id`,
		`SELECT id, action, target_id FROM audit_log ORDER BY id`,
	}
	var b strings.Builder
	for _, q := range queries {
		b.WriteString(dumpRows(ctx, t, f.db, q))
		b.WriteString("--\n")
	}
	return b.String()
}

// dumpRows renders a query's rows as text.
func dumpRows(ctx context.Context, t *testing.T, db *sqlkit.DB, query string) string {
	t.Helper()
	rows, err := db.Leader().QueryContext(ctx, query)
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	var b strings.Builder
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scan: %v", err)
		}
		fmt.Fprintln(&b, vals...)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return b.String()
}

// auditActions counts the audit rows with this action.
func auditActions(ctx context.Context, t *testing.T, db *sqlkit.DB, action audit.Action) int {
	t.Helper()
	var n int
	if err := db.Leader().QueryRowContext(ctx,
		`SELECT count(*) FROM audit_log WHERE action = $1`, string(action)).Scan(&n); err != nil {
		t.Fatalf("count audit %s: %v", action, err)
	}
	return n
}

// verifies reports whether plain matches the user's stored password.
func verifies(ctx context.Context, t *testing.T, users *user.Service, id uuid.UUID, plain string) bool {
	t.Helper()
	c, err := users.Credentials(ctx, id)
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	ok, _, err := password.Verify(plain, c.PasswordHash)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return ok
}

// TestSuperAdminBootstrapCreatesTheAccount checks the first start creates the
// super admin exactly as TRD 7 describes: active, verified, flagged, forced
// to change its password, an active member of the default tenant with no
// roles, and audited.
func TestSuperAdminBootstrapCreatesTheAccount(t *testing.T) {
	ctx := context.Background()
	f := newSuperAdminFixture(t)
	if err := f.start(t); err != nil {
		t.Fatalf("first start: %v", err)
	}

	sa := f.superAdmin(ctx, t)
	if sa.Email != "root@example.com" {
		t.Errorf("email = %q, want the normalized configured address", sa.Email)
	}
	if !sa.Active() || !sa.EmailVerified() || !sa.IsSuperAdmin || !sa.MustChangePassword {
		t.Errorf("super admin = %+v, want active, verified, flagged, must change password", sa)
	}
	if !verifies(ctx, t, f.users(t), sa.ID, testSuperAdmin.Password) {
		t.Error("the configured password does not verify against the stored hash")
	}

	tenants := tenant.NewService(f.cfg.Modules.Tenant, tenant.NewRepository(f.db), nil, nil)
	defaultID, err := tenants.DefaultID(ctx)
	if err != nil {
		t.Fatalf("DefaultID: %v", err)
	}
	m, err := tenants.Member(ctx, defaultID, sa.ID)
	if err != nil {
		t.Fatalf("Member(default tenant): %v", err)
	}
	if !m.Active() || m.JoinedAt == nil {
		t.Errorf("membership = %+v, want active with a join time", m)
	}
	var roles int
	if err := f.db.Leader().QueryRowContext(ctx,
		`SELECT count(*) FROM user_roles WHERE user_id = $1`, sa.ID).Scan(&roles); err != nil {
		t.Fatalf("count roles: %v", err)
	}
	if roles != 0 {
		t.Errorf("super admin has %d user_roles rows, want 0: its permissions come from the flag", roles)
	}
	if n := auditActions(ctx, t, f.db, audit.ActionSuperAdminCreate); n != 1 {
		t.Errorf("%d superadmin.create rows, want 1", n)
	}
}

// TestSuperAdminBootstrapIsIdempotent is the acceptance criterion "second
// startup does nothing": a second start leaves every row it could touch
// byte-for-byte identical, even with different credentials configured.
func TestSuperAdminBootstrapIsIdempotent(t *testing.T) {
	ctx := context.Background()
	f := newSuperAdminFixture(t)
	if err := f.start(t); err != nil {
		t.Fatalf("first start: %v", err)
	}
	before := f.snapshot(ctx, t)

	if err := f.start(t); err != nil {
		t.Fatalf("second start: %v", err)
	}
	// Later starts ignore the settings, including a changed or missing one.
	f.cfg.Modules.User.SuperAdmin = user.SuperAdminConfig{}
	if err := f.start(t); err != nil {
		t.Fatalf("third start without super admin settings: %v", err)
	}
	f.cfg.Modules.User.SuperAdmin = user.SuperAdminConfig{Email: "other@example.com", Password: "another-long-password"}
	if err := f.start(t); err != nil {
		t.Fatalf("fourth start with other settings: %v", err)
	}

	if after := f.snapshot(ctx, t); after != before {
		t.Errorf("state changed across restarts:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestSuperAdminBootstrapConcurrentPods starts several bootstraps at once, as
// pods of one deployment do. The advisory lock serializes them: exactly one
// super admin and one audit row result, and none of them fails.
func TestSuperAdminBootstrapConcurrentPods(t *testing.T) {
	ctx := context.Background()
	f := newSuperAdminFixture(t)
	// The default tenant must exist before the super admin joins it; a
	// start would create it, so create it the same way first.
	tenants := tenant.NewService(f.cfg.Modules.Tenant, tenant.NewRepository(f.db), nil, nil)
	if _, err := tenants.EnsureDefault(ctx); err != nil {
		t.Fatalf("EnsureDefault: %v", err)
	}

	const pods = 4
	var wg sync.WaitGroup
	errs := make(chan error, pods)
	for range pods {
		s := f.admins(t)
		wg.Go(func() { errs <- s.Bootstrap(ctx) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Bootstrap() = %v", err)
		}
	}
	var n int
	if err := f.db.Leader().QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if n != 1 {
		t.Errorf("%d users after %d concurrent bootstraps, want 1", n, pods)
	}
	if n := auditActions(ctx, t, f.db, audit.ActionSuperAdminCreate); n != 1 {
		t.Errorf("%d superadmin.create rows, want 1", n)
	}
}

// TestSuperAdminBootstrapRefusesToStart covers the first-start failures: no
// settings, a password that breaks the policy, and an address that already
// belongs to an ordinary account. Each one stops the start and, because the
// bootstrap is one transaction, leaves nothing behind.
func TestSuperAdminBootstrapRefusesToStart(t *testing.T) {
	tests := []struct {
		name    string
		cfg     user.SuperAdminConfig
		preload bool
		want    error
	}{
		{name: "no settings", cfg: user.SuperAdminConfig{}, want: user.ErrSuperAdminNotConfigured},
		{
			name: "password breaks the policy",
			cfg:  user.SuperAdminConfig{Email: "root@example.com", Password: "short"},
			want: password.ErrTooShort,
		},
		{
			name: "common password",
			cfg:  user.SuperAdminConfig{Email: "root@example.com", Password: "1234567890"},
			want: password.ErrTooCommon,
		},
		{name: "email already registered", cfg: testSuperAdmin, preload: true, want: user.ErrSuperAdminEmailTaken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			f := newSuperAdminFixture(t)
			f.cfg.Modules.User.SuperAdmin = tt.cfg
			if tt.preload {
				if _, err := f.users(t).Create(ctx, &user.CreateParams{
					Email: tt.cfg.Email, Status: user.StatusActive,
				}, ""); err != nil {
					t.Fatalf("preload user: %v", err)
				}
			}
			before := f.snapshot(ctx, t)
			err := f.start(t)
			if !errors.Is(err, tt.want) {
				t.Fatalf("start = %v, want %v", err, tt.want)
			}
			if after := f.snapshot(ctx, t); after != before {
				t.Errorf("a failed start left rows behind:\nbefore:\n%s\nafter:\n%s", before, after)
			}
			var tenants int
			if err := f.db.Leader().QueryRowContext(ctx, `SELECT count(*) FROM tenants`).Scan(&tenants); err != nil {
				t.Fatalf("count tenants: %v", err)
			}
			if tenants != 0 {
				t.Errorf("%d tenants after a failed start, want 0 (one transaction)", tenants)
			}
		})
	}
}

// TestSuperAdminReset is the reset acceptance criterion: the temporary
// password verifies and the old one does not, must_change_password is set,
// every session is revoked, a lockout is cleared and the reset is audited.
func TestSuperAdminReset(t *testing.T) {
	ctx := context.Background()
	f := newSuperAdminFixture(t)
	if err := f.start(t); err != nil {
		t.Fatalf("start: %v", err)
	}
	sa := f.superAdmin(ctx, t)
	users := f.users(t)

	// The admin has signed in and chosen a password, then got locked out.
	if err := users.SetPassword(ctx, sa.ID, mustHash(t, "chosen-later-password")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	until := time.Now().Add(time.Hour)
	if err := users.Lock(ctx, sa.ID, &until); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	sessions := f.sessions()
	tenantID := mustDefaultTenant(ctx, t, f)
	issued, err := sessions.Issue(ctx, sa.ID, tenantID, session.Device{UserAgent: "cli-test"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	temp, err := f.admins(t).Reset(ctx, " ROOT@example.com ")
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if len(temp) < password.MinRunes {
		t.Errorf("temporary password has %d characters, want at least %d", len(temp), password.MinRunes)
	}
	if !verifies(ctx, t, users, sa.ID, temp) {
		t.Error("the temporary password does not verify")
	}
	if verifies(ctx, t, users, sa.ID, "chosen-later-password") {
		t.Error("the old password still verifies")
	}
	after, err := users.Get(ctx, sa.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !after.MustChangePassword || after.LockedUntil != nil || after.FailedLogins != 0 {
		t.Errorf("after reset = %+v, want must change password and no lock", after)
	}
	if !after.IsSuperAdmin {
		t.Error("reset cleared the super admin flag")
	}
	if _, err := sessions.Rotate(ctx, issued.Raw, session.Device{}); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("Rotate() after reset = %v, want ErrRevoked", err)
	}
	if n := auditActions(ctx, t, f.db, audit.ActionSuperAdminReset); n != 1 {
		t.Errorf("%d superadmin.reset rows, want 1", n)
	}

	// A second reset issues a different password.
	again, err := f.admins(t).Reset(ctx, "root@example.com")
	if err != nil {
		t.Fatalf("second Reset: %v", err)
	}
	if again == temp {
		t.Error("two resets produced the same temporary password")
	}
}

// TestSuperAdminResetRefusesOtherAccounts checks reset only ever touches the
// super admin: an ordinary account or an unknown address is refused and
// nothing changes.
func TestSuperAdminResetRefusesOtherAccounts(t *testing.T) {
	ctx := context.Background()
	f := newSuperAdminFixture(t)
	if err := f.start(t); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := f.users(t).Create(ctx, &user.CreateParams{
		Email: "member@example.com", Status: user.StatusActive,
	}, mustHash(t, "member-password-1")); err != nil {
		t.Fatalf("create member: %v", err)
	}
	before := f.snapshot(ctx, t)
	for _, email := range []string{"member@example.com", "nobody@example.com"} {
		if _, err := f.admins(t).Reset(ctx, email); !errors.Is(err, user.ErrNotSuperAdmin) {
			t.Errorf("Reset(%s) = %v, want ErrNotSuperAdmin", email, err)
		}
	}
	if after := f.snapshot(ctx, t); after != before {
		t.Errorf("a refused reset changed state:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestSuperAdminTransfer moves the flag to another active account: the new
// holder is flagged and a member of the default tenant, the old one is not
// flagged and its sessions are revoked, and the change is audited.
func TestSuperAdminTransfer(t *testing.T) {
	ctx := context.Background()
	f := newSuperAdminFixture(t)
	if err := f.start(t); err != nil {
		t.Fatalf("start: %v", err)
	}
	old := f.superAdmin(ctx, t)
	users := f.users(t)
	next, err := users.Create(ctx, &user.CreateParams{Email: "next@example.com", Status: user.StatusActive}, "")
	if err != nil {
		t.Fatalf("create next: %v", err)
	}
	tenantID := mustDefaultTenant(ctx, t, f)
	sessions := f.sessions()
	issued, err := sessions.Issue(ctx, old.ID, tenantID, session.Device{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	id, err := f.admins(t).Transfer(ctx, "Next@Example.com")
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if id != next.ID {
		t.Errorf("Transfer() = %v, want %v", id, next.ID)
	}
	if got := f.superAdmin(ctx, t); got.ID != next.ID {
		t.Errorf("super admin = %v after transfer, want %v", got.ID, next.ID)
	}
	if was, err := users.Get(ctx, old.ID); err != nil || was.IsSuperAdmin {
		t.Errorf("old holder = %+v, %v; want the flag cleared", was, err)
	}
	tenants := tenant.NewService(f.cfg.Modules.Tenant, tenant.NewRepository(f.db), nil, nil)
	if m, err := tenants.Member(ctx, tenantID, next.ID); err != nil || !m.Active() {
		t.Errorf("new holder membership = %+v, %v; want active", m, err)
	}
	if _, err := sessions.Rotate(ctx, issued.Raw, session.Device{}); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("old holder Rotate() = %v, want ErrRevoked", err)
	}
	if n := auditActions(ctx, t, f.db, audit.ActionSuperAdminTransfer); n != 1 {
		t.Errorf("%d superadmin.transfer rows, want 1", n)
	}
}

// TestSuperAdminTransferRefusals covers the transfers that must change
// nothing: to the current holder, to an account that cannot sign in, and to
// an unknown address.
func TestSuperAdminTransferRefusals(t *testing.T) {
	ctx := context.Background()
	f := newSuperAdminFixture(t)
	if err := f.start(t); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := f.users(t).Create(ctx, &user.CreateParams{Email: "pending@example.com"}, ""); err != nil {
		t.Fatalf("create pending: %v", err)
	}
	before := f.snapshot(ctx, t)
	tests := []struct {
		email string
		want  error
	}{
		{"root@example.com", user.ErrAlreadySuperAdmin},
		{"pending@example.com", user.ErrTransferInactive},
		{"nobody@example.com", errorz.ErrNotFound},
	}
	for _, tt := range tests {
		if _, err := f.admins(t).Transfer(ctx, tt.email); !errors.Is(err, tt.want) {
			t.Errorf("Transfer(%s) = %v, want %v", tt.email, err, tt.want)
		}
	}
	if after := f.snapshot(ctx, t); after != before {
		t.Errorf("a refused transfer changed state:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// failingAudit fails every write, to prove a transfer is one transaction.
type failingAudit struct{}

func (failingAudit) Write(context.Context, *user.AuditEvent) error { return errors.New("audit down") }

// TestSuperAdminTransferIsAtomic fails the last step of a transfer (the audit
// write) and checks the flag has not moved: the flag swap, the membership and
// the session revocation all roll back together.
func TestSuperAdminTransferIsAtomic(t *testing.T) {
	ctx := context.Background()
	f := newSuperAdminFixture(t)
	if err := f.start(t); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := f.users(t).Create(ctx, &user.CreateParams{
		Email: "next@example.com", Status: user.StatusActive,
	}, ""); err != nil {
		t.Fatalf("create next: %v", err)
	}
	old := f.superAdmin(ctx, t)
	if _, err := f.sessions().Issue(ctx, old.ID, mustDefaultTenant(ctx, t, f), session.Device{}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	before := f.snapshot(ctx, t)

	cipher, err := newEmailCipher(&f.cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("newEmailCipher: %v", err)
	}
	tenants := tenant.NewService(f.cfg.Modules.Tenant, tenant.NewRepository(f.db), nil, nil)
	broken := user.NewSuperAdmins(f.cfg.Modules.User.SuperAdmin, f.db,
		user.NewRepository(f.db, cipher), user.NewCredentialsRepository(f.db), &user.SuperAdminDeps{
			Passwords:   userPasswords{},
			Memberships: tenantMemberships{svc: tenants},
			Sessions:    f.sessions(),
			Audit:       failingAudit{},
		})
	if _, err := broken.Transfer(ctx, "next@example.com"); err == nil {
		t.Fatal("Transfer() with a failing audit = nil, want the error")
	}
	if after := f.snapshot(ctx, t); after != before {
		t.Errorf("a failed transfer left changes behind:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	var live int
	if err := f.db.Leader().QueryRowContext(ctx,
		`SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL`).Scan(&live); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if live != 1 {
		t.Errorf("%d live sessions after a failed transfer, want 1 (the revocation rolled back)", live)
	}
}

// TestSuperAdminCLIEntryPoints runs the exported reset and transfer the
// server binary calls, which open their own connection from the config.
func TestSuperAdminCLIEntryPoints(t *testing.T) {
	ctx := context.Background()
	f := newSuperAdminFixture(t)
	if err := f.start(t); err != nil {
		t.Fatalf("start: %v", err)
	}
	log := logger.NewNoOp()
	temp, err := SuperAdminReset(ctx, &f.cfg, log, "root@example.com")
	if err != nil {
		t.Fatalf("SuperAdminReset: %v", err)
	}
	if !verifies(ctx, t, f.users(t), f.superAdmin(ctx, t).ID, temp) {
		t.Error("the printed password does not verify")
	}
	next, err := f.users(t).Create(ctx, &user.CreateParams{Email: "next@example.com", Status: user.StatusActive}, "")
	if err != nil {
		t.Fatalf("create next: %v", err)
	}
	id, err := SuperAdminTransfer(ctx, &f.cfg, log, "next@example.com")
	if err != nil || id != next.ID {
		t.Fatalf("SuperAdminTransfer = %v, %v; want %v", id, err, next.ID)
	}
	if _, err := SuperAdminReset(ctx, &f.cfg, log, "root@example.com"); !errors.Is(err, user.ErrNotSuperAdmin) {
		t.Errorf("reset of the former holder = %v, want ErrNotSuperAdmin", err)
	}
}

// mustHash hashes plain with the production parameters.
func mustHash(t *testing.T, plain string) string {
	t.Helper()
	h, err := password.Hash(plain)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	return h
}

// mustDefaultTenant returns the default tenant's ID.
func mustDefaultTenant(ctx context.Context, t *testing.T, f *superAdminFixture) uuid.UUID {
	t.Helper()
	id, err := tenant.NewService(f.cfg.Modules.Tenant, tenant.NewRepository(f.db), nil, nil).DefaultID(ctx)
	if err != nil {
		t.Fatalf("DefaultID: %v", err)
	}
	return id
}
