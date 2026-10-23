package schema_test

import (
	"context"
	"errors"
	"testing"

	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/testkit"
	"github.com/biairmal/go-identity/migrations"
)

// uniqueViolation is the Postgres error class for a broken unique constraint.
const uniqueViolation = "23505"

// TestMigrationsRoundTrip takes the schema down to nothing and back up, so
// every migration's Down is exercised and the second Up proves the files are
// re-runnable on an empty database.
func TestMigrationsRoundTrip(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()

	m, err := database.NewMigrator(db.Leader(), migrations.FS)
	if err != nil {
		t.Fatalf("new migrator: %v", err)
	}

	if _, err := m.DownTo(ctx, 0); err != nil {
		t.Fatalf("down to zero: %v", err)
	}
	if tables := tableCount(ctx, t, db); tables != 0 {
		t.Fatalf("after down to zero: %d identity tables left, want 0", tables)
	}

	if _, err := m.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if tables := tableCount(ctx, t, db); tables == 0 {
		t.Fatal("after up: no identity tables")
	}

	// Running Up with nothing pending must be a no-op, not an error.
	if _, err := m.Up(ctx); err != nil {
		t.Fatalf("up twice: %v", err)
	}
}

// TestOneSuperAdmin checks the partial unique index: the database refuses a
// second super admin, whatever the application code does.
func TestOneSuperAdmin(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()

	insert := func(hash string, super bool) error {
		_, err := db.Leader().ExecContext(ctx,
			`INSERT INTO users (email_enc, email_hash, is_super_admin) VALUES ($1, $2, $3)`,
			[]byte("enc-"+hash), []byte(hash), super)
		return err
	}

	if err := insert("first", true); err != nil {
		t.Fatalf("first super admin: %v", err)
	}
	err := insert("second", true)
	if err == nil {
		t.Fatal("second super admin was accepted, want a unique violation")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != uniqueViolation {
		t.Fatalf("second super admin: %v, want unique violation %s", err, uniqueViolation)
	}

	// Ordinary users are unaffected: the index only covers true.
	if err := insert("third", false); err != nil {
		t.Fatalf("non-super-admin user: %v", err)
	}
	if err := insert("fourth", false); err != nil {
		t.Fatalf("second non-super-admin user: %v", err)
	}
}

// TestRoleMustBelongToTheSameTenant checks the composite foreign key: a role
// from one tenant cannot be granted inside another.
func TestRoleMustBelongToTheSameTenant(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	conn := db.Leader()

	var tenantA, tenantB, userID, roleInA string
	// The slug pattern requires at least two characters.
	mustGet(ctx, t, db, &tenantA, `INSERT INTO tenants (slug, name) VALUES ('tenant-a', 'A') RETURNING id`)
	mustGet(ctx, t, db, &tenantB, `INSERT INTO tenants (slug, name) VALUES ('tenant-b', 'B') RETURNING id`)
	mustGet(ctx, t, db, &userID,
		`INSERT INTO users (email_enc, email_hash) VALUES ('enc', 'hash') RETURNING id`)
	mustGet(ctx, t, db, &roleInA,
		`INSERT INTO roles (tenant_id, name) VALUES ($1, 'admin') RETURNING id`, tenantA)

	// The user is a member of tenant B, and the role belongs to tenant A.
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO tenant_members (tenant_id, user_id) VALUES ($1, $2)`, tenantB, userID); err != nil {
		t.Fatalf("membership in B: %v", err)
	}
	_, err := conn.ExecContext(ctx,
		`INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES ($1, $2, $3)`, tenantB, userID, roleInA)
	if err == nil {
		t.Fatal("granting another tenant's role was accepted, want a foreign-key violation")
	}

	// The same grant inside the role's own tenant works, once the user is a
	// member there.
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO tenant_members (tenant_id, user_id) VALUES ($1, $2)`, tenantA, userID); err != nil {
		t.Fatalf("membership in A: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES ($1, $2, $3)`,
		tenantA, userID, roleInA); err != nil {
		t.Fatalf("granting the tenant's own role: %v", err)
	}
}

// TestAuditLogIsAppendOnly checks the app role may insert and read but not
// change or remove audit rows.
func TestAuditLogIsAppendOnly(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	conn := db.Leader()

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO audit_log (action) VALUES ('auth.login')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var action string
	mustGet(ctx, t, db, &action, `SELECT action FROM audit_log LIMIT 1`)
	if action != "auth.login" {
		t.Fatalf("read back %q, want auth.login", action)
	}
	if _, err := conn.ExecContext(ctx, `UPDATE audit_log SET action = 'tampered'`); err == nil {
		t.Error("UPDATE on audit_log was accepted, want permission denied")
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM audit_log`); err == nil {
		t.Error("DELETE on audit_log was accepted, want permission denied")
	}
}

// tableCount counts the identity tables, ignoring goose's own.
func tableCount(ctx context.Context, t *testing.T, db *sqlkit.DB) int {
	t.Helper()
	var n int
	row := db.Leader().QueryRowContext(ctx,
		`SELECT count(*) FROM pg_tables WHERE schemaname = 'identity' AND tablename <> 'goose_db_version'`)
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count tables: %v", err)
	}
	return n
}

// mustGet runs a one-value query and fails the test when it errors. It takes
// the database rather than calling testkit.Postgres again, which would
// truncate the rows the caller just inserted.
func mustGet(ctx context.Context, t *testing.T, db *sqlkit.DB, dst any, sql string, args ...any) {
	t.Helper()
	if err := db.Leader().QueryRowContext(ctx, sql, args...).Scan(dst); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
}
