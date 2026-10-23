// Package schema_test checks that the end state of all migrations matches the
// reference DDL in TRD 5.2. It lives outside internal/ because it needs both
// the test kit and the migration runner, and it is the one place that pins the
// whole schema: a migration that drifts from the TRD fails here.
package schema_test

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// update rewrites the golden file instead of comparing against it:
//
//	go test ./test/schema -update
//
// Review the diff it produces against TRD 5.2 before committing.
var update = flag.Bool("update", false, "rewrite testdata/schema.txt from the migrated database")

const goldenPath = "testdata/schema.txt"

// TestSchemaMatchesReference dumps the migrated schema in a normalised,
// ordered form and compares it with the golden file. Both the columns and the
// constraints are covered, so a missing CHECK or a changed default fails too.
func TestSchemaMatchesReference(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()

	got := strings.Join([]string{
		section("TABLES AND COLUMNS", dumpColumns(ctx, t, db)),
		section("CONSTRAINTS", dumpConstraints(ctx, t, db)),
		section("INDEXES", dumpIndexes(ctx, t, db)),
		section("PRIVILEGES", dumpPrivileges(ctx, t, db)),
	}, "\n")

	if *update {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o750); err != nil {
			t.Fatalf("create testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Log("golden file rewritten; review it against TRD 5.2")
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if diff := firstDiff(string(want), got); diff != "" {
		t.Fatalf("migrated schema differs from %s:\n%s\n\nRun with -update after checking TRD 5.2.", goldenPath, diff)
	}
}

// dumpColumns lists every column of every identity table with its type,
// nullability, default and identity generation.
func dumpColumns(ctx context.Context, t *testing.T, db *sqlkit.DB) []string {
	return query(ctx, t, db, `
		SELECT format('%s.%s %s%s%s%s',
		           c.table_name, c.column_name,
		           format_type(a.atttypid, a.atttypmod),
		           CASE WHEN c.is_nullable = 'NO' THEN ' NOT NULL' ELSE '' END,
		           CASE WHEN c.is_identity = 'YES'
		                THEN ' GENERATED ' || c.identity_generation || ' AS IDENTITY' ELSE '' END,
		           COALESCE(' DEFAULT ' || c.column_default, ''))
		FROM information_schema.columns c
		JOIN pg_class t  ON t.relname = c.table_name
		JOIN pg_namespace n ON n.oid = t.relnamespace AND n.nspname = c.table_schema
		JOIN pg_attribute a ON a.attrelid = t.oid AND a.attname = c.column_name
		WHERE c.table_schema = 'identity' AND c.table_name <> 'goose_db_version'
		ORDER BY c.table_name, c.ordinal_position`)
}

// dumpPrivileges records the table privileges the app role holds, so the
// append-only audit log cannot quietly become writable.
func dumpPrivileges(ctx context.Context, t *testing.T, db *sqlkit.DB) []string {
	return query(ctx, t, db, `
		SELECT format('%s %s: %s', table_name, grantee, string_agg(privilege_type, ', ' ORDER BY privilege_type))
		FROM information_schema.table_privileges
		WHERE table_schema = 'identity' AND table_name <> 'goose_db_version'
		GROUP BY table_name, grantee
		ORDER BY table_name, grantee`)
}

// dumpConstraints lists primary keys, unique and foreign keys and CHECKs.
// NOT NULL checks are excluded: they already show up as a column's NOT NULL.
func dumpConstraints(ctx context.Context, t *testing.T, db *sqlkit.DB) []string {
	return query(ctx, t, db, `
		SELECT format('%s %s %s', rel.relname, con.conname, pg_get_constraintdef(con.oid))
		FROM pg_constraint con
		JOIN pg_class rel ON rel.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = rel.relnamespace
		WHERE n.nspname = 'identity' AND rel.relname <> 'goose_db_version'
		ORDER BY rel.relname, con.conname`)
}

// dumpIndexes lists every index definition, including the partial ones that
// carry rules (one super admin, role names per tenant, unsent outbox rows).
func dumpIndexes(ctx context.Context, t *testing.T, db *sqlkit.DB) []string {
	return query(ctx, t, db, `
		SELECT indexdef
		FROM pg_indexes
		WHERE schemaname = 'identity' AND tablename <> 'goose_db_version'
		ORDER BY indexname`)
}

// query runs sql and returns its single text column.
func query(ctx context.Context, t *testing.T, db *sqlkit.DB, sql string) []string {
	t.Helper()
	rows, err := db.Leader().QueryContext(ctx, sql)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// section formats one titled block of the dump.
func section(title string, lines []string) string {
	var b strings.Builder
	b.WriteString("== " + title + " ==\n")
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return b.String()
}

// firstDiff reports the first differing line, which points straight at the
// migration that drifted.
func firstDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		lw, lg := at(w, i), at(g, i)
		if lw != lg {
			return "line " + itoa(i+1) + ":\n  golden:   " + lw + "\n  migrated: " + lg
		}
	}
	return ""
}

// at returns line i or a marker when the side has ended.
func at(lines []string, i int) string {
	if i >= len(lines) {
		return "(end of file)"
	}
	return lines[i]
}

// itoa avoids importing strconv for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
