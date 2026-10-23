// Package testkit holds the helpers every integration test shares: a migrated
// Postgres per test package, a controllable clock and an HTTP test server with
// JSON helpers. Import it from tests only.
package testkit

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/migrations"
)

// Credentials of the test database. The app connects as the identity role
// created by deploy/sql/bootstrap.sql, exactly as in a real environment.
const (
	pgImage       = "postgres:16-alpine"
	pgDatabase    = "app"
	pgAdmin       = "postgres"
	pgPassword    = "postgres"
	identityRole  = "identity"
	identityPass  = "identity"
	startupBudget = 2 * time.Minute
)

// shared is the one container per test package (per test binary).
var shared struct {
	once sync.Once
	cfg  sqlkit.Config
	db   *sqlkit.DB
	err  error
}

// Postgres returns a migrated database connected as the identity role. The
// container starts once per test package; every call empties all identity
// tables first, so each test starts clean. Integration tests only: it skips
// under -short.
func Postgres(t *testing.T) *sqlkit.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test: needs Docker")
	}
	shared.once.Do(start)
	if shared.err != nil {
		t.Fatalf("testkit: start postgres: %v", shared.err)
	}
	if err := truncate(context.Background(), shared.db); err != nil {
		t.Fatalf("testkit: truncate: %v", err)
	}
	return shared.db
}

// PostgresConfig returns the connection settings of the Postgres container,
// for code that opens its own connection (such as app.New).
func PostgresConfig(t *testing.T) sqlkit.Config {
	t.Helper()
	Postgres(t)
	return shared.cfg
}

// start runs the container, the bootstrap script and the migrations. The
// container is removed by Testcontainers' reaper when the test binary exits.
func start() {
	ctx, cancel := context.WithTimeout(context.Background(), startupBudget)
	defer cancel()

	c, err := postgres.Run(ctx, pgImage,
		postgres.WithDatabase(pgDatabase),
		postgres.WithUsername(pgAdmin),
		postgres.WithPassword(pgPassword),
		postgres.BasicWaitStrategies(),
		testcontainers.WithFiles(testcontainers.ContainerFile{
			HostFilePath:      filepath.Join(repoRoot(), "deploy", "sql", "bootstrap.sql"),
			ContainerFilePath: "/bootstrap.sql",
			FileMode:          0o644,
		}),
	)
	if err != nil {
		shared.err = err
		return
	}
	if shared.err = bootstrap(ctx, c); shared.err != nil {
		return
	}
	if shared.cfg, shared.err = configFor(ctx, c); shared.err != nil {
		return
	}
	if shared.db, shared.err = sqlkit.New(ctx, &shared.cfg); shared.err != nil {
		return
	}
	m, err := database.NewMigrator(shared.db.Leader(), migrations.FS)
	if err != nil {
		shared.err = err
		return
	}
	_, shared.err = m.Up(ctx)
}

// bootstrap runs deploy/sql/bootstrap.sql as the admin, like an operator would.
func bootstrap(ctx context.Context, c *postgres.PostgresContainer) error {
	code, out, err := c.Exec(ctx, []string{
		"psql", "-v", "ON_ERROR_STOP=1", "-v", "identity_password=" + identityPass,
		"-U", pgAdmin, "-d", pgDatabase, "-f", "/bootstrap.sql",
	})
	if err != nil {
		return err
	}
	if code != 0 {
		b, rerr := io.ReadAll(out)
		if rerr != nil {
			return fmt.Errorf("bootstrap.sql exited %d: %w", code, rerr)
		}
		return fmt.Errorf("bootstrap.sql exited %d: %s", code, b)
	}
	return nil
}

// configFor builds the sqlkit config for the identity role on the container.
func configFor(ctx context.Context, c *postgres.PostgresContainer) (sqlkit.Config, error) {
	host, err := c.Host(ctx)
	if err != nil {
		return sqlkit.Config{}, err
	}
	port, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return sqlkit.Config{}, err
	}
	return sqlkit.Config{
		Leader: sqlkit.DBConfig{
			Driver: database.DriverName, Host: host, Port: int(port.Num()), Database: pgDatabase,
			Username: identityRole, Password: identityPass, SSLMode: "disable",
		},
		Health: sqlkit.HealthConfig{Enabled: true, CheckInterval: time.Second, Timeout: time.Second},
	}, nil
}

// truncate empties every table in the identity schema except goose's.
func truncate(ctx context.Context, db *sqlkit.DB) error {
	rows, err := db.Leader().QueryContext(ctx, `
		SELECT quote_ident(tablename) FROM pg_tables
		WHERE schemaname = 'identity' AND tablename <> 'goose_db_version'`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil || len(tables) == 0 {
		return err
	}
	_, err = db.Leader().ExecContext(ctx, "TRUNCATE "+strings.Join(tables, ", ")+" RESTART IDENTITY CASCADE")
	return err
}

// repoRoot is the module root, found from this file's location.
func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}
