package identity_test

import (
	"context"
	"io/fs"
	"net/http"
	"testing"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/go-chi/chi/v5"

	identity "github.com/biairmal/go-identity"
	"github.com/biairmal/go-identity/internal/app"
	"github.com/biairmal/go-identity/internal/module/user"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// testConfig builds a valid Config over the test kit's migrated Postgres,
// the same way the standalone app's own integration tests do.
func testConfig(t *testing.T) identity.Config {
	t.Helper()
	cfg, err := app.LoadConfig("", "config/config.yaml")
	if err != nil {
		t.Fatalf("default config.yaml must be valid: %v", err)
	}
	cfg.Modules.Auth.Token.SigningKeysDir = testkit.SigningKeys(t, "test-key")
	cfg.Modules.User.SuperAdmin = user.SuperAdminConfig{
		Email:    "root@example.com",
		Password: "first-start-password-42",
	}
	cfg.Database = testkit.PostgresConfig(t)
	return cfg
}

// TestRegisterMountsAlongsideHostRoutes proves a chi host can mount identity
// on its own router (TRD 1.1 "mounted" mode) and keep serving its own route
// from the same binary (IMPLEMENTATION_PLAN T7.2 acceptance).
func TestRegisterMountsAlongsideHostRoutes(t *testing.T) {
	cfg := testConfig(t)

	r := chi.NewRouter()

	db, err := sqlkit.New(context.Background(), &cfg.Database)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("db close: %v", err)
		}
	})

	// Register uses r.Use internally, which chi refuses once a route is
	// already defined on r; the host adds its own routes after this call.
	if err := identity.Register(r, identity.Deps{DB: db, Log: logger.NewNoOp(), Config: cfg}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	r.Get("/host/ping", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	srv := testkit.Server(t, r)

	if s := testkit.Do[any](t, srv, http.MethodGet, "/host/ping", nil, nil).Status; s != http.StatusNoContent {
		t.Errorf("GET /host/ping = %d, want 204 (host's own route)", s)
	}
	if s := testkit.Do[any](t, srv, http.MethodGet, "/healthz", nil, nil).Status; s != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200 (identity's own route)", s)
	}
	if s := testkit.Do[any](t, srv, http.MethodGet, "/readyz", nil, nil).Status; s != http.StatusOK {
		t.Errorf("GET /readyz = %d, want 200: mounted mode has no Serve step to flip it", s)
	}

	// The DB connection stays open after Register returns: a second call
	// using the same db proves Register never closed it.
	if err := db.Leader().PingContext(context.Background()); err != nil {
		t.Errorf("db still usable after Register: %v", err)
	}
}

// TestRegisterFailsOnStaleSchema proves Register trusts the host to run
// identity.Migrations() first: it refuses to serve against a database behind
// the newest migration, the same guard standalone New uses.
func TestRegisterFailsOnStaleSchema(t *testing.T) {
	cfg := testConfig(t)
	db, err := sqlkit.New(context.Background(), &cfg.Database)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("db close: %v", err)
		}
	})
	if _, err := db.Leader().ExecContext(context.Background(), "delete from goose_db_version"); err != nil {
		t.Fatalf("clear migration history: %v", err)
	}

	if err := identity.Register(chi.NewRouter(), identity.Deps{DB: db, Log: logger.NewNoOp(), Config: cfg}); err == nil {
		t.Fatal("Register succeeded against a database with no migration history, want an error")
	}
}

// TestMigrationsIsIdentitysEmbeddedSet proves Migrations() exposes a
// non-empty *.sql set, so a host running it with its own migration tool ends
// up on the schema Register expects.
func TestMigrationsIsIdentitysEmbeddedSet(t *testing.T) {
	files, err := fs.Glob(identity.Migrations(), "*.sql")
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("Migrations() has no *.sql files")
	}
}
