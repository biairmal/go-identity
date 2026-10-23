package database

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

// VersionTable is goose's version table. It is schema-qualified so several
// services can share one database without clashing.
const VersionTable = "identity.goose_db_version"

// Migrator applies the embedded migrations. It always runs on the leader and
// holds a Postgres advisory lock while migrating, so two runners never collide.
type Migrator struct {
	p *goose.Provider
}

// NewMigrator builds a Migrator over leader and the migration files in fsys.
func NewMigrator(leader *sql.DB, fsys fs.FS) (*Migrator, error) {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("migrate: build locker")
	}
	p, err := goose.NewProvider(goose.DialectPostgres, leader, fsys,
		goose.WithTableName(VersionTable),
		goose.WithSessionLocker(locker),
		goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("migrate: build provider")
	}
	return &Migrator{p: p}, nil
}

// Up applies every pending migration. Running it with nothing pending is a no-op.
func (m *Migrator) Up(ctx context.Context) ([]*goose.MigrationResult, error) {
	return m.p.Up(ctx)
}

// Down reverts the most recent migration.
func (m *Migrator) Down(ctx context.Context) (*goose.MigrationResult, error) {
	return m.p.Down(ctx)
}

// DownTo reverts migrations until version is the newest applied (0 reverts all).
func (m *Migrator) DownTo(ctx context.Context, version int64) ([]*goose.MigrationResult, error) {
	return m.p.DownTo(ctx, version)
}

// Status lists every migration with its applied state.
func (m *Migrator) Status(ctx context.Context) ([]*goose.MigrationStatus, error) {
	return m.p.Status(ctx)
}

// EnsureCurrent fails when the database is behind the newest embedded
// migration, so serve never runs against an old schema.
func (m *Migrator) EnsureCurrent(ctx context.Context) error {
	current, target, err := m.p.GetVersions(ctx)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("migrate: read schema version")
	}
	if current < target {
		return errorz.PreconditionFailed().WithMessage(fmt.Sprintf(
			"database schema is at version %d but this binary needs %d: run `server migrate up`", current, target))
	}
	return nil
}

// Create writes a new, empty SQL migration named name into dir, prefixed with
// the current timestamp.
func Create(dir, name string) error {
	return goose.Create(nil, dir, name, "sql")
}
