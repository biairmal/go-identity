package database

import (
	"context"
	"database/sql"

	"github.com/biairmal/go-sdk/lib/sqlkit"
)

// Conn is what repositories run SQL on: the context transaction or the leader.
type Conn interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// WithTx runs fn in one leader transaction. Repositories called with the ctx
// fn receives (through GetConnection or Leader below) join that transaction,
// so a service can make several repositories' writes atomic. fn's error rolls
// everything back.
func WithTx(ctx context.Context, db *sqlkit.DB, fn func(ctx context.Context) error) error {
	return db.WithTransaction(ctx, fn)
}

// Leader returns the context transaction when there is one, else the leader.
// Use it for writes and for reads that must see them.
func Leader(ctx context.Context, db *sqlkit.DB) Conn {
	if tx, ok := sqlkit.ExtractTx(ctx); ok {
		return tx
	}
	return db.Leader()
}
