package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/biairmal/go-sdk/lib/sqlkit"
)

// ErrNoTransaction reports a call that must run inside WithTx but did not.
var ErrNoTransaction = errors.New("database: no transaction in context")

// LockXact takes a transaction-scoped Postgres advisory lock on key and waits
// until it is granted. The lock is released when the surrounding transaction
// commits or rolls back, so it serializes a critical section across every pod
// that shares the database. It refuses to run outside a transaction, where
// the lock would be released at the end of its own statement and guard
// nothing.
func LockXact(ctx context.Context, key int64) error {
	tx, ok := sqlkit.ExtractTx(ctx)
	if !ok {
		return ErrNoTransaction
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, key); err != nil {
		return fmt.Errorf("database: advisory lock: %w", err)
	}
	return nil
}

// InTx runs fn in the context's transaction when there is one, or in a new
// one otherwise. A service step that must be atomic but may also be called
// from a larger transaction (a startup bootstrap) uses it instead of WithTx,
// which refuses to nest.
func InTx(ctx context.Context, db *sqlkit.DB, fn func(ctx context.Context) error) error {
	if _, ok := sqlkit.ExtractTx(ctx); ok {
		return fn(ctx)
	}
	return WithTx(ctx, db, fn)
}
