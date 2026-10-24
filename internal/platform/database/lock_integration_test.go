package database_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// TestLockXactSerializesTransactions holds the lock in one transaction and
// checks a second transaction waits for it: the critical sections never
// overlap.
func TestLockXactSerializesTransactions(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	const key = 42

	var inside, overlaps atomic.Int32
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			err := database.WithTx(ctx, db, func(ctx context.Context) error {
				if err := database.LockXact(ctx, key); err != nil {
					return err
				}
				if inside.Add(1) > 1 {
					overlaps.Add(1)
				}
				time.Sleep(50 * time.Millisecond)
				inside.Add(-1)
				return nil
			})
			if err != nil {
				t.Errorf("WithTx: %v", err)
			}
		})
	}
	wg.Wait()
	if n := overlaps.Load(); n != 0 {
		t.Errorf("%d overlapping critical sections, want 0", n)
	}
}

// TestLockXactNeedsATransaction checks the lock refuses to run where it would
// be released immediately.
func TestLockXactNeedsATransaction(t *testing.T) {
	if err := database.LockXact(context.Background(), 1); !errors.Is(err, database.ErrNoTransaction) {
		t.Fatalf("LockXact() outside a transaction = %v, want ErrNoTransaction", err)
	}
}

// TestInTxJoinsOrOpens checks InTx reuses the caller's transaction (a
// rollback undoes its work) and opens its own when there is none.
func TestInTxJoinsOrOpens(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	insert := func(ctx context.Context) error {
		_, err := database.Leader(ctx, db).ExecContext(ctx,
			`INSERT INTO outbox (topic, payload) VALUES ('test.intx', '{}')`)
		return err
	}
	count := func() int {
		var n int
		if err := db.Leader().QueryRowContext(ctx,
			`SELECT count(*) FROM outbox WHERE topic = 'test.intx'`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	rollback := errors.New("rollback")
	err := database.WithTx(ctx, db, func(ctx context.Context) error {
		if err := database.InTx(ctx, db, insert); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("WithTx = %v, want the rollback error", err)
	}
	if n := count(); n != 0 {
		t.Fatalf("%d rows after the outer rollback, want 0: InTx did not join", n)
	}

	if err := database.InTx(ctx, db, insert); err != nil {
		t.Fatalf("InTx without a transaction: %v", err)
	}
	if n := count(); n != 1 {
		t.Fatalf("%d rows after a standalone InTx, want 1", n)
	}
}
