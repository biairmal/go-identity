package database_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/testkit"
	"github.com/biairmal/go-identity/migrations"
)

func TestMigrationsUpDownUp(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	m, err := database.NewMigrator(db.Leader(), migrations.FS)
	if err != nil {
		t.Fatalf("NewMigrator: %v", err)
	}

	if res, err := m.Up(ctx); err != nil || len(res) != 0 {
		t.Fatalf("second Up should be a no-op: %d results, err %v", len(res), err)
	}
	if err := m.EnsureCurrent(ctx); err != nil {
		t.Fatalf("EnsureCurrent on a current schema: %v", err)
	}

	if _, err := m.DownTo(ctx, 0); err != nil {
		t.Fatalf("DownTo(0): %v", err)
	}
	if tableExists(t, db, "outbox") {
		t.Fatal("outbox still exists after reverting every migration")
	}
	if err := m.EnsureCurrent(ctx); !errors.Is(err, errorz.ErrPreconditionFailed) {
		t.Fatalf("EnsureCurrent behind = %v, want precondition failed", err)
	}

	if _, err := m.Up(ctx); err != nil {
		t.Fatalf("Up after DownTo(0): %v", err)
	}
	if !tableExists(t, db, "outbox") {
		t.Fatal("outbox missing after re-applying migrations")
	}
}

func TestOutboxEnqueueJoinsTransaction(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	ob := database.NewOutbox(db)
	rollback := errors.New("rollback")

	err := database.WithTx(ctx, db, func(ctx context.Context) error {
		if err := ob.Enqueue(ctx, "mail.send", "k", map[string]string{"to": "x"}); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("WithTx = %v, want the rollback error", err)
	}
	if n := countOutbox(t, db, ""); n != 0 {
		t.Fatalf("rolled-back enqueue left %d rows", n)
	}

	if err := database.WithTx(ctx, db, func(ctx context.Context) error {
		return ob.Enqueue(ctx, "mail.send", "k", map[string]string{"to": "x"})
	}); err != nil {
		t.Fatalf("committed enqueue: %v", err)
	}
	if n := countOutbox(t, db, ""); n != 1 {
		t.Fatalf("committed enqueue left %d rows, want 1", n)
	}
}

func TestDispatchersNeverSendARowTwice(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	ob := database.NewOutbox(db)
	const rows = 300
	for i := range rows {
		if err := ob.Enqueue(ctx, "t", "", i); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	var mu sync.Mutex
	sent := map[int64]int{}
	sender := database.SenderFunc(func(_ context.Context, m database.Message) error {
		mu.Lock()
		defer mu.Unlock()
		sent[m.ID]++
		return nil
	})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := database.NewDispatcher(db, map[string]database.Sender{"t": sender}, nil)
			for {
				n, err := d.DispatchOnce(ctx)
				if err != nil {
					t.Errorf("DispatchOnce: %v", err)
					return
				}
				if n == 0 {
					return
				}
			}
		}()
	}
	wg.Wait()

	if len(sent) != rows {
		t.Fatalf("sent %d distinct rows, want %d", len(sent), rows)
	}
	for id, n := range sent {
		if n != 1 {
			t.Fatalf("row %d sent %d times", id, n)
		}
	}
	if n := countOutbox(t, db, "sent_at IS NULL"); n != 0 {
		t.Fatalf("%d rows still unsent", n)
	}
}

func TestDispatcherRecordsFailures(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	ob := database.NewOutbox(db)
	_ = ob.Enqueue(ctx, "fails", "", 1)
	_ = ob.Enqueue(ctx, "no-sender", "", 2)

	var calls atomic.Int32
	failing := database.SenderFunc(func(context.Context, database.Message) error {
		calls.Add(1)
		return errors.New("smtp down")
	})
	d := database.NewDispatcher(db, map[string]database.Sender{"fails": failing}, nil)
	if n, err := d.DispatchOnce(ctx); err != nil || n != 2 {
		t.Fatalf("first DispatchOnce = %d, %v; want 2 claimed", n, err)
	}
	if n := countOutbox(t, db, "attempts = 1 AND last_error <> '' AND sent_at IS NULL"); n != 2 {
		t.Fatalf("%d rows recorded the failure, want 2", n)
	}
	// Both rows are now in backoff (1 s after creation at the earliest).
	if n, err := d.DispatchOnce(ctx); err != nil || n != 0 {
		t.Fatalf("DispatchOnce inside backoff = %d, %v; want 0", n, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("sender called %d times, want 1", calls.Load())
	}
}

func tableExists(t *testing.T, db *sqlkit.DB, name string) bool {
	t.Helper()
	var ok bool
	err := db.Leader().QueryRowContext(context.Background(),
		`SELECT to_regclass('identity.' || $1) IS NOT NULL`, name).Scan(&ok)
	if err != nil {
		t.Fatalf("tableExists: %v", err)
	}
	return ok
}

func countOutbox(t *testing.T, db *sqlkit.DB, where string) int {
	t.Helper()
	q := `SELECT count(*) FROM outbox`
	if where != "" {
		q += " WHERE " + where
	}
	var n int
	if err := db.Leader().QueryRowContext(context.Background(), q).Scan(&n); err != nil {
		t.Fatalf("countOutbox: %v", err)
	}
	return n
}
