package audit

import (
	"context"
	"testing"

	"github.com/biairmal/go-sdk/lib/ctxkit"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/requestip"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// storedRow is one audit_log row read back by the tests.
type storedRow struct {
	TenantID   *uuid.UUID
	ActorID    *uuid.UUID
	Action     string
	TargetType string
	TargetID   string
	Before     *string
	After      *string
	IP         *string
	RequestID  string
}

// TestWriteRecordsTheEvent checks a written event lands with its context
// metadata, and that the optional fields become NULL rather than zero values.
func TestWriteRecordsTheEvent(t *testing.T) {
	db := testkit.Postgres(t)
	w := newTestWriter(db)
	tenantID, actorID := uuid.New(), uuid.New()

	ctx := requestip.With(ctxkit.WithRequestID(context.Background(), "req-1"), "203.0.113.7")
	err := w.Write(ctx, &Event{
		TenantID:   tenantID,
		ActorID:    actorID,
		Action:     ActionRoleUpdate,
		TargetType: TargetRole,
		TargetID:   "role-7",
		Before:     map[string]any{"name": "editor"},
		After:      map[string]any{"name": "publisher"},
	})
	if err != nil {
		t.Fatalf("Write() = %v", err)
	}

	rows := readAll(context.Background(), t, db)
	if len(rows) != 1 {
		t.Fatalf("got %d audit rows, want 1", len(rows))
	}
	got := rows[0]
	if got.Action != string(ActionRoleUpdate) {
		t.Errorf("action = %q, want %q", got.Action, ActionRoleUpdate)
	}
	if got.TenantID == nil || *got.TenantID != tenantID {
		t.Errorf("tenant_id = %v, want %v", got.TenantID, tenantID)
	}
	if got.ActorID == nil || *got.ActorID != actorID {
		t.Errorf("actor_id = %v, want %v", got.ActorID, actorID)
	}
	if got.TargetType != TargetRole || got.TargetID != "role-7" {
		t.Errorf("target = %q/%q, want role/role-7", got.TargetType, got.TargetID)
	}
	if got.RequestID != "req-1" {
		t.Errorf("request_id = %q, want req-1 from the context", got.RequestID)
	}
	if got.IP == nil || *got.IP != "203.0.113.7" {
		t.Errorf("ip = %v, want 203.0.113.7 from the context", got.IP)
	}
	if got.Before == nil || *got.Before != `{"name": "editor"}` {
		t.Errorf("before = %v, want the encoded state", got.Before)
	}
	if got.After == nil || *got.After != `{"name": "publisher"}` {
		t.Errorf("after = %v, want the encoded state", got.After)
	}
}

// TestWriteAnonymousEvent checks a failed sign-in, which has no actor, no
// tenant and no state, stores NULLs instead of zero UUIDs.
func TestWriteAnonymousEvent(t *testing.T) {
	db := testkit.Postgres(t)
	w := newTestWriter(db)

	if err := w.Write(context.Background(), &Event{Action: ActionLoginFailed}); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	rows := readAll(context.Background(), t, db)
	if len(rows) != 1 {
		t.Fatalf("got %d audit rows, want 1", len(rows))
	}
	got := rows[0]
	if got.TenantID != nil || got.ActorID != nil {
		t.Errorf("tenant_id = %v and actor_id = %v, want both NULL", got.TenantID, got.ActorID)
	}
	if got.Before != nil || got.After != nil {
		t.Errorf("before = %v and after = %v, want both NULL", got.Before, got.After)
	}
	if got.IP != nil {
		t.Errorf("ip = %v, want NULL without a request IP", got.IP)
	}
	if got.TargetType != "" || got.TargetID != "" || got.RequestID != "" {
		t.Error("absent text fields should be empty strings, not NULL")
	}
}

// TestWriteJoinsTheCallersTransaction is the guarantee the audit log rests on:
// an event written inside a transaction that rolls back leaves no row, so a
// change and its audit entry can never diverge.
func TestWriteJoinsTheCallersTransaction(t *testing.T) {
	db := testkit.Postgres(t)
	w := newTestWriter(db)
	ctx := context.Background()

	wantErr := errRollback
	err := database.WithTx(ctx, db, func(ctx context.Context) error {
		if err := w.Write(ctx, &Event{Action: ActionRoleCreate}); err != nil {
			return err
		}
		return wantErr
	})
	if err == nil {
		t.Fatal("WithTx() = nil, want the rollback error")
	}
	if rows := readAll(ctx, t, db); len(rows) != 0 {
		t.Fatalf("got %d audit rows after a rollback, want 0", len(rows))
	}

	// The same write in a committed transaction is kept.
	if err := database.WithTx(ctx, db, func(ctx context.Context) error {
		return w.Write(ctx, &Event{Action: ActionRoleCreate})
	}); err != nil {
		t.Fatalf("WithTx() = %v", err)
	}
	if rows := readAll(ctx, t, db); len(rows) != 1 {
		t.Fatalf("got %d audit rows after a commit, want 1", len(rows))
	}
}

// errRollback is returned by a test transaction to roll it back.
var errRollback = &rollbackError{}

type rollbackError struct{}

func (*rollbackError) Error() string { return "rollback" }

// newTestWriter builds a Writer with a silent logger.
func newTestWriter(db *sqlkit.DB) *Writer {
	return NewWriter(NewRepository(db), nil)
}

// readAll returns every audit row, oldest first.
func readAll(ctx context.Context, t *testing.T, db *sqlkit.DB) []storedRow {
	t.Helper()
	rows, err := db.Leader().QueryContext(ctx, `
		SELECT tenant_id, actor_id, action, target_type, target_id,
		       before::text, after::text, host(ip), request_id
		FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatalf("read audit_log: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []storedRow
	for rows.Next() {
		var r storedRow
		if err := rows.Scan(&r.TenantID, &r.ActorID, &r.Action, &r.TargetType, &r.TargetID,
			&r.Before, &r.After, &r.IP, &r.RequestID); err != nil {
			t.Fatalf("scan audit_log: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}
