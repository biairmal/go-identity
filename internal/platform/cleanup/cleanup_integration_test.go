package cleanup

import (
	"context"
	"testing"
	"time"

	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// now is the fixed point the fake clock starts at.
var now = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

// TestRunOnceRemovesOnlyRowsPastTheirWindow is the acceptance criterion: each
// table keeps the rows inside its retention window and drops the rest.
func TestRunOnceRemovesOnlyRowsPastTheirWindow(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	clk := testkit.NewClock(now)
	job := New(db, clk, nil)

	userID, tenantID := seedUserAndTenant(ctx, t, db)

	// oauth_states: expiry alone decides, with no retention window.
	insertOAuthState(ctx, t, db, "live", now.Add(time.Minute))
	insertOAuthState(ctx, t, db, "dead", now.Add(-time.Minute))

	// one_time_tokens: kept for the retention window after use or expiry.
	insertOneTimeToken(ctx, t, db, userID, "fresh", now.Add(time.Hour), nil)
	insertOneTimeToken(ctx, t, db, userID, "recently-expired", now.Add(-time.Hour), nil)
	insertOneTimeToken(ctx, t, db, userID, "long-expired", now.Add(-retention-time.Hour), nil)
	usedLongAgo := now.Add(-retention - time.Hour)
	insertOneTimeToken(ctx, t, db, userID, "used-long-ago", now.Add(time.Hour), &usedLongAgo)

	// refresh_tokens: revoked or past the absolute expiry, plus retention.
	insertRefreshToken(ctx, t, db, userID, tenantID, "live", now.Add(time.Hour), nil)
	insertRefreshToken(ctx, t, db, userID, tenantID, "recently-revoked", now.Add(time.Hour), ptr(now.Add(-time.Hour)))
	insertRefreshToken(ctx, t, db, userID, tenantID, "long-revoked", now.Add(time.Hour),
		ptr(now.Add(-retention-time.Hour)))
	insertRefreshToken(ctx, t, db, userID, tenantID, "long-dead", now.Add(-retention-time.Hour), nil)

	// outbox: sent rows go after a week, unsendable ones after retention.
	insertOutbox(ctx, t, db, "sent-recently", now.Add(-time.Hour), ptr(now.Add(-time.Hour)))
	insertOutbox(ctx, t, db, "sent-long-ago", now.Add(-sentRetention-time.Hour),
		ptr(now.Add(-sentRetention-time.Hour)))
	insertOutbox(ctx, t, db, "unsent-recent", now.Add(-time.Hour), nil)
	insertOutbox(ctx, t, db, "unsent-ancient", now.Add(-retention-time.Hour), nil)

	deleted, err := job.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce() = %v", err)
	}
	for table, want := range map[string]int64{
		"oauth_states": 1, "one_time_tokens": 2, "refresh_tokens": 2,
		"outbox_sent": 1, "outbox_unsendable": 1,
	} {
		if deleted[table] != want {
			t.Errorf("deleted[%s] = %d, want %d", table, deleted[table], want)
		}
	}

	assertKeys(ctx, t, db, `SELECT nonce FROM oauth_states`, []string{"live"})
	assertKeys(ctx, t, db,
		`SELECT payload->>'label' FROM one_time_tokens`, []string{"fresh", "recently-expired"})
	assertKeys(ctx, t, db,
		`SELECT user_agent FROM refresh_tokens`, []string{"live", "recently-revoked"})
	assertKeys(ctx, t, db,
		`SELECT key FROM outbox`, []string{"sent-recently", "unsent-recent"})
}

// TestRunOnceOnAnEmptyDatabase checks the job is a no-op when there is
// nothing to delete, so a daily run on a quiet system does nothing.
func TestRunOnceOnAnEmptyDatabase(t *testing.T) {
	db := testkit.Postgres(t)
	job := New(db, testkit.NewClock(now), nil)

	deleted, err := job.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() = %v", err)
	}
	for table, n := range deleted {
		if n != 0 {
			t.Errorf("deleted[%s] = %d on an empty database, want 0", table, n)
		}
	}
}

// TestRunOnceRespectsTheBatchSize checks one pass is bounded, so a large
// backlog never locks a table for long, and that repeating drains it.
func TestRunOnceRespectsTheBatchSize(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	job := New(db, testkit.NewClock(now), nil)
	job.batch = 2

	for i := range 5 {
		insertOAuthState(ctx, t, db, "dead-"+string(rune('a'+i)), now.Add(-time.Hour))
	}

	deleted, err := job.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce() = %v", err)
	}
	if deleted["oauth_states"] != 2 {
		t.Fatalf("first pass deleted %d rows, want the batch size of 2", deleted["oauth_states"])
	}

	// Repeating drains the rest: 2, then the last 1.
	total := deleted["oauth_states"]
	for range 5 {
		d, err := job.RunOnce(ctx)
		if err != nil {
			t.Fatalf("RunOnce() = %v", err)
		}
		total += d["oauth_states"]
		if d["oauth_states"] == 0 {
			break
		}
	}
	if total != 5 {
		t.Errorf("drained %d rows in total, want 5", total)
	}
}

// ptr returns a pointer to t, for the nullable timestamp columns.
func ptr(t time.Time) *time.Time { return &t }

// seedUserAndTenant creates the rows the token tables point at.
func seedUserAndTenant(ctx context.Context, t *testing.T, db *sqlkit.DB) (userID, tenantID uuid.UUID) {
	t.Helper()
	err := db.Leader().QueryRowContext(ctx,
		`INSERT INTO tenants (slug, name) VALUES ('cleanup', 'Cleanup') RETURNING id`).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	err = db.Leader().QueryRowContext(ctx,
		`INSERT INTO users (email_enc, email_hash) VALUES ('enc', 'hash') RETURNING id`).Scan(&userID)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return userID, tenantID
}

func insertOAuthState(ctx context.Context, t *testing.T, db *sqlkit.DB, label string, expires time.Time) {
	t.Helper()
	_, err := db.Leader().ExecContext(ctx,
		`INSERT INTO oauth_states (state_hash, code_verifier, nonce, redirect_to, expires_at)
		 VALUES ($1, 'verifier', $2, 'https://app.example.com', $3)`,
		[]byte(label), label, expires)
	if err != nil {
		t.Fatalf("insert oauth_state %s: %v", label, err)
	}
}

func insertOneTimeToken(
	ctx context.Context, t *testing.T, db *sqlkit.DB,
	userID uuid.UUID, label string, expires time.Time, used *time.Time,
) {
	t.Helper()
	_, err := db.Leader().ExecContext(ctx,
		`INSERT INTO one_time_tokens (user_id, purpose, token_hash, payload, expires_at, used_at)
		 VALUES ($1, 'verify_email', $2, jsonb_build_object('label', $3::text), $4, $5)`,
		userID, []byte(label), label, expires, used)
	if err != nil {
		t.Fatalf("insert one_time_token %s: %v", label, err)
	}
}

func insertRefreshToken(
	ctx context.Context, t *testing.T, db *sqlkit.DB,
	userID, tenantID uuid.UUID, label string, absoluteExpiry time.Time, revoked *time.Time,
) {
	t.Helper()
	_, err := db.Leader().ExecContext(ctx,
		`INSERT INTO refresh_tokens
			(family_id, user_id, tenant_id, token_hash, expires_at, absolute_expires_at, revoked_at, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $5, $6, $7)`,
		uuid.New(), userID, tenantID, []byte(label), absoluteExpiry, revoked, label)
	if err != nil {
		t.Fatalf("insert refresh_token %s: %v", label, err)
	}
}

func insertOutbox(
	ctx context.Context, t *testing.T, db *sqlkit.DB, label string, created time.Time, sent *time.Time,
) {
	t.Helper()
	_, err := db.Leader().ExecContext(ctx,
		`INSERT INTO outbox (topic, key, payload, created_at, sent_at)
		 VALUES ('mail.send', $1, '{}', $2, $3)`, label, created, sent)
	if err != nil {
		t.Fatalf("insert outbox %s: %v", label, err)
	}
}

// assertKeys checks the surviving rows are exactly want, in any order.
func assertKeys(ctx context.Context, t *testing.T, db *sqlkit.DB, query string, want []string) {
	t.Helper()
	rows, err := db.Leader().QueryContext(ctx, query)
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]bool{}
	for rows.Next() {
		var label string
		if err := rows.Scan(&label); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[label] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(got) != len(want) {
		t.Errorf("%q left %v, want exactly %v", query, keys(got), want)
		return
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("%q removed %q, which is inside its retention window", query, w)
		}
	}
}

// keys lists a set, for failure messages.
func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}
