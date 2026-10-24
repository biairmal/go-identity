package mail_test

import (
	"context"
	"errors"
	"testing"

	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/mail"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// recorder is a Mailer that remembers what it was asked to deliver.
type recorder struct {
	sent []mail.Message
	err  error
}

func (r *recorder) Send(_ context.Context, m *mail.Message) error {
	if r.err != nil {
		return r.err
	}
	r.sent = append(r.sent, *m)
	return nil
}

// TestQueuedMailInARolledBackTransactionIsNeverSent is the reason services
// queue instead of sending: the mail must share the fate of the change that
// triggered it.
func TestQueuedMailInARolledBackTransactionIsNeverSent(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	outbox := database.NewOutbox(db)
	rec := &recorder{}
	dispatcher := database.NewDispatcher(db, map[string]database.Sender{
		mail.Topic: mail.NewSender(rec, db),
	}, nil)

	failure := errors.New("the change failed")
	err := database.WithTx(ctx, db, func(ctx context.Context) error {
		if err := mail.Queue(ctx, outbox, message()); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("WithTx = %v, want the rollback error", err)
	}

	if n, err := dispatcher.DispatchOnce(ctx); err != nil || n != 0 {
		t.Fatalf("DispatchOnce after a rollback = %d, %v; want 0 rows", n, err)
	}
	if len(rec.sent) != 0 {
		t.Fatalf("the mailer was called %d times for a rolled-back mail", len(rec.sent))
	}
}

// TestQueuedMailIsSentAndLosesItsToken covers the committed path and the rule
// that a delivered row keeps no usable token.
func TestQueuedMailIsSentAndLosesItsToken(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	outbox := database.NewOutbox(db)
	rec := &recorder{}
	dispatcher := database.NewDispatcher(db, map[string]database.Sender{
		mail.Topic: mail.NewSender(rec, db),
	}, nil)

	if err := database.WithTx(ctx, db, func(ctx context.Context) error {
		return mail.Queue(ctx, outbox, message())
	}); err != nil {
		t.Fatalf("Queue in a committed transaction: %v", err)
	}

	if n, err := dispatcher.DispatchOnce(ctx); err != nil || n != 1 {
		t.Fatalf("DispatchOnce = %d, %v; want 1 row", n, err)
	}
	if len(rec.sent) != 1 {
		t.Fatalf("the mailer was called %d times, want 1", len(rec.sent))
	}
	got := rec.sent[0]
	if got.Token != "raw-token" || got.To != "bia@example.com" {
		t.Errorf("delivered message = %+v, want the queued one", got)
	}

	if n := countRows(t, db, `sent_at IS NOT NULL`); n != 1 {
		t.Errorf("%d rows marked sent, want 1", n)
	}
	if n := countRows(t, db, `payload ? 'token' AND payload->>'token' IS NOT NULL`); n != 0 {
		t.Error("a delivered mail row still carries its raw token")
	}
}

// TestFailedMailDeliveryKeepsTheToken checks a row that could not be sent
// keeps what the retry needs.
func TestFailedMailDeliveryKeepsTheToken(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	outbox := database.NewOutbox(db)
	rec := &recorder{err: errors.New("smtp down")}
	dispatcher := database.NewDispatcher(db, map[string]database.Sender{
		mail.Topic: mail.NewSender(rec, db),
	}, nil)

	if err := mail.Queue(ctx, outbox, message()); err != nil {
		t.Fatalf("Queue: %v", err)
	}
	if n, err := dispatcher.DispatchOnce(ctx); err != nil || n != 1 {
		t.Fatalf("DispatchOnce = %d, %v; want 1 row", n, err)
	}
	if n := countRows(t, db, `sent_at IS NULL AND attempts = 1 AND payload->>'token' = 'raw-token'`); n != 1 {
		t.Error("a failed mail row did not keep its payload for the retry")
	}
}

// message is the mail the tests queue.
func message() *mail.Message {
	return &mail.Message{
		To:       "bia@example.com",
		Subject:  "Confirm your email address",
		Template: "verify_email",
		LinkPath: "/verify-email",
		Token:    "raw-token",
	}
}

// countRows counts mail outbox rows matching where.
func countRows(t *testing.T, db *sqlkit.DB, where string) int {
	t.Helper()
	var n int
	err := db.Leader().QueryRowContext(context.Background(),
		`SELECT count(*) FROM outbox WHERE topic = $1 AND `+where, mail.Topic).Scan(&n)
	if err != nil {
		t.Fatalf("countRows: %v", err)
	}
	return n
}
