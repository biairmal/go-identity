package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
)

// Dispatcher defaults.
const (
	defaultBatchSize    = 100
	defaultPollInterval = time.Second
	// maxBackoffExponent caps the retry delay at 2^10 s (about 17 minutes).
	maxBackoffExponent = 10
	maxErrorLen        = 1000
)

// Expiry of a message. A payload may carry a top-level "expires_at" (RFC 3339)
// after which the message is worth nothing, like a mail whose one-time link
// has expired.
const (
	// ExpiredReason is the last_error of a row whose expires_at passed before
	// it was sent. Such a row is never handed to a Sender and never claimed
	// again; the cleanup job deletes it.
	ExpiredReason = "expired"
	// PayloadExpiresAt is the SQL for a row's expires_at: NULL when the
	// payload has none, or one that does not parse, so a malformed value
	// cannot fail the query that claims or cleans every other row.
	PayloadExpiresAt = `CASE WHEN pg_input_is_valid(payload->>'expires_at', 'timestamptz')
		THEN (payload->>'expires_at')::timestamptz END`
)

// Message is one outbox row handed to a Sender.
type Message struct {
	ID       int64
	Topic    string
	Key      string
	Payload  json.RawMessage
	Attempts int
}

// claimedRow is a claimed Message and whether its expires_at has passed.
type claimedRow struct {
	Message
	expired bool
}

// Sender delivers messages of one topic (an email, a queue publish). It must
// tolerate duplicates: a crash after sending but before commit resends.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// SenderFunc adapts a function to Sender.
type SenderFunc func(ctx context.Context, m Message) error

// Send calls f.
func (f SenderFunc) Send(ctx context.Context, m Message) error { return f(ctx, m) }

// Outbox writes messages in the caller's transaction.
type Outbox struct {
	db *sqlkit.DB
}

// NewOutbox returns an Outbox over db.
func NewOutbox(db *sqlkit.DB) *Outbox { return &Outbox{db: db} }

// Enqueue stores payload (JSON-encoded) for topic. Inside WithTx it joins the
// transaction, so a rollback drops the message too.
func (o *Outbox) Enqueue(ctx context.Context, topic, key string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("outbox: encode payload")
	}
	_, err = Leader(ctx, o.db).ExecContext(ctx,
		`INSERT INTO outbox (topic, key, payload) VALUES ($1, $2, $3)`, topic, key, b)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("outbox: enqueue")
	}
	return nil
}

// Dispatcher sends unsent outbox rows. Several dispatchers (worker pods) may
// run at once: rows are claimed with FOR UPDATE SKIP LOCKED and stay locked
// until their send is recorded, so no row is sent twice concurrently.
type Dispatcher struct {
	db       *sqlkit.DB
	senders  map[string]Sender
	log      logger.Logger
	batch    int
	interval time.Duration
}

// NewDispatcher returns a Dispatcher routing each topic to its Sender. A row
// whose topic has no Sender counts as a failed attempt. log may be nil.
func NewDispatcher(db *sqlkit.DB, senders map[string]Sender, log logger.Logger) *Dispatcher {
	if log == nil {
		log = logger.NewNoOp()
	}
	return &Dispatcher{db: db, senders: senders, log: log, batch: defaultBatchSize, interval: defaultPollInterval}
}

// Run polls until ctx is done. A full batch is followed immediately by the
// next one; otherwise it waits for the poll interval.
func (d *Dispatcher) Run(ctx context.Context) error {
	for {
		n, err := d.DispatchOnce(ctx)
		if err != nil {
			d.log.ErrorWithContext(ctx, "outbox dispatch failed", logger.F("error", err.Error()))
		}
		if n == d.batch && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(d.interval):
		}
	}
}

// DispatchOnce claims one batch of due rows, sends them and records the
// outcome, all in one transaction. A failed row is retried with exponential
// backoff counted from its creation time. It returns how many rows it claimed.
func (d *Dispatcher) DispatchOnce(ctx context.Context) (int, error) {
	var claimed int
	err := WithTx(ctx, d.db, func(ctx context.Context) error {
		msgs, err := d.claim(ctx)
		if err != nil {
			return err
		}
		claimed = len(msgs)
		for i := range msgs {
			if err := d.deliver(ctx, &msgs[i]); err != nil {
				return err
			}
		}
		return nil
	})
	return claimed, err
}

// claim locks up to one batch of unsent rows whose backoff has elapsed,
// skipping rows already dropped as expired.
func (d *Dispatcher) claim(ctx context.Context) ([]claimedRow, error) {
	rows, err := Leader(ctx, d.db).QueryContext(ctx, `
		SELECT id, topic, key, payload, attempts, coalesce(`+PayloadExpiresAt+` <= now(), false)
		FROM outbox
		WHERE sent_at IS NULL
		  AND last_error <> $3
		  AND created_at + make_interval(secs => power(2, least(attempts, $2)) - 1) <= now()
		ORDER BY id
		LIMIT $1
		FOR UPDATE SKIP LOCKED`, d.batch, maxBackoffExponent, ExpiredReason)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("outbox: claim")
	}
	defer func() { _ = rows.Close() }()
	var msgs []claimedRow
	for rows.Next() {
		var m claimedRow
		if err := rows.Scan(&m.ID, &m.Topic, &m.Key, &m.Payload, &m.Attempts, &m.expired); err != nil {
			return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("outbox: scan")
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("outbox: claim rows")
	}
	return msgs, nil
}

// deliver sends one message and records success or the failure.
func (d *Dispatcher) deliver(ctx context.Context, m *claimedRow) error {
	sendErr := d.send(ctx, m)
	conn := Leader(ctx, d.db)
	var err error
	if sendErr == nil {
		_, err = conn.ExecContext(ctx, `UPDATE outbox SET sent_at = now() WHERE id = $1`, m.ID)
	} else {
		d.log.WarnWithContext(ctx, "outbox send failed",
			logger.F("outbox_id", m.ID), logger.F("topic", m.Topic), logger.F("error", sendErr.Error()))
		_, err = conn.ExecContext(ctx,
			`UPDATE outbox SET attempts = attempts + 1, last_error = $2 WHERE id = $1`, m.ID, truncate(sendErr.Error()))
	}
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("outbox: record delivery")
	}
	return nil
}

// send routes m to its topic's Sender. An expired message fails with
// ExpiredReason without reaching the Sender, which also stops its retries.
func (d *Dispatcher) send(ctx context.Context, m *claimedRow) error {
	if m.expired {
		return errors.New(ExpiredReason)
	}
	s, ok := d.senders[m.Topic]
	if !ok {
		return fmt.Errorf("no sender for topic %q", m.Topic)
	}
	return s.Send(ctx, m.Message)
}

// truncate keeps last_error short.
func truncate(s string) string {
	if len(s) > maxErrorLen {
		return s[:maxErrorLen]
	}
	return s
}
