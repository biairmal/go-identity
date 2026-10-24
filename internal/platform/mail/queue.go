package mail

import (
	"context"
	"encoding/json"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/database"
)

// Enqueuer writes a message on the outbox. It is the subset of
// database.Outbox that queueing a mail needs.
type Enqueuer interface {
	Enqueue(ctx context.Context, topic, key string, payload any) error
}

// Queue puts m on the outbox so the worker delivers it. Services call this
// instead of a Mailer: inside database.WithTx the row joins the caller's
// transaction, so the mail is sent only if the change that triggered it
// commits, and a rollback drops it.
//
// The key is the recipient's hash rather than the address, because outbox rows
// are operational data an operator reads.
func Queue(ctx context.Context, outbox Enqueuer, m *Message) error {
	if m.To == "" {
		return errorz.BadRequest().WithMessage("mail: a message needs a recipient")
	}
	if m.Template == "" {
		return errorz.BadRequest().WithMessage("mail: a message needs a template")
	}
	return outbox.Enqueue(ctx, Topic, m.RecipientHash(), m)
}

// Sender is the outbox Sender for the mail topic: it decodes the queued
// message, hands it to the Mailer, and clears the one-time token from the
// stored payload so a delivered mail leaves no usable token behind.
type Sender struct {
	mailer Mailer
	db     *sqlkit.DB
}

// NewSender returns the Sender internal/app registers for Topic.
func NewSender(mailer Mailer, db *sqlkit.DB) *Sender {
	return &Sender{mailer: mailer, db: db}
}

// Send delivers one queued mail. It runs inside the dispatcher's transaction,
// so clearing the token commits together with the row being marked sent.
func (s *Sender) Send(ctx context.Context, msg database.Message) error {
	var m Message
	if err := json.Unmarshal(msg.Payload, &m); err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("mail: decode queued message")
	}
	if err := s.mailer.Send(ctx, &m); err != nil {
		return err
	}
	return s.clearToken(ctx, msg.ID)
}

// clearToken removes the raw one-time token from a delivered row, leaving the
// rest of the payload for support questions.
func (s *Sender) clearToken(ctx context.Context, id int64) error {
	_, err := database.Leader(ctx, s.db).ExecContext(ctx,
		`UPDATE outbox SET payload = payload - 'token' WHERE id = $1`, id)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("mail: clear queued token")
	}
	return nil
}
