package audit

import (
	"context"
	"encoding/json"

	"github.com/biairmal/go-sdk/lib/ctxkit"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/requestip"
)

// Event is one audited change. Only Action is required: a failed sign-in has
// no actor, and a platform-level event has no tenant.
type Event struct {
	TenantID   uuid.UUID
	ActorID    uuid.UUID
	Action     Action
	TargetType string
	TargetID   string
	// Before and After are the state around the change, as any
	// JSON-serialisable value. They must never contain a secret: no
	// password hashes, tokens or plain email addresses.
	Before any
	After  any
}

// Writer appends events to the log. It is used through a port by the modules
// that change something, and never logs the event's contents.
type Writer struct {
	repo *Repository
	log  logger.Logger
}

// NewWriter returns a Writer over repo. log may be nil.
func NewWriter(repo *Repository, log logger.Logger) *Writer {
	if log == nil {
		log = logger.NewNoOp()
	}
	return &Writer{repo: repo, log: log}
}

// Write appends e. It runs on the context's transaction when there is one, so
// an event written inside WithTx is rolled back with the change it describes.
// The request ID and the caller's IP come from the context, so callers do not
// pass them.
func (w *Writer) Write(ctx context.Context, e *Event) error {
	row, err := w.row(ctx, e)
	if err != nil {
		return err
	}
	return w.repo.Insert(ctx, row)
}

// row turns an Event into the database row, encoding the before and after
// state and taking the request metadata from the context.
func (w *Writer) row(ctx context.Context, e *Event) (*Row, error) {
	before, err := encode(e.Before)
	if err != nil {
		return nil, err
	}
	after, err := encode(e.After)
	if err != nil {
		return nil, err
	}
	return &Row{
		TenantID:   nullableUUID(e.TenantID),
		ActorID:    nullableUUID(e.ActorID),
		Action:     string(e.Action),
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		Before:     before,
		After:      after,
		IP:         nullableString(requestip.Get(ctx)),
		RequestID:  ctxkit.RequestID(ctx),
	}, nil
}

// encode serializes a before or after value; nil stays NULL.
func encode(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("audit: encode event state")
	}
	return b, nil
}

// nullableUUID maps the zero UUID to NULL, for platform-level or anonymous
// events.
func nullableUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// nullableString maps an empty string to NULL, so an absent IP is not stored
// as the empty text an inet column would reject.
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
