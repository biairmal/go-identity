package tracing

import (
	"errors"
	"fmt"
	"testing"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/tracer"
)

// fakeSpan records what End did to it.
type fakeSpan struct {
	tracer.Span
	err   error
	ended bool
}

func (s *fakeSpan) SetError(err error) { s.err = err }
func (s *fakeSpan) End()               { s.ended = true }

func TestEnd(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{"success", nil, false},
		{"plain error", errors.New("boom"), true},
		{"wrapped plain error", fmt.Errorf("note: %w", errors.New("boom")), true},
		{"internal", errorz.Internal(), true},
		{"bad gateway", errorz.BadGateway(), true},
		{"service unavailable", errorz.ServiceUnavailable(), true},
		{"bad request", errorz.BadRequest(), false},
		{"unauthorized", errorz.Unauthorized(), false},
		{"forbidden", errorz.Forbidden(), false},
		{"not found", errorz.NotFound(), false},
		{"wrapped not found", fmt.Errorf("note: %w", errorz.NotFound()), false},
		{"conflict", errorz.Conflict(), false},
		{"precondition required", errorz.PreconditionRequired(), false},
		{"unprocessable", errorz.UnprocessableEntity(), false},
		{"too many requests", errorz.TooManyRequests(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := &fakeSpan{}
			End(span, tt.err)
			if !span.ended {
				t.Fatal("span not ended")
			}
			if got := span.err != nil; got != tt.wantErr {
				t.Fatalf("recorded error = %v, want recorded: %v", span.err, tt.wantErr)
			}
		})
	}
}
