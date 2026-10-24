package mail_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/mail"
)

// TestLink checks the link is built from the frontend base URL with the token
// in the fragment, which is the contract with the frontend pages.
func TestLink(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		msg     mail.Message
		want    string
		wantErr bool
	}{
		{
			name: "verify email",
			base: "http://localhost:3000",
			msg:  mail.Message{LinkPath: "/verify-email", Token: "abc"},
			want: "http://localhost:3000/verify-email#token=abc",
		},
		{
			name: "trailing slash on the base is not doubled",
			base: "https://app.example.com/",
			msg:  mail.Message{LinkPath: "/reset-password", Token: "abc"},
			want: "https://app.example.com/reset-password#token=abc",
		},
		{
			name: "token is escaped",
			base: "http://localhost:3000",
			msg:  mail.Message{LinkPath: "/invite", Token: "a+b/c=="},
			want: "http://localhost:3000/invite#token=a%2Bb%2Fc%3D%3D",
		},
		{
			name: "no token still links to the page",
			base: "http://localhost:3000",
			msg:  mail.Message{LinkPath: "/sign-in"},
			want: "http://localhost:3000/sign-in",
		},
		{
			name: "no path means no link",
			base: "http://localhost:3000",
			msg:  mail.Message{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.msg.Link(tt.base); got != tt.want {
				t.Errorf("Link() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRecipientHashHidesTheAddress checks the hash is stable across
// case and whitespace differences and reveals nothing.
func TestRecipientHashHidesTheAddress(t *testing.T) {
	a := (&mail.Message{To: "bia@example.com"}).RecipientHash()
	b := (&mail.Message{To: "  Bia@Example.COM "}).RecipientHash()
	c := (&mail.Message{To: "other@example.com"}).RecipientHash()

	if a != b {
		t.Errorf("hash of the same address differs by case: %q vs %q", a, b)
	}
	if a == c {
		t.Error("two different addresses hash the same")
	}
	if strings.Contains(a, "example") || strings.Contains(a, "bia") {
		t.Errorf("the hash leaks the address: %q", a)
	}
}

// TestLoggingMailerRefusesProduction is the security rule: the stub prints
// links, so it must not be usable where mail has to be delivered.
func TestLoggingMailerRefusesProduction(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		baseURL     string
		wantErr     bool
	}{
		{name: "local", environment: "local", baseURL: "http://localhost:3000"},
		{name: "staging", environment: "staging", baseURL: "http://localhost:3000"},
		{name: "production", environment: "production", baseURL: "http://localhost:3000", wantErr: true},
		{name: "no base URL", environment: "local", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := mail.NewLogging(nil, tt.environment, tt.baseURL)
			if tt.wantErr {
				if err == nil {
					t.Fatal("NewLogging() succeeded, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewLogging() = %v", err)
			}
			if err := m.Send(context.Background(), &mail.Message{To: "bia@example.com"}); err != nil {
				t.Fatalf("Send() = %v", err)
			}
		})
	}
}

// TestLoggingMailerProductionErrorIsIdentifiable lets a caller branch on the
// refusal rather than matching a message.
func TestLoggingMailerProductionErrorIsIdentifiable(t *testing.T) {
	_, err := mail.NewLogging(nil, "production", "http://localhost:3000")
	if !errors.Is(err, mail.ErrProductionEnvironment) {
		t.Fatalf("NewLogging(production) = %v, want ErrProductionEnvironment", err)
	}
}

// fakeEnqueuer records what Queue wrote instead of touching a database.
type fakeEnqueuer struct {
	topic, key string
	payload    []byte
	err        error
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, topic, key string, payload any) error {
	if f.err != nil {
		return f.err
	}
	f.topic, f.key = topic, key
	b, err := json.Marshal(payload)
	f.payload = b
	return err
}

// TestQueueWritesTheMailTopic checks Queue enqueues under the mail topic,
// keys the row by the recipient's hash rather than the address, and validates
// its input.
func TestQueueWritesTheMailTopic(t *testing.T) {
	ctx := context.Background()
	msg := &mail.Message{To: "bia@example.com", Template: "verify_email", LinkPath: "/verify-email", Token: "tok"}

	q := &fakeEnqueuer{}
	if err := mail.Queue(ctx, q, msg); err != nil {
		t.Fatalf("Queue() = %v", err)
	}
	if q.topic != mail.Topic {
		t.Errorf("topic = %q, want %q", q.topic, mail.Topic)
	}
	if q.key != msg.RecipientHash() {
		t.Errorf("key = %q, want the recipient hash", q.key)
	}
	if strings.Contains(q.key, "@") {
		t.Errorf("the outbox key carries the address: %q", q.key)
	}

	var round mail.Message
	if err := json.Unmarshal(q.payload, &round); err != nil {
		t.Fatalf("payload is not the message: %v", err)
	}
	if round.Token != "tok" || round.To != msg.To {
		t.Errorf("payload round trip = %+v, want the queued message", round)
	}
}

// TestQueueRejectsIncompleteMessages keeps a half-built message out of the
// outbox, where it would be retried forever.
func TestQueueRejectsIncompleteMessages(t *testing.T) {
	tests := []struct {
		name string
		msg  mail.Message
	}{
		{name: "no recipient", msg: mail.Message{Template: "verify_email"}},
		{name: "no template", msg: mail.Message{To: "bia@example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &fakeEnqueuer{}
			if err := mail.Queue(context.Background(), q, &tt.msg); err == nil {
				t.Fatal("Queue() accepted an incomplete message")
			}
			if q.topic != "" {
				t.Error("Queue() enqueued an incomplete message")
			}
		})
	}
}
