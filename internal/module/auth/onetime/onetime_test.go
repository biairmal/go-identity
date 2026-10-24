package onetime

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestCreateRejectsBadInput checks the purpose and the TTL are validated
// before a row is attempted, so a typo fails with a clear error rather than a
// constraint violation.
func TestCreateRejectsBadInput(t *testing.T) {
	tests := []struct {
		name    string
		purpose string
		ttl     time.Duration
		wantErr bool
	}{
		{name: "verify email", purpose: PurposeVerifyEmail, ttl: time.Hour},
		{name: "reset password", purpose: PurposeResetPassword, ttl: time.Hour},
		{name: "invite", purpose: PurposeInvite, ttl: time.Hour},
		{name: "oauth exchange", purpose: PurposeOAuthExchange, ttl: time.Hour},
		{name: "unknown purpose", purpose: "something_else", ttl: time.Hour, wantErr: true},
		{name: "empty purpose", purpose: "", ttl: time.Hour, wantErr: true},
		{name: "zero ttl", purpose: PurposeVerifyEmail, wantErr: true},
		{name: "negative ttl", purpose: PurposeVerifyEmail, ttl: -time.Hour, wantErr: true},
	}
	// A nil repository is enough: a valid purpose and TTL only reach the
	// repository after validation, so the valid rows panic-free check is
	// done by the integration tests instead.
	svc := NewService(nil, nil)
	for _, tt := range tests {
		if !tt.wantErr {
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Create(context.Background(), uuid.New(), tt.purpose, tt.ttl, Options{})
			if err == nil {
				t.Fatalf("Create(%q, %v) succeeded, want an error", tt.purpose, tt.ttl)
			}
		})
	}
}

// TestHashIsStableAndOpaque checks the stored form is a hash of the raw value
// and never the value itself.
func TestHashIsStableAndOpaque(t *testing.T) {
	const raw = "a-raw-token"
	h := Hash(raw)
	if len(h) != 32 {
		t.Fatalf("Hash() returned %d bytes, want 32", len(h))
	}
	if string(h) == raw {
		t.Fatal("Hash() returned the raw token")
	}
	if !bytes.Equal(Hash(raw), h) {
		t.Fatal("Hash() is not stable for the same input")
	}
	if bytes.Equal(Hash(raw+"x"), h) {
		t.Fatal("Hash() collides on different inputs")
	}
}

// TestNewRawTokenIsUniqueAndURLSafe checks a token can go in a URL fragment
// unescaped and does not repeat.
func TestNewRawTokenIsUniqueAndURLSafe(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		raw, err := newRawToken()
		if err != nil {
			t.Fatalf("newRawToken() = %v", err)
		}
		if seen[raw] {
			t.Fatalf("newRawToken() repeated %q", raw)
		}
		seen[raw] = true
		for _, r := range raw {
			isSafe := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_'
			if !isSafe {
				t.Fatalf("token %q contains %q, which needs escaping in a URL", raw, r)
			}
		}
	}
}
