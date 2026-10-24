package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/biairmal/go-sdk/lib/errorz"

	"github.com/biairmal/go-identity/internal/platform/apierr"
)

// TestCheckPassword maps each policy failure onto PASSWORD_POLICY with a
// message for the password field, and accepts a good password.
func TestCheckPassword(t *testing.T) {
	tests := []struct {
		name      string
		plain     string
		minLength int
		wantMsg   string // "" when the password is accepted
	}{
		{"accepted", "correct horse battery", 10, ""},
		{"too short", "short", 10, "must be at least 10 characters"},
		{"below configured minimum", "elevenchars", 12, "must be at least 12 characters"},
		{"too long", strings.Repeat("a", 129), 10, "must be at most 128 characters"},
		{"too common", "1234567890", 10, "is too common"},
		{"not utf-8", "\xff\xfe-not-utf8-pass", 10, "is not valid UTF-8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkPassword(tt.plain, tt.minLength)
			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("checkPassword() = %v, want nil", err)
				}
				return
			}
			if got := apierr.ReasonOf(err); got != apierr.ReasonPasswordPolicy {
				t.Fatalf("reason = %q, want PASSWORD_POLICY", got)
			}
			if fieldMessage(t, err) != tt.wantMsg {
				t.Errorf("meta.fields.password = %q, want %q", fieldMessage(t, err), tt.wantMsg)
			}
		})
	}
}

// TestAcceptedBody pins the one 202 body the enumeration-safe endpoints share.
func TestAcceptedBody(t *testing.T) {
	if accepted != (AcceptedResponse{Status: "accepted"}) {
		t.Errorf("accepted = %+v", accepted)
	}
}

// fieldMessage returns meta.fields.password of err.
func fieldMessage(t *testing.T, err error) string {
	t.Helper()
	var e *errorz.Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %T, want *errorz.Error", err)
	}
	fields, _ := e.Meta[apierr.MetaFields].(map[string]string)
	return fields["password"]
}
