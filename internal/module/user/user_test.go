package user

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"already canonical", "bia@example.com", "bia@example.com"},
		{"surrounding spaces", "  bia@example.com  ", "bia@example.com"},
		{"mixed case", "Bia@Example.COM", "bia@example.com"},
		{"spaces and case together", " Bia@Example.com ", "bia@example.com"},
		{"tabs and newlines", "\tbia@example.com\n", "bia@example.com"},
		{"plus tag is kept", "bia+admin@example.com", "bia+admin@example.com"},
		{"dots are kept", "b.i.a@example.com", "b.i.a@example.com"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeEmail(tt.input); got != tt.want {
				t.Errorf("NormalizeEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestUserState(t *testing.T) {
	now := testTime()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name     string
		user     User
		active   bool
		verified bool
		locked   bool
	}{
		{name: "pending and unverified", user: User{Status: StatusPending}},
		{name: "active", user: User{Status: StatusActive}, active: true},
		{name: "disabled", user: User{Status: StatusDisabled}},
		{
			name:     "verified",
			user:     User{Status: StatusActive, EmailVerifiedAt: &past},
			active:   true,
			verified: true,
		},
		{
			name:   "lock in the future",
			user:   User{Status: StatusActive, LockedUntil: &future},
			active: true,
			locked: true,
		},
		{
			name:   "lock already expired",
			user:   User{Status: StatusActive, LockedUntil: &past},
			active: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := tt.user
			if got := u.Active(); got != tt.active {
				t.Errorf("Active() = %v, want %v", got, tt.active)
			}
			if got := u.EmailVerified(); got != tt.verified {
				t.Errorf("EmailVerified() = %v, want %v", got, tt.verified)
			}
			if got := u.Locked(now); got != tt.locked {
				t.Errorf("Locked() = %v, want %v", got, tt.locked)
			}
		})
	}
}

// TestNewUserResponseCarriesNoSecret pins the DTO's field set: the response must
// expose the account's state without the lockout counters or the super admin
// flag, which are internal.
func TestNewUserResponseCarriesNoSecret(t *testing.T) {
	verified := testTime()
	u := &User{
		ID:              uuid.New(),
		Email:           "bia@example.com",
		DisplayName:     "Bia",
		Status:          StatusActive,
		EmailVerifiedAt: &verified,
		IsSuperAdmin:    true,
		FailedLogins:    7,
		LockedUntil:     &verified,
		Version:         3,
	}
	got := NewUserResponse(u)
	if got.ID != u.ID.String() || got.Email != u.Email || got.Status != StatusActive {
		t.Errorf("NewUserResponse() = %+v, want the identity fields of %+v", got, u)
	}
	if !got.EmailVerified {
		t.Error("NewUserResponse().EmailVerified = false, want true for a verified user")
	}
	if got.Version != u.Version {
		t.Errorf("NewUserResponse().Version = %d, want %d", got.Version, u.Version)
	}
	marshaled, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	for _, leak := range []string{"super", "failed", "locked", "password_hash"} {
		if strings.Contains(string(marshaled), leak) {
			t.Errorf("response JSON %s contains %q, which must not be exposed", marshaled, leak)
		}
	}
}

// testTime is a fixed instant, so the state tests do not depend on the clock.
func testTime() time.Time {
	return time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
}
