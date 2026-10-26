package user

import (
	"time"

	"github.com/google/uuid"
)

// Status values of a user account. A pending account has registered but not
// verified its email; a disabled one cannot sign in and keeps its rows so the
// audit history stays readable.
const (
	StatusPending  = "pending"
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// Membership status values the admin endpoints read and write; tenant owns them.
const (
	MembershipActive   = "active"
	MembershipDisabled = "disabled"
)

// User is one users row, with the email already decrypted: the repository is
// the only place that sees the ciphertext, so services and handlers work with
// the plain value. The struct deliberately holds no password: hashes live in
// Credentials, so reading a user never loads a secret.
type User struct {
	ID                 uuid.UUID
	Email              string
	DisplayName        string
	Status             string
	EmailVerifiedAt    *time.Time
	IsSuperAdmin       bool
	MustChangePassword bool
	FailedLogins       int
	LockedUntil        *time.Time
	LastSignInAt       *time.Time
	Version            int
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// Active reports whether the account may sign in at all, ignoring any lock.
func (u *User) Active() bool { return u.Status == StatusActive }

// EmailVerified reports whether the email has been confirmed.
func (u *User) EmailVerified() bool { return u.EmailVerifiedAt != nil }

// Locked reports whether the account is locked out at the given time. The
// caller passes the time, so a test can drive the decision with a fake clock.
func (u *User) Locked(at time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(at)
}

// Credentials is one credentials row: the password hash of a user, kept in its
// own table so a user read never carries a secret.
type Credentials struct {
	UserID       uuid.UUID
	PasswordHash string
	UpdatedAt    time.Time
}
