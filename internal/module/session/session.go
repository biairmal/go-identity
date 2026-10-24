package session

import (
	"time"

	"github.com/google/uuid"
)

// Token is one refresh-token row. The raw token exists only in the response
// that issued it; the database holds its SHA-256 hash.
type Token struct {
	ID                uuid.UUID
	FamilyID          uuid.UUID
	UserID            uuid.UUID
	TenantID          uuid.UUID
	IssuedAt          time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	RotatedAt         *time.Time
	RevokedAt         *time.Time
	UserAgent         string
	IP                *string
}

// Rotated reports whether the token has already been exchanged.
func (t *Token) Rotated() bool { return t.RotatedAt != nil }

// Revoked reports whether the token, or its whole family, has been revoked.
func (t *Token) Revoked() bool { return t.RevokedAt != nil }

// Issued is a newly issued refresh token: the raw value to return to the
// client, and the stored row.
type Issued struct {
	// Raw is the only time the token is in the clear. It goes into the
	// response and is never logged or stored.
	Raw   string
	Token *Token
}

// Device describes where a session was created, shown in the session list.
type Device struct {
	UserAgent string
	IP        string
}

// Session is one signed-in device as the session list shows it: a family and
// its live token.
type Session struct {
	FamilyID uuid.UUID
	// CreatedAt is when the device signed in.
	CreatedAt time.Time
	// LastUsedAt is when the device last refreshed (or signed in).
	LastUsedAt time.Time
	UserAgent  string
	IP         *string
}
