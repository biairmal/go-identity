// Package onetime issues and consumes the single-use tokens behind email
// verification, password reset, invites and the Google code exchange. Only a
// token's hash is stored: the raw value exists in the email that carries it
// and nowhere else.
package onetime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/clock"
)

// Purposes a token can be issued for. A token is only valid for the purpose
// it was created with, so a reset link can never verify an email.
const (
	PurposeVerifyEmail   = "verify_email"
	PurposeResetPassword = "reset_password"
	PurposeInvite        = "invite"
	PurposeOAuthExchange = "oauth_exchange"
)

// tokenBytes is the entropy of a one-time token: 256 bits, opaque.
const tokenBytes = 32

// Failures callers distinguish. A caller that must not reveal whether a token
// existed maps all of them to the same response.
var (
	// ErrInvalid reports a token that does not exist, was issued for
	// another purpose, or has already been used. The three are one error
	// on purpose: telling them apart would leak whether a link was real.
	ErrInvalid = errors.New("onetime: token is not valid")
	// ErrExpired reports a token past its expiry, which a caller may
	// answer with "ask for a new link".
	ErrExpired = errors.New("onetime: token has expired")
)

// Token is one issued one-time token, without its raw value.
type Token struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TenantID  *uuid.UUID
	Purpose   string
	Payload   []byte
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// Issued is a newly created token: the raw string to put in a link, and the
// stored row.
type Issued struct {
	// Raw is the only place the token is in the clear. It goes into the
	// email and is never logged or stored.
	Raw   string
	Token *Token
}

// Service issues and consumes one-time tokens.
type Service struct {
	repo  *Repository
	clock clock.Clock
}

// NewService returns a Service over repo. clk may be nil.
func NewService(repo *Repository, clk clock.Clock) *Service {
	if clk == nil {
		clk = clock.System{}
	}
	return &Service{repo: repo, clock: clk}
}

// Options are the optional parts of a token: the tenant an invite belongs to
// and any data the consuming flow needs back.
type Options struct {
	// TenantID scopes a token to one tenant; nil for tokens that are not
	// tenant-specific, such as email verification.
	TenantID *uuid.UUID
	// Payload is JSON stored with the token. It must not hold secrets.
	Payload []byte
}

// Create issues a token for userID valid for ttl. It returns the raw value;
// only the hash is written. Called inside database.WithTx, the row joins the
// caller's transaction, so the token and the change that needs it commit
// together.
func (s *Service) Create(
	ctx context.Context, userID uuid.UUID, purpose string, ttl time.Duration, opts Options,
) (*Issued, error) {
	if !validPurpose(purpose) {
		return nil, errorz.BadRequest().WithMessage("onetime: unknown purpose " + purpose)
	}
	if ttl <= 0 {
		return nil, errorz.BadRequest().WithMessage("onetime: ttl must be positive")
	}
	raw, err := newRawToken()
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	t := &Token{
		ID:        uuid.New(),
		UserID:    userID,
		TenantID:  opts.TenantID,
		Purpose:   purpose,
		Payload:   opts.Payload,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	if err := s.repo.Insert(ctx, t, Hash(raw)); err != nil {
		return nil, err
	}
	return &Issued{Raw: raw, Token: t}, nil
}

// Consume spends a token: it looks the raw value up by hash, checks the
// purpose and the expiry, and marks it used. The mark is conditional on the
// token still being unused, so two concurrent calls with the same token cannot
// both succeed.
//
// It returns ErrInvalid for an unknown, mismatched or already-spent token and
// ErrExpired for one past its expiry.
func (s *Service) Consume(ctx context.Context, raw, purpose string) (*Token, error) {
	t, err := s.repo.FindByHash(ctx, Hash(raw))
	if err != nil {
		return nil, err
	}
	if t == nil || t.Purpose != purpose || t.UsedAt != nil {
		return nil, invalid()
	}
	now := s.clock.Now()
	if now.After(t.ExpiresAt) {
		return nil, expired()
	}
	spent, err := s.repo.MarkUsed(ctx, t.ID, now)
	if err != nil {
		return nil, err
	}
	if !spent {
		// Another request consumed it between the read and the update.
		return nil, invalid()
	}
	t.UsedAt = &now
	return t, nil
}

// invalid is the coded error for a token that cannot be used.
func invalid() error {
	return errorz.Wrap(ErrInvalid).WithCode(errorz.CodeBadRequest).WithMessage(ErrInvalid.Error())
}

// expired is the coded error for a token past its expiry.
func expired() error {
	return errorz.Wrap(ErrExpired).WithCode(errorz.CodeBadRequest).WithMessage(ErrExpired.Error())
}

// validPurpose reports whether purpose is one the schema allows, so a typo
// fails before reaching the database constraint.
func validPurpose(purpose string) bool {
	switch purpose {
	case PurposeVerifyEmail, PurposeResetPassword, PurposeInvite, PurposeOAuthExchange:
		return true
	default:
		return false
	}
}

// newRawToken generates 256 bits of randomness, base64url encoded so it is
// safe in a URL fragment.
func newRawToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("onetime: generate token")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Hash is the stored form of a one-time token, so a database leak does not
// yield usable links.
func Hash(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
