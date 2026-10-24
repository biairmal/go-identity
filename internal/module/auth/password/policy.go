package password

import (
	"errors"
	"unicode/utf8"
)

// Policy bounds from TRD 10 "Password policy": a length range in runes and
// no composition rules, because forcing character classes pushes users to
// predictable substitutions instead of longer passwords.
const (
	// MinRunes is the shortest accepted password, counted in runes.
	MinRunes = 10
	// MaxRunes is the longest accepted password. The cap exists so an
	// attacker cannot make the server hash a megabyte.
	MaxRunes = 128
)

// Why a password was rejected. Callers map these onto the API's
// PASSWORD_POLICY reason and decide what to tell the user; this package owns
// no HTTP concerns.
var (
	// ErrTooShort reports a password below MinRunes.
	ErrTooShort = errors.New("password: shorter than the minimum length")
	// ErrTooLong reports a password above MaxRunes.
	ErrTooLong = errors.New("password: longer than the maximum length")
	// ErrTooCommon reports a password in the embedded common-password list.
	ErrTooCommon = errors.New("password: appears in the common-password list")
	// ErrNotUTF8 reports bytes that are not valid UTF-8, which cannot be
	// counted in runes and must not be stored.
	ErrNotUTF8 = errors.New("password: not valid UTF-8")
)

// Validate checks plain against the policy and returns nil when it is
// acceptable. The returned error is one of ErrTooShort, ErrTooLong,
// ErrNotUTF8 or ErrTooCommon; compare with errors.Is.
func Validate(plain string) error {
	if !utf8.ValidString(plain) {
		return ErrNotUTF8
	}
	switch n := utf8.RuneCountInString(plain); {
	case n < MinRunes:
		return ErrTooShort
	case n > MaxRunes:
		return ErrTooLong
	}
	if IsCommon(plain) {
		return ErrTooCommon
	}
	return nil
}
