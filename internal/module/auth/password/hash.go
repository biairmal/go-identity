// Package password hashes sign-in passwords with argon2id and checks a new
// password against the policy in TRD 10. It is a leaf package: it touches no
// database, no HTTP and no other module, so both the sign-in service and the
// super-admin CLI can use it.
//
// A hash carries its own cost parameters in the PHC string it is stored as.
// Verify therefore keeps validating hashes written with older parameters and
// reports that the caller should rehash the password it just accepted.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// variant is the only argon2 flavor this package writes or accepts. argon2i
// and argon2d hashes are rejected rather than silently verified.
const variant = "argon2id"

// Bounds on a decoded hash's salt and key. They are far above the parameters
// in use and exist so a malformed stored value cannot ask for an absurd
// allocation or overflow the uint32 the argon2 API takes.
const (
	maxSaltLen = 1024
	maxKeyLen  = 1024
)

// b64 is the PHC string encoding: standard base64 alphabet, no padding.
var b64 = base64.RawStdEncoding

// ErrInvalidHash reports a stored value that is not a usable argon2id PHC
// string: wrong shape, unknown variant, unsupported version or corrupt
// base64. It is a programming or data error, never a wrong password.
var ErrInvalidHash = errors.New("password: stored hash is not a valid argon2id PHC string")

// Params are the argon2id cost parameters. Memory is in KiB, as the argon2
// API and the PHC string both express it.
type Params struct {
	// Memory is the memory cost in KiB (m).
	Memory uint32
	// Time is the number of passes (t).
	Time uint32
	// Threads is the degree of parallelism (p).
	Threads uint8
	// SaltLen is the salt length in bytes.
	SaltLen uint32
	// KeyLen is the derived key length in bytes.
	KeyLen uint32
}

// DefaultParams returns the parameters new hashes are written with: argon2id
// m=64 MiB, t=3, p=2 and a 16-byte salt (TRD 10 "Password hashing"). Raising
// them here makes every hash written with the old values report needsRehash.
func DefaultParams() Params {
	return Params{
		Memory:  64 * 1024,
		Time:    3,
		Threads: 2,
		SaltLen: 16,
		KeyLen:  32,
	}
}

// Hash derives a PHC string for plain using DefaultParams. It does not check
// the policy; call Validate first when the password comes from a user.
func Hash(plain string) (string, error) {
	return HashWith(plain, DefaultParams())
}

// HashWith is Hash with explicit parameters. Production code uses Hash;
// explicit parameters exist for tests and for rehashing experiments.
func HashWith(plain string, p Params) (string, error) {
	if p.SaltLen == 0 || p.SaltLen > maxSaltLen || p.KeyLen == 0 || p.KeyLen > maxKeyLen {
		return "", fmt.Errorf("%w: salt %d and key %d are out of range", ErrInvalidHash, p.SaltLen, p.KeyLen)
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(plain), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return encode(p, salt, key), nil
}

// Verify reports whether plain is the password behind encoded. needsRehash is
// true only for a match whose stored parameters are weaker than
// DefaultParams: the caller holds the plain password at that moment and
// should store Hash(plain) again. A wrong password is (false, false, nil);
// only an unusable stored value returns an error.
func Verify(plain, encoded string) (match, needsRehash bool, err error) {
	stored, salt, want, err := decode(encoded)
	if err != nil {
		return false, false, err
	}
	got := argon2.IDKey([]byte(plain), salt, stored.Time, stored.Memory, stored.Threads, stored.KeyLen)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	return true, stored.weakerThan(DefaultParams()), nil
}

// NeedsRehash reports whether a stored hash was written with parameters
// weaker than the current ones, without verifying a password. A value that
// cannot be decoded needs rehashing by definition.
func NeedsRehash(encoded string) bool {
	stored, _, _, err := decode(encoded)
	if err != nil {
		return true
	}
	return stored.weakerThan(DefaultParams())
}

// weakerThan reports whether any of p's parameters is below current's, which
// is what makes a stored hash due for a rehash.
func (p Params) weakerThan(current Params) bool {
	return p.Memory < current.Memory ||
		p.Time < current.Time ||
		p.Threads < current.Threads ||
		p.SaltLen < current.SaltLen ||
		p.KeyLen < current.KeyLen
}

// encode writes the PHC string: $argon2id$v=19$m=…,t=…,p=…$salt$key.
func encode(p Params, salt, key []byte) string {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		variant, argon2.Version, p.Memory, p.Time, p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key))
}

// decode parses a PHC string into the parameters it was written with, its
// salt and its expected key.
func decode(encoded string) (p Params, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return Params{}, nil, nil, fmt.Errorf("%w: want 5 fields, got %d", ErrInvalidHash, len(parts)-1)
	}
	if parts[1] != variant {
		return Params{}, nil, nil, fmt.Errorf("%w: variant %q", ErrInvalidHash, parts[1])
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: version %q", ErrInvalidHash, parts[2])
	}
	if version != argon2.Version {
		return Params{}, nil, nil, fmt.Errorf("%w: version %d", ErrInvalidHash, version)
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: parameters %q", ErrInvalidHash, parts[3])
	}
	if salt, err = decodeField(parts[4], maxSaltLen); err != nil {
		return Params{}, nil, nil, err
	}
	if key, err = decodeField(parts[5], maxKeyLen); err != nil {
		return Params{}, nil, nil, err
	}
	p.SaltLen, p.KeyLen = uint32(len(salt)), uint32(len(key)) //nolint:gosec // decodeField bounds both lengths
	return p, salt, key, nil
}

// decodeField decodes one base64 field of the PHC string and rejects an empty
// or implausibly long value.
func decodeField(field string, maxLen int) ([]byte, error) {
	raw, err := b64.DecodeString(field)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidHash, err)
	}
	if len(raw) == 0 || len(raw) > maxLen {
		return nil, fmt.Errorf("%w: field is %d bytes", ErrInvalidHash, len(raw))
	}
	return raw, nil
}
