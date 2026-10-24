package user

import "strings"

// EmailCipher encrypts an email for storage and derives the deterministic
// blind index the lookup uses. It is a port this module owns: internal/app
// wires it over go-sdk crypto, so swapping the implementation never touches
// the module. Both byte slices are stored as-is in bytea columns.
//
// Normalization is not the cipher's business: the repository normalizes an
// email before asking for its blind index, because what counts as the same
// address is this module's rule.
type EmailCipher interface {
	// Encrypt returns the ciphertext of a plain email.
	Encrypt(plain string) ([]byte, error)
	// Decrypt recovers the plain email from a stored ciphertext.
	Decrypt(ciphertext []byte) (string, error)
	// BlindIndex returns the deterministic index of an already-normalized
	// email, used for exact-match lookups.
	BlindIndex(normalized string) []byte
}

// NormalizeEmail is the canonical form of an email for comparison: trimmed of
// surrounding space and lower-cased. Everything stored and every lookup goes
// through it, so " Bia@Example.com " and "bia@example.com" are one address.
// The local part is left otherwise untouched: stripping dots or plus tags
// would merge addresses that some providers treat as distinct.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
