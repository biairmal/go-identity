package app

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/biairmal/go-sdk/lib/crypto"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"

	"github.com/biairmal/go-identity/internal/module/user"
)

// emailCipher adapts go-sdk crypto to the port the user module declares. The
// module stores bytea columns, while crypto returns a base64 string, so the
// adapter is where the two representations meet: the module never learns which
// cipher or which encoding is in use.
type emailCipher struct{ enc *crypto.Encryptor }

// Encrypt returns the ciphertext of a plain email, as bytes for the bytea
// column.
func (c emailCipher) Encrypt(plain string) ([]byte, error) {
	s, err := c.enc.Encrypt([]byte(plain))
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// Decrypt recovers the plain email from a stored ciphertext.
func (c emailCipher) Decrypt(ciphertext []byte) (string, error) {
	plain, err := c.enc.Decrypt(string(ciphertext))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// BlindIndex returns the deterministic index of an already-normalized email.
// The module normalizes before calling, because what counts as the same
// address is its rule, not the cipher's.
func (c emailCipher) BlindIndex(normalized string) []byte {
	return []byte(c.enc.BlindIndex(normalized))
}

// newEmailCipher builds the adapter from the crypto block. Outside production
// and staging, missing keys fall back to derived development keys so a
// developer can run the service without provisioning secrets first; a real
// environment must supply them, which validateCrypto enforces.
func newEmailCipher(cfg *Config, log logger.Logger) (user.EmailCipher, error) {
	c := cfg.Crypto.Config
	if c.EncryptionKey == "" && c.BlindIndexKey == "" {
		log.Warn("no email encryption keys configured: using development keys, " +
			"which are not secret and must never hold real data")
		c = developmentKeys()
	}
	enc, err := crypto.New(c)
	if err != nil {
		return nil, err
	}
	return emailCipher{enc: enc}, nil
}

// developmentKeys derives a fixed key pair from two labels. They are stable
// across restarts, so a local database stays readable, and they are in the
// source tree, so they are worthless as secrets: validateCrypto refuses them
// outside local.
func developmentKeys() crypto.Config {
	return crypto.Config{
		EncryptionKey: derivedKey("go-identity development email encryption key"),
		BlindIndexKey: derivedKey("go-identity development email blind index key"),
	}
}

// derivedKey is 32 base64-encoded bytes derived from a label.
func derivedKey(label string) string {
	sum := sha256.Sum256([]byte(label))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// CryptoConfig holds the field-encryption keys, read by internal/app because
// it owns the adapter over go-sdk crypto that the user module's port uses.
type CryptoConfig struct {
	crypto.Config `mapstructure:",squash"`
}

// validateCrypto requires real keys in staging and production, and accepts
// their absence only in local, where newEmailCipher substitutes development
// keys and warns. Half a pair is always a misconfiguration.
func (c *Config) validateCrypto() error {
	k := c.Crypto.Config
	if k.EncryptionKey == "" && k.BlindIndexKey == "" {
		if c.Service.Environment == EnvLocal {
			return nil
		}
		return errorz.BadRequest().WithMessage(
			"encryption_key and blind_index_key are required outside local")
	}
	return k.Validate()
}
