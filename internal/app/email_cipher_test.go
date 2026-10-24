package app

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/biairmal/go-sdk/lib/crypto"
	"github.com/biairmal/go-sdk/lib/logger"

	"github.com/biairmal/go-identity/internal/module/user"
)

// testKey is n base64-encoded bytes of one value, a deterministic stand-in
// for real key material.
func testKey(fill byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return base64.StdEncoding.EncodeToString(b)
}

// TestEmailCipherRoundTrip checks the adapter satisfies the port: a plain
// email survives encryption and decryption, and the blind index is stable
// while the ciphertext is not.
func TestEmailCipherRoundTrip(t *testing.T) {
	cfg := &Config{Crypto: CryptoConfig{Config: crypto.Config{
		EncryptionKey: testKey(0x11, 32), BlindIndexKey: testKey(0x22, 32),
	}}}
	c, err := newEmailCipher(cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("newEmailCipher() = %v", err)
	}

	const email = "bia@example.com"
	first, err := c.Encrypt(email)
	if err != nil {
		t.Fatalf("Encrypt() = %v", err)
	}
	got, err := c.Decrypt(first)
	if err != nil {
		t.Fatalf("Decrypt() = %v", err)
	}
	if got != email {
		t.Errorf("Decrypt(Encrypt(%q)) = %q", email, got)
	}

	second, err := c.Encrypt(email)
	if err != nil {
		t.Fatalf("second Encrypt() = %v", err)
	}
	if bytes.Equal(first, second) {
		t.Error("the same email encrypted twice gave one ciphertext; the nonce must be random")
	}
	if !bytes.Equal(c.BlindIndex(email), c.BlindIndex(email)) {
		t.Error("BlindIndex is not deterministic")
	}
	if bytes.Equal(c.BlindIndex(email), c.BlindIndex("other@example.com")) {
		t.Error("two addresses share one blind index")
	}
	if bytes.Contains(first, []byte(email)) || bytes.Contains(c.BlindIndex(email), []byte(email)) {
		t.Error("the cipher output contains the plain email")
	}
}

// TestEmailCipherDecryptRejectsTamperedData checks GCM's authentication is
// reported rather than silently returning garbage.
func TestEmailCipherDecryptRejectsTamperedData(t *testing.T) {
	cfg := &Config{Crypto: CryptoConfig{Config: crypto.Config{
		EncryptionKey: testKey(0x11, 32), BlindIndexKey: testKey(0x22, 32),
	}}}
	c, err := newEmailCipher(cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("newEmailCipher() = %v", err)
	}
	enc, err := c.Encrypt("bia@example.com")
	if err != nil {
		t.Fatalf("Encrypt() = %v", err)
	}
	enc[len(enc)-1] ^= 0xff
	if _, err := c.Decrypt(enc); err == nil {
		t.Fatal("Decrypt() of tampered ciphertext = nil, want an error")
	}
}

// TestEmailCipherFallsBackToDevelopmentKeys checks a local run without
// configured keys still works, and that the fallback is deterministic so a
// local database stays readable across restarts.
func TestEmailCipherFallsBackToDevelopmentKeys(t *testing.T) {
	cfg := &Config{Service: ServiceConfig{Environment: EnvLocal}}
	first, err := newEmailCipher(cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("newEmailCipher() without keys = %v", err)
	}
	second, err := newEmailCipher(cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("second newEmailCipher() = %v", err)
	}
	enc, err := first.Encrypt("bia@example.com")
	if err != nil {
		t.Fatalf("Encrypt() = %v", err)
	}
	got, err := second.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt() with a rebuilt cipher = %v", err)
	}
	if got != "bia@example.com" {
		t.Errorf("round trip across two ciphers = %q", got)
	}
}

// TestValidateCrypto covers the one rule internal/app owns here: real keys
// are mandatory outside local, and half a pair is never acceptable.
func TestValidateCrypto(t *testing.T) {
	keys := func(e, b string) CryptoConfig {
		return CryptoConfig{Config: crypto.Config{EncryptionKey: e, BlindIndexKey: b}}
	}
	tests := []struct {
		name    string
		env     string
		crypto  CryptoConfig
		wantErr bool
	}{
		{name: "local without keys", env: EnvLocal},
		{name: "staging without keys", env: EnvStaging, wantErr: true},
		{name: "production without keys", env: EnvProduction, wantErr: true},
		{
			name: "production with keys", env: EnvProduction,
			crypto: keys(testKey(0x11, 32), testKey(0x22, 32)),
		},
		{
			name: "local with only an encryption key", env: EnvLocal,
			crypto: keys(testKey(0x11, 32), ""), wantErr: true,
		},
		{
			name: "local with only a blind index key", env: EnvLocal,
			crypto: keys("", testKey(0x22, 32)), wantErr: true,
		},
		{
			name: "identical keys", env: EnvProduction,
			crypto: keys(testKey(0x11, 32), testKey(0x11, 32)), wantErr: true,
		},
		{
			name: "undersized encryption key", env: EnvProduction,
			crypto: keys(testKey(0x11, 16), testKey(0x22, 32)), wantErr: true,
		},
		{
			name: "undersized blind index key", env: EnvProduction,
			crypto: keys(testKey(0x11, 32), testKey(0x22, 8)), wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Service: ServiceConfig{Environment: tt.env}, Crypto: tt.crypto}
			err := cfg.validateCrypto()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCrypto() = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// emailCipher must satisfy the port the user module declares; wiring it here
// instead of in the module is the point of the adapter.
var _ user.EmailCipher = emailCipher{}
