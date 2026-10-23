package testkit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// signingKeyBits matches the minimum the key loader accepts. Generating a
// larger key would only slow the tests down.
const signingKeyBits = 2048

// SigningKeys writes a signing key and its manifest into a temporary
// directory and returns the path, for tests that build the auth module. Real
// deployments mount these files as a secret and never generate them at
// startup, so this helper exists only for tests.
//
// Extra kids are written as "next" keys, which is what a rotation looks like.
func SigningKeys(t *testing.T, activeKID string, nextKIDs ...string) string {
	t.Helper()
	dir := t.TempDir()
	writeKey(t, dir, activeKID)
	manifest := "active: " + activeKID + "\n"
	if len(nextKIDs) > 0 {
		manifest += "next:\n"
		for _, kid := range nextKIDs {
			writeKey(t, dir, kid)
			manifest += "  - " + kid + "\n"
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "keys.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("testkit: write keys.yaml: %v", err)
	}
	return dir
}

// writeKey generates one PKCS#1 PEM key named after kid.
func writeKey(t *testing.T, dir, kid string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, signingKeyBits)
	if err != nil {
		t.Fatalf("testkit: generate key: %v", err)
	}
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(filepath.Join(dir, kid+".pem"), b, 0o600); err != nil {
		t.Fatalf("testkit: write key: %v", err)
	}
}
