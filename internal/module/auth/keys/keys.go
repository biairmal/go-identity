// Package keys loads the RSA signing keys from the mounted secret and tracks
// which key signs and which are published. Keys are never generated at
// startup: every pod must load the same files, so a token signed by one pod
// validates on another.
package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/errorz"
	"gopkg.in/yaml.v3"
)

// minKeyBits is the smallest RSA key accepted. Startup fails below it rather
// than signing tokens with a weak key.
const minKeyBits = 2048

// manifestName is the file in the keys directory naming the active key.
const manifestName = "keys.yaml"

// ErrNoKeys reports a keys directory without a usable key.
var ErrNoKeys = errors.New("keys: no signing key found")

// manifest is keys.yaml: which key signs, which are published alongside it.
type manifest struct {
	// Active is the kid whose key signs new tokens.
	Active string `yaml:"active"`
	// Next is published before it signs, so a resource service has it
	// cached by the time it is activated.
	Next []string `yaml:"next"`
	// Retiring no longer signs but stays published until the last token it
	// signed has expired.
	Retiring []string `yaml:"retiring"`
}

// Set is the loaded key set: one signing key and every key to publish.
type Set struct {
	active   string
	private  *rsa.PrivateKey
	public   []auth.PublicKey
	statuses map[string]string
}

// Key statuses, as stored in the signing_keys table.
const (
	StatusNext     = "next"
	StatusActive   = "active"
	StatusRetiring = "retiring"
)

// Load reads the manifest and the PEM files from dir. It fails when the
// directory, the manifest or the active key is missing, or when the active key
// is too small, because a service that cannot sign must not start.
func Load(dir string) (*Set, error) {
	m, err := readManifest(dir)
	if err != nil {
		return nil, err
	}
	if m.Active == "" {
		return nil, errorz.Wrap(ErrNoKeys).WithCode(errorz.CodeInternal).
			WithMessage("keys: " + manifestName + " names no active key")
	}

	s := &Set{active: m.Active, statuses: map[string]string{}}
	priv, err := readKey(dir, m.Active)
	if err != nil {
		return nil, err
	}
	if bits := priv.N.BitLen(); bits < minKeyBits {
		return nil, errorz.Wrap(ErrNoKeys).WithCode(errorz.CodeInternal).
			WithMessage(fmt.Sprintf("keys: active key %s is %d bits, want at least %d",
				m.Active, bits, minKeyBits))
	}
	s.private = priv

	// Published in the order a client should prefer them: next keys first,
	// so a rotation is picked up before it starts signing.
	if err := s.add(dir, m.Next, StatusNext); err != nil {
		return nil, err
	}
	s.public = append(s.public, auth.PublicKey{KID: m.Active, Key: &priv.PublicKey})
	s.statuses[m.Active] = StatusActive
	if err := s.add(dir, m.Retiring, StatusRetiring); err != nil {
		return nil, err
	}
	return s, nil
}

// add loads each kid's public key and records its status.
func (s *Set) add(dir string, kids []string, status string) error {
	for _, kid := range kids {
		if kid == s.active || s.statuses[kid] != "" {
			continue // the active key is added once, by Load
		}
		priv, err := readKey(dir, kid)
		if err != nil {
			return err
		}
		s.public = append(s.public, auth.PublicKey{KID: kid, Key: &priv.PublicKey})
		s.statuses[kid] = status
	}
	return nil
}

// ActiveKID is the kid written into the header of new tokens.
func (s *Set) ActiveKID() string { return s.active }

// Private is the key that signs new tokens.
func (s *Set) Private() *rsa.PrivateKey { return s.private }

// Public returns every key to publish at the JWKS endpoint. The slice is
// copied, so a caller cannot mutate the set.
func (s *Set) Public() []auth.PublicKey { return slices.Clone(s.public) }

// Statuses maps each published kid to its status, for the signing_keys table.
func (s *Set) Statuses() map[string]string {
	out := make(map[string]string, len(s.statuses))
	for k, v := range s.statuses {
		out[k] = v
	}
	return out
}

// readManifest parses keys.yaml.
func readManifest(dir string) (*manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).
			WithMessage("keys: read " + manifestName)
	}
	var m manifest
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).
			WithMessage("keys: parse " + manifestName)
	}
	return &m, nil
}

// readKey parses the PEM private key named after kid. Only the private file
// is stored; the public key is derived from it, so the two cannot disagree.
func readKey(dir, kid string) (*rsa.PrivateKey, error) {
	path := filepath.Join(dir, kid+".pem")
	// The path is built from the operator's own manifest, not from a request.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).
			WithMessage("keys: read key " + kid)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errorz.Wrap(ErrNoKeys).WithCode(errorz.CodeInternal).
			WithMessage("keys: " + kid + " is not a PEM file")
	}
	return parsePrivateKey(block.Bytes, kid)
}

// parsePrivateKey accepts both PKCS#1 and PKCS#8 encodings, since key tools
// differ in which they emit.
func parsePrivateKey(der []byte, kid string) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).
			WithMessage("keys: parse key " + kid)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errorz.Wrap(ErrNoKeys).WithCode(errorz.CodeInternal).
			WithMessage("keys: " + kid + " is not an RSA key")
	}
	return key, nil
}
