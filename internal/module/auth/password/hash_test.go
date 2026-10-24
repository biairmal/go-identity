package password

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// weakParams are the parameters an older release might have used: every cost
// below DefaultParams, so a hash written with them is due for a rehash.
func weakParams() Params {
	return Params{Memory: 32 * 1024, Time: 2, Threads: 1, SaltLen: 8, KeyLen: 16}
}

// TestHashFormat pins the PHC string: the variant, the version and the
// parameters a later release reads back to decide on a rehash.
func TestHashFormat(t *testing.T) {
	encoded, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash() = %v", err)
	}
	p := DefaultParams()
	prefix := "$argon2id$v=19$m=65536,t=3,p=2$"
	if !strings.HasPrefix(encoded, prefix) {
		t.Errorf("Hash() = %q, want prefix %q", encoded, prefix)
	}
	if argon2.Version != 19 {
		t.Errorf("argon2.Version = %d, want 19 (the PHC prefix above assumes it)", argon2.Version)
	}
	got, salt, key, err := decode(encoded)
	if err != nil {
		t.Fatalf("decode() = %v", err)
	}
	if got != p {
		t.Errorf("decoded params = %+v, want %+v", got, p)
	}
	if len(salt) != int(p.SaltLen) || len(key) != int(p.KeyLen) {
		t.Errorf("salt %d bytes, key %d bytes; want %d and %d", len(salt), len(key), p.SaltLen, p.KeyLen)
	}
}

// TestHashSaltIsRandom covers the salt: the same password twice must not
// produce the same stored value, or a leaked table would reveal shared
// passwords.
func TestHashSaltIsRandom(t *testing.T) {
	first, err := Hash("a passphrase worth keeping")
	if err != nil {
		t.Fatalf("Hash() = %v", err)
	}
	second, err := Hash("a passphrase worth keeping")
	if err != nil {
		t.Fatalf("Hash() = %v", err)
	}
	if first == second {
		t.Error("two hashes of one password are identical, want different salts")
	}
}

// TestVerify covers the round trip, a wrong password, and the rehash signal
// a hash written with older parameters must raise.
func TestVerify(t *testing.T) {
	const plain = "a passphrase worth keeping"

	current, err := Hash(plain)
	if err != nil {
		t.Fatalf("Hash() = %v", err)
	}
	old, err := HashWith(plain, weakParams())
	if err != nil {
		t.Fatalf("HashWith(weak) = %v", err)
	}
	// Only the memory cost is raised, to prove one weaker parameter is enough.
	memoryOnly := weakParams()
	memoryOnly.Memory = DefaultParams().Memory
	stronger := DefaultParams()
	stronger.Time = DefaultParams().Time + 1
	strongerHash, err := HashWith(plain, stronger)
	if err != nil {
		t.Fatalf("HashWith(stronger) = %v", err)
	}
	partialHash, err := HashWith(plain, memoryOnly)
	if err != nil {
		t.Fatalf("HashWith(memoryOnly) = %v", err)
	}

	tests := []struct {
		name        string
		plain       string
		encoded     string
		wantMatch   bool
		wantRehash  bool
		wantInvalid bool
	}{
		{name: "round trip with current params", plain: plain, encoded: current, wantMatch: true},
		{name: "wrong password", plain: "a passphrase worth keepinq", encoded: current},
		{name: "empty password against a real hash", plain: "", encoded: current},
		{
			name: "older params report needsRehash", plain: plain, encoded: old,
			wantMatch: true, wantRehash: true,
		},
		{
			name: "one weaker param is enough", plain: plain, encoded: partialHash,
			wantMatch: true, wantRehash: true,
		},
		{name: "stronger params need no rehash", plain: plain, encoded: strongerHash, wantMatch: true},
		{name: "wrong password with older params", plain: "not it at all", encoded: old},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, rehash, err := Verify(tt.plain, tt.encoded)
			if (err != nil) != tt.wantInvalid {
				t.Fatalf("Verify() error = %v, wantInvalid %v", err, tt.wantInvalid)
			}
			if match != tt.wantMatch {
				t.Errorf("match = %v, want %v", match, tt.wantMatch)
			}
			if rehash != tt.wantRehash {
				t.Errorf("needsRehash = %v, want %v", rehash, tt.wantRehash)
			}
		})
	}
}

// TestVerifyRejectsMalformedHash covers every way a stored value can be
// unusable. Each must be an error, never a silent match.
func TestVerifyRejectsMalformedHash(t *testing.T) {
	valid, err := Hash("a passphrase worth keeping")
	if err != nil {
		t.Fatalf("Hash() = %v", err)
	}
	fields := strings.Split(valid, "$")

	tests := []struct {
		name    string
		encoded string
	}{
		{name: "empty", encoded: ""},
		{name: "not a PHC string", encoded: "a passphrase worth keeping"},
		{name: "too few fields", encoded: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA"},
		{name: "leading text instead of a dollar", encoded: "x" + valid},
		{name: "wrong variant", encoded: strings.Replace(valid, "$argon2id$", "$argon2i$", 1)},
		{name: "unparsable version", encoded: strings.Replace(valid, "$v=19$", "$v=x$", 1)},
		{name: "unsupported version", encoded: strings.Replace(valid, "$v=19$", "$v=16$", 1)},
		{name: "unparsable params", encoded: strings.Replace(valid, "m=65536,t=3,p=2", "m=a,t=b,p=c", 1)},
		{name: "corrupt salt", encoded: "$" + fields[1] + "$" + fields[2] + "$" + fields[3] + "$!!!$" + fields[5]},
		{name: "corrupt key", encoded: "$" + fields[1] + "$" + fields[2] + "$" + fields[3] + "$" + fields[4] + "$!!!"},
		{name: "empty salt", encoded: "$" + fields[1] + "$" + fields[2] + "$" + fields[3] + "$$" + fields[5]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, rehash, err := Verify("a passphrase worth keeping", tt.encoded)
			if !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("Verify() error = %v, want ErrInvalidHash", err)
			}
			if match || rehash {
				t.Errorf("match = %v, needsRehash = %v; want both false", match, rehash)
			}
			if !NeedsRehash(tt.encoded) {
				t.Error("NeedsRehash() = false for an undecodable hash, want true")
			}
		})
	}
}

// TestHashWithRejectsUnusableParams covers the guard against parameters that
// would produce a hash nothing can verify.
func TestHashWithRejectsUnusableParams(t *testing.T) {
	tests := []struct {
		name   string
		params Params
	}{
		{name: "no salt", params: Params{Memory: 1024, Time: 1, Threads: 1, SaltLen: 0, KeyLen: 32}},
		{name: "no key", params: Params{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 0}},
		{name: "absurd salt", params: Params{Memory: 1024, Time: 1, Threads: 1, SaltLen: maxSaltLen + 1, KeyLen: 32}},
		{name: "absurd key", params: Params{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: maxKeyLen + 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := HashWith("a passphrase worth keeping", tt.params); !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("HashWith() error = %v, want ErrInvalidHash", err)
			}
		})
	}
}

// TestNeedsRehash covers the standalone check used when no plain password is
// at hand.
func TestNeedsRehash(t *testing.T) {
	current, err := Hash("a passphrase worth keeping")
	if err != nil {
		t.Fatalf("Hash() = %v", err)
	}
	old, err := HashWith("a passphrase worth keeping", weakParams())
	if err != nil {
		t.Fatalf("HashWith(weak) = %v", err)
	}
	if NeedsRehash(current) {
		t.Error("NeedsRehash(current) = true, want false")
	}
	if !NeedsRehash(old) {
		t.Error("NeedsRehash(old) = false, want true")
	}
}
