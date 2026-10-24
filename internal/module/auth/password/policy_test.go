package password

import (
	"errors"
	"strings"
	"testing"
)

// TestValidate has one row per policy rule from TRD 10: the length bounds
// and their edges, the common-password list in several casings, and passwords
// that must be accepted because there are no composition rules.
func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		plain   string
		wantErr error
	}{
		{name: "empty", plain: "", wantErr: ErrTooShort},
		{name: "one rune below the minimum", plain: strings.Repeat("x", MinRunes-1), wantErr: ErrTooShort},
		{name: "at the minimum", plain: "zqj-rhmwtv"},
		{name: "at the maximum", plain: strings.Repeat("zqjrhmwtv-", 12) + strings.Repeat("x", 8)},
		{name: "one rune above the maximum", plain: strings.Repeat("x", MaxRunes+1), wantErr: ErrTooLong},
		{name: "runes are counted, not bytes", plain: strings.Repeat("é", MinRunes)},
		{
			name:    "a long password of multi-byte runes is still too long",
			plain:   strings.Repeat("é", MaxRunes+1),
			wantErr: ErrTooLong,
		},
		{
			name:    "multi-byte runes below the minimum are too short",
			plain:   strings.Repeat("é", MinRunes-1),
			wantErr: ErrTooShort,
		},
		{name: "invalid UTF-8", plain: "abcdefghij\xff\xfe", wantErr: ErrNotUTF8},
		{name: "common password", plain: "password123", wantErr: ErrTooCommon},
		{name: "common password upper case", plain: "PASSWORD123", wantErr: ErrTooCommon},
		{name: "common password mixed case", plain: "PassWord123", wantErr: ErrTooCommon},
		{name: "common password title case", plain: "Basketball", wantErr: ErrTooCommon},
		{name: "common password with digits only", plain: "1234567890", wantErr: ErrTooCommon},
		{name: "a short common password is reported as too short", plain: "password", wantErr: ErrTooShort},
		{name: "no composition rules: lower case letters only", plain: "varkenshaasje"},
		{name: "no composition rules: a long passphrase with spaces", plain: "two tired walruses argue"},
		{name: "a common password with a suffix is accepted", plain: "password123-zqjrhmwtv"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.plain)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateMaximumLengthIsExact guards the fixtures above: the row named
// "at the maximum" must really be MaxRunes long, or it proves nothing.
func TestValidateMaximumLengthIsExact(t *testing.T) {
	atMax := strings.Repeat("zqjrhmwtv-", 12) + strings.Repeat("x", 8)
	if len([]rune(atMax)) != MaxRunes {
		t.Fatalf("fixture is %d runes, want %d", len([]rune(atMax)), MaxRunes)
	}
}

// TestIsCommon covers the embedded list directly: a known entry in several
// casings, a password that is not in it, and the list's size.
func TestIsCommon(t *testing.T) {
	tests := []struct {
		name  string
		plain string
		want  bool
	}{
		{name: "first entry", plain: "123456", want: true},
		{name: "last entry", plain: "blitz", want: true},
		{name: "upper case entry", plain: "QWERTYUIOP", want: true},
		{name: "mixed case entry", plain: "QwErTyUiOp", want: true},
		{name: "not in the list", plain: "two tired walruses argue", want: false},
		{name: "empty string", plain: "", want: false},
		{name: "entry with trailing space", plain: "123456 ", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCommon(tt.plain); got != tt.want {
				t.Errorf("IsCommon(%q) = %v, want %v", tt.plain, got, tt.want)
			}
		})
	}
}

// TestCommonListSize pins the embedded list's size, so a truncated or
// replaced common.txt fails the build rather than silently weakening the
// policy. Case-folding collapses a handful of entries that differ only in
// case, so the distinct count is below the 10,000 lines in the file.
func TestCommonListSize(t *testing.T) {
	const wantAtLeast = 9000
	if got := CommonListSize(); got < wantAtLeast {
		t.Errorf("CommonListSize() = %d, want at least %d", got, wantAtLeast)
	}
	if lines := strings.Count(strings.TrimRight(commonListRaw, "\n"), "\n") + 1; lines != 10000 {
		t.Errorf("common.txt has %d lines, want 10000", lines)
	}
}
