package auth

import (
	"strings"
	"testing"
)

// TestPasswordProviderConfigValidateBreachedPasswordCheck covers T9.1: the
// HIBP check is not built, so Validate must refuse breached_password_check:
// true by name instead of silently ignoring it.
func TestPasswordProviderConfigValidateBreachedPasswordCheck(t *testing.T) {
	tests := []struct {
		name    string
		check   bool
		wantErr bool
	}{
		{name: "false validates", check: false},
		{name: "true is refused", check: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			cfg.Providers.Password.BreachedPasswordCheck = tt.check
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			const key = "providers.password.breached_password_check"
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), key) {
				t.Fatalf("Validate() error = %q, want it to name %s", err.Error(), key)
			}
		})
	}
}
