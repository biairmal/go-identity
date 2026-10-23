// Package session owns refresh-token families: issuing them, rotating them on
// every use and revoking a whole family when a rotated token is replayed.
package session

import (
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
)

// Config is the modules.session block. The access-token settings live in
// modules.auth; these are the refresh-token lifetimes.
type Config struct {
	// RefreshTTL is how long a refresh token lives, slid forward on each
	// rotation.
	RefreshTTL time.Duration `mapstructure:"refresh_ttl"`
	// RefreshAbsoluteTTL caps a whole family from the first sign-in,
	// however often it is rotated; after it the user signs in again.
	RefreshAbsoluteTTL time.Duration `mapstructure:"refresh_absolute_ttl"`
	// RefreshReuseGrace tolerates a token presented again shortly after its
	// rotation, which happens when requests race across pods. A replay
	// after it revokes the family.
	RefreshReuseGrace time.Duration `mapstructure:"refresh_reuse_grace"`
}

// Default returns the settings a client starts from: 30-day sliding tokens
// inside a 90-day absolute window.
func Default() Config {
	return Config{
		RefreshTTL:         720 * time.Hour,
		RefreshAbsoluteTTL: 2160 * time.Hour,
		RefreshReuseGrace:  10 * time.Second,
	}
}

// Validate checks the block's own fields.
func (c Config) Validate() error {
	if c.RefreshTTL <= 0 {
		return errorz.BadRequest().WithMessage("refresh_ttl must be positive")
	}
	if c.RefreshAbsoluteTTL < c.RefreshTTL {
		return errorz.BadRequest().WithMessage("refresh_absolute_ttl must be at least refresh_ttl")
	}
	if c.RefreshReuseGrace <= 0 {
		return errorz.BadRequest().WithMessage("refresh_reuse_grace must be positive")
	}
	return nil
}
