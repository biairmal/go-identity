// Package user owns user accounts, their credentials and the super admin
// bootstrap. Email is stored encrypted and found through a blind index, so the
// plain value never reaches the database.
package user

import (
	"strings"

	"github.com/biairmal/go-sdk/lib/errorz"
)

// Config is the modules.user block.
type Config struct {
	// SuperAdmin seeds the one super admin on first start.
	SuperAdmin SuperAdminConfig `mapstructure:"super_admin"`
}

// SuperAdminConfig is the account created on first start. It is read only
// while no super admin exists; later starts ignore it.
type SuperAdminConfig struct {
	Email    string `mapstructure:"email"`
	Password string `mapstructure:"password"`
}

// Default returns the settings a client starts from. The super admin has no
// default: it must be supplied on first start.
func Default() Config { return Config{} }

// Configured reports whether both credentials are set, which first start
// requires.
func (s SuperAdminConfig) Configured() bool {
	return strings.TrimSpace(s.Email) != "" && s.Password != ""
}

// Validate checks the block's own fields. An empty super admin is valid here,
// because it is only required on a first start; the bootstrap fails with a
// clear message when it finds no super admin and no settings.
func (c Config) Validate() error {
	email := strings.TrimSpace(c.SuperAdmin.Email)
	if email == "" {
		if c.SuperAdmin.Password != "" {
			return errorz.BadRequest().WithMessage("super_admin.email is required when a password is set")
		}
		return nil
	}
	if !strings.Contains(email, "@") {
		return errorz.BadRequest().WithMessage("super_admin.email must be an email address")
	}
	if c.SuperAdmin.Password == "" {
		return errorz.BadRequest().WithMessage("super_admin.password is required when an email is set")
	}
	return nil
}
