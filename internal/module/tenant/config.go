// Package tenant owns tenants and their memberships. In single mode one
// default tenant holds everything; in multi mode the super admin creates
// tenants. The schema is the same in both modes, so a client can switch later
// without migrating data.
package tenant

import (
	"regexp"

	"github.com/biairmal/go-sdk/lib/errorz"
)

// Tenancy modes for Config.Mode.
const (
	ModeSingle = "single"
	ModeMulti  = "multi"
)

// Tenant sources for Config.ResolveFrom.
const (
	SourceToken  = "token"
	SourceHeader = "header"
)

// slugPattern matches the CHECK constraint on tenants.slug.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// Config is the modules.tenant block.
type Config struct {
	// Mode is single (one built-in tenant) or multi (tenant management on).
	Mode string `mapstructure:"mode"`
	// DefaultTenantSlug is the tenant created on first start; in single mode
	// it holds everything, and it is the super admin's home tenant.
	DefaultTenantSlug string `mapstructure:"default_tenant_slug"`
	// ResolveFrom lists where a tenant may come from in multi mode. The
	// header is honored only on login and register; everything else reads
	// the token claim.
	ResolveFrom []string `mapstructure:"resolve_from"`
	// AllowSelfServiceTenants lets a signed-up user create a tenant.
	AllowSelfServiceTenants bool `mapstructure:"allow_self_service_tenants"`
}

// Default returns the settings a client starts from.
func Default() Config {
	return Config{
		Mode:              ModeSingle,
		DefaultTenantSlug: "default",
		ResolveFrom:       []string{SourceToken, SourceHeader},
	}
}

// Multi reports whether tenant management is on.
func (c Config) Multi() bool { return c.Mode == ModeMulti }

// Validate checks the block's own fields.
func (c Config) Validate() error {
	if c.Mode != ModeSingle && c.Mode != ModeMulti {
		return errorz.BadRequest().WithMessage("mode must be single or multi")
	}
	if !slugPattern.MatchString(c.DefaultTenantSlug) {
		return errorz.BadRequest().WithMessage("default_tenant_slug must match " + slugPattern.String())
	}
	if len(c.ResolveFrom) == 0 {
		return errorz.BadRequest().WithMessage("resolve_from must list at least one source")
	}
	for _, s := range c.ResolveFrom {
		if s != SourceToken && s != SourceHeader {
			return errorz.BadRequest().WithMessage("resolve_from entries must be token or header")
		}
	}
	return nil
}
