// Package rbac owns the permission catalog, roles and their permissions, role
// assignments and the effective permissions of a user. Permissions are
// declared in configuration because services check them in code; admins
// compose roles from that catalog but cannot invent keys.
package rbac

import (
	"regexp"
	"sort"
	"strings"

	"github.com/biairmal/go-sdk/lib/errorz"
)

// keyPattern matches the CHECK constraint on permissions.key:
// resource:action with an optional :scope suffix.
var keyPattern = regexp.MustCompile(`^[a-z0-9_-]+(:[a-z0-9_-]+){1,2}$`)

// System permissions identity itself checks. They are always in the catalog,
// whatever the configuration lists.
const (
	PermUsersRead     = "users:read"
	PermUsersManage   = "users:manage"
	PermRolesManage   = "roles:manage"
	PermAuditRead     = "audit:read"
	PermTenantsManage = "tenants:manage"
)

// SystemPermissions are seeded with is_system set, so a config change can
// never drop a key identity's own routes require.
func SystemPermissions() []Permission {
	return []Permission{
		{Key: PermUsersRead, Description: "View users"},
		{Key: PermUsersManage, Description: "Invite, disable and assign roles to users"},
		{Key: PermRolesManage, Description: "Create and edit roles"},
		{Key: PermAuditRead, Description: "View the audit log"},
		{Key: PermTenantsManage, Description: "Manage tenants"},
	}
}

// Config is the modules.rbac block.
type Config struct {
	// SeedOnStart creates the configured roles in every tenant that does
	// not have them yet. Existing roles are never overwritten.
	SeedOnStart bool `mapstructure:"seed_on_start"`
	// Permissions is the catalog synced to the permissions table on start.
	Permissions []Permission `mapstructure:"permissions"`
	// Roles maps a role name to the permission keys it grants.
	Roles map[string][]string `mapstructure:"roles"`
}

// Permission is one catalog entry.
type Permission struct {
	Key         string `mapstructure:"key"`
	Description string `mapstructure:"description"`
}

// Default returns the settings a client starts from: seeding on, an empty
// catalog beyond identity's own system permissions.
func Default() Config {
	return Config{SeedOnStart: true}
}

// RoleNames returns the configured role names in a stable order.
func (c Config) RoleNames() []string {
	names := make([]string, 0, len(c.Roles))
	for name := range c.Roles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// HasRole reports whether name is a configured role.
func (c Config) HasRole(name string) bool {
	_, ok := c.Roles[name]
	return ok
}

// Validate checks the block's own fields: well-formed keys, no duplicates,
// and every permission a role grants present in the catalog.
func (c Config) Validate() error {
	catalog, err := c.catalog()
	if err != nil {
		return err
	}
	for _, name := range c.RoleNames() {
		if strings.TrimSpace(name) == "" {
			return errorz.BadRequest().WithMessage("roles has an empty role name")
		}
		for _, key := range c.Roles[name] {
			if !catalog[key] {
				return errorz.BadRequest().
					WithMessage("role " + name + " grants " + key + ", which is not in permissions")
			}
		}
	}
	return nil
}

// catalog indexes the configured and system permission keys, rejecting
// malformed and duplicate entries.
func (c Config) catalog() (map[string]bool, error) {
	keys := make(map[string]bool, len(c.Permissions))
	for _, p := range c.Permissions {
		if !keyPattern.MatchString(p.Key) {
			return nil, errorz.BadRequest().
				WithMessage("permission key " + p.Key + " must match " + keyPattern.String())
		}
		if keys[p.Key] {
			return nil, errorz.BadRequest().WithMessage("permission key " + p.Key + " is listed twice")
		}
		keys[p.Key] = true
	}
	for _, p := range SystemPermissions() {
		keys[p.Key] = true
	}
	return keys, nil
}
