package app

import (
	"strings"
	"testing"
	"time"

	identityauth "github.com/biairmal/go-identity/internal/module/auth"
	"github.com/biairmal/go-identity/internal/module/rbac"
)

// TestModuleConfigValidate covers one valid and one invalid case per rule in
// the TRD 4 validation table, and names the section each rule belongs to.
func TestModuleConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		section string // empty = still valid
	}{
		{"defaults", func(*Config) {}, ""},

		// modules.auth
		{"no provider enabled", func(c *Config) {
			c.Modules.Auth.Providers.Password.Enabled = false
			c.Modules.Auth.Providers.Google.Enabled = false
		}, "modules.auth"},
		{"google without client id", func(c *Config) {
			c.Modules.Auth.Providers.Google.Enabled = true
			c.Modules.Auth.Providers.Google.ClientSecret = "secret"
		}, "modules.auth"},
		{"google without client secret", func(c *Config) {
			c.Modules.Auth.Providers.Google.Enabled = true
			c.Modules.Auth.Providers.Google.ClientID = "id"
		}, "modules.auth"},
		{"google with both credentials", func(c *Config) {
			c.Modules.Auth.Providers.Google.Enabled = true
			c.Modules.Auth.Providers.Google.ClientID = "id"
			c.Modules.Auth.Providers.Google.ClientSecret = "secret"
		}, ""},
		{"password below the floor", func(c *Config) {
			c.Modules.Auth.Providers.Password.MinLength = 8
		}, "modules.auth"},
		{"relative public url", func(c *Config) { c.Modules.Auth.PublicURL = "/identity" }, "modules.auth"},
		{"no frontend urls", func(c *Config) { c.Modules.Auth.FrontendURLs = nil }, "modules.auth"},
		{"frontend url without scheme", func(c *Config) {
			c.Modules.Auth.FrontendURLs = []string{"localhost:3000"}
		}, "modules.auth"},
		{"no signing keys dir", func(c *Config) { c.Modules.Auth.Token.SigningKeysDir = "" }, "modules.auth"},
		{"no token issuer", func(c *Config) { c.Modules.Auth.Token.Issuer = "" }, "modules.auth"},
		{"no token audience", func(c *Config) { c.Modules.Auth.Token.Audience = nil }, "modules.auth"},
		{"zero access ttl", func(c *Config) { c.Modules.Auth.Token.AccessTTL = 0 }, "modules.auth"},
		{"unknown claims mode", func(c *Config) { c.Modules.Auth.Token.Claims = "everything" }, "modules.auth"},
		{"claims with permissions", func(c *Config) {
			c.Modules.Auth.Token.Claims = identityauth.ClaimsRolesAndPermissions
		}, ""},
		{"rate limit without a window", func(c *Config) {
			c.Modules.Auth.Security.LoginRateLimit = "10"
		}, "modules.auth"},
		{"rate limit with a bad count", func(c *Config) {
			c.Modules.Auth.Security.LoginRateLimit = "many/5m"
		}, "modules.auth"},
		{"rate limit with a bad window", func(c *Config) {
			c.Modules.Auth.Security.LoginRateLimit = "10/forever"
		}, "modules.auth"},
		{"zero lockout threshold", func(c *Config) {
			c.Modules.Auth.Security.LockoutAfterFailures = 0
		}, "modules.auth"},
		{"zero lockout duration", func(c *Config) {
			c.Modules.Auth.Security.LockoutDuration = 0
		}, "modules.auth"},
		{"service client without an id", func(c *Config) {
			c.Modules.Auth.ServiceClients = []identityauth.ServiceClient{{SecretHash: "hash"}}
		}, "modules.auth"},
		{"service client without a secret hash", func(c *Config) {
			c.Modules.Auth.ServiceClients = []identityauth.ServiceClient{{ID: "notes"}}
		}, "modules.auth"},
		{"duplicate service client", func(c *Config) {
			c.Modules.Auth.ServiceClients = []identityauth.ServiceClient{
				{ID: "notes", SecretHash: "a"}, {ID: "notes", SecretHash: "b"},
			}
		}, "modules.auth"},
		{"one service client", func(c *Config) {
			c.Modules.Auth.ServiceClients = []identityauth.ServiceClient{{ID: "notes", SecretHash: "hash"}}
		}, ""},

		// modules.session
		{"zero refresh ttl", func(c *Config) { c.Modules.Session.RefreshTTL = 0 }, "modules.session"},
		{"absolute ttl below sliding", func(c *Config) {
			c.Modules.Session.RefreshAbsoluteTTL = c.Modules.Session.RefreshTTL - time.Hour
		}, "modules.session"},
		{"zero reuse grace", func(c *Config) { c.Modules.Session.RefreshReuseGrace = 0 }, "modules.session"},

		// modules.tenant
		{"unknown tenancy mode", func(c *Config) { c.Modules.Tenant.Mode = "many" }, "modules.tenant"},
		{"multi mode", func(c *Config) { c.Modules.Tenant.Mode = "multi" }, ""},
		{"bad default tenant slug", func(c *Config) {
			c.Modules.Tenant.DefaultTenantSlug = "Default Tenant"
		}, "modules.tenant"},
		{"no tenant source", func(c *Config) { c.Modules.Tenant.ResolveFrom = nil }, "modules.tenant"},
		{"unknown tenant source", func(c *Config) {
			c.Modules.Tenant.ResolveFrom = []string{"query"}
		}, "modules.tenant"},

		// modules.user
		{"super admin email without a password", func(c *Config) {
			c.Modules.User.SuperAdmin.Email = "root@example.com"
		}, "modules.user"},
		{"super admin password without an email", func(c *Config) {
			c.Modules.User.SuperAdmin.Password = "a-long-password"
		}, "modules.user"},
		{"super admin email that is not one", func(c *Config) {
			c.Modules.User.SuperAdmin.Email = "root"
			c.Modules.User.SuperAdmin.Password = "a-long-password"
		}, "modules.user"},
		{"super admin fully set", func(c *Config) {
			c.Modules.User.SuperAdmin.Email = "root@example.com"
			c.Modules.User.SuperAdmin.Password = "a-long-password"
		}, ""},

		// modules.rbac
		{"malformed permission key", func(c *Config) {
			c.Modules.RBAC.Permissions = []rbac.Permission{{Key: "Users Manage"}}
		}, "modules.rbac"},
		{"duplicate permission key", func(c *Config) {
			c.Modules.RBAC.Permissions = []rbac.Permission{{Key: "notes:read"}, {Key: "notes:read"}}
		}, "modules.rbac"},
		{"role granting an uncataloged permission", func(c *Config) {
			c.Modules.RBAC.Roles = map[string][]string{"admin": {"notes:write"}}
		}, "modules.rbac"},
		{"role granting a system permission", func(c *Config) {
			c.Modules.RBAC.Permissions = nil
			c.Modules.RBAC.Roles = map[string][]string{"member": {rbac.PermUsersRead}}
		}, ""},
		{"empty role name", func(c *Config) {
			c.Modules.RBAC.Roles = map[string][]string{"": {}}
		}, "modules.rbac"},

		// cross-module
		{"default role that is not a role", func(c *Config) {
			c.Modules.Auth.Registration.DefaultRoles = []string{"ghost"}
		}, "modules"},
		{"default role that exists", func(c *Config) {
			c.Modules.RBAC.Roles = map[string][]string{"staff": {}}
			c.Modules.Auth.Registration.DefaultRoles = []string{"staff"}
		}, ""},
		{"no default roles", func(c *Config) {
			c.Modules.Auth.Registration.DefaultRoles = nil
		}, ""},

		// redis is optional
		{"redis off", func(c *Config) { c.Redis.Address = "" }, ""},
		{"redis on with a known mode", func(c *Config) {
			c.Redis.Address = "localhost:6379"
			c.Redis.Mode = "standalone"
		}, ""},
		{"redis on with an unknown mode", func(c *Config) {
			c.Redis.Address = "localhost:6379"
			c.Redis.Mode = "shards"
		}, "redis"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.section == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "config "+tt.section+":") {
				t.Fatalf("Validate() = %v, want an error naming section %q", err, tt.section)
			}
		})
	}
}

// TestLoadConfigKeepsModuleDefaults checks the YAML is layered over each
// module's Default(), so an unset key keeps the module's own value.
func TestLoadConfigKeepsModuleDefaults(t *testing.T) {
	cfg := validConfig(t)
	if got := cfg.Modules.Session.RefreshReuseGrace; got != 10*time.Second {
		t.Errorf("session.refresh_reuse_grace = %v, want 10s", got)
	}
	if got := cfg.Modules.Auth.Token.Claims; got != identityauth.ClaimsRoles {
		t.Errorf("auth.token.claims = %q, want %q", got, identityauth.ClaimsRoles)
	}
	if !cfg.Modules.RBAC.SeedOnStart {
		t.Error("rbac.seed_on_start = false, want true")
	}
	if cfg.Modules.Tenant.Multi() {
		t.Error("tenant.mode is multi, want single by default")
	}
}

// TestAuthRateLimitParsing pins the "<count>/<window>" syntax.
func TestAuthRateLimitParsing(t *testing.T) {
	tests := []struct {
		raw        string
		wantCount  int
		wantWindow time.Duration
		wantErr    bool
	}{
		{raw: "10/5m", wantCount: 10, wantWindow: 5 * time.Minute},
		{raw: " 3 / 30s ", wantCount: 3, wantWindow: 30 * time.Second},
		{raw: "1/1h", wantCount: 1, wantWindow: time.Hour},
		{raw: "0/5m", wantErr: true},
		{raw: "-1/5m", wantErr: true},
		{raw: "10/0s", wantErr: true},
		{raw: "10", wantErr: true},
		{raw: "", wantErr: true},
		{raw: "10/5x", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			sec := identityauth.SecurityConfig{LoginRateLimit: tt.raw}
			count, window, err := sec.ParsedLoginRateLimit()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsedLoginRateLimit(%q) = (%d, %v, nil), want an error", tt.raw, count, window)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsedLoginRateLimit(%q) = %v, want nil", tt.raw, err)
			}
			if count != tt.wantCount || window != tt.wantWindow {
				t.Errorf("ParsedLoginRateLimit(%q) = (%d, %v), want (%d, %v)",
					tt.raw, count, window, tt.wantCount, tt.wantWindow)
			}
		})
	}
}

// TestAuthAllowsRedirect checks the redirect allow-list: only the configured
// origins, and only at or below their path.
func TestAuthAllowsRedirect(t *testing.T) {
	cfg := identityauth.Default()
	cfg.FrontendURLs = []string{"https://app.example.com", "https://admin.example.com/console"}

	tests := []struct {
		raw  string
		want bool
	}{
		{"https://app.example.com", true},
		{"https://app.example.com/", true},
		{"https://app.example.com/verify-email", true},
		{"https://admin.example.com/console/users", true},
		{"https://admin.example.com/other", false},
		{"https://evil.example.com", false},
		{"http://app.example.com", false},           // scheme must match
		{"https://app.example.com.evil.com", false}, // host must match exactly
		{"/verify-email", false},                    // must be absolute
		{"", false},
		{"https://app.example.com:8443", false}, // port is part of the host
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := cfg.AllowsRedirect(tt.raw); got != tt.want {
				t.Errorf("AllowsRedirect(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

// TestAuthEmailBaseURL checks email links use the first frontend URL.
func TestAuthEmailBaseURL(t *testing.T) {
	cfg := identityauth.Config{FrontendURLs: []string{"https://app.example.com", "https://other.example.com"}}
	if got := cfg.EmailBaseURL(); got != "https://app.example.com" {
		t.Errorf("EmailBaseURL() = %q, want the first frontend URL", got)
	}
	var empty identityauth.Config
	if got := empty.EmailBaseURL(); got != "" {
		t.Errorf("EmailBaseURL() with no URLs = %q, want empty", got)
	}
}
