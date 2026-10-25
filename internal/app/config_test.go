package app

import (
	"strings"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

func validConfig(t *testing.T) Config {
	t.Helper()
	cfg, err := LoadConfig("", "../../config/config.yaml")
	if err != nil {
		t.Fatalf("default config.yaml must be valid: %v", err)
	}
	// The shipped default points at the mounted secret path, which does not
	// exist in a test. Point it at generated keys instead, so building the
	// app in a test loads a real key set.
	cfg.Modules.Auth.Token.SigningKeysDir = testkit.SigningKeys(t, "test-key")
	return cfg
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		section string // empty = valid
	}{
		{"defaults", func(*Config) {}, ""},
		{"no service name", func(c *Config) { c.Service.Name = "" }, "service"},
		{"bad environment", func(c *Config) { c.Service.Environment = "prod" }, "service"},
		{"no addr", func(c *Config) { c.HTTP.Addr = "" }, "http"},
		{"no body limit", func(c *Config) { c.HTTP.MaxBodyBytes = 0 }, "http"},
		{"no db host", func(c *Config) { c.Database.Leader.Host = "" }, "database"},
		{"auth off in production", func(c *Config) { c.Service.Environment = EnvProduction }, "auth"},
		{"auth on needs valid auth config", func(c *Config) { c.Auth.Enabled = true; c.Auth.Mode = "nope" }, "auth"},
		{"email keys required in staging", func(c *Config) { c.Service.Environment = EnvStaging }, "crypto"},
		{"metrics on needs path", func(c *Config) { c.Metrics.Enabled = true; c.Metrics.Path = "" }, "metrics"},
		{"swagger on needs credentials", func(c *Config) { c.Swagger.Enabled = true }, "swagger"},
		{"tracing on needs endpoint", func(c *Config) { c.Tracing.Enabled = true; c.Tracing.Endpoint = "" }, "tracing"},
		{"negative drain delay", func(c *Config) { c.Lifecycle.DrainDelay = -1 }, "lifecycle"},
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

func TestLoadConfigDerivesTracingIdentity(t *testing.T) {
	cfg := validConfig(t)
	if cfg.Tracing.ServiceName != cfg.Service.Name || cfg.Validator.FieldNameTag != "json" {
		t.Errorf("derived defaults not applied: %+v / %+v", cfg.Tracing.Config, cfg.Validator)
	}
}
