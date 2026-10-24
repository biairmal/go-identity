package app

import (
	"testing"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/redis"
)

// TestNewLimiterBackend builds the in-memory limiter without Redis, and falls
// back to it when a configured Redis cannot be reached at startup, because
// Redis is a soft dependency.
func TestNewLimiterBackend(t *testing.T) {
	tests := []struct {
		name  string
		redis RedisConfig
	}{
		{"no redis", RedisConfig{}},
		{"redis unreachable", RedisConfig{Config: redis.Config{Mode: redis.ModeStandalone, Address: "127.0.0.1:1"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Redis = tt.redis
			a := &App{cfg: cfg, log: logger.NewNoOp()}
			l, r, err := a.newLimiters()
			if err != nil {
				t.Fatalf("newLimiters: %v", err)
			}
			if l.Backend() != "memory" || r.Backend() != "memory" || a.redis != nil {
				t.Errorf("backends = %s, %s, redis client = %v; want memory and none", l.Backend(), r.Backend(), a.redis)
			}
		})
	}
}

func TestNewLimiterRejectsBadRate(t *testing.T) {
	for _, mutate := range []func(c *Config){
		func(c *Config) { c.Modules.Auth.Security.LoginRateLimit = "nonsense" },
		func(c *Config) { c.Modules.Auth.Security.RefreshRateLimit = "nonsense" },
	} {
		cfg := validConfig(t)
		mutate(&cfg)
		if _, _, err := (&App{cfg: cfg, log: logger.NewNoOp()}).newLimiters(); err == nil {
			t.Error("newLimiters accepted a malformed rate")
		}
	}
}
