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
			l, err := a.newLimiter()
			if err != nil {
				t.Fatalf("newLimiter: %v", err)
			}
			if l.Backend() != "memory" || a.redis != nil {
				t.Errorf("backend = %s, redis client = %v; want memory and none", l.Backend(), a.redis)
			}
		})
	}
}

func TestNewLimiterRejectsBadRate(t *testing.T) {
	cfg := validConfig(t)
	cfg.Modules.Auth.Security.LoginRateLimit = "nonsense"
	if _, err := (&App{cfg: cfg, log: logger.NewNoOp()}).newLimiter(); err == nil {
		t.Error("newLimiter accepted a malformed rate")
	}
}
