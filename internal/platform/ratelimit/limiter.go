// Package ratelimit builds the service's rate limiter over go-sdk ratelimit:
// a Redis sliding window shared by every pod when Redis is configured, or a
// per-process token bucket otherwise. It holds no identity logic; callers
// choose their own keys.
package ratelimit

import (
	"context"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	sdkratelimit "github.com/biairmal/go-sdk/lib/ratelimit"
	"github.com/biairmal/go-sdk/lib/redis"

	"github.com/biairmal/go-identity/internal/platform/apierr"
)

// keyPrefix namespaces every key, so the limiter can share a Redis with
// other data.
const keyPrefix = "ratelimit:"

// Log is the part of logger.Logger the limiter writes to.
type Log interface {
	Warn(msg string, fields ...logger.Field)
	ErrorWithContext(ctx context.Context, msg string, fields ...logger.Field)
}

// Limiter allows a fixed number of requests per window for each key.
type Limiter struct {
	backend sdkratelimit.Limiter
	name    string
	log     Log
}

// New returns a Limiter allowing count requests per window for each key. With
// a Redis client the limit is a sliding window shared by every process using
// that Redis. Without one it is an in-memory token bucket per process, and a
// warning is logged, because N pods then allow up to N times the limit.
func New(count int, window time.Duration, client redis.Client, log Log) (*Limiter, error) {
	if count <= 0 || window <= 0 {
		return nil, errorz.BadRequest().WithMessage("ratelimit: count and window must be positive")
	}
	if log == nil {
		log = logger.NewNoOp()
	}
	cfg := sdkratelimit.Config{
		Backend: sdkratelimit.BackendMemory,
		Rate:    float64(count) / window.Seconds(),
		Burst:   count,
		Window:  window,
	}
	if client != nil {
		cfg.Backend = sdkratelimit.BackendRedis
	} else {
		log.Warn("no redis configured: rate limits are in-memory and apply per pod")
	}
	backend, err := sdkratelimit.FromConfig(cfg, client)
	if err != nil {
		return nil, err
	}
	return &Limiter{backend: backend, name: cfg.Backend, log: log}, nil
}

// Backend is "redis" or "memory".
func (l *Limiter) Backend() string { return l.name }

// Check consumes one request for key. Over the limit it returns RATE_LIMITED
// with the wait in meta.retry_after, which httpx.Handle copies into the
// Retry-After header. When the backend itself fails (Redis down) the request
// is allowed and the failure logged: a limiter outage must not take sign-in
// down with it, and the account lockout still bounds password guessing.
func (l *Limiter) Check(ctx context.Context, key string) error {
	res, err := l.backend.Allow(ctx, keyPrefix+key)
	if err != nil {
		l.log.ErrorWithContext(ctx, "rate limiter unavailable, allowing request",
			logger.F("error", err.Error()))
		return nil
	}
	if res.Allowed {
		return nil
	}
	return apierr.WithRetryAfter(apierr.ReasonRateLimited, max(res.RetryAfter, time.Second))
}
