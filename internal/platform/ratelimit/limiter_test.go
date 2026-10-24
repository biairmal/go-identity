package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/biairmal/go-sdk/lib/httpkit/handler"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/redis"

	"github.com/biairmal/go-identity/internal/platform/apierr"
)

// recordingLog keeps the messages written to it.
type recordingLog struct {
	mu     sync.Mutex
	warns  []string
	errors []string
}

func (l *recordingLog) Warn(msg string, _ ...logger.Field) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, msg)
}

func (l *recordingLog) ErrorWithContext(_ context.Context, msg string, _ ...logger.Field) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, msg)
}

// fakeRedis answers the sliding-window script; every other method panics
// through the nil embedded interface, so an unexpected call fails loudly.
type fakeRedis struct {
	redis.Client
	keys    []string
	allowed bool
	err     error
}

func (f *fakeRedis) Eval(_ context.Context, _ string, keys []string, _ ...any) (any, error) {
	f.keys = append(f.keys, keys...)
	if f.err != nil {
		return nil, f.err
	}
	if f.allowed {
		return []any{int64(1), int64(4), int64(0)}, nil
	}
	return []any{int64(0), int64(0), int64(2500)}, nil
}

// TestNewWithoutRedisIsInMemoryAndWarns builds the in-memory backend and logs
// that limits apply per pod.
func TestNewWithoutRedisIsInMemoryAndWarns(t *testing.T) {
	log := &recordingLog{}
	l, err := New(2, time.Minute, nil, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if l.Backend() != "memory" {
		t.Errorf("backend = %q, want memory", l.Backend())
	}
	if len(log.warns) != 1 || !strings.Contains(log.warns[0], "in-memory") {
		t.Errorf("warnings = %v, want one about in-memory limits", log.warns)
	}
	ctx := context.Background()
	for i := range 2 {
		if err := l.Check(ctx, "k"); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
	err = l.Check(ctx, "k")
	if apierr.ReasonOf(err) != apierr.ReasonRateLimited {
		t.Fatalf("third request = %v, want RATE_LIMITED", err)
	}
	if handler.StatusCodeFromError(err) != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", handler.StatusCodeFromError(err))
	}
	if s, ok := apierr.RetryAfterOf(err); !ok || s < 1 {
		t.Errorf("retry_after = %d, %v; want at least 1 second", s, ok)
	}
	if err := l.Check(ctx, "other"); err != nil {
		t.Errorf("another key = %v, want allowed", err)
	}
}

// TestNewWithRedisUsesRedis builds the Redis backend, logs no warning and
// sends prefixed keys to Redis.
func TestNewWithRedisUsesRedis(t *testing.T) {
	log := &recordingLog{}
	rc := &fakeRedis{allowed: true}
	l, err := New(5, time.Minute, rc, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if l.Backend() != "redis" {
		t.Errorf("backend = %q, want redis", l.Backend())
	}
	if len(log.warns) != 0 {
		t.Errorf("warnings = %v, want none", log.warns)
	}
	if err := l.Check(context.Background(), "login:ip:1.2.3.4"); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(rc.keys) != 1 || rc.keys[0] != "ratelimit:login:ip:1.2.3.4" {
		t.Errorf("redis keys = %v", rc.keys)
	}

	rc.allowed = false
	err = l.Check(context.Background(), "k")
	if s, _ := apierr.RetryAfterOf(err); apierr.ReasonOf(err) != apierr.ReasonRateLimited || s != 3 {
		t.Errorf("denied = %v (retry_after %d), want RATE_LIMITED with 3 seconds", err, s)
	}
}

// TestCheckFailsOpenOnBackendError allows the request and logs when Redis is
// unreachable.
func TestCheckFailsOpenOnBackendError(t *testing.T) {
	log := &recordingLog{}
	l, err := New(5, time.Minute, &fakeRedis{err: errors.New("connection refused")}, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := l.Check(context.Background(), "k"); err != nil {
		t.Errorf("Check = %v, want nil (fail open)", err)
	}
	if len(log.errors) != 1 {
		t.Errorf("errors logged = %v, want one", log.errors)
	}
}

func TestNewRejectsBadLimits(t *testing.T) {
	for _, tt := range []struct {
		count  int
		window time.Duration
	}{{0, time.Minute}, {5, 0}, {-1, time.Second}} {
		if _, err := New(tt.count, tt.window, nil, nil); err == nil {
			t.Errorf("New(%d, %s) = nil error", tt.count, tt.window)
		}
	}
}
