package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/biairmal/go-sdk/lib/logger"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// newTestApp builds the app against the test kit's Postgres.
func newTestApp(t *testing.T) *App {
	t.Helper()
	cfg := validConfig(t)
	cfg.Database = testkit.PostgresConfig(t)
	cfg.HTTP.Addr = "127.0.0.1:0"
	cfg.Lifecycle.DrainDelay = 300 * time.Millisecond
	a, err := New(context.Background(), &cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestOperationalEndpoints(t *testing.T) {
	a := newTestApp(t)
	srv := testkit.Server(t, a.Handler())
	clk := testkit.NewClock(time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC))

	if r := testkit.Do[any](t, srv, http.MethodGet, "/healthz", nil, nil); r.Status != http.StatusOK {
		t.Fatalf("/healthz = %d", r.Status)
	}
	// Not ready until Serve starts listening.
	if r := testkit.Do[any](t, srv, http.MethodGet, "/readyz", nil, nil); r.Status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz before serving = %d, want 503", r.Status)
	}
	a.ready.Store(true)
	if r := testkit.Do[any](t, srv, http.MethodGet, "/readyz", nil, nil); r.Status != http.StatusOK {
		t.Fatalf("/readyz while serving = %d, want 200", r.Status)
	}
	r := testkit.Do[any](t, srv, http.MethodGet, "/version", nil, http.Header{"X-Request-Id": {"req-1"}})
	if r.Status != http.StatusOK || r.Header.Get("X-Request-Id") != "req-1" {
		t.Fatalf("/version = %d, X-Request-Id %q", r.Status, r.Header.Get("X-Request-Id"))
	}
	clk.Advance(time.Hour)
	if got := clk.Now(); got.Hour() != 1 {
		t.Fatalf("clock = %v", got)
	}
}

func TestShutdownFlipsReadinessThenExits(t *testing.T) {
	a := newTestApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx) }()

	waitFor(t, a.ready.Load)
	cancel()
	waitFor(t, func() bool { return !a.ready.Load() })

	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz while draining = %d, want 503", rec.Code)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil (clean exit)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after shutdown")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
