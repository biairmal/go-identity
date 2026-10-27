package app

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/metrics"
	"github.com/biairmal/go-sdk/lib/tracer"
	"github.com/go-chi/chi/v5"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// TestLogLinesAreJSONWithRequestID runs a request through the real middleware
// chain and checks every log line is a JSON object carrying the request's ID
// and no body.
func TestLogLinesAreJSONWithRequestID(t *testing.T) {
	cfg := Config{
		Service: ServiceConfig{Name: "go-identity", Version: "test", Environment: EnvLocal},
		HTTP:    HTTPConfig{MaxBodyBytes: 1 << 20},
		Log:     logger.Options{Level: logger.LevelInfo, Format: logger.FormatJSON, Output: logger.OutputStdout},
	}
	lines := captureStdout(t, func() {
		log := NewLogger(&cfg)
		a := &App{cfg: cfg}
		chain := middlewareChain(&cfg, log, tracer.NewNoOp(), metrics.NewNoOp())
		srv := testkit.Server(t, a.routes(chi.NewRouter(), nil, chain))
		header := http.Header{"X-Request-Id": {"req-log-test"}}
		testkit.Do[any](t, srv, http.MethodPost, "/v1/nope", map[string]string{"email": "bia@example.com"}, header)
	})

	if len(lines) == 0 {
		t.Fatal("no log lines written")
	}
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line is not JSON: %q (%v)", line, err)
		}
		if entry["request_id"] != "req-log-test" {
			t.Errorf("request_id = %v, want req-log-test in %q", entry["request_id"], line)
		}
		if _, ok := entry["body"]; ok || strings.Contains(line, "bia@example.com") {
			t.Errorf("log line contains the request body: %q", line)
		}
	}
}

// captureStdout returns the non-empty lines fn writes to os.Stdout. The logger
// binds os.Stdout when it is built, so fn must build it.
func captureStdout(t *testing.T, fn func()) []string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	func() {
		defer func() { os.Stdout = orig }()
		fn()
	}()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(<-done)))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}
