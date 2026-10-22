package testkit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/biairmal/go-sdk/lib/httpkit/response"
)

// Server serves h (the full handler chain, e.g. app.Handler()) on a local
// port for the duration of the test.
func Server(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// Response is a decoded go-sdk envelope plus the raw status and headers.
type Response[T any] struct {
	Status int
	Header http.Header
	Data   T
	Error  *response.ErrorPayload
	Raw    []byte
}

// envelope mirrors response.BaseResponse with a typed error.
type envelope[T any] struct {
	Timestamp time.Time              `json:"timestamp"`
	Data      T                      `json:"data"`
	Error     *response.ErrorPayload `json:"error"`
}

// Do sends method path with body encoded as JSON (nil for none) and decodes
// the envelope's data into T. header may be nil.
func Do[T any](t *testing.T, srv *httptest.Server, method, path string, body any, header http.Header) Response[T] {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("testkit: encode body: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+path, rd)
	if err != nil {
		t.Fatalf("testkit: build request: %v", err)
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("testkit: %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("testkit: read body: %v", err)
	}
	out := Response[T]{Status: resp.StatusCode, Header: resp.Header, Raw: raw}
	if len(bytes.TrimSpace(raw)) == 0 {
		return out
	}
	var env envelope[T]
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("testkit: decode %s %s (status %d): %v: %s", method, path, resp.StatusCode, err, raw)
	}
	out.Data, out.Error = env.Data, env.Error
	return out
}
