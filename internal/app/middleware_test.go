package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCORS(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := cors(CORSConfig{AllowedOrigins: []string{"http://app.test"}})(ok)

	tests := []struct {
		name       string
		method     string
		origin     string
		preflight  bool
		wantStatus int
		wantAllow  string
	}{
		{"allowed origin", http.MethodGet, "http://app.test", false, http.StatusOK, "http://app.test"},
		{"other origin gets no header", http.MethodGet, "http://evil.test", false, http.StatusOK, ""},
		{"no origin", http.MethodGet, "", false, http.StatusOK, ""},
		{"preflight allowed", http.MethodOptions, "http://app.test", true, http.StatusNoContent, "http://app.test"},
		{"preflight other origin falls through", http.MethodOptions, "http://evil.test", true, http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, "/v1/x", http.NoBody)
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}
			if tt.preflight {
				r.Header.Set("Access-Control-Request-Method", http.MethodPost)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tt.wantAllow {
				t.Errorf("Allow-Origin = %q, want %q", got, tt.wantAllow)
			}
		})
	}
}

func TestMaxBody(t *testing.T) {
	var readErr error
	h := maxBody(4)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345")))
	if readErr == nil {
		t.Fatal("reading past the limit should fail")
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader("1234")))
	if readErr != nil {
		t.Fatalf("body within the limit failed: %v", readErr)
	}
}
