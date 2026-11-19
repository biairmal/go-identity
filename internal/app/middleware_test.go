package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
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
			if expose := rec.Header().Get("Access-Control-Expose-Headers"); tt.wantAllow != "" &&
				!strings.Contains(expose, "X-Trace-Id") {
				t.Errorf("Expose-Headers = %q, want X-Trace-Id in it", expose)
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

func TestRoutePattern(t *testing.T) {
	var got string
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req)
			got = routePattern(req) // read after routing, as middleware.Tracing does
		})
	})
	r.Route("/v1", func(v1 chi.Router) { v1.Get("/users/{id}", func(http.ResponseWriter, *http.Request) {}) })

	for _, tt := range []struct{ path, want string }{
		{"/v1/users/5f0c9b2e", "/v1/users/{id}"},
		{"/nope", ""},
	} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tt.path, http.NoBody))
		if got != tt.want {
			t.Errorf("routePattern(%s) = %q, want %q", tt.path, got, tt.want)
		}
	}
	if p := routePattern(httptest.NewRequest(http.MethodGet, "/", http.NoBody)); p != "" {
		t.Errorf("without chi: %q, want empty", p)
	}
}
