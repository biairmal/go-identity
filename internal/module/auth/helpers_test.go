package auth

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// testRoutes is a router plus the route groups a module registers into,
// standing in for what internal/app builds.
type testRoutes struct {
	mux    chi.Router
	routes *httpx.Routes
}

// newTestRoutes builds the route groups the way internal/app does, so a
// module's Register is exercised against real chi routers.
func newTestRoutes() *testRoutes {
	r := chi.NewRouter()
	rt := &httpx.Routes{Root: r}
	r.Route("/v1", func(v1 chi.Router) {
		rt.API = v1
		v1.Route("/me", func(g chi.Router) { rt.Me = g })
		v1.Route("/admin", func(g chi.Router) { rt.Admin = g })
		v1.Route("/internal", func(g chi.Router) { rt.Internal = g })
	})
	return &testRoutes{mux: r, routes: rt}
}

// headerKID decodes a JWT's header and returns its kid.
func headerKID(t *testing.T, signed string) string {
	t.Helper()
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		KID string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	if header.Alg != "RS256" {
		t.Errorf("alg = %q, want RS256", header.Alg)
	}
	return header.KID
}

// writeFile writes a test fixture file.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
