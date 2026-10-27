package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/biairmal/go-identity/internal/app"
)

// undocumented are the routes no API description lists: the Swagger UI
// itself, the Prometheus scrape endpoint, and the 404/405 fallbacks.
var undocumented = []string{"/swagger/", "/metrics"}

// notAnnotated are served by go-sdk handlers (httpkit health, readiness and
// version; auth.JWKSHandler): there is no local function to carry swaggo
// annotations, so only api/openapi.yaml describes them.
var notAnnotated = map[string]bool{
	"GET /healthz": true, "GET /readyz": true, "GET /version": true, "GET /.well-known/jwks.json": true,
}

// TestEveryRouteIsDocumented walks the router of an app with every optional
// route on (multi mode, Google, Swagger) and checks each route appears in
// both api/openapi.yaml (what the frontend generates its client from) and the
// annotation-generated api/swagger/swagger.json, so a new handler cannot ship
// undocumented.
func TestEveryRouteIsDocumented(t *testing.T) {
	cfg := identityConfig(t, func(c *app.Config) {
		c.Modules.Tenant.Mode = "multi"
		g := &c.Modules.Auth.Providers.Google
		g.Enabled, g.ClientID, g.ClientSecret = true, googleClientID, googleClientSecret
		c.Swagger = app.SwaggerConfig{Enabled: true, Username: "docs", Password: "docs-password"}
	})
	cfg.Auth.Local.JWKSURL = "http://127.0.0.1/.well-known/jwks.json" // never fetched: no request is served
	a, err := app.New(context.Background(), cfg, logger.NewNoOp())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.DB().Close() })
	router, ok := a.Handler().(chi.Routes)
	if !ok {
		t.Fatal("handler is not a chi.Routes")
	}

	openapi := openAPIRoutes(t)
	swagger := swaggerRoutes(t)
	var missingSpec, missingSwagger []string
	walk := func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		for _, prefix := range undocumented {
			if strings.HasPrefix(route, prefix) {
				return nil
			}
		}
		r := method + " " + strings.TrimSuffix(route, "/")
		if !openapi[r] {
			missingSpec = append(missingSpec, r)
		}
		if !swagger[r] && !notAnnotated[r] {
			missingSwagger = append(missingSwagger, r)
		}
		return nil
	}
	if err := chi.Walk(router, walk); err != nil {
		t.Fatal(err)
	}
	sort.Strings(missingSpec)
	sort.Strings(missingSwagger)
	if len(missingSpec) > 0 {
		t.Errorf("routes missing from api/openapi.yaml:\n  %s", strings.Join(missingSpec, "\n  "))
	}
	if len(missingSwagger) > 0 {
		t.Errorf("routes without swaggo annotations (missing from api/swagger/swagger.json; run make swagger):\n  %s",
			strings.Join(missingSwagger, "\n  "))
	}
}

// openAPIRoutes is every "METHOD /path" in api/openapi.yaml.
func openAPIRoutes(t *testing.T) map[string]bool {
	t.Helper()
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return methodPaths(doc.Paths)
}

// swaggerRoutes is every "METHOD /path" in api/swagger/swagger.json.
func swaggerRoutes(t *testing.T) map[string]bool {
	t.Helper()
	var doc struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "swagger", "swagger.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return methodPaths(doc.Paths)
}

// methodPaths flattens a paths object; keys that are not HTTP methods
// (parameters, summary) are skipped.
func methodPaths(paths map[string]map[string]any) map[string]bool {
	out := map[string]bool{}
	for path, ops := range paths {
		for method := range ops {
			m := strings.ToUpper(method)
			switch m {
			case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				out[m+" "+path] = true
			}
		}
	}
	return out
}
