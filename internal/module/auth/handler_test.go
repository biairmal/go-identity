package auth

import (
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// getAuthConfigRaw serves m's routes and returns the raw data object of
// GET /v1/auth/config, so tests can inspect the exact keys sent.
func getAuthConfigRaw(t *testing.T, m *Module) map[string]any {
	t.Helper()
	rt := newTestRoutes()
	m.Register(rt.routes)
	srv := testkit.Server(t, rt.mux)
	r := testkit.Do[map[string]any](t, srv, http.MethodGet, "/v1/auth/config", nil, nil)
	if r.Status != http.StatusOK {
		t.Fatalf("GET /v1/auth/config = %d: %s", r.Status, r.Raw)
	}
	return r.Data
}

func TestAuthConfigReflectsConfig(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		tenancy string
		want    AuthConfigResponse
	}{
		{
			name:    "defaults",
			mutate:  func(*Config) {},
			tenancy: "single",
			want:    AuthConfigResponse{ProvidersResponse{Password: true}, true, "single"},
		},
		{
			name: "google enabled",
			mutate: func(c *Config) {
				c.Providers.Google = GoogleProviderConfig{Enabled: true, ClientID: "cid", ClientSecret: "csecret"}
			},
			tenancy: "single",
			want:    AuthConfigResponse{ProvidersResponse{Password: true, Google: true}, true, "single"},
		},
		{
			name: "google only",
			mutate: func(c *Config) {
				c.Providers.Password.Enabled = false
				c.Providers.Google = GoogleProviderConfig{Enabled: true, ClientID: "cid", ClientSecret: "csecret"}
			},
			tenancy: "single",
			want:    AuthConfigResponse{ProvidersResponse{Google: true}, true, "single"},
		},
		{
			name:    "registration off",
			mutate:  func(c *Config) { c.Registration.Enabled = false },
			tenancy: "single",
			want:    AuthConfigResponse{ProvidersResponse{Password: true}, false, "single"},
		},
		{
			name:    "multi tenancy",
			mutate:  func(*Config) {},
			tenancy: "multi",
			want:    AuthConfigResponse{ProvidersResponse{Password: true}, true, "multi"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(t)
			tt.mutate(cfg)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("test config invalid: %v", err)
			}
			m, err := New(cfg, Deps{Clock: testkit.NewClock(time.Now()), Tenancy: tt.tenancy})
			if err != nil {
				t.Fatalf("New() = %v", err)
			}
			rt := newTestRoutes()
			m.Register(rt.routes)
			srv := testkit.Server(t, rt.mux)
			r := testkit.Do[AuthConfigResponse](t, srv, http.MethodGet, "/v1/auth/config", nil, nil)
			if r.Status != http.StatusOK {
				t.Fatalf("status = %d: %s", r.Status, r.Raw)
			}
			if r.Data != tt.want {
				t.Errorf("data = %+v, want %+v", r.Data, tt.want)
			}
		})
	}
}

// TestAuthConfigHasNoSecret enables Google with a client ID and secret and
// checks the response holds exactly the documented keys, so nothing from the
// provider settings can leak into it.
func TestAuthConfigHasNoSecret(t *testing.T) {
	cfg := testConfig(t)
	cfg.Providers.Google = GoogleProviderConfig{
		Enabled: true, ClientID: "client-id-value", ClientSecret: "client-secret-value",
		AllowedDomains: []string{"example.com"},
	}
	cfg.ServiceClients = []ServiceClient{{ID: "svc", SecretHash: "hash-value"}}
	m, err := New(cfg, Deps{Clock: testkit.NewClock(time.Now()), Tenancy: "multi"})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	data := getAuthConfigRaw(t, m)

	if got, want := sortedKeys(data), []string{"providers", "registration", "tenancy"}; !slices.Equal(got, want) {
		t.Errorf("keys = %v, want %v", got, want)
	}
	providers, ok := data["providers"].(map[string]any)
	if !ok {
		t.Fatalf("providers = %T, want object", data["providers"])
	}
	if got, want := sortedKeys(providers), []string{"google", "password"}; !slices.Equal(got, want) {
		t.Errorf("providers keys = %v, want %v", got, want)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"client-id-value", "client-secret-value", "hash-value", "example.com"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("response %s contains %q", raw, secret)
		}
	}
}

// TestAuthConfigMatchesOpenAPI checks the handler's JSON keys and types
// against the AuthConfig schema in api/openapi.yaml.
func TestAuthConfigMatchesOpenAPI(t *testing.T) {
	spec := loadOpenAPI(t)
	op, ok := spec.Paths["/v1/auth/config"]["get"]
	if !ok {
		t.Fatal("api/openapi.yaml has no GET /v1/auth/config")
	}
	if op.Security == nil || len(*op.Security) != 0 {
		t.Errorf("GET /v1/auth/config security = %v, want [] (public)", op.Security)
	}
	schema, ok := spec.Components.Schemas["AuthConfig"]
	if !ok {
		t.Fatal("api/openapi.yaml has no AuthConfig schema")
	}

	m := testModule(t, testConfig(t))
	m.authConfig.Tenancy = "single"
	data := getAuthConfigRaw(t, m)
	checkSchema(t, "AuthConfig", &schema, data)
}

// checkSchema asserts value has exactly the schema's properties, all
// required ones present, with matching JSON types and enum values.
func checkSchema(t *testing.T, where string, s *openAPISchema, value any) {
	t.Helper()
	switch s.Type {
	case "object":
		obj, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("%s = %T, want object", where, value)
		}
		var props []string
		for name := range s.Properties {
			props = append(props, name)
		}
		slices.Sort(props)
		if got := sortedKeys(obj); !slices.Equal(got, props) {
			t.Errorf("%s keys = %v, spec properties %v", where, got, props)
		}
		for _, req := range s.Required {
			if _, ok := obj[req]; !ok {
				t.Errorf("%s missing required %q", where, req)
			}
		}
		for name, prop := range s.Properties {
			if v, ok := obj[name]; ok {
				checkSchema(t, where+"."+name, &prop, v)
			}
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			t.Errorf("%s = %T, want boolean", where, value)
		}
	case "string":
		str, ok := value.(string)
		if !ok {
			t.Errorf("%s = %T, want string", where, value)
			return
		}
		if len(s.Enum) > 0 && !slices.Contains(s.Enum, str) {
			t.Errorf("%s = %q, not in enum %v", where, str, s.Enum)
		}
	default:
		t.Fatalf("%s: schema type %q not handled by this test", where, s.Type)
	}
}

// openAPISchema is the subset of a schema object this test compares.
type openAPISchema struct {
	Type       string                   `yaml:"type"`
	Required   []string                 `yaml:"required"`
	Properties map[string]openAPISchema `yaml:"properties"`
	Enum       []string                 `yaml:"enum"`
}

// openAPIDoc is the subset of api/openapi.yaml this test reads.
type openAPIDoc struct {
	Paths map[string]map[string]struct {
		Security *[]map[string][]string `yaml:"security"`
	} `yaml:"paths"`
	Components struct {
		Schemas map[string]openAPISchema `yaml:"schemas"`
	} `yaml:"components"`
}

func loadOpenAPI(t *testing.T) *openAPIDoc {
	t.Helper()
	raw, err := os.ReadFile("../../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var doc openAPIDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	return &doc
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// TestAuthConfigResponseFields guards the DTO itself: a field added to it
// would be served to anonymous callers, so the set is pinned here.
func TestAuthConfigResponseFields(t *testing.T) {
	var got []string
	typ := reflect.TypeFor[AuthConfigResponse]()
	for i := range typ.NumField() {
		got = append(got, typ.Field(i).Tag.Get("json"))
	}
	if want := []string{"providers", "registration", "tenancy"}; !slices.Equal(got, want) {
		t.Errorf("AuthConfigResponse json fields = %v, want %v", got, want)
	}
}
