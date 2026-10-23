package app

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/biairmal/go-identity/internal/platform/httpx"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// groupsModule mounts one route in every group.
type groupsModule struct{}

func (groupsModule) Register(rt *httpx.Routes) {
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	rt.Root.Get("/root", ok)
	rt.API.Get("/api", ok)
	rt.Me.Get("/profile", ok)
	rt.Admin.Get("/users", ok)
	rt.Internal.Get("/users", ok)
}

func TestRouteGroups(t *testing.T) {
	r := (&App{}).routes([]Module{groupsModule{}}, nil)
	var got []string
	if err := chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		got = append(got, method+" "+route)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := testkit.Server(t, r)
	for _, p := range []string{"/root", "/v1/api", "/v1/me/profile", "/v1/admin/users", "/v1/internal/users"} {
		if s := testkit.Do[any](t, srv, http.MethodGet, p, nil, nil).Status; s != http.StatusNoContent {
			t.Errorf("GET %s = %d, want 204 (routes: %v)", p, s, got)
		}
	}
}

func TestUnknownRoutesUseErrorEnvelope(t *testing.T) {
	srv := testkit.Server(t, (&App{}).routes([]Module{groupsModule{}}, nil))
	tests := []struct {
		method, path string
		status       int
		code         string
	}{
		{http.MethodGet, "/nope", http.StatusNotFound, "ERR_NOT_FOUND"},
		{http.MethodGet, "/v1/nope", http.StatusNotFound, "ERR_NOT_FOUND"},
		{http.MethodGet, "/v1/admin/nope", http.StatusNotFound, "ERR_NOT_FOUND"},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed, codeMethodNotAllowed},
		{http.MethodPost, "/v1/me/profile", http.StatusMethodNotAllowed, codeMethodNotAllowed},
	}
	for _, tt := range tests {
		r := testkit.Do[any](t, srv, tt.method, tt.path, nil, nil)
		if r.Status != tt.status || r.Error == nil || r.Error.Code != tt.code {
			t.Errorf("%s %s = %d %s, want %d %s", tt.method, tt.path, r.Status, r.Raw, tt.status, tt.code)
		}
	}
}
