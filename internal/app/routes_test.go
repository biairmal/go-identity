package app

import (
	"net/http"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

func TestUnknownRoutesUseErrorEnvelope(t *testing.T) {
	srv := testkit.Server(t, (&App{}).routes(nil, nil))
	tests := []struct {
		method, path string
		status       int
		code         string
	}{
		{http.MethodGet, "/nope", http.StatusNotFound, "ERR_NOT_FOUND"},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed, codeMethodNotAllowed},
	}
	for _, tt := range tests {
		r := testkit.Do[any](t, srv, tt.method, tt.path, nil, nil)
		if r.Status != tt.status || r.Error == nil || r.Error.Code != tt.code {
			t.Errorf("%s %s = %d %s, want %d %s", tt.method, tt.path, r.Status, r.Raw, tt.status, tt.code)
		}
	}
}
