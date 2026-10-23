package requestip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFrom(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		trustProxy bool
		want       string
	}{
		{
			name:       "connection address",
			remoteAddr: "203.0.113.7:54321",
			want:       "203.0.113.7",
		},
		{
			name:       "connection address without a port",
			remoteAddr: "203.0.113.7",
			want:       "203.0.113.7",
		},
		{
			name:       "ipv6 connection address",
			remoteAddr: "[2001:db8::1]:443",
			want:       "2001:db8::1",
		},
		{
			name:       "forwarded header ignored without trust",
			remoteAddr: "10.0.0.1:1234",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7"},
			want:       "10.0.0.1",
		},
		{
			name:       "forwarded header used with trust",
			remoteAddr: "10.0.0.1:1234",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7"},
			trustProxy: true,
			want:       "203.0.113.7",
		},
		{
			name:       "first address of the chain is the client",
			remoteAddr: "10.0.0.1:1234",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7, 10.0.0.2, 10.0.0.3"},
			trustProxy: true,
			want:       "203.0.113.7",
		},
		{
			name:       "real ip header as a fallback",
			remoteAddr: "10.0.0.1:1234",
			headers:    map[string]string{"X-Real-Ip": "203.0.113.9"},
			trustProxy: true,
			want:       "203.0.113.9",
		},
		{
			name:       "forged header falls back to the connection",
			remoteAddr: "10.0.0.1:1234",
			headers:    map[string]string{"X-Forwarded-For": "not-an-ip"},
			trustProxy: true,
			want:       "10.0.0.1",
		},
		{
			name:       "unparseable connection address yields nothing",
			remoteAddr: "pipe",
			want:       "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			r.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			if got := From(r, tt.trustProxy); got != tt.want {
				t.Errorf("From() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMiddlewarePutsIPInContext(t *testing.T) {
	var got string
	h := Middleware(false)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = Get(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "203.0.113.7:1111"
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != "203.0.113.7" {
		t.Errorf("Get() in handler = %q, want 203.0.113.7", got)
	}
}

func TestGetWithoutMiddleware(t *testing.T) {
	if got := Get(context.Background()); got != "" {
		t.Errorf("Get() on a bare context = %q, want empty", got)
	}
}
