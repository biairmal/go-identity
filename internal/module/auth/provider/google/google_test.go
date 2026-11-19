package google

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// countingTransport counts the requests that went through it.
type countingTransport struct{ n atomic.Int32 }

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}

func TestCallsGoThroughTheConfiguredClient(t *testing.T) {
	idp := testkit.NewOIDC(t, "client", "secret")
	rt := &countingTransport{}
	p := New(Config{
		IssuerURL: idp.URL, ClientID: "client", ClientSecret: "secret", RedirectURL: "http://localhost/cb",
		HTTPClient: &http.Client{Transport: rt},
	})

	const verifier = "verifier-verifier-verifier-verifier-1234"
	if _, err := p.AuthCodeURL(context.Background(), "state", "nonce", verifier); err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	if rt.n.Load() == 0 {
		t.Fatal("discovery did not use the configured client")
	}
}
