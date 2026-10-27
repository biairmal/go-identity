package auth

import (
	"net/http"
	"strings"
	"testing"

	"github.com/biairmal/go-sdk/lib/httpkit/handler"

	"github.com/biairmal/go-identity/internal/module/auth/provider"
	"github.com/biairmal/go-identity/internal/platform/apierr"
)

// TestCheckClaims is the refusal list: an unverified address is 403
// OAUTH_EMAIL_UNVERIFIED and one outside allowed_domains 403
// OAUTH_DOMAIN_NOT_ALLOWED.
func TestCheckClaims(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		claims  provider.Claims
		want    apierr.Reason
	}{
		{"verified, any domain", nil, provider.Claims{Email: "bia@example.com", EmailVerified: true}, ""},
		{"unverified", nil, provider.Claims{Email: "bia@example.com"}, apierr.ReasonOAuthEmailUnverified},
		{"no email", nil, provider.Claims{EmailVerified: true}, apierr.ReasonOAuthEmailUnverified},
		{
			"allowed domain",
			[]string{"client.com"},
			provider.Claims{Email: "bia@client.com", EmailVerified: true},
			"",
		},
		{
			"domain case differs",
			[]string{"Client.com"},
			provider.Claims{Email: "bia@CLIENT.com", EmailVerified: true},
			"",
		},
		{
			"other domain",
			[]string{"client.com"},
			provider.Claims{Email: "bia@example.com", EmailVerified: true},
			apierr.ReasonOAuthDomainNotAllowed,
		},
		{
			"subdomain is not the domain",
			[]string{"client.com"},
			provider.Claims{Email: "bia@evil.client.com", EmailVerified: true},
			apierr.ReasonOAuthDomainNotAllowed,
		},
		{
			"unverified beats domain",
			[]string{"client.com"},
			provider.Claims{Email: "bia@example.com"},
			apierr.ReasonOAuthEmailUnverified,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			cfg.Providers.Google.AllowedDomains = tt.domains
			s := &GoogleSignIns{cfg: &cfg}
			err := s.checkClaims(&tt.claims)
			if got := apierr.ReasonOf(err); got != tt.want {
				t.Fatalf("checkClaims = %v (reason %q), want %q", err, got, tt.want)
			}
			if tt.want != "" && handler.StatusCodeFromError(err) != http.StatusForbidden {
				t.Errorf("status = %d, want 403", handler.StatusCodeFromError(err))
			}
		})
	}
}

func TestDisplayName(t *testing.T) {
	tests := []struct {
		name   string
		claims provider.Claims
		want   string
	}{
		{"google name", provider.Claims{Name: " Bia Irmal ", Email: "bia@example.com"}, "Bia Irmal"},
		{"local part when nameless", provider.Claims{Email: "bia@example.com"}, "bia"},
		{"cut to the limit", provider.Claims{Name: strings.Repeat("é", 150)}, strings.Repeat("é", maxDisplayName)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := displayName(&tt.claims); got != tt.want {
				t.Errorf("displayName = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWithQuery(t *testing.T) {
	tests := []struct {
		raw, key, value, want string
	}{
		{"http://localhost:3000/auth/callback", "code", "abc", "http://localhost:3000/auth/callback?code=abc"},
		{
			"http://localhost:3000/cb?next=%2Fx", "error", "OAUTH_EMAIL_UNVERIFIED",
			"http://localhost:3000/cb?error=OAUTH_EMAIL_UNVERIFIED&next=%2Fx",
		},
		{"http://localhost:3000/cb?linked=0", "linked", "1", "http://localhost:3000/cb?linked=1"},
	}
	for _, tt := range tests {
		got, err := withQuery(tt.raw, tt.key, tt.value)
		if err != nil || got != tt.want {
			t.Errorf("withQuery(%q) = %q, %v; want %q", tt.raw, got, err, tt.want)
		}
	}
}

// TestRandomToken checks the PKCE verifier length rule and that values differ.
func TestRandomToken(t *testing.T) {
	a, b := randomToken(), randomToken()
	if len(a) < 43 || len(a) > 128 || a == b {
		t.Errorf("randomToken = %q, %q: want two distinct 43-128 character values", a, b)
	}
}
