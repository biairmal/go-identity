// Package provider is the boundary between the sign-in flows and an external
// identity provider. Google is the only one (provider/google); another
// provider implements the same interface.
package provider

import "context"

// Claims is what a provider vouches for about the person who signed in.
type Claims struct {
	// Subject is the provider's stable ID for the account.
	Subject string
	Email   string
	// EmailVerified is the provider's word that the person owns Email.
	EmailVerified bool
	Name          string
}

// Provider runs the authorization code flow with PKCE against one identity
// provider.
type Provider interface {
	// AuthCodeURL is where the browser goes to sign in. It carries state,
	// the nonce the ID token must echo and the S256 challenge of verifier.
	AuthCodeURL(ctx context.Context, state, nonce, verifier string) (string, error)
	// Exchange trades the callback's code for an ID token, verifies its
	// signature, issuer, audience, expiry and nonce, and returns its claims.
	Exchange(ctx context.Context, code, verifier, nonce string) (*Claims, error)
}
