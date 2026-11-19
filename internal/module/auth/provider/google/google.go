// Package google signs users in with Google over OpenID Connect.
package google

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/biairmal/go-identity/internal/module/auth/provider"
)

// Issuer is Google's OIDC issuer, the default discovery base.
const Issuer = "https://accounts.google.com"

// Config is what the provider needs from modules.auth.
type Config struct {
	// IssuerURL is the OIDC issuer, Google when empty; discovery reads
	// IssuerURL/.well-known/openid-configuration. Tests point it at a fake.
	IssuerURL    string
	ClientID     string
	ClientSecret string
	// RedirectURL is identity's callback, registered with Google.
	RedirectURL string
	// HTTPClient makes every call to Google (discovery, keys, code exchange);
	// nil uses http.DefaultClient.
	HTTPClient *http.Client
}

// Provider is Google behind provider.Provider. Discovery runs on first use,
// not at startup, so the service starts while Google is unreachable; a
// failed discovery is retried on the next request.
type Provider struct {
	cfg Config
	mu  sync.Mutex
	op  *oidc.Provider
}

var _ provider.Provider = (*Provider)(nil)

// New returns a provider for cfg; an empty IssuerURL is Google. It makes no
// network call.
func New(cfg Config) *Provider {
	cfg.IssuerURL = cmp.Or(cfg.IssuerURL, Issuer)
	return &Provider{cfg: cfg}
}

// discover returns the discovered provider, fetching the document once.
func (p *Provider) discover(ctx context.Context) (*oidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.op != nil {
		return p.op, nil
	}
	// The provider keeps this context for every later key-set fetch, so it carries
	// the client but not the request's span: a later fetch must not join the trace
	// of whichever sign-in happened to run discovery.
	op, err := oidc.NewProvider(p.client(trace.ContextWithSpanContext(ctx, trace.SpanContext{})), p.cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("google: discovery: %w", err)
	}
	p.op = op
	return op, nil
}

// client puts the configured HTTP client on ctx, where go-oidc and oauth2 look
// for it.
func (p *Provider) client(ctx context.Context) context.Context {
	if p.cfg.HTTPClient == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, p.cfg.HTTPClient)
}

// oauth2Config is the client configuration against the discovered endpoints.
func (p *Provider) oauth2Config(op *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		RedirectURL:  p.cfg.RedirectURL,
		Endpoint:     op.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
}

// AuthCodeURL builds the consent URL with state, nonce and the PKCE
// challenge.
func (p *Provider) AuthCodeURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	op, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	return p.oauth2Config(op).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// Exchange redeems the code with the PKCE verifier and verifies the ID token.
func (p *Provider) Exchange(ctx context.Context, code, verifier, nonce string) (*provider.Claims, error) {
	op, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := p.oauth2Config(op).Exchange(p.client(ctx), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("google: exchange code: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, errors.New("google: token response has no id_token")
	}
	idt, err := op.Verifier(&oidc.Config{ClientID: p.cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("google: verify id_token: %w", err)
	}
	if idt.Nonce != nonce {
		return nil, errors.New("google: id_token nonce does not match")
	}
	var c struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idt.Claims(&c); err != nil {
		return nil, fmt.Errorf("google: read id_token claims: %w", err)
	}
	return &provider.Claims{Subject: idt.Subject, Email: c.Email, EmailVerified: c.EmailVerified, Name: c.Name}, nil
}
