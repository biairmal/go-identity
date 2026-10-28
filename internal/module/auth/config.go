// Package auth owns the sign-in flows and is the only issuer of tokens:
// registration, email verification, password and Google sign-in, refresh,
// logout, password reset, invites, tenant switching and service tokens.
package auth

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"

	"github.com/biairmal/go-identity/internal/module/auth/provider/google"
)

// Token claim modes for TokenConfig.Claims.
const (
	// ClaimsRoles puts only role names in the token, keeping it small;
	// resource services map roles to permissions through authz.
	ClaimsRoles = "roles"
	// ClaimsRolesAndPermissions adds a flattened perms claim, so a resource
	// service needs no call back to identity.
	ClaimsRolesAndPermissions = "roles_and_permissions"
)

// Config is the modules.auth block.
type Config struct {
	// PublicURL is identity's own base URL, used in OAuth redirects and
	// email links back to identity.
	PublicURL string `mapstructure:"public_url"`
	// FrontendURLs allow-lists redirect targets. The first entry is the
	// base of the links in emails.
	FrontendURLs []string `mapstructure:"frontend_urls"`
	// ServiceClients are the resource services allowed to call
	// /v1/internal with client credentials.
	ServiceClients []ServiceClient `mapstructure:"service_clients"`
	// Providers are the enabled sign-in methods; at least one must be on.
	Providers ProvidersConfig `mapstructure:"providers"`
	// Registration controls self sign-up.
	Registration RegistrationConfig `mapstructure:"registration"`
	// Token configures the access token; refresh lifetimes are in
	// modules.session.
	Token TokenConfig `mapstructure:"token"`
	// Security holds the brute-force defenses.
	Security SecurityConfig `mapstructure:"security"`
}

// ServiceClient is one resource service's credentials. Only the hash is
// configured; the secret itself lives with the calling service.
type ServiceClient struct {
	ID         string `mapstructure:"id"`
	SecretHash string `mapstructure:"secret_hash"`
}

// ProvidersConfig lists the sign-in methods.
type ProvidersConfig struct {
	Password PasswordProviderConfig `mapstructure:"password"`
	Google   GoogleProviderConfig   `mapstructure:"google"`
}

// PasswordProviderConfig configures email and password sign-in.
type PasswordProviderConfig struct {
	Enabled                  bool `mapstructure:"enabled"`
	MinLength                int  `mapstructure:"min_length"`
	RequireEmailVerification bool `mapstructure:"require_email_verification"`
	// BreachedPasswordCheck would reject passwords found in breach corpora
	// (HIBP k-anonymity API). Not built yet: Validate rejects true so the
	// key never silently does nothing.
	BreachedPasswordCheck bool `mapstructure:"breached_password_check"`
}

// GoogleProviderConfig configures Google OIDC sign-in.
type GoogleProviderConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	// IssuerURL is the OIDC issuer whose discovery document names the
	// endpoints and keys. Empty means Google; tests point it at a fake.
	IssuerURL string `mapstructure:"issuer_url"`
	// AllowedDomains restricts sign-in to these email domains; empty allows
	// any.
	AllowedDomains []string `mapstructure:"allowed_domains"`
	// AutoLinkVerifiedEmail links a Google account to an existing user with
	// the same verified email instead of refusing the sign-in.
	AutoLinkVerifiedEmail bool `mapstructure:"auto_link_verified_email"`
}

// RegistrationConfig controls self sign-up. Disabled means invite-only.
type RegistrationConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	DefaultRoles []string `mapstructure:"default_roles"`
}

// TokenConfig configures the access token identity issues.
type TokenConfig struct {
	Issuer         string        `mapstructure:"issuer"`
	Audience       []string      `mapstructure:"audience"`
	AccessTTL      time.Duration `mapstructure:"access_ttl"`
	Claims         string        `mapstructure:"claims"`
	SigningKeysDir string        `mapstructure:"signing_keys_dir"`
}

// SecurityConfig holds the brute-force defenses.
type SecurityConfig struct {
	// LoginRateLimit is "<count>/<window>", e.g. 10/5m, applied per IP and
	// per email.
	LoginRateLimit string `mapstructure:"login_rate_limit"`
	// RefreshRateLimit is "<count>/<window>" for POST /v1/auth/refresh, per
	// IP. It is looser than the login budget: every signed-in client
	// refreshes on its own, and many may share one address.
	RefreshRateLimit string `mapstructure:"refresh_rate_limit"`
	// LockoutAfterFailures locks an account after this many consecutive
	// failures.
	LockoutAfterFailures int `mapstructure:"lockout_after_failures"`
	// LockoutDuration is how long that lock lasts.
	LockoutDuration time.Duration `mapstructure:"lockout_duration"`
}

// Default returns the settings a client starts from: password sign-in on,
// Google off, open registration, 15-minute access tokens.
func Default() Config {
	return Config{
		PublicURL:    "http://localhost:8080",
		FrontendURLs: []string{"http://localhost:3000"},
		Providers: ProvidersConfig{
			Password: PasswordProviderConfig{Enabled: true, MinLength: 10, RequireEmailVerification: true},
			Google:   GoogleProviderConfig{IssuerURL: google.Issuer, AutoLinkVerifiedEmail: true},
		},
		Registration: RegistrationConfig{Enabled: true, DefaultRoles: []string{"member"}},
		Token: TokenConfig{
			Issuer:         "identity",
			Audience:       []string{"api"},
			AccessTTL:      15 * time.Minute,
			Claims:         ClaimsRoles,
			SigningKeysDir: "/etc/identity/keys",
		},
		Security: SecurityConfig{
			LoginRateLimit:       "10/5m",
			RefreshRateLimit:     "60/5m",
			LockoutAfterFailures: 10,
			LockoutDuration:      15 * time.Minute,
		},
	}
}

// ServiceClient returns the configured client by id, for POST /v1/auth/token.
func (c *Config) ServiceClient(id string) (ServiceClient, bool) {
	for _, sc := range c.ServiceClients {
		if sc.ID == id {
			return sc, true
		}
	}
	return ServiceClient{}, false
}

// EmailBaseURL is the base of the links in emails: the first frontend URL.
func (c *Config) EmailBaseURL() string {
	if len(c.FrontendURLs) == 0 {
		return ""
	}
	return c.FrontendURLs[0]
}

// AllowsRedirect reports whether raw is one of the allow-listed frontend URLs
// or a path below one, so a tampered redirect_to cannot send a user elsewhere.
func (c *Config) AllowsRedirect(raw string) bool {
	target, err := url.Parse(raw)
	if err != nil || !target.IsAbs() {
		return false
	}
	for _, allowed := range c.FrontendURLs {
		base, err := url.Parse(allowed)
		if err != nil {
			continue
		}
		if target.Scheme == base.Scheme && target.Host == base.Host &&
			strings.HasPrefix(path(target), path(base)) {
			return true
		}
	}
	return false
}

// path normalises a URL path to compare prefixes.
func path(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	if !strings.HasSuffix(u.Path, "/") {
		return u.Path + "/"
	}
	return u.Path
}

// Validate checks the block's own fields. Whether registration's default
// roles exist is a cross-module rule and lives in internal/app.
func (c *Config) Validate() error {
	if err := c.validateURLs(); err != nil {
		return err
	}
	if err := c.validateProviders(); err != nil {
		return err
	}
	if err := c.Token.validate(); err != nil {
		return err
	}
	if err := c.Security.validate(); err != nil {
		return err
	}
	return c.validateServiceClients()
}

// validateURLs checks public_url and the frontend allow-list are absolute.
func (c *Config) validateURLs() error {
	if err := absoluteURL("public_url", c.PublicURL); err != nil {
		return err
	}
	if len(c.FrontendURLs) == 0 {
		return errorz.BadRequest().WithMessage("frontend_urls must list at least one URL")
	}
	for _, raw := range c.FrontendURLs {
		if err := absoluteURL("frontend_urls", raw); err != nil {
			return err
		}
	}
	return nil
}

// validateProviders requires at least one enabled provider and complete
// settings for each enabled one.
func (c *Config) validateProviders() error {
	p := c.Providers
	if !p.Password.Enabled && !p.Google.Enabled {
		return errorz.BadRequest().WithMessage("at least one provider must be enabled")
	}
	if p.Password.Enabled && p.Password.MinLength < minPasswordLength {
		return errorz.BadRequest().
			WithMessage(fmt.Sprintf("providers.password.min_length must be at least %d", minPasswordLength))
	}
	if p.Password.BreachedPasswordCheck {
		return errorz.BadRequest().
			WithMessage("providers.password.breached_password_check is not built yet; it must be false")
	}
	if p.Google.Enabled {
		if p.Google.ClientID == "" || p.Google.ClientSecret == "" {
			return errorz.BadRequest().
				WithMessage("providers.google.enabled requires client_id and client_secret")
		}
		if c.PublicURL == "" {
			return errorz.BadRequest().WithMessage("providers.google.enabled requires public_url")
		}
		if p.Google.IssuerURL != "" {
			if err := absoluteURL("providers.google.issuer_url", p.Google.IssuerURL); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateServiceClients requires an id and a secret hash on each entry.
func (c *Config) validateServiceClients() error {
	seen := make(map[string]bool, len(c.ServiceClients))
	for _, sc := range c.ServiceClients {
		if sc.ID == "" {
			return errorz.BadRequest().WithMessage("service_clients entries need an id")
		}
		if seen[sc.ID] {
			return errorz.BadRequest().WithMessage("service_clients id " + sc.ID + " is listed twice")
		}
		seen[sc.ID] = true
		if sc.SecretHash == "" {
			return errorz.BadRequest().WithMessage("service_clients " + sc.ID + " needs a secret_hash")
		}
	}
	return nil
}

// minPasswordLength is the floor for the configurable password length, so a
// client cannot weaken it below the policy in TRD 10.
const minPasswordLength = 10

// validate checks the access-token settings.
func (t *TokenConfig) validate() error {
	if t.Issuer == "" {
		return errorz.BadRequest().WithMessage("token.issuer is required")
	}
	if len(t.Audience) == 0 {
		return errorz.BadRequest().WithMessage("token.audience must list at least one audience")
	}
	if t.AccessTTL <= 0 {
		return errorz.BadRequest().WithMessage("token.access_ttl must be positive")
	}
	if t.Claims != ClaimsRoles && t.Claims != ClaimsRolesAndPermissions {
		return errorz.BadRequest().WithMessage("token.claims must be roles or roles_and_permissions")
	}
	if t.SigningKeysDir == "" {
		return errorz.BadRequest().WithMessage("token.signing_keys_dir is required")
	}
	return nil
}

// validate checks the brute-force settings, including the rate-limit syntax.
func (s SecurityConfig) validate() error {
	if _, _, err := s.ParsedLoginRateLimit(); err != nil {
		return err
	}
	if _, _, err := s.ParsedRefreshRateLimit(); err != nil {
		return err
	}
	if s.LockoutAfterFailures <= 0 {
		return errorz.BadRequest().WithMessage("security.lockout_after_failures must be positive")
	}
	if s.LockoutDuration <= 0 {
		return errorz.BadRequest().WithMessage("security.lockout_duration must be positive")
	}
	return nil
}

// ParsedLoginRateLimit splits "<count>/<window>" into its parts, e.g. 10/5m
// into 10 and 5 minutes.
func (s SecurityConfig) ParsedLoginRateLimit() (count int, window time.Duration, err error) {
	return parseRate("security.login_rate_limit", s.LoginRateLimit)
}

// ParsedRefreshRateLimit splits RefreshRateLimit like ParsedLoginRateLimit.
func (s SecurityConfig) ParsedRefreshRateLimit() (count int, window time.Duration, err error) {
	return parseRate("security.refresh_rate_limit", s.RefreshRateLimit)
}

// parseRate splits a "<count>/<window>" rate; field names it in errors.
func parseRate(field, raw string) (count int, window time.Duration, err error) {
	before, after, found := strings.Cut(strings.TrimSpace(raw), "/")
	if !found {
		return 0, 0, errorz.BadRequest().WithMessage(field + ` must look like "10/5m"`)
	}
	count, err = strconv.Atoi(strings.TrimSpace(before))
	if err != nil || count <= 0 {
		return 0, 0, errorz.BadRequest().WithMessage(field + " count must be a positive number")
	}
	window, err = time.ParseDuration(strings.TrimSpace(after))
	if err != nil || window <= 0 {
		return 0, 0, errorz.BadRequest().WithMessage(field + " window must be a positive duration, e.g. 5m")
	}
	return count, window, nil
}

// absoluteURL requires a parseable absolute http(s) URL.
func absoluteURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return errorz.BadRequest().WithMessage(field + " must be an absolute URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errorz.BadRequest().WithMessage(field + " must be an http or https URL")
	}
	return nil
}
