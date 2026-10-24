// Package token builds identity's access tokens. It takes everything it needs
// as a Subject, so it never imports the user or rbac modules: auth fills the
// subject through its own ports.
package token

import (
	"context"
	"time"

	"github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/google/uuid"

	identitykeys "github.com/biairmal/go-identity/internal/module/auth/keys"
	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/scope"
)

// Claim names. They are chosen so go-sdk auth reads them with no mapping: it
// already takes sub as the subject and roles as roles.
const (
	ClaimTenant     = "tid"
	ClaimRoles      = "roles"
	ClaimPerms      = "perms"
	ClaimSuperAdmin = "sa"
	ClaimTokenID    = "jti"
	ClaimScope      = "scope"
)

// ScopePasswordChange restricts a token to choosing a new password. It is
// issued at sign-in while a password change is forced.
const ScopePasswordChange = "password_change"

// Claims modes, mirroring modules.auth.token.claims.
const (
	ClaimsRoles               = "roles"
	ClaimsRolesAndPermissions = "roles_and_permissions"
)

// Subject is who a token is for. auth fills it from the user and rbac modules
// through its ports, so this package stays independent of both.
type Subject struct {
	UserID uuid.UUID
	// Roles are the role names held in the tenant the token is for.
	Roles []string
	// Permissions is the flattened permission list, used only when the
	// configured claims mode asks for it.
	Permissions []string
	// SuperAdmin adds the sa claim, which authz treats as every permission.
	SuperAdmin bool
	// Scope restricts a token to one purpose, such as a password change
	// after a forced reset. Empty means a full token.
	Scope string
	// SessionID is the refresh-token family the token is issued with, put in
	// the sid claim so the session list can mark the current device. Zero
	// for a token without a session.
	SessionID uuid.UUID
	// TTL overrides the configured access-token lifetime when positive,
	// e.g. for a short-lived restricted token.
	TTL time.Duration
}

// Config is what the builder needs from modules.auth.token.
type Config struct {
	Issuer    string
	Audience  []string
	AccessTTL time.Duration
	Claims    string
}

// Builder signs access tokens with the active key.
type Builder struct {
	cfg    Config
	issuer auth.Issuer
	keys   *identitykeys.Set
	clock  clock.Clock
}

// NewBuilder returns a Builder signing with the set's active key. clock may be
// nil, which uses the system clock.
func NewBuilder(cfg Config, set *identitykeys.Set, clk clock.Clock) (*Builder, error) {
	if set == nil {
		return nil, errorz.BadRequest().WithMessage("token: no key set")
	}
	if clk == nil {
		clk = clock.System{}
	}
	issuer, err := auth.NewRS256Issuer(set.Private(),
		auth.WithIssuerName(cfg.Issuer),
		auth.WithDefaultTTL(cfg.AccessTTL),
		auth.WithKeyID(set.ActiveKID()),
	)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("token: build issuer")
	}
	return &Builder{cfg: cfg, issuer: issuer, keys: set, clock: clk}, nil
}

// Access signs an access token for the subject, acting in tenantID. The
// tenant is always present: in single mode it is the default tenant.
func (b *Builder) Access(_ context.Context, s *Subject, tenantID uuid.UUID) (string, time.Time, error) {
	now := b.clock.Now()
	ttl := b.cfg.AccessTTL
	if s.TTL > 0 {
		ttl = s.TTL
	}
	expiry := now.Add(ttl)

	extra := map[string]any{
		ClaimTenant:  tenantID.String(),
		ClaimTokenID: uuid.NewString(),
	}
	if s.SuperAdmin {
		extra[ClaimSuperAdmin] = true
	}
	if s.SessionID != uuid.Nil {
		extra[scope.ClaimSession] = s.SessionID.String()
	}
	if s.Scope != "" {
		extra[ClaimScope] = s.Scope
	}
	if b.cfg.Claims == ClaimsRolesAndPermissions {
		extra[ClaimPerms] = s.Permissions
	}

	opts := []auth.IssueOption{
		auth.WithTTL(ttl),
		auth.WithIssuedAt(now),
		auth.WithRoles(s.Roles...),
		auth.WithExtraClaims(extra),
	}
	if len(b.cfg.Audience) > 0 {
		opts = append(opts, auth.WithAudience(b.cfg.Audience[0]))
	}

	signed, err := b.issuer.Issue(s.UserID.String(), opts...)
	if err != nil {
		return "", time.Time{}, errorz.Wrap(err).WithCode(errorz.CodeInternal).
			WithMessage("token: sign access token")
	}
	return signed, expiry, nil
}

// PublicKeys returns the keys to publish, for the JWKS endpoint.
func (b *Builder) PublicKeys() []auth.PublicKey { return b.keys.Public() }
