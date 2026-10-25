package rbac

import (
	"context"
	"net/http"
	"sync"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/errorz"

	"github.com/biairmal/go-identity/internal/platform/scope"
)

// Authorizer is the authz.Authorizer identity's own admin routes check with.
// It reads the caller's permissions from the database instead of the token,
// so an admin action never runs on grants up to one access-token lifetime
// stale, and it grants nothing once the user or their membership is no longer
// active. The super admin claim allows everything.
type Authorizer struct {
	repo *Repository
}

var _ authz.Authorizer = (*Authorizer)(nil)

// Can reports whether the caller holds perm.
func (a *Authorizer) Can(ctx context.Context, perm string) bool {
	return a.Require(ctx, perm) == nil
}

// Require returns nil when the caller holds perm, a 401 without an
// authenticated caller and a 403 without the permission.
func (a *Authorizer) Require(ctx context.Context, perm string) error {
	grants, err := a.grants(ctx)
	if err != nil {
		return err
	}
	if !authz.Matches(grants, perm) {
		return errorz.Forbidden().WithMessage("rbac: missing permission "+perm).WithMeta("permission", perm)
	}
	return nil
}

// Permissions returns the caller's grants (["*"] for the super admin), or nil
// when they cannot be resolved.
func (a *Authorizer) Permissions(ctx context.Context) []string {
	grants, err := a.grants(ctx)
	if err != nil {
		return nil
	}
	return grants
}

// RequireIn is Require: identity has no resource-scoped roles.
func (a *Authorizer) RequireIn(ctx context.Context, _ authz.Scope, perm string) error {
	return a.Require(ctx, perm)
}

// grants resolves the caller's permissions, once per request when Memoize
// installed a cache.
func (a *Authorizer) grants(ctx context.Context) ([]string, error) {
	if _, ok := sdkauth.ClaimsFromContext(ctx); !ok {
		return nil, errorz.Unauthorized().WithMessage("rbac: no authenticated caller")
	}
	if authz.IsSuperAdmin(ctx) {
		return []string{"*"}, nil
	}
	m, ok := ctx.Value(memoKey{}).(*memo)
	if !ok {
		return a.load(ctx)
	}
	m.once.Do(func() { m.grants, m.err = a.load(ctx) })
	return m.grants, m.err
}

// load reads the caller's active permissions in the token's tenant.
func (a *Authorizer) load(ctx context.Context) ([]string, error) {
	userID, err := scope.User(ctx)
	if err != nil {
		return nil, err
	}
	tenantID, err := scope.Tenant(ctx)
	if err != nil {
		return nil, err
	}
	return a.repo.ActivePermissions(ctx, tenantID, userID)
}

// memoKey is the context key of the per-request permission cache.
type memoKey struct{}

// memo holds one request's resolved permissions.
type memo struct {
	once   sync.Once
	grants []string
	err    error
}

// Memoize gives each request a cache for the caller's permissions, so the
// route's permission check and the service's own checks read them once.
// internal/app installs it on the admin group.
func Memoize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), memoKey{}, &memo{})))
	})
}
