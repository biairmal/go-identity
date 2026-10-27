package app

import (
	"context"
	"net/http"
	"strings"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit"
	"github.com/biairmal/go-sdk/lib/httpkit/handler"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	_ "github.com/biairmal/go-identity/api/swagger" // registers the generated spec with http-swagger
	identitytoken "github.com/biairmal/go-identity/internal/module/auth/token"
	"github.com/biairmal/go-identity/internal/module/rbac"
	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// routes mounts the middleware chain, operational endpoints, the route
// groups, then every module onto r. Unknown paths and methods get the go-sdk
// error envelope. r is a fresh chi.NewRouter() when identity runs standalone,
// or a host's own router when mounted (identity.Register).
func (a *App) routes(r chi.Router, modules []Module, chain []func(http.Handler) http.Handler) chi.Router {
	r.Use(chain...)
	// Set before the groups are mounted: chi copies them into subrouters at mount time.
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		handler.WriteErrorResponse(w, http.StatusNotFound, errorz.NotFound().WithMessage("route not found"))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		handler.WriteErrorResponse(w, http.StatusMethodNotAllowed,
			errorz.New("method not allowed").WithCode(codeMethodNotAllowed))
	})

	r.Get("/healthz", httpkit.Health())
	r.Get("/readyz", httpkit.Readiness(a.readiness))
	r.Get("/version", httpkit.Version(a.cfg.Service.Version))
	if a.cfg.Swagger.Enabled {
		r.With(middleware.BasicAuth("swagger", map[string]string{a.cfg.Swagger.Username: a.cfg.Swagger.Password})).
			Get("/swagger/*", httpSwagger.Handler())
	}
	if a.cfg.Metrics.Enabled {
		r.Method(http.MethodGet, a.cfg.Metrics.Path, promhttp.HandlerFor(a.metrics, promhttp.HandlerOpts{}))
	}

	rt := groups(r, a.cfg.Modules.Tenant.Multi())
	for _, m := range modules {
		m.Register(&rt)
	}
	return r
}

// groups mounts /v1 and its audience groups. A group's own middleware (token
// restrictions, service-token scope) is added here and nowhere else. multi is
// the tenancy mode: the super-admin group answers 404 in single mode.
func groups(r chi.Router, multi bool) httpx.Routes {
	rt := httpx.Routes{Root: r}
	r.Route("/v1", func(v1 chi.Router) {
		rt.API = v1
		v1.Route("/me", func(g chi.Router) { rt.Me = g })
		v1.Route("/admin", func(g chi.Router) {
			g.Use(rbac.Memoize) // admin permission checks read the caller's grants once per request
			rt.Admin = g
			// The super-admin routes (9.7) are a sub-group that requires the
			// sa claim and answers 404 in single mode.
			rt.Super = g.With(requireSuperAdmin(multi))
		})
		v1.Route("/internal", func(g chi.Router) {
			g.Use(requireServiceScope)
			rt.Internal = g
		})
	})
	return rt
}

// requireSuperAdmin guards the 9.7 routes: 404 in single mode (they do not
// exist there), else the sa claim, or 403. Requests without claims (auth
// disabled) carry no sa claim, so they are refused too.
func requireSuperAdmin(multi bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !multi {
				handler.WriteErrorResponse(w, http.StatusNotFound, errorz.NotFound().WithMessage("route not found"))
				return
			}
			if !authz.IsSuperAdmin(r.Context()) {
				handler.WriteErrorResponse(w, http.StatusForbidden,
					errorz.Forbidden().WithMessage("super admin only"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireServiceScope guards /v1/internal (9.8): only a token with
// scope:internal, from POST /v1/auth/token, may call these routes. Requests
// without claims (auth disabled, or an ordinary user token) carry no such
// scope, so they are refused too.
func requireServiceScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := sdkauth.ClaimsFromContext(r.Context())
		var scope string
		if ok {
			if raw, has := claims.Get(identitytoken.ClaimScope); has {
				if s, isString := raw.(string); isString {
					scope = s
				}
			}
		}
		if scope != identitytoken.ScopeInternal {
			handler.WriteErrorResponse(w, http.StatusForbidden, errorz.Forbidden().WithMessage("service token required"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// scopedRoutes lists, per token scope, the only routes a token carrying that
// scope may call. Every other authenticated route rejects any token with a
// scope claim. A route serving a scoped token is listed here when it is
// mounted. A path ending in "*" matches by prefix, for routes with an {id}.
var scopedRoutes = map[string][]scopedRoute{
	// A forced password change: the token may only choose a new password.
	identitytoken.ScopePasswordChange: {{http.MethodPost, "/v1/me/password"}},
	// A service token (TRD 9.8): only the internal routes.
	identitytoken.ScopeInternal: {
		{http.MethodGet, "/v1/internal/users/*"},
		{http.MethodGet, "/v1/internal/tenants/*"},
		{http.MethodGet, "/v1/internal/roles/permissions"},
	},
}

// scopedRoute is one method and path, or path prefix when it ends in "*".
type scopedRoute struct{ method, path string }

// matches reports whether method and path satisfy r.
func (r scopedRoute) matches(method, path string) bool {
	if r.method != method {
		return false
	}
	if prefix, ok := strings.CutSuffix(r.path, "*"); ok {
		return strings.HasPrefix(path, prefix)
	}
	return r.path == path
}

// routeAllowed reports whether method and path match one of allowed.
func routeAllowed(allowed []scopedRoute, method, path string) bool {
	for _, r := range allowed {
		if r.matches(method, path) {
			return true
		}
	}
	return false
}

// restrictScopedTokens rejects a request whose validated token carries a
// scope claim, unless allowed lists the route for that scope. A
// password-change token answers 403 PASSWORD_CHANGE_REQUIRED (APP_FLOW 9);
// any other scope is a plain 403. Requests without claims (public routes,
// auth disabled) pass through.
func restrictScopedTokens(allowed map[string][]scopedRoute) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := sdkauth.ClaimsFromContext(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			raw, has := claims.Get(identitytoken.ClaimScope)
			if !has {
				next.ServeHTTP(w, r)
				return
			}
			scope, isString := raw.(string)
			if !isString {
				scope = ""
			}
			if routeAllowed(allowed[scope], r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			var err error = errorz.Forbidden().WithMessage("token scope does not allow this route")
			if scope == identitytoken.ScopePasswordChange {
				err = apierr.New(apierr.ReasonPasswordChangeRequired)
			}
			handler.WriteErrorResponse(w, http.StatusForbidden, err)
		})
	}
}

// codeMethodNotAllowed is the error code of the 405 envelope; errorz has no
// code for it, and the status is written directly, so it never maps to 500.
const codeMethodNotAllowed = "ERR_METHOD_NOT_ALLOWED"

// readiness fails while the service is starting or shutting down, or while
// the leader database is unhealthy. Soft dependencies (Redis) never count.
func (a *App) readiness(context.Context) error {
	if !a.ready.Load() {
		return errorz.ServiceUnavailable().WithMessage("not ready")
	}
	if !a.db.IsHealthy() {
		return errorz.ServiceUnavailable().WithMessage("database unavailable")
	}
	return nil
}
