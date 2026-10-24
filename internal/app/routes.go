package app

import (
	"context"
	"net/http"
	"slices"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit"
	"github.com/biairmal/go-sdk/lib/httpkit/handler"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	identitytoken "github.com/biairmal/go-identity/internal/module/auth/token"
	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/httpx"
)

// routes builds the router: the middleware chain, operational endpoints, the
// route groups, then every module. Unknown paths and methods get the go-sdk
// error envelope.
func (a *App) routes(modules []Module, chain []func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()
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
	if a.cfg.Metrics.Enabled {
		r.Method(http.MethodGet, a.cfg.Metrics.Path, promhttp.HandlerFor(a.metrics, promhttp.HandlerOpts{}))
	}

	rt := groups(r)
	for _, m := range modules {
		m.Register(&rt)
	}
	return r
}

// groups mounts /v1 and its audience groups. A group's own middleware (token
// restrictions, service-token scope) is added here and nowhere else.
func groups(r chi.Router) httpx.Routes {
	rt := httpx.Routes{Root: r}
	r.Route("/v1", func(v1 chi.Router) {
		rt.API = v1
		v1.Route("/me", func(g chi.Router) { rt.Me = g })
		v1.Route("/admin", func(g chi.Router) { rt.Admin = g })
		v1.Route("/internal", func(g chi.Router) { rt.Internal = g })
	})
	return rt
}

// scopedRoutes lists, per token scope, the only routes a token carrying that
// scope may call. Every other authenticated route rejects any token with a
// scope claim. A route serving a scoped token is listed here when it is
// mounted.
var scopedRoutes = map[string][]scopedRoute{
	// A forced password change: the token may only choose a new password.
	identitytoken.ScopePasswordChange: {{http.MethodPost, "/v1/me/password"}},
}

// scopedRoute is one method and exact path.
type scopedRoute struct{ method, path string }

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
			if slices.Contains(allowed[scope], scopedRoute{r.Method, r.URL.Path}) {
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
