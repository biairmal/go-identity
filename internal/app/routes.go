package app

import (
	"context"
	"net/http"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit"
	"github.com/biairmal/go-sdk/lib/httpkit/handler"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// routes builds the router: the middleware chain, operational endpoints, then
// every module. Unknown paths and methods get the go-sdk error envelope.
func (a *App) routes(modules []Module, chain []func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()
	r.Use(chain...)
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
	for _, m := range modules {
		m.Register(r)
	}
	return r
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
