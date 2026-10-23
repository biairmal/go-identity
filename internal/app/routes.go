package app

import (
	"context"
	"net/http"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// routes builds the mux: operational endpoints first, then every module.
func (a *App) routes(modules []Module) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", httpkit.Health())
	mux.Handle("GET /readyz", httpkit.Readiness(a.readiness))
	mux.Handle("GET /version", httpkit.Version(a.cfg.Service.Version))
	if a.cfg.Metrics.Enabled {
		mux.Handle("GET "+a.cfg.Metrics.Path, promhttp.HandlerFor(a.metrics, promhttp.HandlerOpts{}))
	}
	for _, m := range modules {
		m.Register(mux)
	}
	return mux
}

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
