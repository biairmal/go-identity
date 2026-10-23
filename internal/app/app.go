// Package app wires the service: it builds shared dependencies from Config,
// assembles the middleware chain and routes, and runs the HTTP server under
// go-sdk lifecycle. It holds no identity logic, so it can later move into the
// service template unchanged.
package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/ctxkit"
	"github.com/biairmal/go-sdk/lib/httpkit/middleware"
	"github.com/biairmal/go-sdk/lib/lifecycle"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/metrics"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/tracer"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/migrations"
)

// App is a built service, ready to serve.
type App struct {
	cfg     Config
	log     logger.Logger
	db      *sqlkit.DB
	tracer  tracer.Tracer
	metrics *prometheus.Registry
	handler http.Handler
	ready   atomic.Bool
}

// NewLogger builds the service logger; every line carries the request,
// correlation, trace and user IDs found in the context.
func NewLogger(cfg *Config) logger.Logger {
	opts := cfg.Log
	opts.ContextExtractor = ctxkit.LoggerExtractor()
	return logger.NewZerolog(&opts)
}

// New builds every dependency and the HTTP handler. It connects to the
// database, so it fails when the leader is unreachable.
func New(ctx context.Context, cfg *Config, log logger.Logger) (*App, error) {
	a := &App{cfg: *cfg, log: log}

	a.metrics = newRegistry()
	tr, rec, err := observability(cfg, log, a.metrics)
	if err != nil {
		return nil, err
	}
	a.tracer = tr

	db, err := sqlkit.New(ctx, &a.cfg.Database)
	if err != nil {
		a.close(ctx)
		return nil, err
	}
	a.db = db

	if err := checkSchema(ctx, db); err != nil {
		a.close(ctx)
		return nil, err
	}

	deps := Deps{
		DB: db, Log: log, V: validator.New(cfg.Validator), Authz: authz.NewNoOp(),
		Outbox: database.NewOutbox(db),
	}
	modules, err := buildModules(&a.cfg, deps)
	if err != nil {
		a.close(ctx)
		return nil, err
	}

	chain := middlewareChain(cfg, log, tr, rec)
	authMW, err := a.authMiddleware()
	if err != nil {
		a.close(ctx)
		return nil, err
	}
	if authMW != nil {
		chain = append(chain, authMW)
	}
	a.handler = a.routes(modules, chain)
	return a, nil
}

// middlewareChain is the shared middleware, outermost first (TRD 3.3). The
// auth middleware is appended after it when auth is enabled.
func middlewareChain(
	cfg *Config, log logger.Logger, tr tracer.Tracer, rec metrics.Recorder,
) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		middleware.Metrics(rec, nil),
		middleware.Recover(),
		middleware.RequestID(),
		middleware.Correlation(),
		middleware.Tracing(tr),
		middleware.Logging(log, &middleware.LoggingOptions{LogResponse: true}),
		cors(cfg.HTTP.CORS),
		maxBody(cfg.HTTP.MaxBodyBytes),
	}
}

// observability builds the tracer and metrics recorder, or NoOps when disabled.
func observability(cfg *Config, log logger.Logger, reg prometheus.Registerer) (tracer.Tracer, metrics.Recorder, error) {
	tr := tracer.NewNoOp()
	if cfg.Tracing.Enabled {
		var err error
		if tr, err = tracer.NewOTel(cfg.Tracing.Config, tracer.WithLogger(log)); err != nil {
			return nil, nil, err
		}
	}
	rec := metrics.NewNoOp()
	if cfg.Metrics.Enabled {
		var err error
		rec, err = metrics.NewPrometheus(cfg.Metrics.Config, metrics.WithLogger(log), metrics.WithRegisterer(reg))
		if err != nil {
			if serr := tr.Shutdown(context.Background()); serr != nil {
				log.Error("tracer shutdown", logger.F("error", serr.Error()))
			}
			return nil, nil, err
		}
	}
	return tr, rec, nil
}

// authMiddleware validates bearer tokens per the route policy, or returns nil
// (every route public) when auth is disabled.
func (a *App) authMiddleware() (func(http.Handler) http.Handler, error) {
	if !a.cfg.Auth.Enabled {
		a.log.Warn("auth is disabled: every route is public")
		return nil, nil
	}
	v, err := auth.FromConfig(&a.cfg.Auth.Config)
	if err != nil {
		return nil, err
	}
	return middleware.Auth(v, middleware.WithPolicy(a.cfg.Auth.Policy())), nil
}

// Handler returns the full HTTP handler, middleware included.
func (a *App) Handler() http.Handler { return a.handler }

// DB returns the database handle.
func (a *App) DB() *sqlkit.DB { return a.db }

// Serve listens on the configured address and blocks until a shutdown signal
// or ctx is done, then drains and closes dependencies in order.
func (a *App) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              a.cfg.HTTP.Addr,
		Handler:           a.handler,
		ReadHeaderTimeout: a.cfg.HTTP.ReadHeaderTimeout,
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", srv.Addr)
	if err != nil {
		a.close(ctx)
		return err
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("http server stopped", logger.F("error", err.Error()))
		}
	}()
	a.ready.Store(true)
	a.log.Info("http server listening", logger.F("addr", ln.Addr().String()))

	return lifecycle.Run(ctx, srv, a.cfg.Lifecycle,
		lifecycle.WithReadiness(&a.ready),
		lifecycle.WithLogger(a.log),
		lifecycle.WithCloser("tracer", lifecycle.CloserFromTracer(a.tracer)),
		lifecycle.WithCloser("db", lifecycle.CloserFromDB(a.db)),
	)
}

// close releases dependencies when startup fails part-way.
func (a *App) close(ctx context.Context) {
	if a.tracer != nil {
		if err := a.tracer.Shutdown(ctx); err != nil {
			a.log.Error("tracer shutdown", logger.F("error", err.Error()))
		}
	}
	if a.db != nil {
		if err := a.db.Close(); err != nil {
			a.log.Error("database close", logger.F("error", err.Error()))
		}
	}
}

// checkSchema refuses to start when the database is behind the newest
// embedded migration.
func checkSchema(ctx context.Context, db *sqlkit.DB) error {
	m, err := database.NewMigrator(db.Leader(), migrations.FS)
	if err != nil {
		return err
	}
	return m.EnsureCurrent(ctx)
}

// newRegistry is the app's own metrics registry (not the process-global
// default), with the Go runtime and process collectors.
func newRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return reg
}
