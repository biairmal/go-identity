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
	"github.com/biairmal/go-sdk/lib/ctxkit"
	"github.com/biairmal/go-sdk/lib/httpkit/middleware"
	"github.com/biairmal/go-sdk/lib/lifecycle"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/metrics"
	"github.com/biairmal/go-sdk/lib/redis"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/tracer"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/biairmal/go-identity/internal/module/rbac"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/ratelimit"
	"github.com/biairmal/go-identity/internal/platform/requestip"
	"github.com/biairmal/go-identity/migrations"
)

// App is a built service, ready to serve.
type App struct {
	cfg     Config
	log     logger.Logger
	db      *sqlkit.DB
	tracer  tracer.Tracer
	metrics *prometheus.Registry
	redis   redis.Client
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

// New builds every dependency and the HTTP handler, including a database
// connection it owns. It fails when the leader is unreachable.
func New(ctx context.Context, cfg *Config, log logger.Logger) (*App, error) {
	db, err := sqlkit.New(ctx, &cfg.Database)
	if err != nil {
		return nil, err
	}
	a, err := build(ctx, cfg, log, db, chi.NewRouter())
	if err != nil {
		if cerr := db.Close(); cerr != nil {
			log.Error("database close", logger.F("error", cerr.Error()))
		}
		return nil, err
	}
	return a, nil
}

// Register builds identity atop a host's own database connection and mounts
// its routes onto r, for a client monolith (TRD 1.1 "mounted" mode) instead
// of running identity as its own process. The host owns db's lifecycle:
// Register never closes it, on success or failure.
func Register(ctx context.Context, r chi.Router, cfg *Config, log logger.Logger, db *sqlkit.DB) (*App, error) {
	a, err := build(ctx, cfg, log, db, r)
	if err != nil {
		return nil, err
	}
	// There is no separate Serve step in mounted mode: readyz must answer
	// 200 as soon as the host starts routing to r.
	a.ready.Store(true)
	return a, nil
}

// build wires every dependency onto db and mounts the handler on r. The
// caller owns db; build only ever closes what it created itself (tracer,
// Redis) when a later step fails.
func build(ctx context.Context, cfg *Config, log logger.Logger, db *sqlkit.DB, r chi.Router) (*App, error) {
	a := &App{cfg: *cfg, log: log, db: db}

	a.metrics = newRegistry()
	tr, rec, err := observability(cfg, log, a.metrics)
	if err != nil {
		return nil, err
	}
	a.tracer = tr

	if err := checkSchema(ctx, db); err != nil {
		a.closeOwn(ctx)
		return nil, err
	}

	limiter, refreshLimiter, err := a.newLimiters()
	if err != nil {
		a.closeOwn(ctx)
		return nil, err
	}
	deps := Deps{
		DB: db, Log: log, V: validator.New(cfg.Validator), Authz: rbac.NewAuthorizer(db),
		Outbox: database.NewOutbox(db), Limiter: limiter, RefreshLimiter: refreshLimiter,
	}
	modules, svc, err := buildModules(&a.cfg, &deps)
	if err != nil {
		a.closeOwn(ctx)
		return nil, err
	}
	if err := a.bootstrap(ctx, svc); err != nil {
		a.closeOwn(ctx)
		return nil, err
	}

	chain := middlewareChain(cfg, log, tr, rec)
	authMW, err := a.authMiddleware()
	if err != nil {
		a.closeOwn(ctx)
		return nil, err
	}
	if authMW != nil {
		chain = append(chain, authMW, restrictScopedTokens(scopedRoutes))
	}
	a.handler = a.routes(r, modules, chain)
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
		requestip.Middleware(cfg.HTTP.TrustProxy),
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

// newLimiters builds the sign-in rate limiter from
// modules.auth.security.login_rate_limit and the refresh limiter from
// refresh_rate_limit. With Redis configured the limits are shared by every
// pod; without it, or when Redis cannot be reached at startup, they are
// in-memory per pod and a warning says so. Redis is a soft dependency (it is
// never a readiness check), so an outage must not stop the service from
// starting.
func (a *App) newLimiters() (login, refresh *ratelimit.Limiter, err error) {
	sec := a.cfg.Modules.Auth.Security
	count, window, err := sec.ParsedLoginRateLimit()
	if err != nil {
		return nil, nil, err
	}
	refreshCount, refreshWindow, err := sec.ParsedRefreshRateLimit()
	if err != nil {
		return nil, nil, err
	}
	if a.cfg.Redis.Enabled() {
		client, err := redis.NewClient(&a.cfg.Redis.Config)
		if err != nil {
			a.log.Error("redis unreachable at startup, falling back to in-memory rate limits",
				logger.F("error", err.Error()))
		} else {
			a.redis = client
		}
	}
	if login, err = ratelimit.New(count, window, a.redis, a.log); err != nil {
		return nil, nil, err
	}
	if refresh, err = ratelimit.New(refreshCount, refreshWindow, a.redis, logger.NewNoOp()); err != nil {
		return nil, nil, err
	}
	return login, refresh, nil
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
		lifecycle.WithCloser("redis", lifecycle.CloserFromRedis(a.redis)),
	)
}

// close releases every dependency, db included. Only New's own App, which
// owns its database connection, may call this; build and Register must not,
// since a host passes its own db into Register and keeps owning it.
func (a *App) close(ctx context.Context) {
	a.closeOwn(ctx)
	if a.db != nil {
		if err := a.db.Close(); err != nil {
			a.log.Error("database close", logger.F("error", err.Error()))
		}
	}
}

// closeOwn releases the dependencies build creates itself (tracer, Redis),
// never db: its caller owns that connection's lifecycle, whether it is New
// (which then closes db too) or a host calling Register.
func (a *App) closeOwn(ctx context.Context) {
	if a.tracer != nil {
		if err := a.tracer.Shutdown(ctx); err != nil {
			a.log.Error("tracer shutdown", logger.F("error", err.Error()))
		}
	}
	if a.redis != nil {
		if err := a.redis.Close(); err != nil {
			a.log.Error("redis close", logger.F("error", err.Error()))
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
