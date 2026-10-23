# AGENTS.md

**Development guidelines for `github.com/biairmal/go-identity`**, for humans and AI agents alike. Read this before
any change. Examples live in [docs/PATTERNS.md](docs/PATTERNS.md); the reasons behind choices in
[docs/DECISIONS.md](docs/DECISIONS.md). The specs (PRD, TRD, APP_FLOW, implementation plan) live in the project's
`phase2/backend/` folder; when this file and the TRD disagree, the TRD wins.

## Orientation

`go-identity` is the sign-in service and the only issuer of tokens: password and Google sign-in, users, roles,
permissions, tenants, an admin API and an audit log. It is built on
[go-sdk](https://github.com/biairmal/go-sdk) and follows its conventions. `internal/app` and `internal/platform`
are generic service-template code (no identity logic) so they can later move into `go-service-template`.

| Path | Role |
|---|---|
| `cmd/server` | One binary: `serve` (default), `worker`, `migrate` |
| `internal/app` | Config, dependency wiring, middleware chain, routes and route groups, adapters between modules, lifecycle |
| `internal/platform/*` | Generic plumbing, no business rules: database, HTTP conventions and `httpx.Routes`, list queries, tenant scope, API errors, test kit. Never imports `app` or a module |
| `internal/module/<name>` | One feature boundary each (`audit`, `tenant`, `rbac`, `session`, `user`, `auth`); helpers used by one module are its subpackages |
| `migrations/` | goose SQL, embedded |
| `config/config.yaml` | Defaults with `${VAR:default}` |

`internal/` holds only these three directories.

## Commands

```bash
make up                # Postgres via Compose
make run               # serve against it
make check             # CI gate: format-check, lint, unit tests, coverage, vulncheck (must pass)
make test              # go test -short ./...
make test-integration  # all tests, Testcontainers needs Docker
make help
```

## Rules

- `context.Context` is the first parameter of every I/O function. No globals; no `init()` except driver
  registration.
- Return `error`, never `*errorz.Error` (typed-nil trap). Wrap causes and attach an `errorz` code; compare with
  `errors.Is`. Never invent a custom `code` (it maps to 500): finer reasons go in `meta.reason`.
- Routing is go-chi/chi v5. Handlers are `handler.Func` wrapped by `httpx.Handle`; path parameters come from
  `chi.URLParam`. Never write status codes by hand.
- Layers inside a module: `handler` → `service` → `repository`. No upward imports.
- Modules: `module.go` with `New(cfg, Deps)` and `Register(rt *httpx.Routes)`. A module mounts its routes into every
  group it serves (`rt.API`, `rt.Me`, `rt.Admin`, `rt.Internal`, `rt.Root`) and never creates a group; group
  middleware lives in `internal/app/routes.go`. Each module's `Config` lives under the YAML key
  `modules.<name>`, has `Default()` and `Validate()`, and is one row in the validation table in
  `internal/app/config.go`. A setting belongs to the module that reads it; `internal/app` validates only rules
  that span modules.
- **No module imports another.** Declare a small port in the consumer and wire an adapter in `internal/app`.
  The architecture test `internal/app/arch_test.go` (in `make test`) enforces it, and keeps `platform` from
  importing `app` or a module.
- Response DTOs are never the row struct.
- Repositories: named-column intent updates only, `tenant_id` in every `WHERE`, a `version` check on editable
  aggregates, no repository cache. Emails and queue messages go through the outbox in the caller's transaction.
- Never log secrets, tokens, passwords, emails or request/response bodies.
- Files `lower_snake.go`. Table-driven tests. Integration tests in `*_integration_test.go`, skipped under
  `testing.Short()`. Repositories are tested against real Postgres. Mocks are generated into the package that
  uses them; small fakes are fine for a module's own ports.
- Lint limits: line ≤ 120, func ≤ 100 lines / 50 statements, cyclomatic < 15, cognitive < 25.
- Comments describe the code, not its history (no task IDs).
- When the TRD is unclear, pick the simplest option consistent with it and add a line to `docs/DECISIONS.md`.

## Definition of Done

- [ ] `make check` passes; `make test-integration` passes when the change touches the database.
- [ ] New behaviour has table-driven tests.
- [ ] New exported symbols have doc comments.
- [ ] No module-to-module imports; no secrets in logs.
