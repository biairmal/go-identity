# go-identity

[![CI](https://github.com/biairmal/go-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/biairmal/go-identity/actions/workflows/ci.yml)

The sign-in service and the only issuer of tokens for your other services. It covers password and Google sign-in,
users with roles and permissions, single or multi tenancy, and an admin API with an audit log. It signs RS256 tokens
that resource services verify through `/.well-known/jwks.json`. Built on [go-sdk](https://github.com/biairmal/go-sdk).

Run it as its own service, or mount its routes into your own chi app as one binary (see
[examples/monolith](examples/monolith/main.go)). New to the codebase? Start with
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start

Needs Go 1.26+, Docker, and Bash for `make keys` (Git Bash works on Windows).

```bash
cp .env.example .env
# In .env, set the first super admin (read on first start only, changed at first sign-in):
#   SUPER_ADMIN_EMAIL=admin@example.com
#   SUPER_ADMIN_PASSWORD=<10-128 characters, not a common password>
make up           # Postgres in Docker
make migrate-up   # the server refuses to start on an old schema
make run          # dev signing key + Swagger docs, then the API on http://localhost:8080
```

Check it:

```bash
curl localhost:8080/readyz
curl -X POST localhost:8080/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"<your password>"}'
```

The API docs are at http://localhost:8080/swagger/index.html (basic auth: `SWAGGER_USERNAME` / `SWAGGER_PASSWORD`).

## API

The contract is [api/openapi.yaml](api/openapi.yaml). Run `make openapi-mock` to get a mock on `:4010`.

| Group | Paths | For |
|---|---|---|
| Health | `/healthz`, `/readyz`, `/version`, `/metrics` | Probes and Prometheus (`/metrics` when `METRICS_ENABLED`) |
| Keys | `/.well-known/jwks.json` | Resource services verifying tokens |
| Auth | `/v1/auth/*` | Sign-up, sign-in (password, Google), refresh, logout, password reset, email verification, invites, tenant switch, client-credentials tokens |
| Me | `/v1/me/*` | The signed-in user: profile, password, tenants, sessions, linked Google account |
| Admin | `/v1/admin/*` | Users, roles, permissions, tenants, role templates, audit log |
| Internal | `/v1/internal/*` | Resource services with a client-credentials token: user and tenant lookups, role-to-permission mapping |

## Server commands

`bin/server` (or `go run ./cmd/server`) takes a subcommand:

| Command | What it does |
|---|---|
| `serve` | HTTP API (the default) |
| `worker` | Background runner: sends queued mail |
| `migrate up\|down\|status\|create <name>` | Database migrations |
| `superadmin reset --email <e>` | Prints a new temporary super admin password once, forces a change, revokes sessions |
| `superadmin transfer --to <e>` | Moves the super admin flag to another active account |

## Configuration

Settings come from [config/config.yaml](config/config.yaml), which reads environment variables. Every variable is
listed with its default and meaning in [.env.example](.env.example). Local defaults work as they are. Outside local,
set these:

| Variable | Why |
|---|---|
| `SUPER_ADMIN_EMAIL`, `SUPER_ADMIN_PASSWORD` | Required on first start in every environment |
| `EMAIL_ENCRYPTION_KEY`, `EMAIL_BLIND_INDEX_KEY` | Stored-email encryption; required in staging and production |
| `SIGNING_KEYS_DIR` | Mounted signing keys (see [key rotation](docs/runbooks/key-rotation.md)) |
| `SMTP_HOST`, `MAIL_FROM` | The worker won't start in production without them |
| `REDIS_ADDR` | Shared rate limits when more than one pod runs |
| `TENANCY_MODE` | `single` or `multi` |
| `TRUST_PROXY` | `true` only behind a trusted proxy |

## Development

```bash
make help              # every target
make test              # unit tests
make test-integration  # unit + integration + e2e (Docker, Testcontainers)
make check             # the CI gate: format, lint, unit tests, coverage, vulncheck
make migrate-create name=add_x
```

You need `golangci-lint`, `gofumpt` and `govulncheck` on your PATH for `make check`, and `npx` for the OpenAPI
targets.

| Path | Holds |
|---|---|
| `cmd/server` | The binary and its subcommands |
| `internal/module` | Identity's features (auth, user, tenant, RBAC, audit, ...) |
| `internal/app`, `internal/platform` | Wiring and generic service code |
| `api` | OpenAPI contract and generated Swagger docs |
| `migrations` | SQL migrations, embedded in the binary |
| `config` | `config.yaml` |
| `deploy` | Docker Compose (local and VPS), Helm chart, database bootstrap SQL |
| `test` | e2e, tenant isolation and schema suites ([test/e2e](test/e2e/README.md)) |
| `examples` | Mounting identity into a host app |
| `docs` | [Architecture](docs/ARCHITECTURE.md), [patterns](docs/PATTERNS.md), [decisions](docs/DECISIONS.md), [runbooks](docs/runbooks) |

## Deployment

- **Image:** `make image` builds `ghcr.io/biairmal/go-identity:<git sha>`.
- **VPS:** Docker Compose with Caddy for TLS. The steps are at the top of
  [deploy/compose/docker-compose.yaml](deploy/compose/docker-compose.yaml).
- **Kubernetes:** the Helm chart in [deploy/helm/identity](deploy/helm/identity).
- **Database:** run [deploy/sql/bootstrap.sql](deploy/sql/bootstrap.sql) once per environment, then `migrate up`
  before each release.

Runbooks: [backup and restore](docs/runbooks/backup-restore.md), [key rotation](docs/runbooks/key-rotation.md),
[super admin recovery](docs/runbooks/superadmin-recovery.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the git conventions, PR process and Definition of Done, and
[AGENTS.md](AGENTS.md) for the code rules. Both apply to humans and AI agents alike.

## Security

Report vulnerabilities privately, never in a public issue. [SECURITY.md](SECURITY.md) has how to report, what the
service defends against, and a checklist for deploying it safely.
