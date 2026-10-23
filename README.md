# go-identity

The sign-in service and the single issuer of tokens: password and Google sign-in, users with roles and
permissions, single or multi tenancy, an admin API with an audit log, and RS256 tokens verified by resource
services through `/.well-known/jwks.json`. Built on [go-sdk](https://github.com/biairmal/go-sdk).

## Run locally

```bash
cp .env.example .env
make up      # Postgres in Docker
make run     # http://localhost:8080
curl localhost:8080/healthz
curl localhost:8080/readyz
```

## Commands

| Command | What it does |
|---|---|
| `server serve` | HTTP API (default) |
| `server worker` | Background runner |
| `server migrate up\|down\|status\|create <name>` | Database migrations |

`make help` lists the Makefile targets. `make check` is the CI gate.

## Endpoints so far

| Path | Purpose |
|---|---|
| `GET /healthz` | Liveness |
| `GET /readyz` | Readiness: 503 while starting, shutting down, or when the leader database is unhealthy |
| `GET /version` | Build version |
| `GET /metrics` | Prometheus, when enabled |

See [AGENTS.md](AGENTS.md) for the rules every change follows.
