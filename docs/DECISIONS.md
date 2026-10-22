# Decisions

Choices made where the TRD was silent or unclear. One line each: `date · task · decision · reason`.

| Date | Task | Decision | Reason |
|---|---|---|---|
| 2026-10-22 | T0.1 | `go.mod` replaces go-sdk with `../go-sdk` | `authz` is not tagged yet; T1.4 tags go-sdk and removes the replace |
| 2026-10-22 | T0.1 | `Deps.Authz` is `authz.NewNoOp()` | No module uses it yet; the database-backed authorizer arrives with the admin routes (T5) |
| 2026-10-22 | T0.1 | Newer grpc, otel and x/text in `go.mod` than go-sdk pins | go-sdk's pinned versions fail govulncheck; the remaining findings (stdlib, x/net) need a newer Go toolchain, installed by the developer |
| 2026-10-22 | T1.2 | `authz.New` takes `*Config` instead of `Config` | go-sdk passes large configs by pointer (`sqlkit`, `kafka`, `redis`); the value form fails the `hugeParam` lint |
| 2026-10-22 | T1.2 | Identity source down past 10 × `cache_ttl` returns 503, not 403 | An outage is not a permission decision; `Can` still reports false |
| 2026-10-22 | T1.2 | Scoped roles with the `token` source map through `authz.roles` | A token carries no role → permission map |
| 2026-10-22 | T0.2 | Migration files are named `YYYYMMDDHHMMSS_name.sql` | TRD 3.4 names them this way (the plan's `00001_` examples differ; the TRD wins) |
| 2026-10-22 | T0.2 | goose v3.27.0 through `goose.Provider`, not the global API | v3.28 needs Go 1.26; the Provider avoids package-level state |
| 2026-10-22 | T0.2 | Outbox retry backoff is `2^attempts - 1` seconds from `created_at`, capped at 2^10 s | The TRD 5.2 `outbox` table has no next-attempt column; this needs none |
| 2026-10-22 | T0.2 | Outbox rows stay locked while they are sent, inside the claiming transaction | Guarantees two dispatchers never send one row concurrently without an extra lease column |
| 2026-10-22 | T0.2 | `bootstrap.sql` also creates `pgcrypto` | The `identity` role may lack the privilege to create extensions |
