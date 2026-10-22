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
