# End-to-end suite

`test/e2e` runs identity next to a resource service the way they are deployed: separate HTTP
servers that talk only over HTTP, on a real Postgres and Redis (Testcontainers).

- **`sampleresource/`** is a small notes service built only on go-sdk: `auth` validates
  identity's tokens through `/.well-known/jwks.json`, and `authz` (source `identity`) maps the caller's
  roles to permissions through `/v1/internal/roles/permissions`, using a client-credentials token
  from `/v1/auth/token`. Notes are scoped to the token's `tid` (tenant) and `sub` (owner).
  `notes:read` reads your own notes, `notes:read:any` reads every note in your tenant, and
  `notes:write` creates notes.
- **Identity replicas** are `app.New` instances on their own ports, sharing the database, the
  signing keys and Redis. A round-robin balancer stands in for a Kubernetes Service.

Run it with the rest of the integration tests (Docker needed):

```sh
make test-integration                  # everything
go test -count=1 ./test/e2e/...        # this suite only
```

## TRD 12 acceptance criteria → tests

Each item names at least one test. "e2e" tests live here; the others live where the behaviour
does.

| TRD 12 acceptance item | Test(s) |
| --- | --- |
| Three configs pass the end-to-end suite: password only, Google only, both | e2e `TestNotesWithEachProvider/{password_only,google_only,both}` (Google through the in-process fake OIDC provider) |
| Single and multi tenancy both pass, and switching single → multi on an existing database keeps users and roles | e2e `TestNotesWithEachProvider` (single), e2e `TestTenantIsolationInTheResourceService` (multi); `internal/app` `TestSingleToMultiMigrationKeepsUsersAndRoles` |
| An admin creates a role, picks permissions, assigns it to a user with another role; the next token and `/v1/me` show the union | `internal/app` `TestAdminUserRoles`, `TestRefreshShowsNewRolesIntegration`, `TestAdminRolesCRUD`; e2e `TestNotesWithEachProvider` (a granted role reaches the resource service at the next token; removed roles are 403 there) |
| Self-escalation, removing the last `roles:manage` holder, and any API change to the super admin are refused | `internal/app` `TestAdminRoleSelfEscalation`, `TestAdminLastAdmin`, `TestAdminUserLastAdmin`, `TestAdminSuperAdminProtected` |
| Cross-tenant: a tenant A admin cannot list, read or change tenant B users, roles or template resources | `test/isolation` `TestCrossTenantByIDReturns404`, `TestListRoutesAreTenantScoped`, `TestCrossTenantWritesStayInTheCallersTenant`; e2e `TestTenantIsolationInTheResourceService` (resource-service notes) |
| A refresh token reused after `refresh_reuse_grace` revokes its family; parallel refreshes inside the grace all succeed | `internal/app` `TestRefreshReuseRevokesTheWholeFamilyIntegration`, `TestRefreshConcurrentInsideTheGraceIntegration` |
| Signing key rotation runs with the resource service under load and zero 401s | e2e `TestKeyRotationUnderLoad` |
| Login rate limit and lockout work across two replicas (Redis backend) | e2e `TestLoginLimitsAcrossReplicas` |
| Identity runs standalone and mounted via `identity.Register(r, deps)` on a chi router | standalone: every e2e test; mounted: `identity_test.go` `TestRegisterMountsAlongsideHostRoutes` and `examples/monolith` |
| Updating a user's profile, roles or status never changes their credentials | `internal/app` `TestMeIntegration` (profile), `TestAdminUserRoles` (roles), `TestAdminUserDisableEnable` (status) |
| go-sdk ships `authz` (with `ScopeResolver` and `RequireIn`), `RequirePermission`, `auth.WithKeyID` and `auth.JWKSHandler`, under a tagged version | go-sdk `v0.2.0`: `lib/authz/authz__test.go` (incl. `TestRequireIn`), `lib/httpkit/middleware/authz_test.go`, `lib/auth/jwks_handler__test.go` (`WithKeyID` and the handler); e2e `sampleresource` uses them against the real identity |
