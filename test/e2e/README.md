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

## PRD must-have requirements → tests

Every **M** requirement in the PRD (section 6) and at least one test that proves it. Test kinds:
**int** means an integration test against Postgres; **unit** means a module test with fakes;
**e2e** means this suite. All of them run in `make test-integration`, and the unit tests also run
in `make check`.

| PRD | Requirement (short) | Test(s) |
| --- | --- | --- |
| FR-1 | Register with email, password, display name | int `TestRegisterNewEmail`, `TestRegisterRejected` |
| FR-2 | Registration never reveals an existing email | int `TestRegisterExistingEmail` |
| FR-3 | Verify email before sign-in when required; resend | int `TestVerifyEmail`, `TestVerifyEmailBadToken`, `TestResendVerification`; unit `TestLoginStatusOnlyAfterPassword` (`EMAIL_NOT_VERIFIED`) |
| FR-4 | Sign in with email and password | int `TestLoginSuccessIntegration`; e2e `TestNotesWithEachProvider/password_only` |
| FR-5 | Sign in with Google; allowed domains | int `TestGoogleNewUserIntegration`, `TestGoogleLinkedUserIntegration`, `TestGoogleRefusalsByRedirectIntegration` (`OAUTH_DOMAIN_NOT_ALLOWED`); e2e `TestNotesWithEachProvider/google_only` |
| FR-6 | Google auto-links a verified email, else creates an account if registration is open | int `TestGoogleAutoLinkIntegration`, `TestGoogleNewUserIntegration`, `TestGoogleRefusalsByRedirectIntegration` (registration closed, auto-link off) |
| FR-7 | Either provider can be off; at least one stays on | int `TestGoogleDisabledIntegration`; unit `TestLoginValidationAndProvider` (`PROVIDER_DISABLED`), `TestModuleConfigValidate` (no provider enabled); e2e `TestNotesWithEachProvider` |
| FR-8 | Lockout; rate limit per IP and per email | int `TestLoginLockoutIntegration`, `TestLoginRateLimitIntegration`, `TestLoginRateLimitByEmail`; e2e `TestLoginLimitsAcrossReplicas` |
| FR-9 | Password reset link; signs out everywhere | int `TestPasswordResetIntegration`, `TestPasswordResetRejections`, `TestForgotPasswordIdenticalBody` |
| FR-10 | Temporary password must be changed at first sign-in | int `TestLoginMustChangePasswordIntegration`, `TestChangePasswordRestrictedTokenIntegration`, `TestSuperAdminReset` |
| FR-11 | Sessions: 30 days sliding, 90 days absolute | int `TestIssueAndRotate`, `TestRotateExpired` (session), `TestRefreshFailuresIntegration` |
| FR-12 | Reused refresh token ends the family | int `TestRefreshReuseRevokesTheWholeFamilyIntegration`, `TestReuseAfterTheGraceRevokesTheFamily`, `TestRefreshConcurrentInsideTheGraceIntegration` |
| FR-13 | Sign out of this device or all devices | int `TestLogoutIntegration`, `TestLogoutAllIntegration`, `TestMeSessionsIntegration` |
| FR-20 | See profile, tenant, roles, effective permissions | int `TestMeIntegration` |
| FR-21 | Change display name and password | int `TestMeIntegration`, `TestChangePasswordIntegration` |
| FR-24 | See and switch tenants (multi) | int `TestMeTenantsIntegration`, `TestSwitchTenantHappyPath`, `TestSwitchTenantErrors` |
| FR-30 | Permission catalog from config; admins cannot invent keys | int `TestSyncCatalogAddsConfiguredAndSystemKeys`, `TestSyncCatalogKeepsGrantedKeysOutOfTheConfig`, `TestAdminRoleValidation` |
| FR-31 | Create, rename, describe, delete roles; pick permissions | int `TestAdminRolesCRUD`, `TestAdminRoleInUse`, `TestAdminSystemRole` |
| FR-32 | Many roles; permissions are the union | int `TestEffectivePermissionsIsTheUnion`, `TestAdminUserRoles` |
| FR-33 | Seed once; admin edits survive restarts | int `TestSeedTenantDoesNotOverwriteAdminEdits`, `TestSyncCatalogIsIdempotentAndUpdatesDescriptions` |
| FR-34 | Grant only held permissions; no self-change; keep the last admin | int `TestAdminRolePermissionNotHeld`, `TestAdminRoleSelfEscalation`, `TestAdminLastAdmin`, `TestAdminUserLastAdmin` |
| FR-35 | Role changes at next refresh, or at once on session revoke | int `TestRefreshShowsNewRolesIntegration`, `TestAdminRevokeSessions`; e2e `TestNotesWithEachProvider` |
| FR-36 | Resource services check permissions with go-sdk `authz` (`:any`, wildcards) | go-sdk `TestMatches`, `TestRequireIn`; int `TestAuthzSourceIdentityIntegration`; e2e `TestNotesWithEachProvider`, `TestTenantIsolationInTheResourceService` |
| FR-40 | List and search users by name, email, role, status | int `TestAdminUsersList` |
| FR-41 | Invite with roles; 7-day expiry; re-send | int `TestInviteNewAccount`, `TestInviteExistingAccount`, `TestInviteRefusals` (expiry, re-invite replaces the link) |
| FR-42 | Disable, enable, revoke sessions, remove from tenant | int `TestAdminUserDisableEnable`, `TestTenantScopedDisable`, `TestAdminRevokeSessions`, `TestAdminUserRemove` |
| FR-43 | Audit every change and sign-in; admins filter and read it | int `TestAdminAuditRead`, `TestWriteJoinsTheCallersTransaction`, `TestLoginSuccessIntegration` (`auth.login`), `TestLoginLockoutIntegration` (`auth.login_failed`); schema `TestAuditLogIsAppendOnly` |
| FR-50 | One super admin from config, forced password change | int `TestSuperAdminBootstrapCreatesTheAccount`, `TestSuperAdminBootstrapIsIdempotent`, `TestSuperAdminBootstrapConcurrentPods`; schema `TestOneSuperAdmin` |
| FR-51 | Super admin protected from the API; CLI recovery and transfer | int `TestAdminSuperAdminProtected`, `TestSuperAdminReset`, `TestSuperAdminTransfer`, `TestSuperAdminCLIEntryPoints` |
| FR-52 | Super admin creates, renames, suspends tenants (multi) | int `TestSuperAdminTenantsCRUD`, `TestCreateTenantFirstAdminCanAccept`, `TestSuperAdminRoleTemplatesCRUD` |
| FR-53 | Suspension blocks sign-in and refresh (multi) | unit `TestLoginTenantResolution` (suspended tenant), `TestRefreshRechecksTheAccount` (suspended tenant); int `TestSwitchTenantErrors` (`TENANT_SUSPENDED`) |
| FR-55 | Single → multi keeps users and roles | int `TestSingleToMultiMigrationKeepsUsersAndRoles` |
| FR-60 | Public JWKS; no per-request call to identity | unit `TestJWKSEndpointPublishesEveryKey`, `TestAccessTokenValidatesThroughJWKS`; e2e `TestNotesWithEachProvider`, `TestKeyRotationUnderLoad` |
| FR-61 | Service credential reads user, tenant status, role map | int `TestServiceTokenIntegration`, `TestInternalRoutesIntegration`, `TestAuthzSourceIdentityIntegration` |
| FR-62 | Standalone or mounted with one call; own migrations first | `identity_test.go` `TestRegisterMountsAlongsideHostRoutes`, `TestRegisterFailsOnStaleSchema`, `TestMigrationsIsIdentitysEmbeddedSet`; e2e (standalone) |
| FR-63 | API described in an OpenAPI file | e2e `TestEveryRouteIsDocumented` (every route in `api/openapi.yaml` and `api/swagger/swagger.json`); unit `TestAuthConfigMatchesOpenAPI` (schema); `make openapi-lint` |

FR-53 has no integration test for sign-in or refresh into a suspended tenant: the reason is
decided in `auth` (unit tests above), and only switch-tenant is covered over HTTP.
