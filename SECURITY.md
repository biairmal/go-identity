# Security

go-identity signs users in and issues the tokens every other service trusts, so a flaw here affects every service
built on it. This page covers how to report a vulnerability, what the service defends against, how to deploy it
safely, and the limits it has today.

## Reporting a vulnerability

**Do not open a public issue, PR or discussion for a security problem.**

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**.
Include:

- what an attacker can do, and what they need first (an account, a role, network access);
- steps or a request sequence that reproduces it;
- the commit or image tag you tested.

You can expect an acknowledgement within 7 days. Once the issue is confirmed, the fix is released, and a GitHub
security advisory credits you unless you'd rather stay anonymous. Please give us a reasonable time to ship the fix
before you disclose it.

**In scope:** this repository's code, its configuration defaults, its Docker image, and the Compose and Helm files
in `deploy/`.
**Out of scope:** findings that need a deployment to ignore the [deployment checklist](#deploying-safely) (for
example, auth turned off, or `/v1/internal` exposed publicly), and denial of service by sheer request volume.
Vulnerabilities in go-sdk belong in [biairmal/go-sdk](https://github.com/biairmal/go-sdk).

## Supported versions

There are no tagged releases yet. Fixes land on `main` and ship in the next image built from it
(`ghcr.io/biairmal/go-identity:main` and `:<git sha>`). Once releases begin, only the latest release gets fixes.

## What the service defends against

| Threat | Defence | Where |
|---|---|---|
| Password guessing | Rate limits per IP and per email (`login_rate_limit`, default 10 per 5 min). The account locks for 15 minutes after 10 failures | `modules.auth.security`, `internal/module/auth/login.go` |
| Finding out which emails have accounts | Sign-in, sign-up, resend and forgot-password give the same answer whether or not the email exists. An unknown email is checked against a dummy hash, so timing matches too | `internal/module/auth/login.go`, `register.go`, `reset.go` |
| Stolen password database | argon2id (64 MiB, 3 passes, 2 lanes, 16-byte salt). Weaker stored hashes are upgraded at the next sign-in. Passwords are 10 to 128 characters, and the 10,000 most common are refused | `internal/module/auth/password` |
| Stolen database dump: emails and tokens | Emails are encrypted (AES-256-GCM) and looked up through a keyed blind index. Refresh, one-time and OAuth-state tokens are stored only as SHA-256 hashes. Private signing keys are never in the database | `internal/app/email_cipher.go`, `internal/module/session`, `internal/module/auth` |
| Stolen refresh token | Every refresh rotates the token. Reusing an old token after the 10-second grace window revokes the whole family (device). Sessions end after 30 idle days and 90 days total | `internal/module/session/service.go` |
| Forged or tampered tokens | RS256 tokens with a `kid`. Resource services check signature, issuer, audience and expiry against the published JWKS. Keys can be rotated without signing anyone out | `internal/module/auth/keys`, [key rotation runbook](docs/runbooks/key-rotation.md) |
| Admin powers that outlive a demotion | Admin routes read the caller's permissions from the database on every request, not from the token, so a removed role or disabled admin loses access at once | `internal/module/rbac/authorizer.go` |
| Privilege escalation by an admin | Admins can only grant permissions they hold, cannot change their own roles, and cannot remove the last user who can manage roles. The super admin cannot be changed through the API | `internal/module/rbac`, `internal/module/user` |
| Reading another tenant's data | Every tenant-owned query filters on the tenant from the token's `tid`, never from the request. Cross-tenant tests run in CI | `internal/platform/scope`, `test/isolation` |
| Google sign-in attacks (CSRF, code interception, open redirect) | Authorization code with PKCE (S256). `state` and `nonce` are checked, and `state` can be used once. `redirect_to` must be one of the configured frontend URLs. Tokens never travel in a URL: the frontend trades a one-time code for them | `internal/module/auth/google.go`, `oauth_state.go` |
| Misusing restricted tokens | A `password_change` token can only change the password. A service token (`scope: internal`) can only call `/v1/internal` | `internal/app/routes.go` |
| Secrets leaking into logs | Tokens, passwords, emails, and request and response bodies are never logged. Delivered mail has its one-time token cleared from the outbox row | [AGENTS.md](AGENTS.md), `internal/platform/mail/queue.go` |
| Unaudited changes | Changes to roles, memberships, tenants and the super admin, plus sign-ins, failures and resets, are written to `audit_log` in the same transaction as the change, with the request ID and IP | `internal/module/audit` |
| Vulnerable dependencies | `govulncheck` runs in CI (`make check`). Renovate keeps dependencies current | `Makefile`, `renovate.json` |

More detail on how these fit together is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Deploying safely

The service refuses to start in `production` without auth enabled, without the email encryption keys (required
outside `local`), or with the development mail stub. Everything below is the operator's job:

- [ ] `APP_ENV=production` (or `staging`), and `AUTH_ENABLED=true` in every environment except your own machine.
- [ ] Signing keys come from a mounted secret, never `make keys`. RSA 2048 bits or more.
- [ ] `EMAIL_ENCRYPTION_KEY` and `EMAIL_BLIND_INDEX_KEY` are two distinct random values, kept in a secret store and
      backed up. Losing them makes stored emails unreadable.
- [ ] `/v1/internal` is not reachable from the internet. Keep `route.blockInternalPath: true` in Helm, or the
      Caddy rule in Compose.
- [ ] `/metrics` is not reachable from the internet. It is a public route inside the service.
- [ ] `SWAGGER_ENABLED=false`, or a strong `SWAGGER_PASSWORD`.
- [ ] `REDIS_ADDR` is set when more than one API pod runs. Otherwise each pod has its own rate-limit counters.
- [ ] `TRUST_PROXY=true` only behind a proxy that overwrites `X-Forwarded-For`. Otherwise clients can fake their IP
      and dodge per-IP rate limits.
- [ ] `CORS_ORIGINS` and `FRONTEND_URL` list only your real frontends.
- [ ] TLS terminates at the edge (Ingress, Route or Caddy), and the database connection uses `DB_SSLMODE=require` or
      stricter when Postgres is on another host.
- [ ] Service-client secrets are long and random. Only their argon2id hash goes into config.
- [ ] Database backups are encrypted and access to them is restricted. See the
      [backup runbook](docs/runbooks/backup-restore.md).

## Known limitations

These are deliberate for now. They are not bugs to report:

- **No MFA**, and no sign-in methods beyond password and Google.
- **No breached-password check** (`breached_password_check`). Setting it to `true` is refused at startup.
- **Rate limits fail open** if Redis errors while running. The per-account lockout still limits guessing.
- **Access tokens can't be revoked early.** A token stays valid until it expires (15 minutes), even after sign-out.
  Identity's own admin routes do re-check that the user and membership are still active. Resource services that need faster blocking can check
  `GET /v1/internal/tenants/{id}` or `/v1/internal/users/{id}`.
- **`/v1/internal` inside the service** is protected only by the service-token check. Keeping it off the public
  edge is the deployment's job (see the checklist).
- **No Postgres row-level security.** Tenant isolation relies on the query rules and their tests.
