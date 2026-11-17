<!--
Title (becomes the squash commit on main): <type>(<scope>)?: <what it does, lower case> (<task id>)
  e.g. feat(auth): lock the account after 5 failed sign-ins (T3.6)
Branch: <type>/<group>/<task-id>-<slug>, e.g. feat/p2/T3.6-login
Keep sections in this order. Delete a section only when it has nothing to say; never write "N/A".
Write facts in present tense with exact names and codes. Delete these comments.
-->

## <Task ID> <Task name>

<One or two sentences: what changes for the caller or operator.>

**Base:** `main` (<short sha>)
<!-- or: **Stacked on** #<n> (`<branch>`): merge that first, then retarget this PR to `main`. -->
**Risk:** low | medium | high, because <one line>
**Start reviewing at:** `<file>`, because <why that file first>

### Why

**Kind:** requirement | bug fix | security / dependency | refactor / tech debt | tooling / docs

<!-- Answer the prompt for the kind you picked, delete the others. -->
- Requirement: the task and spec it answers (`IMPLEMENTATION_PLAN T3.6`, `TRD 9.4`, `APP_FLOW 3`) and the need in one line.
- Bug fix: the symptom someone saw, how to reproduce it, and the root cause.
- Security / dependency: the advisory or version (`GO-2026-6865`) and what is exposed without the change.
- Refactor / tooling / docs: what was hard or wrong before, and what this unblocks.

### What changed

- **<Behaviour>.** The mechanism and the exact status/reason (`401 ACCOUNT_LOCKED`, `meta.retry_after`).

### Wiring

<!-- Only when ports, adapters or Deps changed. -->
- Ports declared in the module, adapters in `internal/app/adapters.go`, signature changes.

### API / schema change

<!-- Only when api/openapi.yaml, migrations, config keys or the TRD/plan text changed. -->
- What changed and why. New migration `<n>_<name>`; new config key also in `.env.example`; `redocly lint` result.

### Verification

<!--
Quote what each command printed on the last run of the pushed head (after any rebase), never "tests pass".
Keep a failed or skipped check in the table with its result. Add rows for anything else you ran.
-->

| Check | Command / tool | Result |
|---|---|---|
| Format, lint, unit tests, coverage, vulncheck | `make check` | `0 issues.`, unit `ok`, coverage `<n>%`, `No vulnerabilities found.`, exit 0 |
| Integration tests (Postgres via Testcontainers) | `make test-integration` | every package `ok`, exit 0 |
| Swagger in sync | `make swagger && git diff --exit-code api/swagger` | exit 0 |
| CI on the pushed head | `gh pr checks` | <each check and its state> |

**Not verified:** <what was not run and why, or "nothing">

### Acceptance → evidence

| Criterion (from the plan) | Proven by |
|---|---|
| <one row per acceptance criterion> | `TestName` (unit / integration) |

### Judgement calls

<!-- Every choice the plan or TRD did not settle, also recorded in docs/DECISIONS.md, so a reviewer can overrule it cheaply. -->
-

### Not covered / follow-ups

-
