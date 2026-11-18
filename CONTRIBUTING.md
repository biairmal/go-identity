# Contributing

How a change gets from an idea to `main`. It applies to everyone, human or AI agent. How the code itself is written
(layout, layering, module rules, test conventions) is in [AGENTS.md](AGENTS.md), and it binds humans too.

## Before you start

1. Get the service running with the [README quick start](README.md#quick-start).
2. Read [AGENTS.md](AGENTS.md) for the code rules, and [docs/PATTERNS.md](docs/PATTERNS.md) for examples of them.
3. Find the spec for your change. The specs (PRD, TRD, APP_FLOW, implementation plan) live in the project's
   `phase2/backend/` folder. When a spec and AGENTS.md disagree, the TRD wins. When the TRD is unclear, pick the
   simplest option that fits it and add a line to [docs/DECISIONS.md](docs/DECISIONS.md).

## Git conventions

`.github/workflows/pr-conventions.yml` checks these on every PR. PRs are squash-merged, so the PR title becomes the
commit on `main`.

- **Branch:** `<type>/<group>/<task-id>-<slug>`. `<group>` is optional and names the work stream, so parallel streams
  don't collide. The task ID keeps the plan's casing. Examples: `feat/p2/T10.3-audit-target`, `fix/deps/klauspost-cve`.
- **Commit and PR title:** [Conventional Commits](https://www.conventionalcommits.org/),
  `<type>(<scope>)?: <what it does, lower case>`, plus ` (<task id>)` on the PR title. Types:
  `feat fix refactor perf test docs build ci chore revert`. A breaking change adds `!` and a `BREAKING CHANGE:`
  footer. The commit body says why, not how.
- **PR body:** fill in [.github/pull_request_template.md](.github/pull_request_template.md). `### Why` (requirement,
  bug, security, or refactor, with its source), `### What changed` and `### Verification` are required. Verification
  quotes each command's real output from the final pushed head, keeps failed or skipped checks in the table, and
  lists what was not verified.

## Definition of Done

- [ ] `make check` passes; `make test-integration` passes when the change touches the database.
- [ ] New behaviour has table-driven tests.
- [ ] New exported symbols have doc comments.
- [ ] No module-to-module imports; no secrets in logs.
- [ ] The README, `.env.example` and `api/openapi.yaml` match the change when it touches setup, config, commands or
      the API.
