# go-identity Makefile. `make help` lists targets.

COMPOSE := docker compose -f deploy/compose/docker-compose.yaml
COVERAGE_OUT := out/coverage.out

.DEFAULT_GOAL := help
.PHONY: help up down run test test-integration lint format format-check coverage vulncheck check \
	migrate-up migrate-down migrate-create keys

help: ## Show targets
	@grep -E "^[a-z-]+:.*## " Makefile | sed -e "s/:.*## /\t/"

up: ## Start the local stack (Postgres)
	$(COMPOSE) up -d --wait

down: ## Stop the local stack
	$(COMPOSE) down

keys: ## Generate a local signing key (development only; real envs mount a secret)
	bash scripts/gen-dev-keys.sh ./keys

run: keys ## Run the API against the local stack
	SIGNING_KEYS_DIR=./keys go run ./cmd/server serve

test: ## Unit tests
	go test -short ./...

test-integration: ## Unit + integration tests (Docker needed for Testcontainers)
	go test ./...

lint: ## golangci-lint
	golangci-lint run ./...

format: ## gofumpt
	gofumpt -w .

format-check: ## Fail when a file is not gofumpt-formatted
	@test -z "$$(gofumpt -l .)" || (gofumpt -l . && exit 1)

coverage: ## Unit-test coverage into out/
	@mkdir -p out
	go test -short -coverprofile=$(COVERAGE_OUT) -covermode=atomic ./...
	go tool cover -func=$(COVERAGE_OUT)

vulncheck: ## govulncheck
	govulncheck ./...

check: format-check lint test coverage vulncheck ## CI gate: format, lint, unit tests, coverage, vulncheck

migrate-up: ## Apply migrations
	go run ./cmd/server migrate up

migrate-down: ## Revert the last migration
	go run ./cmd/server migrate down

migrate-create: ## New migration: make migrate-create name=add_x
	go run ./cmd/server migrate create $(name)
