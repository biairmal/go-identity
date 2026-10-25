# go-identity Makefile. `make help` lists targets.

COMPOSE := docker compose -f deploy/compose/docker-compose.yaml
COVERAGE_OUT := out/coverage.out
SWAG := go run github.com/swaggo/swag/cmd/swag@v1.16.6
SWAGGER_DIR := api/swagger
BIN := bin/server

.DEFAULT_GOAL := help
.PHONY: help up down run build swagger test test-integration lint format format-check coverage vulncheck check \
	migrate-up migrate-down migrate-create keys openapi-lint openapi-mock

help: ## Show targets
	@grep -E "^[a-z-]+:.*## " Makefile | sed -e "s/:.*## /\t/"

up: ## Start the local stack (Postgres)
	$(COMPOSE) up -d --wait

down: ## Stop the local stack
	$(COMPOSE) down

keys: ## Generate a local signing key (development only; real envs mount a secret)
	bash scripts/gen-dev-keys.sh ./keys

swagger: ## Generate Swagger docs from handler annotations into api/swagger
	$(SWAG) init -g cmd/server/main.go -o $(SWAGGER_DIR) --packageName swagger --outputTypes go,json --parseDependency --parseInternal

build: swagger ## Generate Swagger docs, then build bin/server
	go build -o $(BIN) ./cmd/server

run: keys swagger ## Generate Swagger docs, then run the API against the local stack
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

openapi-lint: ## Validate api/openapi.yaml (needs npx)
	npx --yes @redocly/cli@latest lint api/openapi.yaml

openapi-mock: ## Serve api/openapi.yaml as a mock on :4010 (needs npx)
	npx --yes @stoplight/prism-cli@latest mock api/openapi.yaml -p 4010

check: format-check lint test coverage vulncheck ## CI gate: format, lint, unit tests, coverage, vulncheck

migrate-up: ## Apply migrations
	go run ./cmd/server migrate up

migrate-down: ## Revert the last migration
	go run ./cmd/server migrate down

migrate-create: ## New migration: make migrate-create name=add_x
	go run ./cmd/server migrate create $(name)
