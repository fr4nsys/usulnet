.PHONY: all build build-agent run test test-coverage test-check-coverage test-benchmark test-e2e clean dev-up dev-down migrate lint lint-fix fmt vet templ css install-hooks help docker-build-recon-toolkit docker-build-recon-spiderfoot docker-build-recon publish-public publish-public-check publish-public-test publish-public-clean

# Variables
BINARY_NAME=usulnet
AGENT_BINARY_NAME=usulnet-agent
MAIN_PATH=./cmd/usulnet
AGENT_PATH=./cmd/usulnet-agent
BUILD_DIR=./bin

# Go commands
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GORUN=$(GOCMD) run
GOFMT=gofmt
GOVET=$(GOCMD) vet

# Templ and Tailwind
TEMPL=$(shell which templ 2>/dev/null || echo "templ")
TAILWIND=./bin/tailwindcss

# Build flags
LDFLAGS=-ldflags "-s -w -X main.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)"

all: templ css lint test build

# Generate Templ templates
templ:
	@echo "Generating Templ templates..."
	@which templ > /dev/null || (echo "Installing templ..." && go install github.com/a-h/templ/cmd/templ@latest)
	$(TEMPL) generate

# Watch Templ for development
templ-watch:
	$(TEMPL) generate --watch

# Compile Tailwind CSS
css:
	@echo "Compiling Tailwind CSS..."
	@if [ ! -f $(TAILWIND) ]; then \
		echo "Downloading Tailwind CSS standalone CLI..."; \
		mkdir -p bin; \
		curl -sLo $(TAILWIND) https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64; \
		chmod +x $(TAILWIND); \
	fi
	$(TAILWIND) -i web/static/src/input.css -o web/static/css/style.css --minify

# Watch CSS for development
css-watch:
	$(TAILWIND) -i web/static/src/input.css -o web/static/css/style.css --watch

# Combined frontend build
frontend: templ css

build: frontend
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)

build-agent:
	@echo "Building $(AGENT_BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(AGENT_BINARY_NAME) $(AGENT_PATH)

build-all: build build-agent

run:
	$(GORUN) $(MAIN_PATH)

test:
	$(GOTEST) -v -race -cover ./...

test-coverage:
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

test-check-coverage:
	@echo "Running coverage threshold check..."
	@bash scripts/check-coverage.sh 40

test-benchmark:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem -run=^$$ ./tests/benchmarks/...

test-e2e:
	@echo "Running E2E tests..."
	$(GOTEST) -tags=e2e -v -timeout=120s ./tests/e2e/...

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html

# Development environment
dev-up:
	docker compose -f docker-compose.dev.yml up -d
	@echo "Waiting for services to be ready..."
	@sleep 5
	@echo "Development environment is ready"

dev-down:
	docker compose -f docker-compose.dev.yml down

dev-logs:
	docker compose -f docker-compose.dev.yml logs -f

# Database
migrate:
	$(GORUN) $(MAIN_PATH) migrate up

migrate-down:
	$(GORUN) $(MAIN_PATH) migrate down

migrate-status:
	$(GORUN) $(MAIN_PATH) migrate status

# Code quality
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

lint-fix:
	@echo "Running linter with auto-fix..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run --fix ./...

fmt:
	$(GOFMT) -s -w .

vet:
	$(GOVET) ./...

# Generate
generate:
	$(GOCMD) generate ./...

# Dependencies
deps:
	$(GOCMD) mod download
	$(GOCMD) mod tidy

# Docker
docker-build:
	docker build -t usulnet:latest .

docker-build-agent:
	docker build -f Dockerfile.agent -t usulnet-agent:latest .

# Recon module images (RFC: docs/recon.md §12). Multi-arch via buildx.
# Note: `--load` only supports a single platform locally; override
# PLATFORMS=linux/amd64 (or linux/arm64) when building on a host that
# cannot fan out, or drop --load and add --push in CI.
RECON_PLATFORMS ?= linux/amd64,linux/arm64
RECON_TOOLKIT_TAG ?= ghcr.io/fr4nsys/usulnet-recon-toolkit:dev
RECON_SPIDERFOOT_TAG ?= ghcr.io/fr4nsys/usulnet-recon-spiderfoot:dev

docker-build-recon-toolkit:
	docker buildx build \
		--platform $(RECON_PLATFORMS) \
		--tag $(RECON_TOOLKIT_TAG) \
		--load deploy/recon/toolkit

docker-build-recon-spiderfoot:
	docker buildx build \
		--platform $(RECON_PLATFORMS) \
		--tag $(RECON_SPIDERFOOT_TAG) \
		--load deploy/recon/spiderfoot

docker-build-recon: docker-build-recon-toolkit docker-build-recon-spiderfoot

docker-run:
	docker run --rm -p 8080:8080 usulnet:latest

# Development with agent profile
dev-up-agent:
	docker compose -f docker-compose.dev.yml --profile agent up -d
	@echo "Development environment with agent is ready"

# Git hooks
install-hooks:
	@echo "Installing git hooks..."
	@cp scripts/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed"

# Naming convention check (usulnet always lowercase; USULNET_ env prefix allowed)
.PHONY: check-naming
check-naming:
	@scripts/check-naming.sh

# Quality gate — run all quality checks
quality: lint vet check-naming test-check-coverage
	@echo "All quality checks passed!"

# Public-repo split (docs/0526/, scripts/publish-public.sh).
# Produces build/public/ ready for the S03 mirror workflow.
publish-public:
	@bash scripts/publish-public.sh --dry-run

publish-public-check:
	@bash scripts/publish-public.sh --check-denied

publish-public-test:
	@bash scripts/publish-public_test.sh

publish-public-clean:
	@bash scripts/publish-public.sh --clean

# Help
help:
	@echo "usulnet — Docker Management Platform"
	@echo ""
	@echo "Build:"
	@echo "  make build              Full build (templ + CSS + Go binary)"
	@echo "  make build-agent        Build agent binary only"
	@echo "  make build-all          Build both binaries"
	@echo "  make frontend           Generate templates + compile CSS"
	@echo ""
	@echo "Run:"
	@echo "  make run                Run the server (go run)"
	@echo "  make dev-up             Start dev services (PostgreSQL, Redis, NATS)"
	@echo "  make dev-down           Stop dev services"
	@echo "  make dev-up-agent       Start dev services with agent profile"
	@echo ""
	@echo "Test:"
	@echo "  make test               Run tests with race detection and coverage"
	@echo "  make test-coverage      Generate HTML coverage report"
	@echo "  make test-check-coverage  Check 40%% coverage threshold"
	@echo "  make test-benchmark     Run benchmark tests"
	@echo "  make test-e2e           Run E2E tests (requires running services)"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint               Run golangci-lint"
	@echo "  make lint-fix           Run golangci-lint with auto-fix"
	@echo "  make fmt                Format Go source files"
	@echo "  make vet                Run go vet"
	@echo "  make quality            Full quality gate (lint + vet + coverage)"
	@echo ""
	@echo "Database:"
	@echo "  make migrate            Run migrations up"
	@echo "  make migrate-down       Roll back migrations"
	@echo "  make migrate-status     Show migration status"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build       Build production Docker image"
	@echo "  make docker-build-agent Build agent Docker image"
	@echo "  make docker-build-recon-toolkit     Build recon toolkit image"
	@echo "  make docker-build-recon-spiderfoot  Build SpiderFoot image"
	@echo "  make docker-build-recon             Build both recon images"
	@echo ""
	@echo "Public-split (May 2026 pivot, docs/0526/):"
	@echo "  make publish-public        Dry-run the public-repo split into build/public/"
	@echo "  make publish-public-check  Fail if any denied path leaked into build/public/"
	@echo "  make publish-public-test   Run the publish-public shell test suite"
	@echo "  make publish-public-clean  Remove build/public/"
	@echo ""
	@echo "Other:"
	@echo "  make deps               Download and tidy Go modules"
	@echo "  make install-hooks      Install git pre-commit hook"
	@echo "  make clean              Remove build artifacts"
