.PHONY: all build build-agent run test clean dev-up dev-down migrate lint fmt templ css

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
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

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

docker-run:
	docker run --rm -p 8080:8080 usulnet:latest

# Development with agent profile
dev-up-agent:
	docker compose -f docker-compose.dev.yml --profile agent up -d
	@echo "Development environment with agent is ready"
