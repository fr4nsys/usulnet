.PHONY: all build build-agent run test test-coverage test-check-coverage test-benchmark test-e2e smoke-e2e clean dev-up dev-down dev-certs migrate lint lint-fix fmt vet templ css install-hooks install-completions help docker-build-recon-toolkit docker-build-recon-spiderfoot docker-build-recon publish-public publish-public-check publish-public-test publish-public-clean check-tenant-isolation check-recon-audit-append-only cloud-test cloud-spike cloud-app-test cloud-verifiers-test cloud-connectors-test sandbox-test sandbox-bench scheduler-test findings-test reports-test pdf-builder-test pdf-builder-go-test delta-test weekly-digest-test weekly-digest-smoke brokers-test brokers-smoke erasure-test erasure-smoke support-inbox-test support-inbox-smoke onboarding-test onboarding-smoke

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

# Tailwind v3.x — the project is on v3 syntax (per CLAUDE.md). Pin the
# release URL because the `latest` link now resolves to v4 which has
# breaking changes (`@apply` rules with v3-only utilities like `px-4` no
# longer compile).
TAILWIND_VERSION=v3.4.17
TAILWIND_URL=https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-linux-x64

# Compile Tailwind CSS. Invoked from web/static/ so the relative `content`
# paths in tailwind.config.js (../../internal/web/templates/**/*.templ)
# resolve against the templates tree.
css:
	@echo "Compiling Tailwind CSS..."
	@if [ ! -f $(TAILWIND) ]; then \
		echo "Downloading Tailwind CSS standalone CLI ($(TAILWIND_VERSION))..."; \
		mkdir -p bin; \
		curl -sLo $(TAILWIND) $(TAILWIND_URL); \
		chmod +x $(TAILWIND); \
	fi
	cd web/static && ../../$(TAILWIND) -i src/input.css -o css/style.css --minify

# Watch CSS for development
css-watch:
	cd web/static && ../../$(TAILWIND) -i src/input.css -o css/style.css --watch

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
	@bash scripts/check-coverage.sh 15

test-benchmark:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem -run=^$$ ./tests/benchmarks/...

test-e2e:
	@echo "Running E2E tests..."
	$(GOTEST) -tags=e2e -v -timeout=120s ./tests/e2e/...

# smoke-e2e is the release-gate smoke (Tier 0 / session 01 of v26.5.2 plan).
# It boots the actual compose stack against a freshly built image,
# logs in as admin, walks the sidebar, and asserts no panic in logs.
# Excluded from `test-e2e` because it owns the full Docker daemon.
smoke-e2e:
	@echo "Running smoke E2E (builds image, brings up compose, walks routes)..."
	$(GOTEST) -tags=e2e -v -timeout=10m -run TestSmokeE2E ./tests/e2e/smoke/...

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

# Pre-generate the self-signed certs used by the in-cluster Postgres /
# Redis / NATS containers when USULNET_TLS_LOCAL_SERVICES=true. The
# deploy/tls/*.sh entrypoints will generate certs on first boot
# automatically; this target is for operators who want them on the
# host filesystem ahead of time (audit, mTLS, verify-full). Gated by
# the same env var so plain-TCP installs are a no-op.
dev-certs:
	@if [ "$$USULNET_TLS_LOCAL_SERVICES" != "true" ]; then \
		echo "dev-certs: USULNET_TLS_LOCAL_SERVICES is not true — skipping (set USULNET_TLS_LOCAL_SERVICES=true to generate)"; \
		exit 0; \
	fi
	@command -v openssl >/dev/null 2>&1 || { echo "dev-certs: openssl not found in PATH"; exit 1; }
	@mkdir -p deploy/tls/certs/postgres deploy/tls/certs/redis deploy/tls/certs/nats
	@for svc in postgres redis nats; do \
		dir=deploy/tls/certs/$$svc; \
		if [ -s $$dir/server.crt ] && [ -s $$dir/server.key ]; then \
			echo "dev-certs: $$svc cert already present ($$dir/server.crt) — keeping"; \
		else \
			echo "dev-certs: generating self-signed ECDSA P-256 cert for $$svc"; \
			openssl ecparam -name prime256v1 -genkey -noout -out $$dir/server.key; \
			openssl req -new -x509 -key $$dir/server.key -out $$dir/server.crt -days 3650 \
				-subj "/CN=usulnet-$$svc" \
				-addext "subjectAltName=DNS:$$svc,DNS:localhost,IP:127.0.0.1"; \
			cp $$dir/server.crt $$dir/ca.crt; \
			chmod 600 $$dir/server.key; \
			chmod 644 $$dir/server.crt $$dir/ca.crt; \
		fi; \
	done
	@echo "dev-certs: all certs in deploy/tls/certs/{postgres,redis,nats}/"

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

# Shell tab-completion install
# Generates and writes bash/zsh/fish completion files for usulnet and
# usulnet-agent. Defaults to the per-user path; pass SYSTEM=1 for
# system-wide install (sudo required). Pass SHELL_OVERRIDE=zsh to
# force a shell other than $SHELL.
.PHONY: install-completions
install-completions:
	@bash deploy/install-completions.sh \
		$(if $(SHELL_OVERRIDE),--shell $(SHELL_OVERRIDE)) \
		$(if $(SYSTEM),--system)

# Naming convention check (usulnet always lowercase; USULNET_ env prefix allowed)
.PHONY: check-naming
check-naming:
	@scripts/check-naming.sh

.PHONY: verify-migrations
verify-migrations:
	@bash scripts/verify-migrations.sh

# govulncheck allowlist justification assertion (cheap, no network).
# The full govulncheck scan runs in CI via .github/workflows/govulncheck.yml
# because it requires vuln.go.dev access; this target pins the empirical
# claims behind the allowlist (no PluginInstall calls, no daemon imports,
# authorization-plugins string scoped to dockerconfig).
.PHONY: check-govulncheck-allowlist
check-govulncheck-allowlist:
	@bash scripts/check-govulncheck-allowlist.sh

# Quality gate — run all quality checks
quality: lint vet check-naming verify-migrations check-govulncheck-allowlist test-check-coverage
	@echo "All quality checks passed!"

# Public-repo split (docs/0526/, scripts/publish-public.sh).
# Produces build/public/ ready for the S03 mirror workflow.
publish-public:
	@bash scripts/publish-public.sh --dry-run

# publish-public-check runs the publish dry-run + denial verifier, and
# also asserts the tenancy isolation invariant introduced by S04. The
# private SaaS tree must not leak (verified by publish-public.sh) AND
# must not contain raw D1 access that bypasses the tenant() wrapper.
publish-public-check: check-tenant-isolation check-recon-audit-append-only
	@bash scripts/publish-public.sh --check-denied

publish-public-test:
	@bash scripts/publish-public_test.sh

publish-public-clean:
	@bash scripts/publish-public.sh --clean

# Cloud SaaS (cloud-private/) — S04 introduced these. Standalone so a
# developer iterating on the wrapper does not need to run the full Go
# quality gate.
check-tenant-isolation:
	@bash scripts/check-tenant-isolation.sh

# S08 audit append-only static guard. Mirrors the AGPL guard at
# internal/repository/postgres/recon_audit_append_only_test.go — refuses
# to let any non-test code under cloud-private/ carry a SQL string that
# mentions UPDATE / DELETE / TRUNCATE against recon_audit_log.
check-recon-audit-append-only:
	@bash scripts/check-recon-audit-append-only.sh

cloud-test:
	@cd cloud-private/db && node --test --experimental-sqlite tenant.test.js tenant-verification.test.js
	@node --test --experimental-sqlite cloud-private/recon/api.test.js
	@node --test --experimental-sqlite cloud-private/recon/scans.test.js
	@node --test --experimental-sqlite cloud-private/recon/findings.test.js
	@node --test --experimental-sqlite cloud-private/recon/paid-connectors.test.js
	@node --test --experimental-sqlite cloud-private/recon/connectors-health.test.js
	@node --test usulnetdotcom-main/recon/delta.test.js
	@node --test --experimental-sqlite cloud-private/recon/delta.test.js
	@node --test --experimental-sqlite cloud-private/weekly-digest/core.test.js
	@node --test usulnetdotcom-main/recon/brokers/probe.test.js
	@node --test --experimental-sqlite cloud-private/recon/brokers.test.js
	@node --test --experimental-sqlite cloud-private/cloud-app/api-broker-settings.test.js
	@node --test --experimental-sqlite cloud-private/cloud-app/api-account-erase.test.js
	@node --test --experimental-sqlite cloud-private/cloud-app/admin/queries.test.js
	@node --test --experimental-sqlite cloud-private/cloud-app/admin/index.test.js
	@node --test --experimental-sqlite cloud-private/erasure/core.test.js
	@node --test cloud-private/lib/sentry.test.js
	@node --test cloud-private/lib/health.test.js

# Scan scheduler tests (S09). Exercises runScheduler() + dispatchScan()
# against an in-process node:sqlite stub + the FakeLauncher. The scheduler
# is the only cloud-private/ Worker that legitimately needs cross-tenant
# DB access; check-tenant-isolation.sh allow-lists scheduler/db.js.
scheduler-test:
	@node --test --experimental-sqlite cloud-private/scheduler/core.test.js

# Findings storage + retention tests (S10). The crypto helper test lives
# under usulnetdotcom-main/crypto (no tenant data touched); the
# storeFindings test lives under cloud-private/recon; the retention
# worker test lives under cloud-private/retention.
findings-test:
	@node --test usulnetdotcom-main/crypto/findings.test.js
	@node --test --experimental-sqlite cloud-private/recon/findings.test.js
	@node --test --experimental-sqlite cloud-private/retention/core.test.js

# Exposure-view + PDF endpoint tests (S12). Exercises the four
# /api/v1/recon/targets/:id/{findings,findings/:fid/raw,report,report.pdf}
# endpoints, including the tenancy 404 invariant.
reports-test:
	@node --test --experimental-sqlite cloud-private/recon/reports.test.js

# pdf-builder Worker tests (S12). Exercises the cron loop end-to-end
# against a node:sqlite outbox stub, a fake builder, and an in-memory
# R2 stub. Verifies the outbox row's payload is rewritten with the R2
# key on success and the error string on failure.
pdf-builder-test:
	@node --test --experimental-sqlite cloud-private/pdf-builder/core.test.js

# Run-delta tests (S13). The pure delta function lives at
# usulnetdotcom-main/recon/delta.js (no D1, no tenancy); the orchestrator
# + API handler live at cloud-private/recon/delta.js (uses tenant()).
# Each test file runs independently — the pure one runs under plain
# Node, the orchestrator one needs --experimental-sqlite.
delta-test:
	@node --test usulnetdotcom-main/recon/delta.test.js
	@node --test --experimental-sqlite cloud-private/recon/delta.test.js

# Weekly-digest worker tests + smoke (S13). The cron loop test exercises
# the active-subscription filter + quiet-week skip + outbox payload
# shape against an in-process node:sqlite stub. The smoke drives a
# full cycle end-to-end (cron → outbox → dispatcher → captured email)
# and writes the rendered body to
# dev/0526/cloud/screenshots/session-13-digest-{smoke.json,email.html,email.txt}.
weekly-digest-test:
	@node --test --experimental-sqlite cloud-private/weekly-digest/core.test.js

# Curated data-broker probe tests + smoke (S14). The pure probe + schema
# lives at usulnetdotcom-main/recon/brokers/ (no D1, no tenancy); the
# orchestrator + API handler live at cloud-private/ (uses tenant()). The
# smoke drives runBrokersForScan end-to-end against an in-memory D1 stub
# and writes the per-run report to
# dev/0526/cloud/screenshots/session-14-brokers-{smoke.json,summary.md}.
brokers-test:
	@node --test usulnetdotcom-main/recon/brokers/probe.test.js
	@node --test --experimental-sqlite cloud-private/recon/brokers.test.js
	@node --test --experimental-sqlite cloud-private/cloud-app/api-broker-settings.test.js

brokers-smoke:
	@node --experimental-sqlite cloud-private/recon/brokers-smoke.js

# Right-to-erasure flow tests (S16). The orchestrator test (core.test.js)
# exercises runErasure() against the full schema (billing + cloud-private
# migrations 0001-0007) with a capturing Polar mock. The API test
# (api-account-erase.test.js) exercises the two POST endpoints — /erase
# enqueues the cascade row + the confirmation email; /erase/cancel deletes
# the row while the 7-day window is still open. Dispatcher delegation +
# the full time-warp cycle (enqueue → 7d → cascade) live in
# usulnetdotcom-main/dispatcher/index.test.js under `npm test`.
erasure-test:
	@node --test --experimental-sqlite cloud-private/cloud-app/api-account-erase.test.js
	@node --test --experimental-sqlite cloud-private/erasure/core.test.js

# Right-to-erasure end-to-end smoke (S16). Drives a typical account
# through enqueue → 7d → cascade with a capturing Polar mock + the
# real dispatcher loop, then writes a structured artifact + the
# rendered confirmation email to dev/0526/cloud/screenshots/ so the
# operator can eyeball the byte-count + Polar payload + per-table
# delta + the email body without re-running.
erasure-smoke:
	@node --experimental-sqlite cloud-private/erasure/smoke.js

weekly-digest-smoke:
	@node --experimental-sqlite cloud-private/weekly-digest/smoke.js

# Landing-page screenshot smoke (S21). Renders /app/targets, /app/scans,
# and /app/targets/:id against a seeded in-memory SQLite, writes the HTML
# artefacts under dev/0526/cloud/screenshots/session-21-*.html, then
# `playwright screenshot` converts each to a PNG under
# usulnetdotcom-main/cloud/screenshots/<page>.png — the file the landing
# embeds. Reviewer can rerun this make target to regenerate all three.
.PHONY: landing-smoke
landing-smoke:
	@node --experimental-sqlite cloud-private/cloud-app/smoke-render-landing.js
	@for f in targets scans exposure; do \
	  npx --no-install playwright screenshot \
	    --browser=chromium \
	    --color-scheme=dark \
	    --viewport-size=1280,800 \
	    --wait-for-timeout=400 \
	    "file://$(CURDIR)/dev/0526/cloud/screenshots/session-21-$$f.html" \
	    "usulnetdotcom-main/cloud/screenshots/$$f.png" >/dev/null 2>&1 \
	    && echo "  ok  usulnetdotcom-main/cloud/screenshots/$$f.png" \
	    || echo "  FAIL screenshot $$f"; \
	done

# Support inbox Email Worker tests (S20). Exercises the core
# extract / throttle / outbox-insert pipeline with in-memory fakes
# for D1 + KV — no Wrangler, no Cloudflare bindings required. The
# Worker entry point (index.js) is the only thin shell layer; the
# core tests pin the contract that matters.
support-inbox-test:
	@node --test cloud-private/support-inbox/core.test.js

# Onboarding email sequence tests (S22). The dispatcher's branch
# handlers + the new render functions live under usulnetdotcom-main/
# (covered by `npm test`); this target runs the cloud-private side:
# the email-preferences API + helper.
.PHONY: onboarding-test
onboarding-test:
	@node --test --experimental-sqlite \
		cloud-private/cloud-app/api-email-preferences.test.js
	@node --test cloud-private/cloud-app/render/pages/settings.test.js

# Onboarding sequence end-to-end smoke (S22). Drives a sandbox
# subscription through subscription.created → magic_link → +1d
# onboarding_d1 → +30d onboarding_d30, plus an opt-out tail that
# proves the soft-consume path. Writes a structured artifact + the
# rendered D1 and D30 emails to dev/0526/cloud/screenshots/ so the
# operator can eyeball the body without re-running.
.PHONY: onboarding-smoke
onboarding-smoke:
	@node --experimental-sqlite cloud-private/onboarding/smoke.js

# Support inbox end-to-end smoke (S20). Drives the three brief
# scenarios (first ack / throttled / post-window ack) through the
# core, captures the per-tick result + the resulting outbox rows +
# the KV-key shape in a JSON artifact under screenshots/. The
# artifact is what the operator inspects in the PR.
support-inbox-smoke:
	@node cloud-private/support-inbox/smoke.js

# cmd/pdf-builder Go binary tests (S12). The binary itself stays in the
# AGPL repo per ADR 07; the cloud Worker invokes it on the sandbox
# cluster. Tests verify the stdin→stdout contract + byte-deterministic
# output (the R2 key is content-addressed on the SHA-256 of the bytes).
pdf-builder-go-test:
	@go test ./cmd/pdf-builder/...

cloud-spike:
	@node --experimental-sqlite cloud-private/spike/benchmark.js

# Dashboard shell tests (S05+). Runs every *.test.js under
# cloud-private/cloud-app/. No --experimental-sqlite needed — these
# tests exercise pure rendering and routing, not D1. New session-06
# tests (settings, settings-delete, pii) are picked up automatically.
#
# S18 admin tests live in their own subtree (cloud-private/cloud-app/
# admin/). The query + handler tests need --experimental-sqlite (they
# spin up an in-memory SQLite to exercise the cross-tenant SELECTs);
# the renderer + operator-emails tests are pure JS and run without it.
cloud-app-test:
	@node --test \
		cloud-private/cloud-app/routes.test.js \
		cloud-private/cloud-app/render/layout.test.js \
		cloud-private/cloud-app/render/pages/settings.test.js \
		cloud-private/cloud-app/render/pages/settings-delete.test.js \
		cloud-private/cloud-app/render/pages/help.test.js \
		cloud-private/cloud-app/lib/pii.test.js \
		cloud-private/cloud-app/index.test.js \
		cloud-private/cloud-app/admin/operator-emails.test.js \
		cloud-private/cloud-app/admin/render.test.js
	@node --test --experimental-sqlite \
		cloud-private/cloud-app/admin/queries.test.js \
		cloud-private/cloud-app/admin/index.test.js \
		cloud-private/cloud-app/api-email-preferences.test.js

# Sandbox-cluster launcher + spike-endpoint tests (S07). Exercises
# JobSpec validation, the SandboxLauncher contract (against a fake
# binding), and the /api/v1/recon/scans/_spike HTTP surface.
sandbox-test:
	@node --test \
		cloud-private/sandbox/spec.test.js \
		cloud-private/sandbox/launcher.test.js \
		cloud-private/sandbox/spike.test.js

# Sandbox-cluster launcher overhead benchmark (S07). Feeds the
# "Worker-side floor" numbers in ADR 04. Pass --json to capture
# machine-readable output.
sandbox-bench:
	@node cloud-private/sandbox/benchmark.js

# Verifier strategy tests (S08). The verifier modules live under
# usulnetdotcom-main/verifiers/ because they touch no tenant data; the
# tests live next to them and run independently of the cloud-private/
# orchestration tests.
cloud-verifiers-test:
	@node --test \
		usulnetdotcom-main/verifiers/dns-txt.test.js \
		usulnetdotcom-main/verifiers/email-link.test.js \
		usulnetdotcom-main/verifiers/rdap.test.js \
		usulnetdotcom-main/verifiers/admin-attest.test.js \
		usulnetdotcom-main/verifiers/self-assert.test.js

# Connector strategy tests (S11). HIBP / Shodan / IntelX modules live
# under usulnetdotcom-main/connectors/ for the same reason as the
# verifiers — they touch no tenant data. The tenant-scoped orchestration
# tests (paid-connectors.test.js + connectors-health.test.js) run as
# part of cloud-test above.
cloud-connectors-test:
	@node --test \
		usulnetdotcom-main/connectors/semaphore.test.js \
		usulnetdotcom-main/connectors/hibp.test.js \
		usulnetdotcom-main/connectors/shodan.test.js \
		usulnetdotcom-main/connectors/intelx.test.js

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
	@echo "  make dev-certs          Generate self-signed certs for Postgres/Redis/NATS"
	@echo "                          (requires USULNET_TLS_LOCAL_SERVICES=true)"
	@echo ""
	@echo "Test:"
	@echo "  make test               Run tests with race detection and coverage"
	@echo "  make test-coverage      Generate HTML coverage report"
	@echo "  make test-check-coverage  Check coverage threshold (interim 15%%, target 40%%)"
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
	@echo "Public-split (May 2026 pivot, dev/0526/):"
	@echo "  make publish-public        Dry-run the public-repo split into build/public/"
	@echo "  make publish-public-check  Fail if any denied path leaked into build/public/"
	@echo "  make publish-public-test   Run the publish-public shell test suite"
	@echo "  make publish-public-clean  Remove build/public/"
	@echo ""
	@echo "Cloud SaaS (cloud-private/, S04+):"
	@echo "  make check-tenant-isolation         Static guard: no raw env.DB.* under cloud-private/"
	@echo "  make check-recon-audit-append-only  Static guard: no UPDATE/DELETE recon_audit_log (S08)"
	@echo "  make cloud-test                     Run cloud-private/db/ + cloud-private/recon/ tests"
	@echo "  make cloud-spike                    Run the S04 substrate spike benchmark"
	@echo "  make cloud-app-test                 Run cloud-private/cloud-app/ shell tests (S05)"
	@echo "  make cloud-verifiers-test           Run usulnetdotcom-main/verifiers/ tests (S08)"
	@echo "  make sandbox-test                   Run cloud-private/sandbox/ launcher + spike tests (S07)"
	@echo "  make sandbox-bench                  Run the S07 sandbox launcher overhead benchmark"
	@echo "  make scheduler-test                 Run cloud-private/scheduler/ tests (S09)"
	@echo "  make findings-test                  Run S10 findings + retention tests"
	@echo "  make reports-test                   Run S12 exposure-view + PDF API tests"
	@echo "  make pdf-builder-test               Run S12 pdf-builder Worker tests"
	@echo "  make pdf-builder-go-test            Run S12 cmd/pdf-builder Go binary tests"
	@echo "  make delta-test                     Run S13 delta function + orchestrator tests"
	@echo "  make weekly-digest-test             Run S13 weekly-digest Worker tests"
	@echo "  make weekly-digest-smoke            Run S13 weekly-digest end-to-end smoke"
	@echo "  make brokers-test                   Run S14 broker probe + orchestrator tests"
	@echo "  make brokers-smoke                  Run S14 broker probe end-to-end smoke"
	@echo "  make erasure-test                   Run S16 right-to-erasure tests"
	@echo "  make erasure-smoke                  Run S16 right-to-erasure end-to-end smoke"
	@echo "  make support-inbox-test             Run S20 support-inbox Email Worker tests"
	@echo "  make support-inbox-smoke            Run S20 support-inbox end-to-end smoke"
	@echo ""
	@echo "Other:"
	@echo "  make deps                  Download and tidy Go modules"
	@echo "  make install-hooks         Install git pre-commit hook"
	@echo "  make install-completions   Install shell tab-completion for usulnet+agent"
	@echo "                             (SYSTEM=1 for system-wide; SHELL_OVERRIDE=zsh to override)"
	@echo "  make clean                 Remove build artifacts"
