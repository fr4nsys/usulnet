# GitHub Copilot Instructions for usulnet

## Project Overview

**usulnet** is a self-hosted Docker Management Platform written in **Go** — a single-binary alternative to Portainer. It provides container lifecycle management, security scanning, backup management, reverse proxy configuration, monitoring, multi-node orchestration, and developer tooling through a unified web UI.

- **Module path:** `github.com/fr4nsys/usulnet`
- **Go version:** 1.25.7
- **License:** AGPL-3.0-or-later
- **Current release:** v26.2.0 Beta

## Architecture

### Operation Modes

The platform supports three operation modes:

1. **standalone** — Single Docker host. All services local. No NATS required.
2. **master** — Standalone + NATS gateway server for remote agent management.
3. **agent** — Connects to master via NATS. No web UI. Executes Docker operations on its local host.

### Entry Points

| Binary | Location | Framework | Purpose |
|--------|----------|-----------|---------|
| `usulnet` | `cmd/usulnet/` | Cobra CLI | Main server (`serve`, `migrate`, `config`, `admin`, `version`) |
| `usulnet-agent` | `cmd/usulnet-agent/` | `flag` package | Remote node agent |

### Key Directories

- `cmd/` — Binary entry points (usulnet and usulnet-agent)
- `internal/api/` — REST API layer with Chi router and middleware
- `internal/services/` — Business logic layer (~39 service packages)
- `internal/repository/postgres/` — PostgreSQL repositories with migrations
- `internal/web/` — Web UI layer (server-side rendered with Templ)
- `web/static/` — Static assets (CSS, JS, fonts)
- `tests/` — Tests (unit, integration, e2e, benchmarks, load)

## Technology Stack

### Backend

- **Language:** Go 1.25.7
- **HTTP Router:** go-chi/chi/v5
- **Database:** PostgreSQL via pgx/v5 + sqlx
- **Cache:** Redis (go-redis/v9)
- **Messaging:** NATS with JetStream
- **Docker:** Docker SDK v28.5.1
- **Auth:** JWT (golang-jwt/jwt/v5), OIDC, LDAP
- **Logging:** uber-go/zap with structured logging
- **Config:** spf13/viper + spf13/cobra
- **Validation:** go-playground/validator/v10

### Frontend

- **Templates:** Templ v0.3.977 (type-safe Go HTML templates)
- **CSS:** Tailwind CSS v3.4.17 (standalone CLI, no Node.js)
- **Reactivity:** Alpine.js 3.14.8
- **Interactivity:** HTMX 2.0.4
- **Charts:** Chart.js
- **Terminal:** xterm.js (WebSocket-based)
- **Code Editor:** Monaco Editor
- **RDP:** Apache Guacamole
- **Fonts:** IBM Plex Sans/Mono, Space Grotesk (self-hosted)

## Code Conventions

### File Naming

- `handler_<feature>.go` — Web page handlers
- `adapter_<feature>.go` — Type adapters (service → web layer)
- `routes_<area>.go` — Route registration
- `*_templ.go` — Auto-generated from `.templ` files (DO NOT EDIT)
- `*_test.go` — Test files

### Required Copyright Header

Every Go file must include this header:

```go
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet
```

### Import Organization

Group imports in this order:
1. Standard library
2. Third-party packages
3. Local packages (`github.com/fr4nsys/usulnet/...`)

Local imports use the module path prefix configured in `.golangci.yml` via goimports.

### Error Handling

- Always wrap errors with context: `fmt.Errorf("descriptive context: %w", err)`
- Services return errors; handlers log and respond with structured JSON
- Non-fatal failures are logged but don't block startup

### Logging

- Use **zap** via wrapper at `internal/pkg/logger`
- Structured key-value pairs: `log.Info("message", "key", value, "key2", value2)`
- Levels: debug, info, warn, error, fatal
- JSON in production, console in development

### Service Architecture

- **Constructor injection:** `NewService(repo, deps..., config, logger)`
- All services accept a `*logger.Logger`
- Lifecycle methods: `Start(ctx)` / `Stop()` where applicable
- **Nil-safe design:** handlers check if services are nil
- **Repository pattern:** each domain has a repository in `internal/repository/postgres/`

### RBAC

Three role tiers enforced via Chi middleware:
- `admin` — Full access (`RequireAdmin` middleware)
- `operator` — Operational access (`RequireOperator` middleware)
- `viewer` — Read-only (`RequireViewer` middleware)

## Build & Development

### Quick Commands

```bash
# Build
make build           # Full build: templ + CSS + go build
make build-agent     # Build agent binary only
make frontend        # Generate templates + compile CSS

# Run
make run             # go run ./cmd/usulnet
make dev-up          # Start dev services (PostgreSQL, Redis, NATS, MinIO)
make dev-down        # Stop dev services

# Test
make test            # go test -v -race -cover ./...
make test-coverage   # Coverage with HTML report
make test-e2e        # E2E tests (requires services, build tag: e2e)

# Quality
make lint            # golangci-lint run ./...
make lint-fix        # Auto-fix linting issues
make fmt             # gofmt -s -w .
make vet             # go vet ./...
make quality         # Full quality gate (lint + vet + coverage check)

# Database
make migrate         # Run migrations up
make migrate-down    # Roll back migrations
make migrate-status  # Show migration status

# Hooks
make install-hooks   # Install pre-commit hook
```

### Development Workflow

1. Start infrastructure: `make dev-up`
2. Run server: `make run`
3. Edit `.templ` files → `make templ` (or `make templ-watch`)
4. Edit CSS → `make css` (or `make css-watch`)
5. Run tests: `make test`
6. Run linter: `make lint`
7. Full check: `make quality`
8. Build: `make build`

### Adding New Features

When adding a feature, follow this pattern:
1. Add models in `internal/models/`
2. Add repository in `internal/repository/postgres/` with migration
3. Add service in `internal/services/<feature>/`
4. Add API handlers in `internal/api/handlers/`
5. Add web handlers in `internal/web/handler_<feature>.go`
6. Register routes in `internal/web/routes_*.go` or `internal/api/router.go`
7. Wire service in `internal/app/app.go`

## Database

### PostgreSQL

- Driver: `pgx/v5` + `sqlx`
- 36 numbered migrations in `internal/repository/postgres/migrations/`
- Naming: `NNN_description.{up,down}.sql`
- Run: `make migrate` or `go run ./cmd/usulnet migrate up`
- Status: `make migrate-status`

### Redis

- Session storage and JWT blacklisting
- Client at `internal/repository/redis/`

## Configuration

- Loaded via **Viper** with `mapstructure` tags
- Override with env vars: `USULNET_<KEY>_<NESTED_KEY>`
- Main config: `config.yaml`
- Agent config: `config.agent.yaml`

Key sections: `server`, `database`, `redis`, `nats`, `security`, `storage`, `trivy`, `docker`, `logging`, `metrics`, `observability`

## Testing

| Type | Command | Coverage |
|------|---------|----------|
| Unit/Integration | `make test` | 40% minimum |
| Coverage report | `make test-coverage` | Outputs `coverage.html` |
| Benchmarks | `make test-benchmark` | Router, JWT validation |
| E2E | `make test-e2e` | Requires services |
| Load | `tests/load/` | k6 script |

Test environment uses `docker-compose.test.yml` with offset ports.

## Linting

Uses **golangci-lint** with 15 linters (see `.golangci.yml`):

gosec, staticcheck, govet, errcheck, ineffassign, unused, gocritic, revive, gofmt, goimports, prealloc, nilerr, errorlint, misspell, unconvert, whitespace

**Exclusions:**
- `*_templ.go` files fully excluded
- Test files excluded from gosec, errcheck, gocritic, prealloc
- `G101` (hardcoded credentials) excluded from gosec
- `fieldalignment` and `shadow` disabled in govet

## Pre-commit Hook

Install: `make install-hooks`

Runs:
1. `gofmt` check (excludes `_templ.go`)
2. `go vet ./...`
3. `go test -short -count=1 ./...`
4. `golangci-lint run --fast ./...` (if installed)

## Docker

### Development

```bash
make dev-up    # Start PostgreSQL, Redis, NATS, MinIO
make run       # Run server locally
make dev-down  # Stop services
```

### Production Build

3-stage multi-stage Dockerfile:
1. golang:1.25.7-alpine — Templ CLI, generate templates, build binary
2. alpine:3.21 — Download Tailwind CLI, compile CSS
3. alpine:3.21 — Runtime (docker-cli, trivy, neovim, ripgrep, non-root user)

Ports: **8080** (HTTP), **7443** (HTTPS with self-signed TLS)

## Best Practices

### Code Quality

- **Fix bugs when found** — Don't defer unless it requires multi-day work
- **Choose correct fix over quick fix** — Avoid technical debt
- **Never assume, always verify** — Read code, check behavior
- **Document with file:line references** — Context for future sessions
- **Use existing libraries** — Only add new deps if absolutely necessary

### Testing

- Write tests that match existing patterns
- Use table-driven tests for multiple scenarios
- Mock external dependencies (Docker, NATS, etc.)
- Test error paths, not just happy paths
- E2E tests require build tag: `e2e`

### Comments

- Don't add comments unless they match file style or explain complex logic
- Code should be self-documenting where possible
- Use structured logging for runtime information

### Tools

- Prefer Makefile targets over direct tool calls
- Use ecosystem tools (npm init, pip install) to automate
- Use refactoring tools for automated changes
- Run linters to fix style issues

## Security

- No hardcoded secrets in source code
- Use AES-256-GCM for encryption (`internal/pkg/crypto`)
- Password hashing via bcrypt
- JWT with blacklisting support
- TOTP 2FA support (`internal/pkg/totp`)
- Input validation via `go-playground/validator`

## Key Dependencies

| Category | Package |
|----------|---------|
| HTTP | go-chi/chi/v5 |
| Templates | a-h/templ |
| Database | jackc/pgx/v5, jmoiron/sqlx |
| Redis | redis/go-redis/v9 |
| Messaging | nats-io/nats.go |
| Docker | docker/docker v28.5.1 |
| Auth | golang-jwt/jwt/v5, coreos/go-oidc/v3, go-ldap/ldap/v3 |
| Logging | uber-go/zap |
| Config | spf13/viper, spf13/cobra |
| Observability | OpenTelemetry |

## Additional Resources

- Full guide: `CLAUDE.md` (comprehensive AI assistant instructions)
- Architecture: `docs/architecture.md`
- Development: `docs/development.md`
- API docs: `docs/api.md`
- Agent docs: `AGENT_DEVELOPMENT.md`
