# Development & Contribution Guide

> **usulnet** - Docker Management Platform
> Guide for setting up the development environment and contributing to the project.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Development Environment Setup](#development-environment-setup)
3. [Project Structure](#project-structure)
4. [Makefile Reference](#makefile-reference)
5. [Development Workflow](#development-workflow)
6. [Code Style Guide](#code-style-guide)
7. [Commit Conventions](#commit-conventions)
8. [Testing](#testing)
9. [Pull Request Process](#pull-request-process)
10. [Common Development Tasks](#common-development-tasks)
11. [Profiling](#profiling)

---

## Prerequisites

### Required Tools

| Tool | Version | Installation |
|------|---------|-------------|
| **Go** | 1.25+ | [go.dev/dl](https://go.dev/dl/) |
| **Docker** | 24.0+ | [docs.docker.com](https://docs.docker.com/get-docker/) |
| **Docker Compose** | v2.20+ | Included with Docker Desktop or `docker-compose-plugin` |
| **templ** | 0.3.977+ | `go install github.com/a-h/templ/cmd/templ@latest` |
| **Git** | 2.40+ | System package manager |

### Optional Tools

| Tool | Purpose | Installation |
|------|---------|-------------|
| **golangci-lint** | Code linting | `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest` |
| **k6** | Load testing | [k6.io/docs/get-started](https://k6.io/docs/get-started/installation/) |
| **psql** | Database debugging | `apt install postgresql-client` |
| **redis-cli** | Cache debugging | `apt install redis-tools` |

> **Note:** Tailwind CSS standalone CLI is downloaded automatically by `make css`. No Node.js or npm is required.

---

## Development Environment Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/fr4nsys/usulnet.git
cd usulnet
```

### Step 2: Start Infrastructure Services

The development compose file starts PostgreSQL, Redis, and NATS with ports exposed for debugging:

```bash
make dev-up
```

This runs `docker-compose.dev.yml` which starts:

| Service | Host Port | Purpose |
|---------|-----------|---------|
| PostgreSQL | 5432 | Database |
| Redis | 6379 | Cache/sessions |
| NATS | 4222 (client), 8222 (monitoring) | Messaging |

### Step 3: Install Go Dependencies

```bash
make deps
```

### Step 4: Generate Templates and CSS

```bash
make frontend
```

This runs `templ generate` to compile `.templ` files to Go code, and downloads + runs the Tailwind CSS standalone CLI to compile `web/static/src/input.css` to `web/static/css/style.css`.

### Step 5: Run Database Migrations

```bash
make migrate
```

### Step 6: Run the Application

```bash
make run
```

The application starts on `http://localhost:8080`. Default credentials: `admin` / `usulnet`.

### Development with Hot Reload

For active development, run template and CSS watchers in separate terminals:

```bash
# Terminal 1: Watch templates
make templ-watch

# Terminal 2: Watch CSS
make css-watch

# Terminal 3: Run the app (restart manually on Go changes)
make run
```

### Development with Agent

To also start an agent for multi-host development:

```bash
make dev-up-agent
```

### Stopping the Environment

```bash
make dev-down
```

---

## Project Structure

```
usulnet/
+-- cmd/                      # Application entry points
|   +-- usulnet/              # Main server (cobra CLI: serve, migrate)
|   +-- usulnet-agent/        # Remote agent binary
+-- internal/                 # Private application code
|   +-- api/                  # REST API (handlers, middleware, DTOs, router)
|   +-- web/                  # Web UI (page handlers, adapters, templates)
|   +-- app/                  # Bootstrap, config, scheduler setup
|   +-- services/             # Business logic (37 packages)
|   +-- repository/           # Data access (PostgreSQL repos, Redis, migrations)
|   +-- models/               # Domain models and types
|   +-- docker/               # Docker Engine client wrapper
|   +-- gateway/              # NATS gateway (master side)
|   +-- agent/                # Agent implementation
|   +-- nats/                 # NATS client wrapper
|   +-- scheduler/            # Cron job scheduler
|   +-- license/              # License validation
|   +-- integrations/         # External integrations (Git providers)
|   +-- observability/        # Logging, tracing
|   +-- pkg/                  # Shared utilities (crypto, errors, logger, totp, validator)
+-- web/static/               # Frontend assets (CSS, JS)
+-- deploy/                   # Production deployment files
+-- tests/                    # Test suites (e2e, benchmarks, load)
+-- scripts/                  # Build scripts
+-- docs/                     # Documentation
+-- .github/workflows/        # CI/CD pipelines
```

### Key Patterns

- **Handlers** (`internal/web/handler_*.go`): Each handler serves one or more related web pages. They use adapters to fetch data from services.
- **Adapters** (`internal/web/adapter_*.go`): Bridge between web handlers and services. Translate between web-layer DTOs and service-layer models.
- **Services** (`internal/services/*/`): Contain business logic. Created via constructor injection (`NewService(deps)`). Depend on interfaces for testability.
- **Repositories** (`internal/repository/postgres/`): Data access objects using `pgx/v5`. Each repository implements a specific interface.
- **Templates** (`internal/web/templates/`): Templ files (`.templ`) that compile to type-safe Go functions.

---

## Makefile Reference

| Target | Description |
|--------|-------------|
| `make all` | Full build: templ + css + lint + test + build |
| `make build` | Build the main binary (includes frontend generation) |
| `make build-agent` | Build the agent binary |
| `make build-all` | Build both binaries |
| `make run` | Run the application with `go run` |
| `make templ` | Generate Go code from `.templ` files |
| `make templ-watch` | Watch mode for template generation |
| `make css` | Compile Tailwind CSS |
| `make css-watch` | Watch mode for CSS compilation |
| `make frontend` | Run both `templ` and `css` |
| `make test` | Run all tests with race detector and coverage |
| `make test-coverage` | Generate HTML coverage report (`coverage.html`) |
| `make test-check-coverage` | Check coverage against 40% threshold |
| `make test-benchmark` | Run performance benchmarks |
| `make test-e2e` | Run end-to-end tests |
| `make lint` | Run golangci-lint |
| `make lint-fix` | Run linter with auto-fix |
| `make fmt` | Format code with `gofmt` |
| `make vet` | Run `go vet` |
| `make quality` | Run all quality checks (lint + vet + coverage) |
| `make migrate` | Apply pending database migrations |
| `make migrate-down` | Rollback database migrations |
| `make migrate-status` | Show migration status |
| `make dev-up` | Start development infrastructure (PostgreSQL, Redis, NATS) |
| `make dev-down` | Stop development infrastructure |
| `make dev-logs` | View development service logs |
| `make dev-up-agent` | Start development with agent profile |
| `make docker-build` | Build main Docker image |
| `make docker-build-agent` | Build agent Docker image |
| `make deps` | Download and tidy Go modules |
| `make generate` | Run `go generate` |
| `make clean` | Remove build artifacts |
| `make install-hooks` | Install git pre-commit hook |

---

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feat/my-feature
```

### 2. Implement Changes

- Write code following the [Code Style Guide](#code-style-guide)
- Add or update tests for your changes
- Run `make templ` if you modified `.templ` files
- Run `make css` if you added new Tailwind classes

### 3. Validate Locally

```bash
# Run tests
make test

# Run linter
make lint

# Full quality gate
make quality
```

### 4. Commit Changes

Follow [Commit Conventions](#commit-conventions):

```bash
git add -A
git commit -m "feat(containers): add bulk restart operation"
```

### 5. Push and Create PR

```bash
git push -u origin feat/my-feature
```

Create a pull request on GitHub following the [PR Process](#pull-request-process).

---

## Code Style Guide

### General Principles

- Follow standard Go idioms (`gofmt`, `govet`)
- Exported identifiers must have documentation comments (godoc format)
- Keep functions short and focused (< 50 lines preferred)
- Return early on errors (guard clauses)
- Use context propagation (`ctx context.Context` as first parameter)

### Error Handling

```go
// Use the internal errors package
import "github.com/fr4nsys/usulnet/internal/pkg/errors"

// Wrap errors with context
if err != nil {
    return errors.Wrap(err, "failed to list containers")
}

// Return domain errors for expected failures
return errors.NotFound("container %s not found", containerID)
```

### Logging

```go
// Use structured logging with context
logger := logger.FromContext(ctx)
logger.Info("Container started",
    "container_id", containerID,
    "host_id", hostID,
)

// Never log sensitive data
// BAD: logger.Info("User login", "password", password)
// GOOD: logger.Info("User login", "username", username)
```

### Service Pattern

```go
// Constructor injection
type Service struct {
    containerRepo repository.ContainerRepository
    dockerClient  docker.Client
    logger        *logger.Logger
}

func NewService(repo repository.ContainerRepository, client docker.Client, log *logger.Logger) *Service {
    return &Service{
        containerRepo: repo,
        dockerClient:  client,
        logger:        log,
    }
}

// Interface-based dependencies for testability
type ContainerRepository interface {
    List(ctx context.Context, filters ListFilters) ([]models.Container, error)
    Get(ctx context.Context, id string) (*models.Container, error)
    // ...
}
```

### Repository Pattern

```go
// Use parameterized queries (NEVER string concatenation)
func (r *containerRepo) List(ctx context.Context, hostID string) ([]models.Container, error) {
    query := `SELECT id, name, status FROM containers WHERE host_id = $1 ORDER BY created_at DESC`
    rows, err := r.pool.Query(ctx, query, hostID)
    // ...
}
```

### Template Pattern

```go
// Templ templates in internal/web/templates/pages/
// Use typed props, not interface{}
templ ContainerList(containers []ContainerView, pagination PaginationView) {
    @layouts.Base("Containers") {
        <div class="p-6">
            for _, c := range containers {
                @ContainerCard(c)
            }
        </div>
    }
}
```

### Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Package | lowercase, short | `container`, `auth`, `backup` |
| Interface | noun or -er suffix | `ContainerRepository`, `Authenticator` |
| Struct | PascalCase | `ContainerService`, `BackupHandler` |
| Method | PascalCase (exported), camelCase (unexported) | `ListContainers`, `parseFilters` |
| Constant | PascalCase or ALL_CAPS | `MaxRetries`, `DefaultTimeout` |
| File | snake_case | `container_handler.go`, `auth_service.go` |

---

## Commit Conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Code style (formatting, missing semicolons, etc.) |
| `refactor` | Code refactoring (no feature or bug fix) |
| `perf` | Performance improvement |
| `test` | Adding or updating tests |
| `build` | Build system or external dependencies |
| `ci` | CI/CD configuration |
| `chore` | Maintenance tasks |

### Scopes (Optional)

| Scope | Area |
|-------|------|
| `api` | REST API handlers/middleware |
| `web` | Web UI handlers/templates |
| `containers` | Container management |
| `images` | Image management |
| `stacks` | Stack management |
| `hosts` | Host management |
| `agent` | Agent system |
| `security` | Security scanning |
| `backup` | Backup/restore |
| `proxy` | Reverse proxy |
| `auth` | Authentication/authorization |
| `db` | Database/migrations |
| `config` | Configuration |
| `ci` | CI/CD |
| `docs` | Documentation |

### Examples

```bash
feat(containers): add bulk restart operation
fix(auth): prevent timing attack on login
docs(api): add curl examples for container endpoints
refactor(security): extract scanner interface
test(backup): add integration tests for S3 storage
ci: add coverage threshold check to pipeline
chore: update Go to 1.25.7
```

---

## Testing

### Running Tests

```bash
# All tests with race detector
make test

# Generate coverage report
make test-coverage
# Open coverage.html in browser

# Check coverage threshold (40% minimum)
make test-check-coverage

# Run benchmarks
make test-benchmark

# Run E2E tests (requires infrastructure)
make test-e2e
```

### Test Structure

Tests follow Go conventions:

```
internal/
  services/
    container/
      service.go
      service_test.go      # Unit tests
  api/
    handlers/
      containers.go
      containers_test.go   # Integration tests with httptest
      testutil_test.go     # Test helpers and fixtures
```

### Writing Tests

```go
func TestContainerService_List(t *testing.T) {
    // Arrange
    repo := &mockContainerRepo{
        containers: []models.Container{{ID: "abc123", Name: "test"}},
    }
    svc := container.NewService(repo, nil, logger.Nop())

    // Act
    result, err := svc.List(context.Background(), container.ListFilters{})

    // Assert
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(result) != 1 {
        t.Errorf("expected 1 container, got %d", len(result))
    }
}
```

### Test Infrastructure

For integration tests, use `docker-compose.test.yml`:

```bash
# Start test infrastructure (isolated ports)
docker compose -f docker-compose.test.yml up -d

# Run E2E tests
make test-e2e

# Stop test infrastructure
docker compose -f docker-compose.test.yml down -v
```

Test infrastructure uses isolated ports:
- PostgreSQL: 15432
- Redis: 16379
- NATS: 14222

---

## Pull Request Process

### Before Creating a PR

1. Ensure all tests pass: `make test`
2. Ensure linter passes: `make lint`
3. Run the full quality gate: `make quality`
4. Verify templates compile: `make templ`
5. Verify CSS compiles: `make css`

### PR Template

```markdown
## Summary
Brief description of the changes.

## Changes
- Added X
- Fixed Y
- Updated Z

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Screenshots
(if UI changes)
```

### Review Process

1. Create a PR from your feature branch to `main`
2. CI pipeline runs automatically (lint, test, build, security scan)
3. At least one reviewer must approve
4. All CI checks must pass
5. Squash merge or regular merge (maintainer's choice)

---

## Common Development Tasks

### Adding a New API Endpoint

1. Create/update the handler in `internal/api/handlers/`
2. Define request/response DTOs in `internal/api/dto/`
3. Register routes in the handler's `Routes()` method
4. Mount the handler in `internal/api/router.go`
5. Add tests in `*_test.go`

### Adding a New Web Page

1. Create the handler method in the appropriate `internal/web/handler_*.go`
2. Create the Templ template in `internal/web/templates/pages/`
3. Create an adapter in `internal/web/adapter_*.go` if needed
4. Register the route in `internal/web/routes_frontend.go`
5. Run `make templ` to compile

### Adding a Database Migration

1. Create new migration files:
   ```
   internal/repository/postgres/migrations/
     031_my_feature.up.sql
     031_my_feature.down.sql
   ```
2. Write the UP migration (create tables, add columns, etc.)
3. Write the DOWN migration (reverse the UP changes)
4. Apply: `make migrate`
5. Verify rollback works: `make migrate-down` then `make migrate`

### Adding a New Service

1. Create the package: `internal/services/myservice/`
2. Define the service struct with constructor injection
3. Define the interface for testability
4. Wire the service in `internal/app/app.go`
5. Add tests

### Debugging

```bash
# View application logs
make run 2>&1 | jq .  # If JSON logging

# Connect to database
docker exec -it usulnet-postgres psql -U usulnet

# Connect to Redis
docker exec -it usulnet-redis redis-cli

# Check NATS monitoring
curl http://localhost:8222/varz

# Check Docker socket
curl --unix-socket /var/run/docker.sock http://localhost/version
```

---

## Profiling

The Go runtime ships with first-class CPU and heap profilers; this
section is the repeatable procedure for using them against usulnet.

The goal is not to chase micro-optimizations — it's to find the
*real* hot paths and prove any change pays for itself with a
benchmark before/after. Two rules govern this loop:

1. **Numbers come from the same machine on the same load.** Capture
   the baseline (`git stash`), pop the patch, capture the after run.
   Never compare a stash-pop after to a number you wrote down hours
   earlier — machine load drift is huge and will fool you.
2. **<5% improvement is noise — drop the change.** Use
   `-benchtime=5s -count=8` so per-bench variance is small enough
   for a 5% delta to actually mean something. If the delta is
   smaller than that, your change is decoration, not optimization.

### Tools

| Tool | Install | Purpose |
|---|---|---|
| `go test -bench` | bundled with Go | Repeatable micro-benchmarks (the source of truth for "is this faster?"). |
| `go tool pprof` | bundled with Go | Analyze CPU and heap profiles. |
| `hey` | `go install github.com/rakyll/hey@latest` | Hammer a running server when you want a profile that reflects real HTTP traffic. |
| `k6` | https://k6.io | Optional — `tests/load/k6_api_test.js` is shipped; use it for scripted scenarios that hit auth + multiple endpoints. |

### Baseline benchmarks (per-PR before/after)

`tests/benchmarks/benchmark_test.go` covers the API hot paths
(router, JWT, JSON, health, paginated responses). The repeatable
A/B loop:

```bash
# 1. Baseline (current code).
git stash
go test -bench=. -benchmem -benchtime=5s -count=8 \
    ./tests/benchmarks/ | tee /tmp/profile/bench-before.txt

# 2. Apply the change.
git stash pop

# 3. After.
go test -bench=. -benchmem -benchtime=5s -count=8 \
    ./tests/benchmarks/ | tee /tmp/profile/bench-after.txt

# 4. Compare (benchstat is the canonical diff tool).
go install golang.org/x/perf/cmd/benchstat@latest
benchstat /tmp/profile/bench-before.txt /tmp/profile/bench-after.txt
```

Paste the `benchstat` output into the PR body. The Liveness fast-path
in #46 is the worked example — `ns/op -9.0%`, `B/op -5.6%`,
`allocs/op -14.3%`, all comfortably above the 5% noise floor.

### CPU and heap profiles from the benchmarks

When the question is *which line* dominates, capture profiles from
the benchmark binary itself — they're reproducible across machines
and don't need any server up:

```bash
mkdir -p /tmp/profile
go test -bench=. -benchmem -benchtime=5s -count=1 \
    -cpuprofile=/tmp/profile/cpu.prof \
    -memprofile=/tmp/profile/mem.prof \
    ./tests/benchmarks/

# Top-N flat (where time is *spent*, not just attributed):
go tool pprof -top -flat -nodecount=20 \
    ./tests/benchmarks/benchmarks.test /tmp/profile/cpu.prof

# Top-N cumulative (which call tree owns the cost):
go tool pprof -top -cum -nodecount=15 \
    ./tests/benchmarks/benchmarks.test /tmp/profile/cpu.prof

# Drill into a specific function (use the symbol shown by -top):
go tool pprof -list 'SystemHandler.*Health' \
    ./tests/benchmarks/benchmarks.test /tmp/profile/cpu.prof

# Heap (objects allocated, not just bytes — alloc count usually
# dominates GC pressure):
go tool pprof -top -alloc_objects -nodecount=15 \
    ./tests/benchmarks/benchmarks.test /tmp/profile/mem.prof
```

### Profiles from a running server (real traffic shape)

The benchmarks miss anything outside the API hot path (DB queries,
templated HTML, websocket terminal, background workers). For those,
profile against a running `usulnet serve` while a load generator
hammers it:

```bash
# Terminal 1 — run the server.
make dev-up
USULNET_RECON_ENABLED=true make run

# Terminal 2 — sustained load. Pick whichever shape matches what
# you're investigating. JWT auth path:
TOKEN=$(curl -sS -X POST http://127.0.0.1:8080/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"usulnet"}' | jq -r .access_token)
hey -z 60s -c 50 \
    -H "Authorization: Bearer $TOKEN" \
    http://127.0.0.1:8080/api/v1/containers

# Terminal 3 — capture CPU + heap concurrently.
go tool pprof -seconds=30 \
    http://127.0.0.1:8080/debug/pprof/profile > /tmp/profile/cpu-live.prof
go tool pprof http://127.0.0.1:8080/debug/pprof/heap > /tmp/profile/heap-live.prof
```

> **Note (v26.5.0)**: the `/debug/pprof` endpoints are not wired into
> the API router yet; profiling a running server today still goes
> through the benchmark binary, or requires a debug build that
> imports `net/http/pprof`. Adding a config-gated `/debug/pprof`
> mount on a separate listener is a small, isolated follow-up that
> belongs in its own PR.

### Baseline snapshot — May 2026

Reference numbers from `tests/benchmarks/` on an Intel Xeon @ 2.10 GHz,
4 cores, Go 1.25.7, `-benchtime=5s -count=1`. Use them to spot
regressions, not as a fixed target — machine drift makes absolute
numbers noisy across hardware.

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `LivenessEndpoint` (post-#46) | 4 638 | 7 053 | 30 |
| `HealthEndpoint` (2 checkers) | 7 464 | 8 273 | 50 |
| `HealthWithMultipleCheckers` (4 checkers) | 9 696 | 9 158 | 68 |
| `AuthenticatedRequest` | 123 168 | 13 187 | 117 |
| `JWTTokenGeneration` | 4 186 | 2 905 | 34 |
| `JWTTokenValidation` | 6 794 | 3 264 | 53 |
| `JSONSerialization` | 1 294 | 512 | 7 |
| `JSONDeserialization` | 1 201 | 1 008 | 10 |
| `PaginatedResponse` (100 items, `[]map[string]any`) | 62 421 | 27 859 | 703 |

**Top cumulative CPU contributors** (from the May-2026 baseline run):

1. `runtime.mallocgc` — ~27 % cum. Allocation-heavy: any reduction
   in per-request allocs feeds back here.
2. `encoding/json` (`mapEncoder.encode`, `structEncoder.encode`,
   `appendString`) — ~19 % cum. Map-shaped payloads are the
   expensive case (key sort, reflection, per-element encoder
   lookup); typed structs are several times cheaper. The
   `PaginatedResponse` benchmark's 703 allocs/op is the smoking
   gun — it's encoding `[]map[string]any`.
3. `chi/v5.(*Mux).ServeHTTP` — ~19 % cum. Routing trie walk plus
   middleware orchestration. Hard to move without forking chi;
   middleware ordering is the lever we control.
4. JWT validation (`jwt.ParseWithClaims` + HMAC SHA-256) — ~1 % cum
   flat, but the dominant per-call cost on
   `AuthenticatedRequest`. CPU-bound HMAC; the practical lever is
   caching validated tokens for short windows when the token store
   already supports it.

### Known wins shipped so far

- **#46 — Liveness fast-path.** Pre-encoded response body.
  -9.0 % ns/op, -14.3 % allocs/op.

### Catalogued non-wins (and why)

These were tried and rejected because they didn't clear the 5%
threshold or because the win was masked by an unrelated bottleneck.
Recorded here so future profiling rounds don't redo the work:

- **Health-handler single-checker fast-path.** A synchronous code
  path for the `n == 1` case avoids a goroutine spawn, the
  `WaitGroup`, the per-component mutex and a `context.WithTimeout`
  child. Real win — but the existing `BenchmarkHealthEndpoint`
  setup uses 2 mock checkers and `BenchmarkHealthWithMultipleCheckers`
  uses 4, so the optimised branch is never executed. The win would
  only show up against a new single-checker benchmark; not in this
  series.
- **Hoisting the per-request `secrets` slice in
  `middleware.Auth`.** ~40 B and one `append` per authenticated
  request. Total impact on `BenchmarkAuthenticatedRequest`
  (~13 kB/req) is well below 1 % — drowned in JWT verification
  cost. Skipped.

### Profiling fix workflow

1. Pick **one** hot path. Don't stack optimisations.
2. Capture before with `-count=8` so per-run jitter washes out.
3. Make the change.
4. Capture after the same way. Run `benchstat`.
5. **≥ 5 % on at least one of `ns/op`, `B/op`, `allocs/op`?** Ship
   it (one PR per fix), paste the `benchstat` table in the PR body.
6. **< 5 %?** Drop the change. Add a brief entry to the
   "Catalogued non-wins" list above so the next profiler doesn't
   chase the same dead end.

---

*For more information, see the [Architecture Guide](architecture.md) and [API Documentation](api.md).*
