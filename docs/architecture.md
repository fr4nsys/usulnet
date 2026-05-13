# Architecture Documentation

> **usulnet** - Docker Management Platform
> System architecture, design decisions, and component overview.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [High-Level Architecture](#high-level-architecture)
3. [Component Diagram](#component-diagram)
4. [Application Layers](#application-layers)
5. [Request Flow](#request-flow)
6. [Master-Agent Architecture](#master-agent-architecture)
7. [Data Model](#data-model)
8. [Technology Stack](#technology-stack)
9. [Architecture Decision Records](#architecture-decision-records)
10. [Directory Structure](#directory-structure)

---

## System Overview

usulnet is a self-hosted Docker management platform written in Go. It provides a web-based interface for managing Docker containers, images, volumes, networks, stacks, and multi-host environments. The platform supports security scanning, backup/restore, reverse proxy management, monitoring, and enterprise features like LDAP/OAuth authentication and RBAC.

### Key Characteristics

- **Server-Side Rendered (SSR):** No SPA framework. HTML is generated server-side using Go's `templ` library
- **Multi-Host:** Master-agent architecture via NATS JetStream for managing remote Docker hosts
- **Enterprise-Ready:** RBAC, LDAP, OAuth2/OIDC, 2FA, audit logging, security scanning
- **Single Binary:** The entire application compiles to a single statically-linked Go binary
- **Pluggable Proxy:** Supports both Caddy and Nginx Proxy Manager as reverse proxy backends

---

## High-Level Architecture

```
                         +-----------------+
                         |    Browser      |
                         | HTMX + Alpine.js|
                         +--------+--------+
                                  |
                           HTTP / WebSocket
                                  |
+---------------------------------------------------------------------------------------------+
|                              GO APPLICATION                                                  |
|                                                                                              |
|  +------------------------+            +-------------------------------+                     |
|  |    Web Layer (SSR)     |            |    REST API Layer (/api/v1/)  |                     |
|  |  routes_frontend.go    |            |    api/router.go              |                     |
|  |  handler_*.go (60+)    |            |    api/handlers/*.go (31)     |                     |
|  |  adapter_*.go (16)     |            |    api/middleware/*.go         |                     |
|  |  templates/ (templ)    |            |    api/dto/ (request/response)|                     |
|  +-----------+------------+            +---------------+---------------+                     |
|              |                                         |                                     |
|  +-----------v-----------------------------------------v---------------+                     |
|  |                    Service Layer (internal/services/)                |                     |
|  |   37 packages: auth, container, image, volume, network, stack,      |                     |
|  |   host, security, backup, proxy, storage, ssh, rdp, user, team,     |                     |
|  |   notification, metrics, compliance, config, update, deploy,        |                     |
|  |   capture, ldapbrowser, database, shortcuts, swarm, ephemeral,      |                     |
|  |   opa, logagg, imagesign, runtime, manifest, gitsync, monitoring    |                     |
|  +-----------+---------------------------------------------------------+                     |
|              |                                                                               |
|  +-----------v-----------------------------------------+                                     |
|  |           Repository Layer (internal/repository/)    |                                     |
|  |   postgres/ (55 repos, pgx/v5, pgxpool)             |                                     |
|  |   redis/ (sessions, cache, locks, JWT blacklist)     |                                     |
|  +-----------+------------------+-----------------------+                                     |
+---------------------------------------------------------------------------------------------+
               |                  |
     +---------v----+    +--------v------+    +----------+    +---------+
     |  PostgreSQL  |    |    Redis      |    |   NATS   |    | Docker  |
     |  16-alpine   |    |  8-alpine     |    | JetStream|    | Engine  |
     +--------------+    +---------------+    +-----+----+    +---------+
                                                    |
                                           +--------v--------+
                                           |  Remote Agents   |
                                           | (usulnet-agent)  |
                                           +-----------------+
```

---

## Component Diagram

### External Dependencies

| Component | Purpose | Connection |
|-----------|---------|------------|
| **PostgreSQL 16** | Primary database (users, config, audit, backups, etc.) | TCP :5432 |
| **Redis 8** | Sessions, cache, JWT blacklist, distributed locks, pub/sub | TCP :6379 |
| **NATS 2.12** | Agent communication via JetStream (durable messaging) | TCP :4222 |
| **Docker Engine** | Container runtime management via Docker SDK | Unix socket |
| **Apache Guacamole (guacd)** | RDP/VNC web gateway | TCP :4822 |
| **Trivy** | Vulnerability scanning for containers and images | CLI binary |

### Internal Components

| Component | Location | Description |
|-----------|----------|-------------|
| **HTTP Router** | `internal/api/router.go` | Chi v5 router with middleware chain |
| **Web Handlers** | `internal/web/handler_*.go` | 60+ SSR page handlers |
| **API Handlers** | `internal/api/handlers/` | 31 REST API handler files |
| **Service Adapters** | `internal/web/adapter_*.go` | 16 adapters bridging web handlers to services |
| **Services** | `internal/services/` | 37 business logic packages |
| **Repositories** | `internal/repository/postgres/` | 55 PostgreSQL data access objects |
| **Templates** | `internal/web/templates/` | 124+ Templ SSR templates |
| **Middleware** | `internal/api/middleware/` | Auth, RBAC, CORS, rate limiting, license |
| **Gateway** | `internal/gateway/` | Master-side NATS gateway for agent communication |
| **Agent** | `internal/agent/` | Agent-side executor and NATS client |
| **Scheduler** | `internal/scheduler/` | Cron-based job scheduling (backups, cleanup, inventory) |
| **License** | `internal/license/` | JWT-based license validation and feature gating |

---

## Application Layers

The application follows a layered architecture with clear separation of concerns:

### Layer 1: Presentation (Web + API)

**Web Layer** — Server-side rendered HTML pages using Templ templates. Handlers in `internal/web/handler_*.go` fetch data through service adapters and render Templ templates. Client-side interactivity is provided by HTMX (partial page updates, polling), Alpine.js (UI state, modals), and WebSocket (terminals, log streaming).

**API Layer** — RESTful JSON API under `/api/v1`. Handlers in `internal/api/handlers/` implement CRUD operations. The Chi v5 router provides middleware chains for authentication, authorization, rate limiting, CORS, and license checking.

### Layer 2: Business Logic (Services)

37 service packages in `internal/services/` implement domain logic. Services are created via constructor injection (`NewXxxService(deps)`) and depend on interfaces for testability. Each service encapsulates operations for its domain (e.g., `container.Service` handles container lifecycle, `backup.Service` handles backup scheduling and execution).

### Layer 3: Data Access (Repository)

55 PostgreSQL repositories in `internal/repository/postgres/` implement data persistence using `pgx/v5` (native PostgreSQL protocol) and `sqlx` (named queries). Redis repositories handle sessions, caching, JWT blacklisting, and distributed locks. All database operations use parameterized queries (no string concatenation).

### Layer 4: Infrastructure

External integrations: Docker Engine SDK, NATS client, LDAP client, OAuth2/OIDC providers, S3/Azure Blob storage, Trivy scanner, Guacamole RDP gateway.

---

## Request Flow

### HTTP Request (SSR Page)

```
Browser GET /containers
  -> Chi Router (route matching)
    -> Middleware Chain:
       1. RequestID (assigns unique ID)
       2. RealIP (extracts client IP from proxy headers)
       3. Logging (structured request logging)
       4. Recovery (panic handling)
       5. CORS (cross-origin)
       6. License (injects license context)
       7. Session (loads user session from Redis)
       8. CSRF (validates anti-forgery token)
       9. Theme (injects dark/light theme preference)
       10. Stats (tracks page views)
       11. Auth (validates session, redirects if unauthenticated)
       12. Permission (checks RBAC permission: container:view)
    -> Web Handler (handler_frontend.go)
       -> Service Adapter (adapter_container.go)
         -> Container Service (services/container/)
           -> Docker Client (docker/client.go)
             -> Docker Engine (unix socket)
       -> Templ Template (templates/pages/containers/list.templ)
         -> HTML Response (full page or HTMX partial)
```

### API Request (JSON)

```
Client GET /api/v1/containers
  -> Chi Router
    -> Middleware Chain:
       1. RequestID, RealIP, Logging, Recovery, CORS, License
       2. Timeout (30s default)
       3. Auth (JWT token validation or API key)
       4. APIRateLimit
       5. RequireViewer (minimum role check)
    -> API Handler (handlers/containers.go)
       -> Container Service (services/container/)
         -> Docker Client -> Docker Engine
       -> JSON Response with pagination
```

### WebSocket Connection

```
Client WS /api/v1/ws/containers/{id}/logs
  -> Chi Router (no timeout middleware to preserve http.Hijacker)
    -> WebSocket Handler (handlers/websocket.go)
       -> HTTP Upgrade to WebSocket
       -> Container Service (log streaming)
         -> Docker Client (container logs attach)
       -> Real-time log streaming over WebSocket
```

---

## Master-Agent Architecture

usulnet supports managing multiple Docker hosts through a master-agent model using NATS JetStream for reliable, persistent messaging.

### Operation Modes

| Mode | Description |
|------|-------------|
| `standalone` | Single host. All services run locally. No NATS required for agent communication. |
| `master` | Multi-host control plane. Accepts agent connections via NATS. Orchestrates remote operations. |
| `agent` | Remote host. Connects to master via NATS. Executes Docker commands locally and reports results. |

### Communication Flow

```
+-------------------+          NATS JetStream          +-------------------+
|                   |  <============================>  |                   |
|   Master (usulnet)|         Commands & Results        |  Agent (usulnet-  |
|                   |                                   |   agent)          |
|  +-------------+  |    1. Master publishes command    |  +-------------+  |
|  | Gateway     |------> (e.g., list containers)  --->|  | Agent Core  |  |
|  +-------------+  |                                   |  +------+------+  |
|  | Scheduler   |  |    2. Agent executes locally      |         |         |
|  +-------------+  |                                   |  +------v------+  |
|  | Services    |  |    3. Agent publishes result   <--|  | Executor    |  |
|  +-------------+  |                                   |  +------+------+  |
|  | Repository  |  |    4. Master processes result     |         |         |
|  +-------------+  |                                   |  +------v------+  |
|                   |                                   |  | Docker SDK  |  |
+-------------------+                                   |  +------+------+  |
                                                        |         |         |
                                                        |  +------v------+  |
                                                        |  | Docker      |  |
                                                        |  | Engine      |  |
                                                        |  +-------------+  |
                                                        +-------------------+
```

### Agent Lifecycle

1. **Startup:** Agent connects to NATS, generates or loads agent ID
2. **Registration:** Agent sends registration message with capabilities, hostname, labels
3. **Heartbeat:** Agent sends periodic heartbeats (configurable interval)
4. **Inventory:** Agent periodically collects and reports local container/image inventory
5. **Commands:** Agent subscribes to its command queue, executes Docker operations
6. **Results:** Agent publishes operation results back to master via NATS
7. **Reconnection:** On disconnection, agent auto-reconnects with exponential backoff

### NATS JetStream

JetStream provides durable message persistence, ensuring commands and results are not lost during network interruptions. Key configuration:

- Max payload: 8 MB per message
- Automatic reconnection with backoff
- Subject-based routing (per-agent command queues)
- Acknowledgment patterns for reliable delivery

---

## Data Model

### Core Entities

```
users ──────────┐
  |              |
  | 1:N          | N:M
  v              v
sessions     team_members ──> teams
api_keys         |
                 v
             resource_permissions
```

### Docker Resources

```
hosts ─────────> containers
  |              |
  |              +──> container_stats
  |              +──> container_logs
  |
  +────────────> images (via Docker API, not stored)
  +────────────> volumes (via Docker API, not stored)
  +────────────> networks (via Docker API, not stored)

stacks ────────> stack_logs
```

### Security & Compliance

```
security_scans ──> security_issues
compliance_policies ──> compliance_violations
```

### Backup & Configuration

```
backups ──────> backup_schedules
               backup_storage_configs

config_variables
config_templates
config_syncs ──> config_audit_log
```

### Infrastructure

```
proxy_hosts ──> proxy_certificates
               proxy_dns_providers

ssh_connections ──> ssh_keys
                   ssh_sessions

notification_channels ──> notification_logs
alert_rules ──> alert_events
audit_log
jobs ──> scheduled_jobs
```

### Database Statistics

| Metric | Count |
|--------|-------|
| Migration pairs | 30 |
| Database tables | 110+ |
| PostgreSQL repositories | 55 |

---

## Technology Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Language | Go | 1.25 | Application code |
| HTTP Router | chi/v5 | 5.2.2 | Request routing and middleware |
| Templates | templ (a-h/templ) | 0.3.977 | Server-side HTML rendering |
| CSS | Tailwind CSS | 3.4.17 | Utility-first styling (standalone CLI, no Node.js) |
| Client JS | HTMX + Alpine.js | -- | Partial updates, UI state |
| Database | PostgreSQL | 16-alpine | Primary data store |
| Cache | Redis | 8-alpine | Sessions, cache, JWT blacklist |
| Messaging | NATS (JetStream) | 2.12-alpine | Agent communication |
| Docker API | docker/docker client | 28.5.1 | Container management |
| RDP Gateway | Apache Guacamole (guacd) | 1.5.5 | Remote desktop web access |
| Scanner | Trivy | latest | Vulnerability scanning |
| JWT | golang-jwt/jwt/v5 | 5.2.2 | Token authentication |
| LDAP | go-ldap/ldap/v3 | 3.4.12 | Directory authentication |
| OAuth/OIDC | coreos/go-oidc/v3 | 3.17.0 | SSO authentication |
| Cloud Storage | aws-sdk-go-v2, Azure SDK | -- | S3/Blob backup storage |
| CLI | spf13/cobra | 1.10.2 | Command-line interface |
| Config | spf13/viper | 1.21.0 | Configuration management |
| Logging | uber/zap | 1.27.1 | Structured logging |
| Observability | OpenTelemetry | 1.33.0 | Distributed tracing |
| Validation | go-playground/validator/v10 | 10.24.0 | Request validation |
| Cron | robfig/cron/v3 | 3.0.1 | Job scheduling |

---

## Architecture Decision Records

### ADR-001: Go as the Primary Language

**Decision:** The entire application is written in Go.

**Rationale:**
- Single statically-linked binary simplifies deployment
- Excellent concurrency model for handling multiple Docker operations
- Strong standard library for HTTP, JSON, and crypto
- Native Docker SDK support
- Fast compilation and low memory footprint
- Cross-platform compilation (linux/darwin, amd64/arm64)

### ADR-002: Server-Side Rendering with Templ

**Decision:** Use Templ for server-side HTML rendering instead of a SPA framework (React, Vue).

**Rationale:**
- Type-safe templates compiled to Go code
- No separate frontend build pipeline (Node.js)
- Lower client-side complexity
- SEO-friendly (not a concern here, but faster initial page load)
- HTMX provides SPA-like interactivity without a JavaScript framework
- The platform is primarily a management dashboard, not a highly interactive app

### ADR-003: NATS JetStream for Agent Communication

**Decision:** Use NATS with JetStream for master-agent communication instead of gRPC or REST polling.

**Rationale:**
- Publish-subscribe pattern fits the command/result flow
- JetStream provides durable message persistence (commands survive network issues)
- Low latency for real-time operations
- Built-in reconnection and backoff
- Subject-based routing simplifies per-agent command queues
- Lightweight compared to Kafka or RabbitMQ

### ADR-004: pgx Instead of GORM

**Decision:** Use `pgx/v5` (native PostgreSQL driver) with `sqlx` for named queries instead of GORM.

**Rationale:**
- Full control over SQL queries (no hidden N+1 queries)
- Native PostgreSQL protocol (faster than database/sql)
- Better performance for complex queries
- Explicit query patterns are easier to optimize and debug
- Supports PostgreSQL-specific features (advisory locks, LISTEN/NOTIFY)

### ADR-005: Chi v5 Router

**Decision:** Use Chi as the HTTP router instead of Gin, Echo, or Fiber.

**Rationale:**
- Follows `net/http` patterns (standard interfaces)
- Composable middleware chains
- No reflection or code generation
- Lightweight with no external dependencies
- Native `http.Handler` compatibility

### ADR-006: Tailwind CSS with Standalone CLI

**Decision:** Use Tailwind CSS via its standalone CLI binary instead of Node.js/npm.

**Rationale:**
- Eliminates Node.js as a build dependency
- Single binary download, no `node_modules`
- Consistent with the Go single-binary philosophy
- Tailwind's utility-first approach works well with Templ components

### ADR-007: License System with JWT

**Decision:** Use RSA-signed JWT tokens for license validation.

**Rationale:**
- Asymmetric cryptography: public key in binary, private key with license issuer
- Standard JWT format, well-understood validation
- Feature flags and limits embedded in the token claims
- Instance fingerprinting prevents license sharing
- Graceful degradation when license expires

---

## Directory Structure

```
usulnet/
+-- cmd/
|   +-- usulnet/              # Main server entry point (Cobra CLI)
|   +-- usulnet-agent/        # Agent entry point
+-- internal/
|   +-- api/                  # REST API layer
|   |   +-- handlers/         # 31 API handler files
|   |   +-- middleware/        # Auth, RBAC, CORS, rate limit, license
|   |   +-- dto/              # Request/response DTOs
|   |   +-- errors/           # API error types
|   |   +-- router.go         # Chi v5 route definitions
|   +-- web/                  # Web UI layer
|   |   +-- handler_*.go      # 60+ SSR page handlers
|   |   +-- adapter_*.go      # 16 service adapters
|   |   +-- templates/        # 124+ Templ template files
|   |   |   +-- layouts/      # Base layout templates
|   |   |   +-- pages/        # Page templates
|   |   |   +-- components/   # Reusable UI components
|   |   |   +-- partials/     # HTMX partial templates
|   |   +-- routes_frontend.go # Frontend route definitions
|   |   +-- middleware.go      # Web-specific middleware
|   +-- app/                  # Application bootstrap
|   |   +-- app.go            # Dependency injection, service initialization
|   |   +-- config.go         # Configuration loading (Viper)
|   |   +-- scheduler_adapters.go # Scheduler job definitions
|   +-- services/             # 37 business logic packages
|   |   +-- auth/             # Authentication (JWT, LDAP, OAuth)
|   |   +-- container/        # Container management
|   |   +-- image/            # Image management
|   |   +-- volume/           # Volume management
|   |   +-- network/          # Network management
|   |   +-- stack/            # Stack (Compose) management
|   |   +-- host/             # Host management
|   |   +-- security/         # Security scanning (Trivy)
|   |   +-- backup/           # Backup and restore
|   |   +-- proxy/            # Reverse proxy (Caddy/NPM)
|   |   +-- notification/     # Notification channels (Slack, Email, Webhook)
|   |   +-- user/             # User management
|   |   +-- team/             # Team management
|   |   +-- ...               # (and 24 more)
|   +-- repository/           # Data access layer
|   |   +-- postgres/         # 55 PostgreSQL repositories
|   |   |   +-- migrations/   # 30 migration pairs (up/down SQL)
|   |   +-- redis/            # Redis repositories
|   +-- models/               # Domain models
|   +-- docker/               # Docker Engine client wrapper
|   +-- gateway/              # NATS gateway (master side)
|   |   +-- protocol/         # Message protocol definitions
|   |   +-- events.go         # Gateway event handling
|   +-- agent/                # Agent implementation
|   |   +-- agent.go          # Agent core
|   |   +-- executor/         # Docker command executor
|   +-- nats/                 # NATS client wrapper
|   +-- scheduler/            # Cron-based job scheduler
|   |   +-- workers/          # Scheduler worker definitions
|   +-- license/              # License validation (JWT, feature flags)
|   +-- integrations/         # External integrations
|   |   +-- git/              # Git providers (Gitea, GitHub, GitLab)
|   +-- observability/        # Logging, tracing, metrics
|   +-- pkg/                  # Shared utility packages
|       +-- crypto/           # AES-256-GCM, bcrypt, PKI
|       +-- errors/           # Error types and wrapping
|       +-- logger/           # Zap logger wrapper
|       +-- totp/             # TOTP 2FA implementation
|       +-- validator/        # Input validation helpers
+-- web/
|   +-- static/               # Frontend static assets
|       +-- src/input.css     # Tailwind source
|       +-- css/style.css     # Compiled CSS (generated)
|       +-- js/               # JavaScript (Guacamole client)
|       +-- tailwind.config.js # Tailwind configuration
+-- deploy/                   # Deployment files
|   +-- docker-compose.prod.yml
|   +-- .env.example
|   +-- install.sh
+-- tests/                    # Test suites
|   +-- e2e/                  # End-to-end tests
|   +-- benchmarks/           # Performance benchmarks
|   +-- load/                 # k6 load tests
+-- scripts/                  # Build and utility scripts
+-- docs/                     # Documentation
+-- .github/workflows/        # CI/CD pipelines
+-- docker-compose.yml        # Production compose
+-- docker-compose.dev.yml    # Development compose
+-- docker-compose.test.yml   # Test compose
+-- Dockerfile                # Main app image
+-- Dockerfile.agent          # Agent image
+-- Makefile                  # Build automation
+-- .golangci.yml             # Linter configuration
+-- go.mod                    # Go module definition
```

---

*For more information, see the [API Documentation](api.md), [Development Guide](development.md), and [Agent Configuration Guide](agents.md).*
