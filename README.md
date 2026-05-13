# usulnet

Self-hosted Docker management plane with built-in OSINT and metadata-hygiene
modules. Single Go binary, AGPL-3.0.

[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Release](https://img.shields.io/github/v/release/fr4nsys/usulnet?include_prereleases&color=success)](https://github.com/fr4nsys/usulnet/releases)

usulnet runs container lifecycle, security scanning, backups, reverse-proxy
configuration, monitoring, multi-node orchestration, and an opt-in privacy
module (OSINT recon plus file metadata hygiene) from a single process on
hardware you own.

v26.5.0 Beta — functional, but rough edges are expected. Bug reports:
[issues](https://github.com/fr4nsys/usulnet/issues).

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/fr4nsys/usulnet/main/deploy/install.sh | sudo bash
```

Open `https://<host>:7443`, log in as `admin` / `usulnet`, then change the
password. The installer pulls the production compose file, generates the
database password, JWT secret, AES-256 key, and a self-signed TLS cert.
Manual Docker Compose install, binary install, and offline procedures live
in [docs/installation.md](docs/installation.md).

## Features

### Docker control plane

| Area | Capability |
| --- | --- |
| Containers | Full lifecycle (create / start / stop / restart / pause / kill / remove), bulk operations, real-time stats, exec terminal, log viewer, filesystem browser. |
| Images | Pull, inspect, prune, layer history; Docker Hub and private registries with encrypted credentials. |
| Volumes and networks | Create, inspect, prune, file browser; bridge / overlay / macvlan; connect and disconnect containers. |
| Stacks | Docker Compose deployments from YAML, Git repositories, or built-in catalogue. |
| Swarm | Cluster init, node management, services, replica scaling, standalone-to-swarm conversion. |
| Multi-node | `standalone`, `master`, and `agent` modes; agent ↔ master traffic over NATS with mTLS; agent deploy from the UI via SSH. |
| Reverse proxy | Caddy and Nginx Proxy Manager adapters; Let's Encrypt with auto-renewal; TCP/UDP stream proxying. |
| Backups | Container / volume / stack targets; cron schedules with retention; gzip or zstd; local, S3, MinIO, Azure Blob, GCS, B2, SFTP. |
| Monitoring | Per-container and per-host CPU / RAM / network / disk; threshold alerts with `OK → Pending → Firing → Resolved` state machine; 11 notification channels (Email, Slack, Discord, Telegram, Gotify, ntfy, PagerDuty, Opsgenie, Microsoft Teams, generic webhook, custom). |
| Logs and events | Aggregated container logs with search; Docker event stream with filtering; packet capture per network interface. |
| Vulnerabilities | Trivy CVE scans for images and filesystems; 0–100 security score per container and infrastructure-wide; SBOM in CycloneDX and SPDX; Docker CIS Benchmark checks. |

### Privacy and recon (opt-in)

Off by default — every recon route returns 404 until an admin sets
`USULNET_RECON_ENABLED=true` and records the legal-notice acknowledgement
(`POST /api/v1/recon/_ack`). Full design and threat model in
[docs/recon.md](docs/recon.md); signed v26.5 review at
[docs/v26.5/security-review-checklist.md](docs/v26.5/security-review-checklist.md).

| Area | Capability |
| --- | --- |
| OSINT recon | SpiderFoot-driven passive scans against emails, domains, phones, IPs, usernames. Ownership is verified (DNS TXT, e-mail link, RDAP, admin-attest, self-assert) before a scan can start. |
| Scan profiles | Four built-in profiles plus full CRUD for user-defined profiles. Built-in rows are immutable; the module catalogue is closed. |
| Reports | Per-scan JSON, CSV, and paginated A4 PDF at `/api/v1/recon/scans/{id}/report.{json,csv,pdf}`. PDF is pure Go and byte-deterministic. |
| Metadata hygiene | `mat2` strip plus `exiftool` / `pdfid` / `oletools` extract. Each job runs in a fresh container with read-only rootfs, all Linux capabilities dropped, seccomp default, and PID / memory caps. |
| Sandbox network | Dedicated `usulnet-recon` Docker network with a strict egress allow-list (DNS, 80, 443 by default). |
| HIBP connector | Optional Have-I-Been-Pwned integration. Credentials AES-256-GCM at rest in `recon_connectors`; keys are never returned through the API or logs. |
| Retention | Daily prune of findings, scans, and audit log past the per-tenant TTL (default 90 days). Two-phase delete on metadata artifacts. |
| Audit | Append-only `recon_audit_log` records every state-changing action with actor, target, and request hash. |

### Auth, RBAC, platform

| Area | Capability |
| --- | --- |
| Authentication | JWT with configurable expiry; `X-API-KEY` for programmatic access; TOTP 2FA with backup codes; LDAP / Active Directory; OAuth2 / OIDC (GitHub, Google, Microsoft, custom). |
| Authorisation | RBAC with 44+ granular permissions, custom roles, team-based resource scoping. |
| Secrets | AES-256-GCM at rest for every sensitive value; bcrypt password hashing; configurable password complexity; account lockout. |
| Transport | TLS with auto-generated self-signed certs (or BYO); mTLS for inter-node messaging; configurable rate limiting; CSRF; secure cookie defaults. |
| Audit | Per-user action log persisted to PostgreSQL with IP, timestamp, detail; CSV export. |
| Observability | Prometheus `/metrics` (admin-auth) including Go runtime and process metrics; OpenTelemetry instrumentation. |
| API | REST under `/api/v1`; OpenAPI 3.0 at `/api/v1/openapi.json`; Swagger UI at `/docs/api`; WebSocket streams for logs, exec, stats, events, metrics, packet capture, and nvim. |

### Developer tools

Web-based terminal hub (xterm.js) with container exec and host SSH. Monaco
editor and Neovim with `lazy.nvim` for in-browser file editing. Filesystem
browsers for containers, hosts, and SFTP. Snippets and cheat sheets.
Outgoing webhooks on container events with retry. Auto-deploy rules
triggered by Git push. Runbooks for multi-step operations. Cron-scheduled
jobs for backups, scans, metrics, update checks, recon retention, and
cleanup.

## Architecture

usulnet ships as a single binary that runs in one of three modes:

- `standalone` — one Docker host, all services local. NATS not required.
- `master` — `standalone` plus a NATS gateway server for remote agents.
- `agent` — connects to a master via NATS. No web UI; executes Docker
  operations against its local host.

PostgreSQL stores domain state (44 migrations covering users, RBAC,
connections, backups, scans, alerts, recon, audit log, etc.). Redis backs
session storage and JWT blacklisting. NATS with JetStream carries
inter-node traffic with persistence. Full component diagram, request flow,
and topology in [docs/architecture.md](docs/architecture.md); the
agent protocol is documented in [docs/agents.md](docs/agents.md).

### Stack

| Layer | Component |
| --- | --- |
| Language | Go 1.25.7 |
| HTTP router | Chi v5 |
| Templates | Templ (compile-time HTML) |
| CSS | Tailwind via the standalone CLI (no Node.js) |
| Browser | Alpine.js, HTMX, xterm.js, Monaco |
| Database | PostgreSQL 16 via pgx/v5 and sqlx |
| Cache / sessions | Redis 7 |
| Messaging | NATS 2.10 with JetStream |
| Auth | JWT, OAuth2 / OIDC, LDAP, TOTP |
| Vulnerability scanner | Trivy |
| PDF | gofpdf (pure Go) |
| Scheduling | robfig/cron v3 |

## Configuration

`config.yaml` plus environment variables prefixed `USULNET_` (nested keys
joined by `_`). The Viper loader treats environment overrides as canonical.
Examples:

```bash
USULNET_SERVER_PORT=9090
USULNET_DATABASE_URL=postgres://usulnet:secret@db/usulnet?sslmode=disable
USULNET_SECURITY_JWT_SECRET=...
USULNET_RECON_ENABLED=true
USULNET_MODE=standalone
```

Full reference, defaults, and the production compose template are in
[docs/installation.md](docs/installation.md).

## CLI

```
usulnet serve              # run the server
usulnet migrate up         # apply pending migrations
usulnet migrate status     # show migration state
usulnet migrate down [N]   # roll back N migrations (default 1)
usulnet config check       # validate configuration
usulnet config show        # display config with secrets masked
usulnet admin reset-password   # reset the admin password
usulnet version            # print build info
```

The agent binary (`usulnet-agent`) is documented in
[docs/agents.md](docs/agents.md).

## Documentation

| Topic | Path |
| --- | --- |
| Installation and deployment | [docs/installation.md](docs/installation.md) |
| Development setup and workflow | [docs/development.md](docs/development.md) |
| REST and WebSocket API | [docs/api.md](docs/api.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| Recon and metadata modules | [docs/recon.md](docs/recon.md) |
| Multi-node agents | [docs/agents.md](docs/agents.md) |
| Licensing | [docs/licensing.md](docs/licensing.md) |
| Signed security review (recon, v26.5) | [docs/v26.5/security-review-checklist.md](docs/v26.5/security-review-checklist.md) |
| Release notes | [CHANGELOG.md](CHANGELOG.md) |
| Screenshots | [docs/screenshots/](docs/screenshots/) |

## Development

```bash
git clone https://github.com/fr4nsys/usulnet.git
cd usulnet
make dev-up      # postgres, redis, nats, minio
make build       # templ generate + tailwind compile + go build
make run
```

`make quality` runs the lint, vet, and 40% coverage gate. The full
developer guide — workflow, hooks, profiling, debugging — is in
[docs/development.md](docs/development.md).

Commits follow [Conventional Commits](https://www.conventionalcommits.org).

## Security

Report vulnerabilities to <security@usulnet.com>. Do not open public issues
for security findings.

The recon module ships with a signed
[security review checklist](docs/v26.5/security-review-checklist.md):
feature-flagged off by default, admin acknowledgement enforced before any
route resolves, append-only audit log, AES-256-GCM at rest for raw engine
payloads and connector credentials, hardened container sandbox (read-only
rootfs, all caps dropped, seccomp default), PII hashing for indexed
identifiers.

## License

[AGPL-3.0-or-later](LICENSE). Self-hosted use is free in perpetuity;
commercial licensing terms (SSO, audit retention, on-prem support) are
documented in [docs/licensing.md](docs/licensing.md).
