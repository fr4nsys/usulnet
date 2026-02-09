<p align="center">
  <a href="https://usulnet.com/"><img src="docs/screenshots/logo.png" alt="usulnet" width="320" /></a>
</p>

<p align="center">
  <strong>Self-Hosted Docker Management Platform</strong><br/>
  A modern, feature-rich platform for managing Docker infrastructure across single and multi-node deployments.
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.25+"/></a>
  <a href="#license"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue?style=flat-square" alt="AGPL-3.0"/></a>
  <a href="#deployment"><img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker Ready"/></a>
  <a href="https://github.com/fr4nsys/usulnet/releases"><img src="https://img.shields.io/github/v/release/fr4nsys/usulnet?style=flat-square&color=success&include_prereleases" alt="Release"/></a> <!-- Stable only:https://img.shields.io/github/v/release/fr4nsys/usulnet?style=flat-square&color=success -->
</p>

<p align="center">
  <a href="#-fast-deployment">Fast Deploy</a>&nbsp;&bull;
  <a href="#features">Features</a>&nbsp;&bull;
  <a href="#screenshots">Screenshots</a>&nbsp;&bull;
  <a href="#deployment">Deployment</a>&nbsp;&bull;
  <a href="#configuration">Configuration</a>&nbsp;&bull;
  <a href="#api">API</a>&nbsp;&bull;
  <a href="#architecture">Architecture</a>&nbsp;&bull;
  <a href="#contributing">Contributing</a>
</p>

---

> **v26.2.0 &mdash; First Public Beta Release**
>
> This is the first public release of usulnet. The platform is functional, but as a beta release, you may encounter bugs or incomplete features. We appreciate your feedback &mdash; please report any issues on [GitHub Issues](https://github.com/fr4nsys/usulnet/issues). Your reports help to improve usulnet for everyone.

---

## Support the Project

usulnet is built and maintained only by me at the moment. If you find it useful, consider supporting its continued development:

<p align="center">
  <a href="https://buymeacoffee.com/fransys"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me a Coffee"/></a>&nbsp;&nbsp;
  <a href="https://usulnet.com/#pricing"><img src="https://img.shields.io/badge/Business%20License-ff6b35?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJibGFjayI+PHBhdGggZD0iTTEyIDFMMyA1djZjMCA1LjU1IDMuODQgMTAuNzQgOSAxMiA1LjE2LTEuMjYgOS02LjQ1IDktMTJWNWwtOS00eiIvPjwvc3ZnPg==&logoColor=black" alt="Business License"/></a>
</p>

| Channel | Description |
|---|---|
| [Buy Me a Coffee](https://buymeacoffee.com/fransys) | One-time or recurring donations to support development |
| [Business License](https://usulnet.com/#pricing) | Purchase a Business or Enterprise license starting at &euro;79/node/year |
| [GitHub Sponsors](https://github.com/sponsors/fr4nsys) | Sponsor via GitHub for recurring monthly support |

Every contribution, whether a coffee, a license purchase, or a star on GitHub, help to keep this project alive and growing. Thank you.

---

## &#9889; Fast Deployment

Deploy usulnet in one command. No manual configuration needed &mdash; all secrets are generated automatically.

```bash
curl -fsSL https://raw.githubusercontent.com/fr4nsys/usulnet/main/deploy/install.sh | bash
```

This will:
- Download the production Docker Compose configuration
- Auto-generate secure database passwords, JWT secrets, and encryption keys
- Start usulnet with PostgreSQL, Redis, and NATS
- Be ready in under 60 seconds (pre-built images, no compilation)

**Access:** `https://your-server-ip:7443` &mdash; Default credentials: `admin` / `usulnet`

Or deploy manually with Docker Compose:

```bash
# Download the files
mkdir -p /opt/usulnet && cd /opt/usulnet
curl -fsSL https://raw.githubusercontent.com/fr4nsys/usulnet/main/deploy/docker-compose.prod.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/fr4nsys/usulnet/main/deploy/.env.example -o .env

# Generate secrets (or edit .env manually)
sed -i "s|CHANGE_ME_GENERATE_RANDOM_PASSWORD|$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)|" .env
sed -i "s|CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32|$(openssl rand -hex 32)|" .env
sed -i "s|CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32|$(openssl rand -hex 32)|" .env

# Start
docker compose up -d
```

---

## Overview

**usulnet** is a self-hosted Docker management platform built with Go that gives engineering teams full control over their container infrastructure. It replaces the need for multiple tools by providing a unified interface for container orchestration, security scanning, backup management, reverse proxy configuration, monitoring, and multi-node deployment &mdash; all from a single, modern web UI.

Designed for **sysadmins**, **DevOps engineers**, and **platform teams** who need a production-grade, self-hosted alternative to cloud-native container management solutions without vendor lock-in.

### Why usulnet?

- **Single binary** &mdash; No runtime dependencies like Node.js or Python. Templates are compiled into the binary at build time.
- **Multi-node out of the box** &mdash; Master/agent architecture with NATS messaging, mTLS, and auto-deployment of agents.
- **Security-first** &mdash; Built-in Trivy scanning, RBAC with 44+ permissions, 2FA, LDAP/OIDC auth, encrypted secrets, audit logging.
- **Full-stack management** &mdash; Containers, images, volumes, networks, stacks, proxies, backups, SSH, databases, LDAP, Git &mdash; everything in one place.
- **Lightweight** &mdash; ~50 MB binary. No Electron, no bloated frontend frameworks. Pure Templ + Tailwind + Alpine.js + HTMX.

---

## Features

### Core Docker Management

| Feature | Description |
|---|---|
| **Containers** | Full lifecycle management &mdash; create, start, stop, restart, pause, kill, remove. Bulk operations, real-time stats, settings editor, filesystem browser. |
| **Images** | Pull, inspect, remove, prune. Registry support (Docker Hub, private registries). Layer history and size analysis. |
| **Volumes** | Create, inspect, remove, prune. Built-in file browser for volume contents. |
| **Networks** | Create, inspect, remove, prune. Connect/disconnect containers. Bridge, overlay, macvlan support. |
| **Stacks** | Docker Compose deployment, management, and monitoring. Built-in stack catalog with one-click deployment. |
| **Docker Swarm** | Initialize clusters, manage nodes, create HA services, scale replicas, convert standalone containers. |

### Security & Compliance

| Feature | Description |
|---|---|
| **Vulnerability Scanning** | Integrated Trivy scanner for container images and filesystems. CVE detection with severity classification. |
| **Security Scoring** | 0-100 composite security score per container and across the infrastructure. Trends tracking over time. |
| **SBOM Generation** | Software Bill of Materials in CycloneDX and SPDX formats. |
| **RBAC** | Role-based access control with 44+ granular permissions. Custom roles. Team-based resource scoping. |
| **2FA / TOTP** | Two-factor authentication with TOTP (Google Authenticator, Authy) and backup codes. |
| **LDAP / OIDC** | Enterprise authentication via Active Directory, LDAP, OAuth2, and OIDC (GitHub, Google, Microsoft, custom). |
| **Audit Logging** | Every user action logged with IP, timestamp, and details. Exportable as CSV, PDF, or JSON. |
| **Encrypted Secrets** | AES-256-GCM encryption for all sensitive configuration values (passwords, tokens, keys). |
| **API Key Auth** | Programmatic access via `X-API-KEY` header alongside JWT authentication. |

### Monitoring & Alerting

| Feature | Description |
|---|---|
| **Real-time Metrics** | CPU, memory, network I/O, disk I/O per container and per host. WebSocket-powered live dashboards. |
| **Alert Rules** | Threshold-based alerts on any metric. States: OK &rarr; Pending &rarr; Firing &rarr; Resolved. Silence rules. |
| **11 Notification Channels** | Email, Slack, Discord, Telegram, Gotify, ntfy, PagerDuty, Opsgenie, Microsoft Teams, Generic Webhook, Custom. |
| **Event Stream** | Real-time Docker event stream (container, image, volume, network events) with filtering. |
| **Centralized Logs** | Aggregated container logs with search, filtering, and custom log file upload for analysis. |
| **Prometheus Metrics** | Native `/metrics` endpoint for Prometheus scraping. Go runtime and process metrics included. |

### Backup & Recovery

| Feature | Description |
|---|---|
| **Backup Targets** | Back up individual containers, volumes, or entire stacks. |
| **Scheduled Backups** | Cron-based backup scheduling with retention policies. |
| **Storage Backends** | Local filesystem, AWS S3, MinIO, Azure Blob, Google Cloud Storage, Backblaze B2, SFTP. |
| **Compression** | gzip or zstd compression with configurable levels. |
| **One-click Restore** | Restore any backup to its original or a different target. |

### Multi-Node Architecture

| Feature | Description |
|---|---|
| **Operation Modes** | `standalone` (single node), `master` (control plane), `agent` (worker node). |
| **NATS Messaging** | Inter-node communication via NATS with JetStream persistence. |
| **Internal PKI & mTLS** | Auto-generated certificates for secure agent-master communication. |
| **Auto Agent Deploy** | Deploy agents to remote hosts directly from the web UI via SSH. |
| **Gateway Routing** | API gateway automatically routes requests to the correct node. |
| **Host Switching** | Seamlessly switch between managed hosts from any page. |

### Reverse Proxy

| Feature | Description |
|---|---|
| **Caddy Integration** | Configure Caddy reverse proxy via API. Auto-HTTPS with Let's Encrypt. |
| **Nginx Proxy Manager** | Full NPM integration &mdash; proxy hosts, certificates, redirections, streams, access lists. |
| **Certificate Management** | Let's Encrypt, custom certificates, auto-renewal, expiration alerts. |
| **Stream Proxying** | TCP/UDP stream proxy configuration for non-HTTP services. |

### Developer Tools

| Feature | Description |
|---|---|
| **Terminal Hub** | Multi-tab terminal with container exec and host SSH in the browser (xterm.js). |
| **Monaco Editor** | Full VS Code editor experience in the browser for editing files inside containers and on hosts. |
| **Neovim in Browser** | Neovim with lazy.nvim plugin manager running directly in the browser via WebSocket. |
| **Container Filesystem** | Browse, read, edit, upload, download, and delete files inside running containers. |
| **Host Filesystem** | Browse and manage files on managed hosts (requires nsenter). |
| **SFTP Browser** | Browse remote filesystems over SSH/SFTP with upload, download, and directory management. |
| **Snippets** | Save and manage code snippets and configuration files with the built-in editor. |
| **Command Cheat Sheet** | Quick-reference for Docker, Linux, networking, and custom commands. |

### Connections & Integrations

| Feature | Description |
|---|---|
| **SSH Connections** | Manage SSH connections with password or key-based auth. Web terminal, SFTP browser, tunnel/port forwarding. |
| **RDP Connections** | Remote Desktop connections to Windows servers. Configurable resolution, color depth, NLA/TLS security modes. |
| **Database Browser** | Connect to PostgreSQL, MySQL/MariaDB, MongoDB, Redis, and SQLite. Execute queries, browse tables. |
| **LDAP Browser** | Connect to LDAP directories. Search, browse entries, view attributes. Settings and delete management. |
| **Git Integration** | Unified Git provider support (Gitea, GitHub, GitLab). Repository management, file editing, PRs, issues, CI/CD workflows. |
| **Container Registries** | Manage authentication for multiple private registries with encrypted credentials. |
| **Web Shortcuts** | Bookmark frequently accessed URLs with custom icons and categories. |

### Automation

| Feature | Description |
|---|---|
| **Outgoing Webhooks** | HTTP webhooks triggered by container events (start, stop, die, health changes). Delivery logs with retry. |
| **Auto-Deploy Rules** | Automatically redeploy stacks on Git push events. Match by source repo and branch. |
| **Runbooks** | Define multi-step operational procedures. Execute manually or triggered by events. Execution history. |
| **Scheduled Jobs** | Cron-based scheduling for backups, security scans, metrics collection, update checks, and cleanup tasks. |
| **Image Updates** | Detect available image updates, apply individually or in batch, with rollback capability. |

### API & Extensibility

| Feature | Description |
|---|---|
| **REST API** | Full CRUD API at `/api/v1` with JWT and API key authentication. |
| **OpenAPI 3.0** | Auto-generated specification at `/api/v1/openapi.json`. Swagger UI at `/docs/api`. |
| **WebSocket API** | Real-time streams for logs, exec, stats, events, metrics, and terminal sessions. |
| **Ansible Inventory** | Parse and browse Ansible inventory files (INI and YAML formats). |
| **Network Capture** | Packet capture on container network interfaces for traffic analysis. |

---

## Screenshots

### Dashboard

> Infrastructure overview with container status, resource utilization, security score, and recent events.

![Dashboard](docs/screenshots/dashboard.png)

### Login & 2FA

> Secure login with optional TOTP two-factor authentication, backup codes, and account lockout protection.

![Login](docs/screenshots/login01.png)

<details>
<summary>More screenshots</summary>

![2FA Setup](docs/screenshots/2fa.png)
![2FA Login](docs/screenshots/2falogin.png)
![2FA Login Code](docs/screenshots/2falogin01.png)
![2FA Disable](docs/screenshots/2fadisable.png)

</details>

### Container Management

> Full container lifecycle management with real-time stats, logs, exec terminal, filesystem browser, and settings editor.

![Containers](docs/screenshots/containers.png)

<details>
<summary>More screenshots</summary>

![Containers List](docs/screenshots/containers01.png)
![Container Detail](docs/screenshots/containers02.png)
![Container Stats](docs/screenshots/containers03.png)
![Container Logs](docs/screenshots/containers04.png)
![Container Exec](docs/screenshots/containers05.png)
![Container Filesystem](docs/screenshots/containers06.png)
![Container Settings](docs/screenshots/containers07.png)
![Container Network](docs/screenshots/containers08.png)
![Container Volumes](docs/screenshots/container09.png)
![Container Environment](docs/screenshots/containers10.png)
![Container Actions](docs/screenshots/container11.png)

</details>

### Images

> Pull, inspect, remove, and prune Docker images. Registry support with layer history and size analysis.

![Images](docs/screenshots/images.png)

### Volumes

> Create, inspect, remove, and prune Docker volumes. Built-in file browser for volume contents.

![Volumes](docs/screenshots/volumes.png)

### Networks

> Create, inspect, and manage Docker networks. Bridge, overlay, and macvlan support with visual topology.

![Networks](docs/screenshots/networks.png)

<details>
<summary>More screenshots</summary>

![Networks Detail](docs/screenshots/networks01.png)
![Networks Config](docs/screenshots/networks02.png)
![Network Topology](docs/screenshots/net-topology.png)

</details>

### Stacks & Deployment

> Deploy Docker Compose stacks from YAML, from Git repositories, or from the built-in stack catalog.

![Stacks](docs/screenshots/stacks.png)

<details>
<summary>More screenshots</summary>

![Deploy Stacks](docs/screenshots/deploystacks.png)
![Custom Deploy](docs/screenshots/deploy-custom.png)
![Custom Deploy Detail](docs/screenshots/deploy-custom01.png)

</details>

### Security & Vulnerability Scanning

> Trivy-powered vulnerability scanning with security scoring, trend analysis, SBOM generation, and exportable reports.

![Security](docs/screenshots/security.png)

<details>
<summary>More screenshots</summary>

![Security Overview](docs/screenshots/security01.png)
![Security Scan](docs/screenshots/security02.png)
![Security Details](docs/screenshots/security03.png)
![Security Report](docs/screenshots/securityreport.png)
![Security Report Detail](docs/screenshots/securityreport01.png)
![Security Report Export](docs/screenshots/securityreport02.png)

</details>

### Logs

> Aggregated container logs with search and filtering. Centralized log collection and custom log file upload for analysis.

![Logs](docs/screenshots/logs.png)

<details>
<summary>More screenshots</summary>

![Centralized Logs](docs/screenshots/centralized-logs.png)
![Centralized Logs Detail](docs/screenshots/centralized-logs01.png)

</details>

### Terminal & SSH

> Multi-tab browser terminal with container exec and host SSH. SFTP browser, tunnel/port forwarding. Powered by xterm.js.

![SSH](docs/screenshots/ssh.png)

<details>
<summary>More screenshots</summary>

![SSH Session](docs/screenshots/ssh01.png)
![SSH SFTP](docs/screenshots/ssh02.png)

</details>

### Code Editor

> Full VS Code editor (Monaco) and Neovim in the browser for editing files inside containers, on hosts, or in your snippet library.

![Monaco Editor](docs/screenshots/monaco.png)

<details>
<summary>More screenshots</summary>

![Neovim](docs/screenshots/nvim.png)

</details>

### Multi-Node Management

> Manage Docker hosts across your infrastructure from a single pane of glass. Auto-deploy agents via SSH with mTLS.

![Nodes](docs/screenshots/nodes.png)

<details>
<summary>More screenshots</summary>

![Nodes List](docs/screenshots/nodes01.png)
![Node Detail](docs/screenshots/nodes02.png)
![Node Stats](docs/screenshots/nodes03.png)
![Node Config](docs/screenshots/node04.png)
![Node Agent](docs/screenshots/nodes05.png)
![Node Deploy](docs/screenshots/nodes06.png)

</details>

### Users & Teams

> User management with role assignment, team-based resource scoping, and profile editing.

![Users](docs/screenshots/users.png)

<details>
<summary>More screenshots</summary>

![Edit User](docs/screenshots/edituser.png)
![Teams](docs/screenshots/teams.png)

</details>

### Roles & Permissions

> Role-based access control with 44+ granular permissions. Create custom roles with fine-grained permission assignment.

![Roles](docs/screenshots/roles.png)

<details>
<summary>More screenshots</summary>

![Custom Role](docs/screenshots/custom-role.png)

</details>

### LDAP Integration

> Enterprise authentication via Active Directory and LDAP. Provider management, group mapping, and connection testing.

![LDAP](docs/screenshots/ldap.png)

<details>
<summary>More screenshots</summary>

![LDAP Config](docs/screenshots/ldap--.png)
![LDAP Provider](docs/screenshots/ldap01.png)
![LDAP Groups](docs/screenshots/ldap02.png)
![LDAP Test](docs/screenshots/ldap03.png)
![LDAP Browser](docs/screenshots/ldap04.png)

</details>

### Settings & Administration

> Platform settings, license management, update checker, and command cheat sheet.

![Settings](docs/screenshots/settings.png)

<details>
<summary>More screenshots</summary>

![License](docs/screenshots/license.png)
![Updates](docs/screenshots/updates.png)
![Cheatsheet](docs/screenshots/cheatsheet.png)

</details>

---

## Quick Start

### Docker &mdash; Pre-built Image (recommended)

The fastest way to get started. Uses pre-built images, no compilation required:

```bash
curl -fsSL https://raw.githubusercontent.com/fr4nsys/usulnet/main/deploy/install.sh | bash
```

See [Fast Deployment](#-fast-deployment) above for details and manual options.

### Build from Source

```bash
# Prerequisites: Go 1.25+, Make, Docker
git clone https://github.com/fr4nsys/usulnet.git
cd usulnet

# Build and run with Docker Compose (builds from source, ~10-15 min first time)
docker compose -f docker-compose.dev.yml build
docker compose -f docker-compose.dev.yml up -d

# Or build natively
make build && make run
```

---

## Deployment

### Docker Compose (Production)

```yaml
services:
  usulnet:
    image: ghcr.io/fr4nsys/usulnet:latest
    ports:
      - "8080:8080"    # HTTP
      - "7443:7443"    # HTTPS (auto-TLS)
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - usulnet-data:/var/lib/usulnet
    environment:
      - USULNET_DATABASE_URL=postgres://usulnet:secret@postgres:5432/usulnet?sslmode=disable
      - USULNET_REDIS_URL=redis://redis:6379/0
      - USULNET_NATS_URL=nats://nats:4222
      - USULNET_SECURITY_JWT_SECRET=your-secret-key-min-32-chars-long
      - USULNET_SECURITY_CONFIG_ENCRYPTION_KEY=your-64-hex-char-aes-256-key-here
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started
      nats:
        condition: service_started
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: usulnet
      POSTGRES_USER: usulnet
      POSTGRES_PASSWORD: secret
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U usulnet"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis-data:/data
    restart: unless-stopped

  nats:
    image: nats:2.10-alpine
    command: ["--jetstream", "--store_dir", "/data"]
    volumes:
      - nats-data:/data
    restart: unless-stopped

volumes:
  usulnet-data:
  postgres-data:
  redis-data:
  nats-data:
```

### Multi-Node Deployment

**Master node:**

```yaml
# config.yaml on master
mode: master
server:
  port: 8080
nats:
  url: nats://nats-server:4222
  jetstream:
    enabled: true
```

**Agent node:**

```yaml
# config.yaml on agent
mode: agent
agent:
  master_url: nats://master-nats:4222
  name: worker-01
  token: your-auth-token
  heartbeat_interval: 30s
  metrics_interval: 1m
```

Or deploy agents directly from the web UI:

1. Go to **Nodes** &rarr; **Add Node**
2. Enter the host's SSH credentials
3. Click **Deploy Agent** &mdash; usulnet will install and configure the agent automatically

### System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| **CPU** | 1 vCPU | 2+ vCPU |
| **RAM** | 2 GB | 4 GB (standalone) / 8 GB (master) |
| **Disk** | 10 GB | 50 GB+ (with backups) |
| **OS** | Linux (amd64, arm64) | Debian/Ubuntu/RHEL |
| **Docker** | 20.10+ | Latest stable |
| **PostgreSQL** | 12+ | 16+ |
| **Redis** | 5+ | 7+ |
| **NATS** | 2.0+ | 2.10+ |

---

## Configuration

usulnet is configured via `config.yaml` or environment variables (prefix `USULNET_`, nested with `_`).

### Server

```yaml
server:
  host: 0.0.0.0
  port: 8080
  https_port: 7443
  base_url: https://usulnet.example.com
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s
  max_request_size: 52428800  # 50 MB
  rate_limit_rps: 100
  tls:
    enabled: true
    auto_tls: true            # Auto-generate self-signed certs
    # cert_file: /path/to/cert.pem   # Or use custom certs
    # key_file: /path/to/key.pem
```

### Database

```yaml
database:
  url: postgres://usulnet:password@localhost:5432/usulnet?sslmode=disable
  max_open_conns: 25
  max_idle_conns: 10
  conn_max_lifetime: 30m
  query_timeout: 30s
```

### Security

```yaml
security:
  jwt_secret: "your-secret-at-least-32-characters"
  jwt_expiry: 24h
  refresh_expiry: 168h                  # 7 days
  config_encryption_key: "64-hex-chars" # AES-256 key for secrets at rest
  cookie_secure: true
  cookie_samesite: strict
  password_min_length: 8
  password_require_uppercase: true
  password_require_number: true
  max_failed_logins: 5
  lockout_duration: 15m
```

### Backup Storage

```yaml
storage:
  type: s3                    # local | s3
  path: /var/lib/usulnet      # local storage path
  s3:
    endpoint: s3.amazonaws.com
    bucket: usulnet-backups
    region: us-east-1
    access_key: AKIA...
    secret_key: ...
    use_path_style: false     # true for MinIO
  backup:
    compression: zstd         # gzip | zstd
    compression_level: 3
    default_retention_days: 30
```

### Trivy Security Scanner

```yaml
trivy:
  enabled: true
  cache_dir: /var/lib/usulnet/trivy
  timeout: 5m
  severity: CRITICAL,HIGH,MEDIUM
  ignore_unfixed: false
  update_db_on_start: true
```

### Reverse Proxy (Caddy)

```yaml
caddy:
  enabled: true
  admin_url: http://caddy:2019
  acme_email: admin@example.com
```

### Notifications (Examples)

Notification channels are configured through the web UI at **Admin &rarr; Notification Channels**. Supported types:

```
Email (SMTP), Slack, Discord, Telegram, Gotify, ntfy,
PagerDuty, Opsgenie, Microsoft Teams, Generic Webhook
```

### Environment Variables

Any configuration key can be set via environment variable:

```bash
USULNET_SERVER_PORT=9090
USULNET_DATABASE_URL=postgres://...
USULNET_SECURITY_JWT_SECRET=...
USULNET_REDIS_URL=redis://...
USULNET_NATS_URL=nats://...
USULNET_TRIVY_ENABLED=true
USULNET_MODE=standalone
```

---

## API

usulnet exposes a full REST API at `/api/v1` with OpenAPI 3.0 documentation.

### Authentication

```bash
# Login to get a JWT token
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "usulnet"}'

# Use the token
curl http://localhost:8080/api/v1/containers \
  -H "Authorization: Bearer <token>"

# Or use an API key
curl http://localhost:8080/api/v1/containers \
  -H "X-API-KEY: your-api-key"
```

### Endpoints

| Method | Endpoint | Description |
|---|---|---|
| **Auth** | | |
| `POST` | `/auth/login` | Authenticate and receive JWT |
| `POST` | `/auth/refresh` | Refresh expired token |
| `POST` | `/auth/logout` | Invalidate session |
| **System** | | |
| `GET` | `/system/info` | System and Docker engine info |
| `GET` | `/system/version` | Application version |
| `GET` | `/system/health` | Health status |
| `GET` | `/system/metrics` | System metrics |
| **Containers** | | |
| `GET` | `/containers` | List all containers |
| `GET` | `/containers/{id}` | Container details |
| `POST` | `/containers/{id}/start` | Start container |
| `POST` | `/containers/{id}/stop` | Stop container |
| `POST` | `/containers/{id}/restart` | Restart container |
| `DELETE` | `/containers/{id}` | Remove container |
| `GET` | `/containers/{id}/logs` | Container logs |
| `GET` | `/containers/{id}/stats` | Resource stats |
| **Images** | | |
| `GET` | `/images` | List images |
| `GET` | `/images/{id}` | Image details |
| `POST` | `/images/pull` | Pull image |
| `DELETE` | `/images/{id}` | Remove image |
| **Volumes** | | |
| `GET` | `/volumes` | List volumes |
| `POST` | `/volumes` | Create volume |
| `GET` | `/volumes/{name}` | Volume details |
| `DELETE` | `/volumes/{name}` | Remove volume |
| **Networks** | | |
| `GET` | `/networks` | List networks |
| `POST` | `/networks` | Create network |
| `GET` | `/networks/{id}` | Network details |
| `DELETE` | `/networks/{id}` | Remove network |
| **Stacks** | | |
| `GET` | `/stacks` | List stacks |
| `POST` | `/stacks/deploy` | Deploy stack |
| `GET` | `/stacks/{name}` | Stack details |
| `DELETE` | `/stacks/{name}` | Remove stack |
| **Hosts** | | |
| `GET` | `/hosts` | List managed nodes |
| `POST` | `/hosts` | Add node |
| `GET` | `/hosts/{id}` | Node details |
| `PUT` | `/hosts/{id}` | Update node |
| `DELETE` | `/hosts/{id}` | Remove node |
| **Backups** | | |
| `GET` | `/backups` | List backups |
| `POST` | `/backups` | Create backup |
| `POST` | `/backups/{id}/restore` | Restore backup |
| `DELETE` | `/backups/{id}` | Delete backup |
| **Security** | | |
| `POST` | `/security/scan` | Scan all containers |
| `POST` | `/security/scan/{id}` | Scan specific container |
| **Updates** | | |
| `GET` | `/updates` | List available updates |
| `POST` | `/updates/check` | Check for updates |
| **Proxy** | | |
| `GET` | `/proxy/hosts` | List proxy hosts |
| `POST` | `/proxy/hosts` | Create proxy host |
| `PUT` | `/proxy/hosts/{id}` | Update proxy host |
| `DELETE` | `/proxy/hosts/{id}` | Remove proxy host |
| **Users** (admin) | | |
| `GET` | `/users` | List users |
| `POST` | `/users` | Create user |
| `PUT` | `/users/{id}` | Update user |
| `DELETE` | `/users/{id}` | Delete user |

### WebSocket Endpoints

| Endpoint | Description |
|---|---|
| `/ws/logs/{id}` | Real-time container log streaming |
| `/ws/exec/{id}` | Interactive container terminal |
| `/ws/stats/{id}` | Live container resource stats |
| `/ws/events` | Docker event stream |
| `/ws/metrics` | System metrics stream |
| `/ws/monitoring/stats` | Monitoring dashboard data |
| `/ws/monitoring/container/{id}` | Per-container monitoring |
| `/ws/jobs/{id}` | Job progress tracking |
| `/ws/capture/{id}` | Packet capture stream |
| `/ws/editor/nvim` | Neovim terminal session |

### OpenAPI Documentation

Interactive API documentation is available at:
- **Swagger UI**: `http://localhost:8080/docs/api`
- **OpenAPI JSON**: `http://localhost:8080/api/v1/openapi.json`

---

## Architecture

### System Architecture

```
                                    +-------------------+
                                    |    Web Browser     |
                                    |  (Tailwind/Alpine/ |
                                    |   HTMX/xterm.js)  |
                                    +---------+---------+
                                              |
                                    HTTP/WS/HTTPS
                                              |
+---------------------------------------------------------------------+
|                          usulnet (master)                            |
|                                                                     |
|  +------------+  +------------+  +-----------+  +----------------+  |
|  | Chi Router |  | Templ UI   |  | REST API  |  | WebSocket Hub  |  |
|  | (Frontend) |  | (SSR HTML) |  | (JSON)    |  | (Real-time)    |  |
|  +------+-----+  +------+-----+  +-----+-----+  +-------+--------+  |
|         |               |              |                 |           |
|  +------+---------------+--------------+-----------------+--------+  |
|  |                     Service Layer                              |  |
|  |  container | image | volume | network | stack | security       |  |
|  |  backup | proxy | auth | user | team | ssh | git | monitoring  |  |
|  +------+---------------+--------------+-----------------+--------+  |
|         |               |              |                 |           |
|  +------+-----+  +------+-----+  +----+------+  +-------+-------+  |
|  | PostgreSQL  |  |   Redis    |  |   NATS    |  |Docker Socket  |  |
|  | (Data)      |  | (Sessions/ |  | (JetStream|  |(Docker API)   |  |
|  |             |  |  Cache)    |  |  Messaging|  |               |  |
|  +-------------+  +------------+  +-----------+  +---------------+  |
+---------------------------------------------------------------------+
         |                                    |
    NATS (mTLS)                          NATS (mTLS)
         |                                    |
+--------+--------+               +----------+--------+
| usulnet (agent)  |               | usulnet (agent)  |
|   worker-01      |               |   worker-02      |
|  +-------------+ |               |  +-------------+ |
|  |Docker Socket| |               |  |Docker Socket| |
|  +-------------+ |               |  +-------------+ |
+------------------+               +------------------+
```

### Tech Stack

| Layer | Technology |
|---|---|
| **Language** | Go 1.25+ |
| **Web Framework** | [Chi](https://github.com/go-chi/chi) v5 |
| **Templates** | [Templ](https://templ.guide) &mdash; compile-time type-safe HTML |
| **CSS** | [Tailwind CSS](https://tailwindcss.com) (standalone CLI, no Node.js) |
| **Frontend JS** | [Alpine.js](https://alpinejs.dev) + [HTMX](https://htmx.org) |
| **Terminal** | [xterm.js](https://xtermjs.org) v5 |
| **Editor** | [Monaco](https://microsoft.github.io/monaco-editor/) v0.52 + [Neovim](https://neovim.io) |
| **Database** | PostgreSQL 16 ([pgx](https://github.com/jackc/pgx) + [sqlx](https://github.com/jmoiron/sqlx)) |
| **Cache** | Redis 7 |
| **Messaging** | [NATS](https://nats.io) 2.10 with JetStream |
| **Auth** | JWT + OAuth2/OIDC + LDAP + TOTP |
| **Security** | [Trivy](https://trivy.dev) vulnerability scanner |
| **Logging** | [zap](https://github.com/uber-go/zap) (structured JSON) |
| **Scheduling** | [cron](https://github.com/robfig/cron) v3 |
| **Docker** | [Docker SDK](https://pkg.go.dev/github.com/docker/docker) for Go |

### Directory Structure

```
cmd/
  usulnet/              # Main application entry point (serve, migrate, config, admin)
  usulnet-agent/        # Agent binary entry point

internal/
  api/                  # REST API handlers, middleware, router
    handlers/           # Per-resource API handlers
    middleware/         # Auth, RBAC, CORS, rate limiting, logging
  app/                  # Application bootstrap, config loading, service wiring
  agent/                # Agent mode: heartbeat, inventory, command execution
  docker/               # Docker client wrapper with multi-host support
  gateway/              # API gateway for master mode (routes to agents)
  integrations/         # External system integrations
    gitea/              # Gitea Git provider
    github/             # GitHub Git provider
    gitlab/             # GitLab Git provider
    npm/                # Nginx Proxy Manager
  models/               # Domain models and types (34 types)
  nats/                 # NATS client with JetStream support
  pkg/                  # Shared packages
    crypto/             # AES-256-GCM encryption, password hashing
    logger/             # Structured logging (zap wrapper)
    validator/          # Request validation
  repository/           # Data access layer
    postgres/           # PostgreSQL repositories (22 migrations)
    redis/              # Redis session store
  scheduler/            # Cron job scheduler
    workers/            # Job implementations (backup, scan, cleanup, metrics)
  services/             # Business logic (30+ services)
    auth/               # JWT, OIDC, LDAP authentication
    backup/             # Backup creation, restore, scheduling
    container/          # Container lifecycle management
    git/                # Unified Git provider (Gitea/GitHub/GitLab)
    image/              # Image pull, inspect, prune
    monitoring/         # Metrics collection, alert engine
    network/            # Docker network management
    notification/       # Multi-channel notification dispatch
    proxy/              # Caddy/NPM reverse proxy
    security/           # Trivy scanning, scoring, SBOM
    ssh/                # SSH connections, SFTP, tunnels
    stack/              # Docker Compose stack management
    storage/            # S3/local backup storage
    volume/             # Docker volume management
  web/                  # Web UI layer
    templates/          # Templ templates (117 files)
      components/       # Reusable UI components
      layouts/          # Page layouts (base, auth)
      pages/            # Full page templates
      partials/         # HTMX partial responses
    handler_*.go        # 37 web handlers

web/
  static/               # Static assets
    src/input.css        # Tailwind source CSS
    css/output.css       # Compiled CSS
    js/                  # Alpine.js, HTMX, xterm.js, Monaco

deploy/                 # Production Docker Compose files
docs/                   # Developer documentation
nvim/                   # Neovim editor configuration (lazy.nvim)
```

### Database Schema

22 migrations managing tables for:

- Users, roles, permissions, teams
- SSH connections, SSH keys
- Container registries
- Configuration variables and templates
- Backup schedules and metadata
- Security scan results and issues
- Notification configurations
- Alert rules, events, and silences
- Outgoing webhooks and delivery logs
- Auto-deploy rules
- Runbooks and execution history
- Git connections and repositories
- Terminal session history
- Metrics time-series data
- Audit log entries
- User preferences

---

## CLI Reference

```bash
usulnet [command] [flags]

Commands:
  serve           Start the usulnet server
  migrate         Database migration management
  config          Configuration utilities
  admin           Administrative commands
  version         Print version information

# Server
usulnet serve --config config.yaml --mode standalone

# Migrations
usulnet migrate up                    # Apply pending migrations
usulnet migrate down [N]              # Rollback N migrations (default: 1)
usulnet migrate status                # Show migration status

# Config
usulnet config check                  # Validate configuration
usulnet config show                   # Display config (secrets masked)

# Admin
usulnet admin reset-password [PASS]   # Reset admin password (default: usulnet)

# Version
usulnet version                       # Show version, commit, build date
```

---

## Development

### Prerequisites

- Go 1.25+
- Make
- Docker & Docker Compose (for dev services)

### Setup

```bash
# Clone
git clone https://github.com/fr4nsys/usulnet.git
cd usulnet

# Start dev services (PostgreSQL, Redis, NATS, MinIO)
make dev-up

# Install Templ CLI
go install github.com/a-h/templ/cmd/templ@latest

# Full build
make build

# Run
make run
```

### Development Workflow

```bash
# Terminal 1: Watch and regenerate templates
make templ-watch

# Terminal 2: Watch and recompile CSS
make css-watch

# Terminal 3: Run the application
make run
```

### Testing

```bash
# Run all tests with race detection
make test

# Generate HTML coverage report
make test-coverage

# Lint
make lint

# Format
make fmt
```

### Build Targets

```bash
make build           # Build main binary (templ + css + go build)
make build-agent     # Build agent binary
make build-all       # Build both binaries
make frontend        # Regenerate templates + CSS only
make clean           # Clean build artifacts
make docker-build    # Build Docker image
```

---

## Security

### Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Email: [security@usulnet.com](mailto:security@usulnet.com)
3. Include a detailed description and steps to reproduce
4. We will respond within 48 hours

### Security Features Checklist

- [x] JWT authentication with configurable expiry
- [x] API key authentication for programmatic access
- [x] TOTP 2FA with backup codes
- [x] LDAP/Active Directory integration
- [x] OAuth2/OIDC (GitHub, Google, Microsoft, custom)
- [x] RBAC with 44+ granular permissions
- [x] Team-based resource scoping
- [x] AES-256-GCM encryption for secrets at rest
- [x] bcrypt password hashing
- [x] Account lockout after failed logins
- [x] Password complexity policies
- [x] CSRF protection
- [x] Secure cookie settings (HttpOnly, SameSite)
- [x] TLS/HTTPS with auto-generated certificates
- [x] mTLS for inter-node communication
- [x] Rate limiting (configurable per endpoint)
- [x] Comprehensive audit logging
- [x] Trivy vulnerability scanning
- [x] SBOM generation (CycloneDX, SPDX)
- [x] Security scoring (0-100)
- [x] Docker CIS Benchmark compliance checks

---

## License

usulnet is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-or-later).

This means you are free to use, modify, and distribute usulnet, provided that:

- Any modified version that is made available over a network must also be released under AGPL-3.0
- The source code must be made available to users who interact with the software over a network
- All copyright notices and license headers are preserved

For commercial licensing options, contact [license@usulnet.com](mailto:license@usulnet.com).

---

## Contributing

Contributions are welcome. Please read the contributing guidelines before submitting a pull request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'feat: add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

### Commit Convention

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature
fix: resolve bug
docs: update documentation
refactor: restructure code
test: add or update tests
chore: maintenance tasks
```

---

## Acknowledgments

usulnet is built on the shoulders of exceptional open-source projects:

- [Go](https://go.dev) &mdash; The language that makes this possible
- [Docker](https://docker.com) &mdash; Container runtime
- [Chi](https://github.com/go-chi/chi) &mdash; HTTP router
- [Templ](https://templ.guide) &mdash; Type-safe HTML templates
- [Tailwind CSS](https://tailwindcss.com) &mdash; Utility-first CSS
- [Alpine.js](https://alpinejs.dev) &mdash; Lightweight JS framework
- [HTMX](https://htmx.org) &mdash; HTML over the wire
- [xterm.js](https://xtermjs.org) &mdash; Terminal emulator
- [Monaco Editor](https://microsoft.github.io/monaco-editor/) &mdash; Code editor
- [Trivy](https://trivy.dev) &mdash; Vulnerability scanner
- [NATS](https://nats.io) &mdash; Messaging system
- [PostgreSQL](https://postgresql.org) &mdash; Database

---

<p align="center">
  <sub>Built with care for the infrastructure community.</sub><br/>
  <sub><strong>v26.2.0 Beta</strong> &mdash; Found a bug? <a href="https://github.com/fr4nsys/usulnet/issues/new">Report it here</a>. Your feedback makes usulnet better.</sub><br/><br/>
  <a href="https://github.com/fr4nsys/usulnet">GitHub</a>&nbsp;&bull;
  <a href="https://github.com/fr4nsys/usulnet/issues">Issues</a>&nbsp;&bull;
  <a href="https://github.com/fr4nsys/usulnet/discussions">Discussions</a>
</p>
