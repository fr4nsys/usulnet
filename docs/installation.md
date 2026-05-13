# Installation & Deployment Guide

> **usulnet** - Docker Management Platform
> This guide covers all methods to install and run usulnet in production.

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation with Docker Compose (Recommended)](#installation-with-docker-compose)
3. [Installation with Standalone Binary](#installation-with-standalone-binary)
4. [First Access & Initial Setup](#first-access--initial-setup)
5. [HTTPS / TLS Configuration](#https--tls-configuration)
6. [Multi-Host Setup (Master + Agents)](#multi-host-setup-master--agents)
7. [Recon Module (Opt-In)](#recon-module-opt-in)
8. [Upgrading](#upgrading)
9. [Uninstalling](#uninstalling)
10. [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4 cores |
| RAM | 2 GB | 4 GB |
| Disk | 20 GB | 50 GB+ |
| OS | Linux (amd64/arm64) | Ubuntu 22.04+, Debian 12+, RHEL 9+ |

### Software Requirements

| Software | Version | Required For |
|----------|---------|-------------|
| Docker Engine | 24.0+ | Container runtime |
| Docker Compose | v2.20+ | Orchestration (Docker Compose method) |
| Go | 1.25+ | Building from source only |

### Network Requirements

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | TCP | HTTP web interface |
| 7443 | TCP | HTTPS web interface (auto-TLS) |
| 4222 | TCP | NATS (internal, agent communication) |
| 5432 | TCP | PostgreSQL (internal) |
| 6379 | TCP | Redis (internal) |

> **Note:** Ports 4222, 5432, and 6379 are only used internally between containers and are not exposed to the host by default.

---

## Installation with Docker Compose

This is the recommended method for production deployments.

### Step 1: Clone or Download

```bash
# Option A: Clone the repository
git clone https://github.com/fr4nsys/usulnet.git
cd usulnet

# Option B: Download only the compose file
mkdir usulnet && cd usulnet
curl -LO https://raw.githubusercontent.com/fr4nsys/usulnet/main/docker-compose.yml
curl -LO https://raw.githubusercontent.com/fr4nsys/usulnet/main/deploy/.env.example
```

### Step 2: Configure Environment Variables

```bash
cp deploy/.env.example .env
```

Edit `.env` and change the following values:

```bash
# REQUIRED: Generate a secure database password
DB_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)

# Optional: Customize ports
USULNET_HTTP_PORT=8080
USULNET_HTTPS_PORT=7443

# Optional: Set operation mode
# standalone = single host (default)
# master     = multi-host control plane
USULNET_MODE=standalone
```

**Environment Variable Reference:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PASSWORD` | *none* | **Required.** PostgreSQL password |
| `DB_USER` | `usulnet` | PostgreSQL username |
| `DB_NAME` | `usulnet` | PostgreSQL database name |
| `USULNET_VERSION` | `latest` | Docker image tag |
| `USULNET_HTTP_PORT` | `8080` | HTTP port on host |
| `USULNET_HTTPS_PORT` | `7443` | HTTPS port on host |
| `USULNET_MODE` | `standalone` | Operation mode: `standalone` or `master` |
| `HOST_TERMINAL_ENABLED` | `true` | Allow web terminal to Docker host |
| `HOST_TERMINAL_USER` | `nobody` | User for host terminal sessions |
| `AGENT_TOKEN` | `change-me` | Token for agent authentication (multi-host only) |

### Step 3: Start the Stack

```bash
docker compose up -d
```

This starts the following services:
- **usulnet** - Main application server
- **postgres** - PostgreSQL 16 database
- **redis** - Redis 8 cache and session store
- **nats** - NATS 2.12 message broker (JetStream)
- **guacd** - Apache Guacamole daemon (RDP/VNC gateway)

### Step 4: Verify the Installation

Wait for all services to become healthy:

```bash
# Check service status
docker compose ps

# Verify health endpoint
curl -sf http://localhost:8080/health
```

Expected health response:

```json
{
  "status": "healthy",
  "checks": {
    "postgresql": {"status": "up"},
    "redis": {"status": "up"},
    "nats": {"status": "up"},
    "docker": {"status": "up"}
  }
}
```

### Step 5: Access the Web Interface

Open your browser and navigate to:

- HTTP: `http://localhost:8080`
- HTTPS: `https://localhost:7443` (self-signed certificate)

Default credentials:

```
Username: admin
Password: usulnet
```

> **Important:** Change the default password immediately after first login.

---

## Installation with Standalone Binary

For environments where Docker Compose is not desired, you can run usulnet as a standalone binary. You must provide PostgreSQL, Redis, and NATS separately.

### Step 1: Install Prerequisites

Ensure the following services are running and accessible:
- PostgreSQL 16+
- Redis 8+
- NATS 2.12+ (with JetStream enabled)
- Docker Engine 24+

### Step 2: Download the Binary

Download the latest release from the [GitHub Releases](https://github.com/fr4nsys/usulnet/releases) page:

```bash
# Linux amd64
curl -LO https://github.com/fr4nsys/usulnet/releases/latest/download/usulnet-linux-amd64
chmod +x usulnet-linux-amd64
sudo mv usulnet-linux-amd64 /usr/local/bin/usulnet

# Linux arm64
curl -LO https://github.com/fr4nsys/usulnet/releases/latest/download/usulnet-linux-arm64
chmod +x usulnet-linux-arm64
sudo mv usulnet-linux-arm64 /usr/local/bin/usulnet
```

### Step 3: Create Configuration File

Create `config.yaml`:

```yaml
mode: "standalone"

server:
  host: "0.0.0.0"
  port: 8080
  https_port: 7443
  tls:
    enabled: true
    auto_tls: true

database:
  url: "postgres://usulnet:YOUR_PASSWORD@localhost:5432/usulnet?sslmode=disable"
  max_open_conns: 25
  max_idle_conns: 10

redis:
  url: "redis://localhost:6379"

nats:
  url: "nats://localhost:4222"
  jetstream:
    enabled: true

security:
  jwt_secret: "GENERATE_64_HEX_CHARS"
  config_encryption_key: "GENERATE_64_HEX_CHARS"
  password_min_length: 8

storage:
  type: "local"
  path: "/var/lib/usulnet/data"

trivy:
  enabled: true
  cache_dir: "/var/lib/usulnet/trivy"
  severity: "CRITICAL,HIGH,MEDIUM"

logging:
  level: "info"
  format: "json"
```

Generate the required secrets:

```bash
# Generate JWT secret (64 hex characters)
openssl rand -hex 32

# Generate encryption key (64 hex characters)
openssl rand -hex 32
```

### Step 4: Create Database

```bash
# Connect to PostgreSQL and create the database
psql -U postgres -c "CREATE USER usulnet WITH PASSWORD 'YOUR_PASSWORD';"
psql -U postgres -c "CREATE DATABASE usulnet OWNER usulnet;"
```

### Step 5: Run Database Migrations

```bash
usulnet migrate up
```

### Step 6: Start the Server

```bash
# Run in foreground
usulnet serve --config config.yaml

# Or run as a systemd service (see below)
```

### Optional: Systemd Service

Create `/etc/systemd/system/usulnet.service`:

```ini
[Unit]
Description=usulnet Docker Management Platform
After=network.target postgresql.service redis.service nats.service
Requires=docker.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/usulnet serve --config /etc/usulnet/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now usulnet
sudo systemctl status usulnet
```

---

## First Access & Initial Setup

1. Open the web interface at `http://localhost:8080` (or your configured URL)
2. Log in with the default credentials: `admin` / `usulnet`
3. **Change the admin password immediately** via the profile page
4. Configure system settings in **Admin > Settings**:
   - Set the platform name and base URL
   - Configure email/SMTP for notifications (optional)
   - Configure backup storage (optional)
   - Set up LDAP authentication if required (requires Business/Enterprise license)

---

## HTTPS / TLS Configuration

### Auto-Generated Self-Signed Certificate (Default)

usulnet automatically generates a self-signed TLS certificate when `auto_tls: true` is set. Access the platform via `https://localhost:7443`. Browsers will show a certificate warning.

### Let's Encrypt (Recommended for Production)

For production, place usulnet behind a reverse proxy (Caddy, Nginx, Traefik) with Let's Encrypt:

```yaml
# Example with Caddy as reverse proxy
# Caddyfile
yourdomain.com {
    reverse_proxy localhost:8080
}
```

### Custom Certificate

To use your own certificate:

```yaml
# config.yaml
server:
  tls:
    enabled: true
    auto_tls: false
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"
```

With Docker Compose, mount the certificates:

```yaml
volumes:
  - ./certs/cert.pem:/app/certs/cert.pem:ro
  - ./certs/key.pem:/app/certs/key.pem:ro
```

---

## Multi-Host Setup (Master + Agents)

usulnet supports managing multiple Docker hosts through a master-agent architecture using NATS JetStream.

### Configure the Master

Set the mode to `master` on the control plane host:

```bash
# .env
USULNET_MODE=master
AGENT_TOKEN=your-secure-agent-token
```

```bash
docker compose up -d
```

### Deploy an Agent on a Remote Host

On each remote host you want to manage:

```bash
docker run -d \
  --name usulnet-agent \
  --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock \
  usulnet/usulnet-agent:latest \
  --gateway nats://MASTER_IP:4222 \
  --token your-secure-agent-token
```

Or use the agent profile in Docker Compose:

```bash
docker compose --profile agent up -d
```

> For detailed agent configuration, see [Agent Configuration Guide](agents.md).

---

## Recon Module (Opt-In)

The v26.5.0 recon and metadata module ships **off by default**. A fresh install (or an upgrade from v26.4.x) behaves exactly like a Docker-management-only deployment unless an administrator explicitly turns it on. Setting `USULNET_RECON_ENABLED=true` (or `recon.enabled: true` in `config.yaml`) is necessary but not sufficient: every `/recon/*` and `/metadata/*` route returns `409 acknowledgement_required` until an admin signs the in-app legal notice, and the SpiderFoot + recon-toolkit containers are only pulled and started after that acknowledgement is recorded in the audit log. Before flipping the flag in production, read [`docs/v26.5/security-review-checklist.md`](v26.5/security-review-checklist.md) &mdash; it cites the `file:line` of every sandbox control (capability drop, read-only rootfs, seccomp default, egress allow-list, retention worker, append-only audit log) and links the unit test that exercises it.

---

## Upgrading

### Docker Compose

```bash
# Pull new images
docker compose pull

# Restart with new images (migrations run automatically)
docker compose up -d

# Verify health
docker compose ps
curl -sf http://localhost:8080/health
```

### Standalone Binary

```bash
# Download new binary
curl -LO https://github.com/fr4nsys/usulnet/releases/latest/download/usulnet-linux-amd64

# Stop the service
sudo systemctl stop usulnet

# Replace binary
sudo mv usulnet-linux-amd64 /usr/local/bin/usulnet
sudo chmod +x /usr/local/bin/usulnet

# Run migrations
usulnet migrate up --config /etc/usulnet/config.yaml

# Start the service
sudo systemctl start usulnet
```

---

## Uninstalling

### Docker Compose

```bash
# Stop and remove containers
docker compose down

# Remove all data (WARNING: destructive)
docker compose down -v
```

### Standalone Binary

```bash
sudo systemctl stop usulnet
sudo systemctl disable usulnet
sudo rm /etc/systemd/system/usulnet.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/usulnet
sudo rm -rf /etc/usulnet /var/lib/usulnet
```

---

## Troubleshooting

### Docker Socket Permission Denied

```
Error: permission denied while trying to connect to the Docker daemon socket
```

**Solution:** Ensure the usulnet container has access to the Docker socket. The container runs an entrypoint script that adjusts the Docker socket group. If you still see errors:

```bash
# Check Docker socket permissions on the host
ls -la /var/run/docker.sock

# Ensure the docker group exists and the container uses it
docker compose restart usulnet
```

### Database Connection Failed

```
Error: connection refused (PostgreSQL)
```

**Solutions:**
- Verify PostgreSQL is running: `docker compose ps postgres`
- Check database password matches in `.env`
- Check logs: `docker compose logs postgres`
- Verify the database was created: `docker exec -it usulnet-postgres psql -U usulnet -c '\l'`

### Port Already in Use

```
Error: bind: address already in use
```

**Solution:** Change the port in `.env`:

```bash
USULNET_HTTP_PORT=9090
USULNET_HTTPS_PORT=9443
```

### NATS Connection Issues

```
Error: nats: no servers available for connection
```

**Solutions:**
- Verify NATS is running: `docker compose ps nats`
- Check NATS health: `curl http://localhost:8222/healthz` (if port exposed)
- Check logs: `docker compose logs nats`
- Ensure JetStream is enabled (default in the compose file)

### Redis Connection Issues

```
Error: dial tcp: connection refused (Redis)
```

**Solutions:**
- Verify Redis is running: `docker compose ps redis`
- Check logs: `docker compose logs redis`
- Verify Redis responds: `docker exec usulnet-redis redis-cli ping`

### Migrations Failed

```
Error: migration failed
```

**Solutions:**
- Check migration status: `usulnet migrate status` (standalone) or check container logs
- Verify database connectivity
- Check for advisory lock conflicts if running multiple instances:
  ```bash
  docker exec -it usulnet-postgres psql -U usulnet -c "SELECT * FROM pg_locks WHERE locktype = 'advisory';"
  ```

### Container Logs Show "Unhealthy" Dependencies

If usulnet reports unhealthy dependencies at startup:

```bash
# Check all service health
docker compose ps

# View detailed logs
docker compose logs -f usulnet

# Restart problematic service
docker compose restart <service-name>
```

### Memory Issues

If you see OOM kills, adjust resource limits in `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      memory: 2G  # Increase from default 1G
```

---

*For more information, see the [Architecture Guide](architecture.md) and [Development Guide](development.md).*
