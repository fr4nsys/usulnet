# Agent Configuration Guide

> **usulnet** - Docker Management Platform
> Guide for deploying and configuring agents for multi-host Docker management.

---

## Table of Contents

1. [Overview](#overview)
2. [Agent Requirements](#agent-requirements)
3. [Installation Methods](#installation-methods)
4. [Configuration Reference](#configuration-reference)
5. [Connecting to the Master](#connecting-to-the-master)
6. [Security](#security)
7. [Agent Operations](#agent-operations)
8. [Monitoring Agent Health](#monitoring-agent-health)
9. [Upgrading Agents](#upgrading-agents)
10. [Troubleshooting](#troubleshooting)

---

## Overview

The usulnet agent is a lightweight binary that runs on remote Docker hosts and connects to a usulnet master instance via NATS JetStream. The agent enables centralized management of Docker containers, images, volumes, and networks across multiple hosts from a single web interface.

### Architecture

```
+--------------------+         NATS JetStream          +--------------------+
|   Master (usulnet) | <=============================> |  Agent (usulnet-   |
|                    |      Commands & Results          |   agent)           |
|  - Web UI          |                                  |  - Docker SDK      |
|  - REST API        |                                  |  - Command executor|
|  - PostgreSQL      |                                  |  - Inventory        |
|  - Redis           |                                  |    collector       |
+--------------------+                                  +--------------------+
                                                               |
                                                        +------v------+
                                                        | Docker      |
                                                        | Engine      |
                                                        +-------------+
```

### What the Agent Does

- Reports container and image inventory to the master
- Executes Docker operations (start, stop, pull, deploy, etc.) on behalf of the master
- Sends periodic heartbeats to indicate availability
- Streams container logs back to the master
- Executes security scans when requested
- Runs backup operations on local volumes

---

## Agent Requirements

### System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 core | 2 cores |
| RAM | 64 MB | 256 MB |
| Disk | 1 GB | 5 GB |
| OS | Linux (amd64/arm64) | Ubuntu 22.04+, Debian 12+ |

### Software Requirements

| Software | Version | Purpose |
|----------|---------|---------|
| Docker Engine | 24.0+ | Container runtime (required) |

### Network Requirements

| Direction | Port | Protocol | Purpose |
|-----------|------|----------|---------|
| Agent -> Master | 4222 | TCP | NATS connection (outbound) |

> **Note:** The agent only makes outbound connections to the master's NATS port. No inbound ports need to be opened on the agent host.

---

## Installation Methods

### Method 1: Docker (Recommended)

The simplest way to deploy an agent is as a Docker container:

```bash
docker run -d \
  --name usulnet-agent \
  --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v usulnet_agent_data:/app/data \
  usulnet/usulnet-agent:latest \
  --gateway nats://MASTER_HOST:4222 \
  --token YOUR_AGENT_TOKEN
```

**Required flags:**
- `--gateway` - NATS URL of the master instance
- `--token` - Authentication token (generated on the master)

**Required volumes:**
- `/var/run/docker.sock` - Docker socket for container management

### Method 2: Docker Compose

Add the agent to your existing Docker Compose setup:

```yaml
services:
  usulnet-agent:
    image: usulnet/usulnet-agent:latest
    container_name: usulnet-agent
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - agent_data:/app/data
    environment:
      - USULNET_GATEWAY_URL=nats://MASTER_HOST:4222
      - USULNET_AGENT_TOKEN=YOUR_AGENT_TOKEN
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: "0.5"

volumes:
  agent_data:
```

### Method 3: Standalone Binary

Download the agent binary from [GitHub Releases](https://github.com/fr4nsys/usulnet/releases):

```bash
# Linux amd64
curl -LO https://github.com/fr4nsys/usulnet/releases/latest/download/usulnet-agent-linux-amd64
chmod +x usulnet-agent-linux-amd64
sudo mv usulnet-agent-linux-amd64 /usr/local/bin/usulnet-agent

# Linux arm64
curl -LO https://github.com/fr4nsys/usulnet/releases/latest/download/usulnet-agent-linux-arm64
chmod +x usulnet-agent-linux-arm64
sudo mv usulnet-agent-linux-arm64 /usr/local/bin/usulnet-agent
```

Run the agent:

```bash
usulnet-agent \
  --gateway nats://MASTER_HOST:4222 \
  --token YOUR_AGENT_TOKEN \
  --docker unix:///var/run/docker.sock
```

### Method 4: Systemd Service (Binary)

Create `/etc/systemd/system/usulnet-agent.service`:

```ini
[Unit]
Description=usulnet Remote Agent
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/usulnet-agent \
  --gateway nats://MASTER_HOST:4222 \
  --token YOUR_AGENT_TOKEN \
  --docker unix:///var/run/docker.sock \
  --log-level info \
  --log-format json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now usulnet-agent
sudo systemctl status usulnet-agent
```

---

## Configuration Reference

### CLI Flags

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--gateway` | `USULNET_GATEWAY_URL` | `nats://localhost:4222` | NATS server URL of the master |
| `--token` | `USULNET_AGENT_TOKEN` | *none* | **Required.** Agent authentication token |
| `--docker` | `USULNET_DOCKER_HOST` | `unix:///var/run/docker.sock` | Docker socket path |
| `--hostname` | `USULNET_HOSTNAME` | *auto-detected* | Override the reported hostname |
| `--config` | -- | -- | Path to YAML config file |
| `--data-dir` | `USULNET_DATA_DIR` | `/app/data` | Local state directory |
| `--log-level` | `USULNET_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--log-format` | `USULNET_LOG_FORMAT` | `json` | Log format: `json`, `console` |
| `--version` | -- | -- | Show version and exit |

### YAML Configuration File

The agent can also be configured via a YAML file (`config.agent.yaml`):

```yaml
# NATS connection to the master
gateway_url: "nats://master.example.com:4222"

# Authentication token (generated on master)
token: "your-secure-agent-token"

# Docker socket
docker_host: "unix:///var/run/docker.sock"

# Override hostname (auto-detected if empty)
hostname: ""

# Agent ID (auto-generated UUID if empty)
agent_id: ""

# Custom labels for agent categorization
labels:
  environment: "production"
  datacenter: "us-east-1"
  tier: "web"

# Local data directory
data_dir: "/var/lib/usulnet-agent"

# Logging
log_level: "info"
log_format: "json"

# TLS configuration for NATS (optional)
tls:
  enabled: false
  cert_file: "/etc/usulnet-agent/certs/agent.crt"
  key_file: "/etc/usulnet-agent/certs/agent.key"
  ca_file: "/etc/usulnet-agent/certs/ca.crt"
```

**Priority order** (highest first):
1. CLI flags
2. Environment variables
3. YAML config file
4. Defaults

---

## Connecting to the Master

### Step 1: Configure the Master for Multi-Host Mode

On the master, set the operation mode to `master`:

```bash
# .env (Docker Compose)
USULNET_MODE=master
```

Or in `config.yaml`:

```yaml
mode: "master"
```

### Step 2: Generate an Agent Token

Agent tokens are used to authenticate agents connecting to the master. Generate a secure token:

```bash
openssl rand -hex 32
```

Set this token on both the master and agent:

**Master (.env):**
```bash
AGENT_TOKEN=your-generated-token
```

**Agent:**
```bash
usulnet-agent --gateway nats://master:4222 --token your-generated-token
```

### Step 3: Expose NATS Port on the Master

Ensure the NATS port (4222) is accessible from agent hosts. In Docker Compose, add port mapping:

```yaml
# docker-compose.yml - NATS service
nats:
  ports:
    - "4222:4222"  # Expose for remote agents
```

> **Security Warning:** Only expose NATS to trusted networks. Use TLS for production deployments (see [Security](#security)).

### Step 4: Verify Connection

After starting the agent, verify the connection on the master:

1. Open the web interface
2. Navigate to **Hosts** in the sidebar
3. The agent should appear as a connected host
4. Check the agent's containers and images are visible

---

## Security

### Authentication

Agents authenticate with the master using a shared token. The token is sent with every NATS connection and verified by the master's gateway.

**Best practices:**
- Use a strong, random token (minimum 32 characters)
- Rotate tokens periodically
- Use different tokens for different environments

### TLS Encryption

For production deployments, enable TLS to encrypt the NATS connection between master and agents:

**Agent configuration:**

```yaml
tls:
  enabled: true
  cert_file: "/etc/usulnet-agent/certs/agent.crt"
  key_file: "/etc/usulnet-agent/certs/agent.key"
  ca_file: "/etc/usulnet-agent/certs/ca.crt"
```

**NATS server configuration (on master):**

```
# nats-server.conf
tls {
  cert_file: "/etc/nats/certs/server.crt"
  key_file: "/etc/nats/certs/server.key"
  ca_file: "/etc/nats/certs/ca.crt"
  verify: true
}
```

### Credential Security

- Registry credentials (for private Docker registries) are transmitted encrypted from master to agent
- Credentials are never persisted to disk on the agent
- All sensitive data in transit uses the platform's encryption layer (`internal/pkg/crypto/` - AES-256-GCM)

### Network Security

- Agents only make **outbound** connections (no listening ports required)
- Use firewall rules to restrict NATS port access to known agent IPs
- Consider using a VPN or private network for agent-master communication

---

## Agent Operations

### Container Management

Once connected, the master can remotely manage containers on the agent:

- List containers (with filters: status, name, image)
- Start, stop, restart, pause, unpause containers
- View container logs (streaming)
- Execute commands in containers (exec)
- Create new containers
- Remove containers

### Image Management

- List available images (with tags, size, creation date)
- Pull images from registries (including private registries)
- Remove images
- Image pull progress reporting

### Backup Operations

Agents can execute volume backup operations locally when backup is enabled. The master orchestrates:
- Backup scheduling
- Storage provider selection (local, S3, Azure)
- Retention policy enforcement

### Security Scanning

Agents can run Trivy security scans on local containers and images. Results are reported back to the master for centralized tracking.

### Inventory Collection

The agent periodically collects and reports inventory to the master:
- Running and stopped containers
- Available images
- Volume and network information
- Host metrics (CPU, memory, disk)

---

## Monitoring Agent Health

### From the Web Interface

Navigate to **Hosts** to see all connected agents with:
- Connection status (connected/disconnected)
- Last heartbeat time
- Container count
- Resource utilization

### From Logs

Agent logs include connection events:

```json
{"level":"info","msg":"Connected to gateway","url":"nats://master:4222"}
{"level":"info","msg":"Agent registered","agent_id":"abc-123","hostname":"worker-01"}
{"level":"info","msg":"Heartbeat sent","active_jobs":0}
```

### Health Indicators

| Status | Meaning |
|--------|---------|
| **Connected** | Agent is active and responding to heartbeats |
| **Disconnected** | Agent has not sent a heartbeat recently (>5 minutes) |
| **Reconnecting** | Agent lost connection and is attempting to reconnect |

### Notifications

Configure notification channels (Slack, Email, Webhook) on the master to receive alerts when agents disconnect. This can be configured in **Admin > Notification Channels**.

---

## Upgrading Agents

### Docker Agent

```bash
# Pull the new image
docker pull usulnet/usulnet-agent:latest

# Restart the agent
docker restart usulnet-agent
```

Or with Docker Compose:

```bash
docker compose pull usulnet-agent
docker compose up -d usulnet-agent
```

### Binary Agent

```bash
# Download new binary
curl -LO https://github.com/fr4nsys/usulnet/releases/latest/download/usulnet-agent-linux-amd64

# Stop the agent
sudo systemctl stop usulnet-agent

# Replace binary
sudo mv usulnet-agent-linux-amd64 /usr/local/bin/usulnet-agent
sudo chmod +x /usr/local/bin/usulnet-agent

# Start the agent
sudo systemctl start usulnet-agent
```

### Version Compatibility

Agents should generally run the same version as the master. Minor version differences are tolerated, but major version differences may cause protocol incompatibilities.

---

## Troubleshooting

### Agent Cannot Connect to Master

**Symptoms:** Agent logs show connection errors or timeouts.

**Checklist:**
1. Verify NATS is running on the master: `docker compose ps nats`
2. Verify NATS port is accessible from agent host: `nc -zv MASTER_HOST 4222`
3. Verify the token matches between master and agent
4. Check firewall rules between agent and master
5. If using TLS, verify certificates are valid and trusted

```bash
# Test NATS connectivity from agent host
nc -zv master.example.com 4222

# Check agent logs
docker logs usulnet-agent
# or
journalctl -u usulnet-agent -f
```

### Agent Connects but Disconnects Frequently

**Symptoms:** Agent oscillates between connected and disconnected state.

**Possible causes:**
- Network instability between agent and master
- NATS server resource exhaustion
- Agent host under heavy load

**Solutions:**
- Check network quality (latency, packet loss)
- Increase NATS max payload if large operations are failing
- Check agent resource usage: `docker stats usulnet-agent`
- Review NATS monitoring: `curl http://MASTER_HOST:8222/connz`

### Agent Connected but No Containers Visible

**Symptoms:** Agent appears connected in the Hosts page but shows 0 containers.

**Checklist:**
1. Verify Docker socket is mounted: `docker exec usulnet-agent ls -la /var/run/docker.sock`
2. Verify Docker is running on the agent host: `docker ps`
3. Check agent logs for Docker connection errors
4. Verify agent has permission to access the Docker socket

```bash
# Test Docker access from inside the agent container
docker exec usulnet-agent docker ps
```

### Docker Socket Permission Denied

**Symptoms:** Agent logs show `permission denied` when accessing Docker.

**Solutions:**
```bash
# Check Docker socket permissions
ls -la /var/run/docker.sock

# If using a binary agent, ensure it runs as root
# or add the user to the docker group
sudo usermod -aG docker usulnet-agent
```

### Agent Uses Too Much Memory

**Symptoms:** Agent container uses more memory than expected.

**Solutions:**
- Set memory limits in Docker Compose:
  ```yaml
  deploy:
    resources:
      limits:
        memory: 256M
  ```
- Reduce log level to `warn` or `error`
- Check if there are many large log streaming operations

### TLS Certificate Errors

**Symptoms:** `x509: certificate signed by unknown authority` or similar TLS errors.

**Solutions:**
1. Ensure the CA certificate is correctly mounted and referenced
2. Verify the certificate is not expired: `openssl x509 -in cert.pem -noout -dates`
3. Verify the certificate matches the hostname: `openssl x509 -in cert.pem -noout -subject`
4. If using self-signed certificates, ensure the CA is trusted by both sides

---

*For more information, see the [Installation Guide](installation.md) and [Architecture Guide](architecture.md).*
