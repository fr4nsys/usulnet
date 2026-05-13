# API Documentation

> **usulnet** - Docker Management Platform
> REST API Reference (v1)

---

## Table of Contents

1. [Overview](#overview)
2. [Base URL](#base-url)
3. [Authentication](#authentication)
4. [Common Patterns](#common-patterns)
5. [Endpoints Reference](#endpoints-reference)
   - [Health & System](#health--system)
   - [Authentication](#authentication-endpoints)
   - [Containers](#containers)
   - [Images](#images)
   - [Volumes](#volumes)
   - [Networks](#networks)
   - [Stacks](#stacks)
   - [Hosts](#hosts)
   - [Security](#security)
   - [Backups](#backups)
   - [Configuration](#configuration)
   - [Updates](#updates)
   - [Jobs](#jobs)
   - [Notifications](#notifications)
   - [SSH](#ssh)
   - [Proxy](#proxy)
   - [Users (Admin)](#users-admin)
   - [Audit (Admin)](#audit-admin)
   - [Settings (Admin)](#settings-admin)
   - [License (Admin)](#license-admin)
   - [WebSocket](#websocket)
6. [Error Handling](#error-handling)
7. [Pagination, Filtering & Sorting](#pagination-filtering--sorting)
8. [Rate Limiting](#rate-limiting)
9. [OpenAPI Specification](#openapi-specification)

---

## Overview

The usulnet API is a RESTful HTTP API served under `/api/v1`. All endpoints return JSON responses. The API uses JWT tokens for authentication and supports API key authentication for programmatic access.

**Key characteristics:**
- JSON request/response format
- JWT Bearer token authentication
- Role-based access control (Viewer, Operator, Admin)
- Rate limiting per endpoint category
- Pagination for list endpoints
- WebSocket support for real-time operations

---

## Base URL

```
http://localhost:8080/api/v1
```

Or with HTTPS:

```
https://localhost:7443/api/v1
```

---

## Authentication

### Obtaining a JWT Token

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-password"
  }'
```

Response:

```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_at": "2026-02-15T14:00:00Z",
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "username": "admin",
      "role": "admin"
    }
  }
}
```

### Using the Token

Include the JWT token in the `Authorization` header:

```bash
curl http://localhost:8080/api/v1/containers \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

Alternative methods (less preferred):
- Query parameter: `?token=eyJhbGciOiJIUzI1NiIs...`
- Cookie: `auth_token=eyJhbGciOiJIUzI1NiIs...`

### Refreshing a Token

```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
  }'
```

### API Key Authentication

API keys can be used as an alternative to JWT tokens for programmatic access. Create an API key in the web interface under **Profile > API Keys**.

```bash
curl http://localhost:8080/api/v1/containers \
  -H "Authorization: Bearer usulnet_apikey_..."
```

### Roles and Permissions

| Role | Description | Access Level |
|------|-------------|-------------|
| **Admin** | Full access to all operations | All endpoints |
| **Operator** | Can perform mutations on resources | Read/write on Docker resources, proxy |
| **Viewer** | Read-only access to resources | Read-only on Docker resources |

---

## Common Patterns

### Request Format

All request bodies must be JSON with the `Content-Type: application/json` header.

### Success Response

```json
{
  "success": true,
  "data": { ... }
}
```

### List Response

```json
{
  "success": true,
  "data": [ ... ],
  "pagination": {
    "total": 150,
    "page": 1,
    "per_page": 20,
    "total_pages": 8
  }
}
```

### Error Response

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request body",
    "details": [
      {"field": "name", "message": "name is required"}
    ]
  }
}
```

---

## Endpoints Reference

### Health & System

Health endpoints do not require authentication.

#### `GET /health`

Full system health check including all dependencies.

```bash
curl http://localhost:8080/health
```

```json
{
  "status": "healthy",
  "checks": {
    "postgresql": {"status": "up", "latency_ms": 2},
    "redis": {"status": "up", "latency_ms": 1},
    "nats": {"status": "up", "latency_ms": 1},
    "docker": {"status": "up", "version": "27.5.1"}
  }
}
```

#### `GET /healthz`

Kubernetes liveness probe. Returns `200 OK` if the process is alive.

```bash
curl http://localhost:8080/healthz
```

#### `GET /ready`

Kubernetes readiness probe. Returns `200 OK` when the application is ready to serve traffic (migrations applied, dependencies connected).

```bash
curl http://localhost:8080/ready
```

#### `GET /api/v1/system/version`

Returns the application version. No authentication required.

```bash
curl http://localhost:8080/api/v1/system/version
```

#### `GET /api/v1/system/info`

Returns detailed system information. Requires authentication (viewer+).

```bash
curl http://localhost:8080/api/v1/system/info \
  -H "Authorization: Bearer $TOKEN"
```

#### `GET /metrics`

Prometheus metrics endpoint. No authentication required (for scraper access).

```bash
curl http://localhost:8080/metrics
```

---

### Authentication Endpoints

#### `POST /api/v1/auth/login`

Authenticate a user and obtain JWT tokens.

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'
```

**TOTP (2FA):** If the user has TOTP enabled, include the code:

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password", "totp_code": "123456"}'
```

#### `POST /api/v1/auth/refresh`

Refresh an expired JWT token.

```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJ..."}'
```

#### `POST /api/v1/auth/logout`

Invalidate the current token (adds to JWT blacklist).

```bash
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/password-reset/request`

Request a password reset email.

```bash
curl -X POST http://localhost:8080/api/v1/password-reset/request \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

#### `POST /api/v1/password-reset/confirm`

Reset password with a valid token.

```bash
curl -X POST http://localhost:8080/api/v1/password-reset/confirm \
  -H "Content-Type: application/json" \
  -d '{"token": "reset-token", "new_password": "new-secure-password"}'
```

---

### Containers

All container endpoints require authentication (viewer+ for reads, internal RBAC for writes).

#### `GET /api/v1/containers`

List all containers.

```bash
curl http://localhost:8080/api/v1/containers \
  -H "Authorization: Bearer $TOKEN"
```

Query parameters: `?status=running&name=web&host_id=<uuid>&page=1&per_page=20`

#### `GET /api/v1/containers/{id}`

Get container details.

```bash
curl http://localhost:8080/api/v1/containers/abc123 \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/containers`

Create a new container.

```bash
curl -X POST http://localhost:8080/api/v1/containers \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-container",
    "image": "nginx:latest",
    "ports": [{"host": 80, "container": 80}],
    "env": {"KEY": "value"},
    "restart_policy": "unless-stopped"
  }'
```

#### `POST /api/v1/containers/{id}/start`

Start a stopped container.

```bash
curl -X POST http://localhost:8080/api/v1/containers/abc123/start \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/containers/{id}/stop`

Stop a running container.

```bash
curl -X POST http://localhost:8080/api/v1/containers/abc123/stop \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/containers/{id}/restart`

Restart a container.

```bash
curl -X POST http://localhost:8080/api/v1/containers/abc123/restart \
  -H "Authorization: Bearer $TOKEN"
```

#### `DELETE /api/v1/containers/{id}`

Remove a container.

```bash
curl -X DELETE http://localhost:8080/api/v1/containers/abc123 \
  -H "Authorization: Bearer $TOKEN"
```

#### `GET /api/v1/containers/{id}/logs`

Get container logs.

```bash
curl "http://localhost:8080/api/v1/containers/abc123/logs?tail=100&since=1h" \
  -H "Authorization: Bearer $TOKEN"
```

#### `GET /api/v1/containers/{id}/stats`

Get container resource statistics.

```bash
curl http://localhost:8080/api/v1/containers/abc123/stats \
  -H "Authorization: Bearer $TOKEN"
```

---

### Images

#### `GET /api/v1/images`

List all Docker images.

```bash
curl http://localhost:8080/api/v1/images \
  -H "Authorization: Bearer $TOKEN"
```

#### `GET /api/v1/images/{id}`

Get image details including layer history.

```bash
curl http://localhost:8080/api/v1/images/sha256:abc123 \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/images/pull`

Pull an image from a registry.

```bash
curl -X POST http://localhost:8080/api/v1/images/pull \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"image": "nginx", "tag": "latest"}'
```

#### `DELETE /api/v1/images/{id}`

Remove an image.

```bash
curl -X DELETE http://localhost:8080/api/v1/images/sha256:abc123 \
  -H "Authorization: Bearer $TOKEN"
```

---

### Volumes

#### `GET /api/v1/volumes`

List all Docker volumes.

```bash
curl http://localhost:8080/api/v1/volumes \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/volumes`

Create a new volume.

```bash
curl -X POST http://localhost:8080/api/v1/volumes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-volume", "driver": "local"}'
```

#### `DELETE /api/v1/volumes/{name}`

Remove a volume.

```bash
curl -X DELETE http://localhost:8080/api/v1/volumes/my-volume \
  -H "Authorization: Bearer $TOKEN"
```

---

### Networks

#### `GET /api/v1/networks`

List all Docker networks.

```bash
curl http://localhost:8080/api/v1/networks \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/networks`

Create a new network.

```bash
curl -X POST http://localhost:8080/api/v1/networks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-network", "driver": "bridge"}'
```

#### `DELETE /api/v1/networks/{id}`

Remove a network.

```bash
curl -X DELETE http://localhost:8080/api/v1/networks/abc123 \
  -H "Authorization: Bearer $TOKEN"
```

---

### Stacks

#### `GET /api/v1/stacks`

List all stacks (Docker Compose deployments).

```bash
curl http://localhost:8080/api/v1/stacks \
  -H "Authorization: Bearer $TOKEN"
```

#### `GET /api/v1/stacks/{id}`

Get stack details.

```bash
curl http://localhost:8080/api/v1/stacks/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/stacks`

Deploy a new stack from a Compose file.

```bash
curl -X POST http://localhost:8080/api/v1/stacks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-stack",
    "compose_file": "version: \"3.8\"\nservices:\n  web:\n    image: nginx:latest\n    ports:\n      - \"80:80\"",
    "env": {"KEY": "value"}
  }'
```

#### `PUT /api/v1/stacks/{id}`

Update a running stack.

```bash
curl -X PUT http://localhost:8080/api/v1/stacks/550e8400-... \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"compose_file": "...", "env": {}}'
```

#### `DELETE /api/v1/stacks/{id}`

Remove a stack and its containers.

```bash
curl -X DELETE http://localhost:8080/api/v1/stacks/550e8400-... \
  -H "Authorization: Bearer $TOKEN"
```

---

### Hosts

#### `GET /api/v1/hosts`

List all managed hosts.

```bash
curl http://localhost:8080/api/v1/hosts \
  -H "Authorization: Bearer $TOKEN"
```

#### `GET /api/v1/hosts/{id}`

Get host details and metrics.

```bash
curl http://localhost:8080/api/v1/hosts/550e8400-... \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/hosts`

Register a new host.

```bash
curl -X POST http://localhost:8080/api/v1/hosts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "production-01", "hostname": "192.168.1.10", "type": "agent"}'
```

#### `DELETE /api/v1/hosts/{id}`

Remove a host from management.

```bash
curl -X DELETE http://localhost:8080/api/v1/hosts/550e8400-... \
  -H "Authorization: Bearer $TOKEN"
```

---

### Security

#### `GET /api/v1/security/scans`

List security scan results.

```bash
curl http://localhost:8080/api/v1/security/scans \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/security/scan`

Trigger a security scan on a container or image.

```bash
curl -X POST http://localhost:8080/api/v1/security/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "container_id_or_image", "type": "container"}'
```

#### `GET /api/v1/security/scans/{id}`

Get detailed scan results including vulnerabilities.

```bash
curl http://localhost:8080/api/v1/security/scans/550e8400-... \
  -H "Authorization: Bearer $TOKEN"
```

---

### Backups

#### `GET /api/v1/backups`

List all backups.

```bash
curl http://localhost:8080/api/v1/backups \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/backups`

Create a new backup.

```bash
curl -X POST http://localhost:8080/api/v1/backups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "daily-backup", "type": "volume", "target": "my-volume"}'
```

#### `POST /api/v1/backups/{id}/restore`

Restore from a backup.

```bash
curl -X POST http://localhost:8080/api/v1/backups/550e8400-.../restore \
  -H "Authorization: Bearer $TOKEN"
```

---

### Configuration

#### `GET /api/v1/config/variables`

List configuration variables.

```bash
curl http://localhost:8080/api/v1/config/variables \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/config/variables`

Create or update a configuration variable.

```bash
curl -X POST http://localhost:8080/api/v1/config/variables \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "APP_ENV", "value": "production", "encrypted": false}'
```

---

### Updates

#### `GET /api/v1/updates`

Check for available updates.

```bash
curl http://localhost:8080/api/v1/updates \
  -H "Authorization: Bearer $TOKEN"
```

---

### Jobs

#### `GET /api/v1/jobs`

List scheduled and completed jobs.

```bash
curl http://localhost:8080/api/v1/jobs \
  -H "Authorization: Bearer $TOKEN"
```

---

### Notifications

#### `GET /api/v1/notifications/channels`

List notification channels.

```bash
curl http://localhost:8080/api/v1/notifications/channels \
  -H "Authorization: Bearer $TOKEN"
```

---

### SSH

#### `GET /api/v1/ssh/connections`

List SSH connections.

```bash
curl http://localhost:8080/api/v1/ssh/connections \
  -H "Authorization: Bearer $TOKEN"
```

---

### Proxy

Proxy endpoints manage the reverse proxy (Caddy or Nginx Proxy Manager).

#### `GET /api/v1/proxy/health`

Check proxy backend health.

```bash
curl http://localhost:8080/api/v1/proxy/health \
  -H "Authorization: Bearer $TOKEN"
```

#### `GET /api/v1/proxy/hosts`

List proxy hosts.

```bash
curl http://localhost:8080/api/v1/proxy/hosts \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /api/v1/proxy/hosts`

Create a proxy host (operator+ required).

```bash
curl -X POST http://localhost:8080/api/v1/proxy/hosts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "app.example.com",
    "forward_host": "192.168.1.10",
    "forward_port": 3000,
    "ssl": true
  }'
```

#### `PUT /api/v1/proxy/hosts/{id}`

Update a proxy host (operator+ required).

#### `DELETE /api/v1/proxy/hosts/{id}`

Delete a proxy host (operator+ required).

#### `GET /api/v1/proxy/certificates`

List SSL certificates.

#### `POST /api/v1/proxy/certificates`

Upload a custom SSL certificate (operator+ required).

---

### Users (Admin)

Admin-only endpoints for user management.

#### `GET /api/v1/users`

List all users.

```bash
curl http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

#### `POST /api/v1/users`

Create a new user.

```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "password": "secure-password", "role": "operator"}'
```

#### `PUT /api/v1/users/{id}`

Update a user.

#### `DELETE /api/v1/users/{id}`

Delete a user.

---

### Audit (Admin)

#### `GET /api/v1/audit`

List audit log entries. Admin-only.

```bash
curl "http://localhost:8080/api/v1/audit?page=1&per_page=50" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

### Settings (Admin)

#### `GET /api/v1/settings`

Get current system settings. Admin-only.

```bash
curl http://localhost:8080/api/v1/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

#### `PUT /api/v1/settings`

Update system settings. Admin-only.

```bash
curl -X PUT http://localhost:8080/api/v1/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"session_timeout": "24h", "max_login_attempts": 5}'
```

#### `GET /api/v1/settings/ldap`

Get LDAP configuration. Requires LDAP feature license.

#### `PUT /api/v1/settings/ldap`

Update LDAP configuration.

#### `POST /api/v1/settings/ldap/test`

Test LDAP connection with provided parameters.

```bash
curl -X POST http://localhost:8080/api/v1/settings/ldap/test \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "ldap.example.com",
    "port": 389,
    "base_dn": "dc=example,dc=com",
    "bind_dn": "cn=admin,dc=example,dc=com",
    "bind_password": "password"
  }'
```

---

### License (Admin)

#### `GET /api/v1/license`

Get current license information. Admin-only.

```bash
curl http://localhost:8080/api/v1/license \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

#### `POST /api/v1/license`

Activate a new license. Admin-only.

```bash
curl -X POST http://localhost:8080/api/v1/license \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"license_key": "eyJhbGciOiJSUzUxMiIs..."}'
```

#### `DELETE /api/v1/license`

Deactivate the current license (reverts to Community Edition). Admin-only.

```bash
curl -X DELETE http://localhost:8080/api/v1/license \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"confirm": true}'
```

---

### WebSocket

WebSocket endpoints are available at `/api/v1/ws` for real-time operations.

#### Container Logs Streaming

```
ws://localhost:8080/api/v1/ws/containers/{id}/logs
```

#### Web Terminal

```
ws://localhost:8080/api/v1/ws/terminal
```

#### Real-time Stats

```
ws://localhost:8080/api/v1/ws/stats
```

**WebSocket Authentication:** Include the JWT token as a query parameter:

```
ws://localhost:8080/api/v1/ws/containers/abc123/logs?token=eyJ...
```

---

## Error Handling

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `201` | Created |
| `204` | No Content (successful deletion) |
| `400` | Bad Request (validation error) |
| `401` | Unauthorized (missing or invalid token) |
| `403` | Forbidden (insufficient permissions) |
| `404` | Not Found |
| `409` | Conflict (resource already exists) |
| `422` | Unprocessable Entity (invalid data) |
| `429` | Too Many Requests (rate limited) |
| `500` | Internal Server Error |
| `501` | Not Implemented |

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": []
  }
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid authentication token |
| `FORBIDDEN` | Insufficient role or permissions |
| `NOT_FOUND` | Resource does not exist |
| `VALIDATION_ERROR` | Request body failed validation |
| `CONFLICT` | Resource already exists or state conflict |
| `RATE_LIMITED` | Too many requests |
| `NOT_IMPLEMENTED` | Endpoint not yet implemented |
| `INTERNAL_ERROR` | Unexpected server error |

---

## Pagination, Filtering & Sorting

### Pagination

List endpoints support pagination via query parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `page` | `1` | Page number (1-based) |
| `per_page` | `20` | Items per page (max 100) |

```bash
curl "http://localhost:8080/api/v1/containers?page=2&per_page=50" \
  -H "Authorization: Bearer $TOKEN"
```

Response includes pagination metadata:

```json
{
  "pagination": {
    "total": 150,
    "page": 2,
    "per_page": 50,
    "total_pages": 3
  }
}
```

### Filtering

Filter parameters vary by endpoint. Common patterns:

```bash
# Filter containers by status
?status=running

# Filter by name (partial match)
?name=web

# Filter by host
?host_id=550e8400-...

# Filter by date range
?since=2026-01-01T00:00:00Z&until=2026-02-01T00:00:00Z
```

### Sorting

```bash
# Sort by field (ascending)
?sort=name

# Sort by field (descending)
?sort=-created_at
```

---

## Rate Limiting

The API enforces rate limits to prevent abuse:

| Endpoint Category | Limit |
|-------------------|-------|
| Authentication (`/auth/*`) | Stricter rate limiting (auth-specific) |
| Standard API endpoints | Configurable (default: 100 req/min) |
| Health checks | No rate limiting |

When rate limited, the API returns `429 Too Many Requests` with a `Retry-After` header.

---

## Recon & Metadata (v26.5.0)

The recon + metadata module is **disabled by default**. When the
feature flag is off (`recon.enabled: false` or `USULNET_RECON_ENABLED`
unset / false), every endpoint listed below returns
`404 module_disabled`. When enabled, an admin must first acknowledge
the in-app legal notice via `POST /api/v1/recon/_ack`; until that
acknowledgement is recorded, all other recon and metadata routes
return `409 acknowledgement_required`.

The middleware chain for the subtree is:

```
auth (JWT or API key)
  -> recon feature flag        (404 module_disabled if off)
  -> recon acknowledgement     (409 acknowledgement_required until acked)
  -> RBAC                      (per-route viewer / operator / admin)
```

The acknowledgement endpoint (`POST /api/v1/recon/_ack`) is mounted on
a sibling branch that skips the acknowledgement middleware, so an
admin can record consent without first satisfying it.

### Error codes

In addition to the codes documented above, the recon module surfaces:
`ownership_required`, `ownership_pending`, `engine_unavailable`,
`module_disabled`, `acknowledgement_required`,
`unsupported_target_type`, `profile_target_mismatch`,
`artifact_too_large`, `mime_not_supported`.

### Targets

| Method | Path | RBAC | Description |
|--------|------|------|-------------|
| POST | `/api/v1/recon/targets` | operator+ | Register a target identifier (domain, email, ip, ip_range, phone, username). |
| GET | `/api/v1/recon/targets` | viewer+ | List targets (paginated; filter by `type`, `created_by`). |
| GET | `/api/v1/recon/targets/{id}` | viewer+ | Fetch a single target. |
| DELETE | `/api/v1/recon/targets/{id}` | operator+ | Delete a target and cascade its scans / findings. |
| POST | `/api/v1/recon/targets/{id}/ownership/verify` | operator+ | Start and verify an ownership proof. Body: `{"method":"dns_txt|email_link|rdap_match|admin_attest|self_assert","input":{}}`. Returns 409 `ownership_pending` if the proof is started but not yet verified. |

### Profiles

| Method | Path | RBAC | Description |
|--------|------|------|-------------|
| GET | `/api/v1/recon/profiles` | viewer+ | List builtin and custom profiles. |
| POST | `/api/v1/recon/profiles` | operator+ | Create a custom profile. Body: `{"name":"…","description":"…","target_types":["email", …],"modules":["sfp_haveibeen", …],"options":{}}`. Returns 409 `ALREADY_EXISTS` on duplicate name, 400 `INVALID_INPUT` for unknown target types or modules outside the closed catalogue. |
| PUT | `/api/v1/recon/profiles/{id}` | operator+ | Update a custom profile (same body shape as `POST`). Returns 403 `FORBIDDEN` for builtin rows, 404 if the profile does not exist. |
| DELETE | `/api/v1/recon/profiles/{id}` | admin | Delete a custom profile. Returns 403 `FORBIDDEN` for builtin rows, 409 `CONFLICT` when the profile is referenced by existing scans (`recon_scans.profile_id ON DELETE RESTRICT`). |

### Scans

| Method | Path | RBAC | Description |
|--------|------|------|-------------|
| POST | `/api/v1/recon/scans` | operator+ | Start a new scan. Body: `{"target_id":"<uuid>","profile_id":"<uuid>"}`. Returns 403 `ownership_required` if the target is unverified. |
| GET | `/api/v1/recon/scans` | viewer+ | List scans (filter by `target_id`, `status`). |
| GET | `/api/v1/recon/scans/{id}` | viewer+ | Fetch a single scan. |
| DELETE | `/api/v1/recon/scans/{id}` | operator+ | Cancel a running scan. |
| GET | `/api/v1/recon/scans/{id}/findings` | viewer+ | List normalised findings for a scan (filter by `severity`, `module`, `category`). |
| GET | `/api/v1/recon/scans/{id}/report.json` | viewer+ | Self-contained JSON report (summary + findings). |
| GET | `/api/v1/recon/scans/{id}/report.csv` | viewer+ | CSV export of all findings. |
| GET | `/api/v1/recon/scans/{id}/report.pdf` | viewer+ | Paginated A4 PDF report (target/profile header, severity-coloured summary, one section per category). Pure-Go, byte-deterministic for the same scan inputs. |

### Metadata jobs

Upload limits default to **100 MiB per file** and **200 MiB per
request body**. Both are configurable.

| Method | Path | RBAC | Description |
|--------|------|------|-------------|
| POST | `/api/v1/metadata/jobs` | operator+ | Create an extract / strip / both job. `multipart/form-data` body: form field `mode` (one of `extract`, `strip`, `both`; default `extract`), plus one or more `files` parts. Returns 413 `artifact_too_large` if a file or the envelope exceeds limits. |
| GET | `/api/v1/metadata/jobs` | viewer+ | List metadata jobs (filter by `status`, `created_by`). |
| GET | `/api/v1/metadata/jobs/{id}` | viewer+ | Fetch a job and its artifact rows. |
| GET | `/api/v1/metadata/jobs/{id}/artifacts/{aid}/stripped` | viewer+ | Stream the cleaned bytes of one artifact. Response is `application/octet-stream`. |

### Connectors

External-API connectors (HIBP, Shodan, …) are admin-only. Credentials
are encrypted at rest by the existing `internal/pkg/crypto` helper and
are never returned in responses.

| Method | Path | RBAC | Description |
|--------|------|------|-------------|
| GET | `/api/v1/recon/connectors` | admin | List configured connectors. |
| PUT | `/api/v1/recon/connectors/{kind}` | admin | Set credentials and/or enable state for a connector. Body: `{"enabled":true,"credentials":{...}}`. |

### Acknowledgement

| Method | Path | RBAC | Description |
|--------|------|------|-------------|
| POST | `/api/v1/recon/_ack` | admin | Acknowledge the legal notice. Idempotent (subsequent calls also return 204). Exempt from the acknowledgement middleware so an admin can unblock the gated subtree. |

---

## OpenAPI Specification

The full OpenAPI 3.0 specification is available at:

```
GET /api/v1/openapi.json
```

This can be used with tools like Swagger UI, Postman, or code generators.

---

*For more information, see the [Installation Guide](installation.md) and [Architecture Guide](architecture.md).*
