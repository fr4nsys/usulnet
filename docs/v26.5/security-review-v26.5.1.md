# v26.5.1 — Hardening audit and capability review

This document captures the full security audit of v26.5.1 against the
isolated-container posture set out in
[`docs/0526/x/principles.md`](../0526/x/principles.md) §3 and §4. It
mirrors the structure of the v26.5.0 baseline checklist
([`security-review-checklist.md`](security-review-checklist.md)) and
extends it with the controls introduced by the eleven new modules
ported in sessions 01–14 (firewall, crontab, backup verification,
automated rollback, SSL observatory, Docker engine config, WireGuard,
image builder, proxy extended, DNS, calendar, marketplace, sidebar
edition cleanup, infrastructure parity / opt-in local-services TLS).

Every delta from the v26.5.0 baseline is called out explicitly. New
rows are additive — none of the v26.5.0 recon controls were modified
in this release.

## Scope

The audit covers:

1. The external port surface exposed by `docker-compose.yml`,
   `deploy/docker-compose.prod.yml`, and the `Dockerfile`.
2. Every bind mount declared in those two production compose files.
3. Every outbound HTTP / DNS / TCP call the Go binary is capable of
   making (`grep -rnE 'http\.Get|http\.Post|http\.NewRequest|net\.Dial' internal/`).
4. The container user that the usulnet binary, the agent binary, and
   the recon sandbox images run under.
5. Every `cap_add` / `cap_drop` reference across compose files and the
   recon sandbox spec, with a justification line for each capability.
6. Static analysis (`gosec`), dependency vulnerability scanning
   (`govulncheck`), and the full `golangci-lint` gate.

Out of scope, by the principles §3 acceptance criteria of session 15:

- A pentest. That belongs to a real security-research engagement.
- Disabling features for security trade-offs without a clearly stated
  reason — hardening refines, never reduces.

## 1. External port surface

| Source | Line | Port | Bind | Justification |
|---|---|---|---|---|
| `Dockerfile` | 172 | `EXPOSE 8080 7443` | container-internal | HTTP healthcheck (8080) + HTTPS public surface (7443) |
| `docker-compose.yml` | 47 (commented) | `${USULNET_HTTP_PORT:-8080}:8080` | host:container | Operator opt-in only; commented by default — HTTP→HTTPS redirect runs internally |
| `docker-compose.yml` | 48 | `${USULNET_HTTPS_PORT:-7443}:7443` | host:container | HTTPS — default entry point, auto-TLS via self-signed cert |
| `deploy/docker-compose.prod.yml` | 32 (commented) | `${USULNET_HTTP_PORT:-8080}:8080` | host:container | Operator opt-in only; commented by default |
| `deploy/docker-compose.prod.yml` | 33 | `${USULNET_HTTPS_PORT:-7443}:7443` | host:container | HTTPS — default entry point |

**NATS port 4222** stays on the private `usulnet-backend` Docker
network and is **never** published to the host in the canonical
compose file. Operators running master/agent split deployments
publish it themselves; the in-repo files keep it internal.

**Other internal-only ports** (postgres 5432, redis 6379, NATS 4222,
guacd 4822, NATS monitor 8222) all attach to `usulnet-backend` only;
none are forwarded to the host.

**Result:** matches the documented minimal set (8080 internal + 7443
public). **No new external port introduced by sessions 01–14.**

**Delta from v26.5.0 baseline:** none.

## 2. Bind mount audit

Each bind mount in the two production compose files is enumerated
with the principle-§3 justification:

### `docker-compose.yml` — `usulnet` service (lines 49–55)

| Mount | Justification |
|---|---|
| `/var/run/docker.sock:/var/run/docker.sock` | Required for the Docker management plane: every container lifecycle action (start/stop/build/exec/inspect) goes through this socket. The recon sandbox launcher rewrites this mount to never propagate the socket into a recon container (`internal/services/recon/sandbox/spec.go:112-117`). |
| `usulnet_data:/app/data` | Named volume. Persists backups, PKI certs, license payload, and feature databases. No host path — managed by Docker. |
| `trivy_cache:/var/lib/usulnet/trivy` | Named volume. Trivy vulnerability DB cache so each container scan does not re-download upstream. No host path. |

### `docker-compose.yml` — `usulnet-agent` service (lines 135–137; profile `agent`)

| Mount | Justification |
|---|---|
| `/var/run/docker.sock:/var/run/docker.sock` | The agent executes Docker operations on remote hosts on behalf of the master via the NATS gateway; the local socket is its only contact surface to the agent's host daemon. |
| `agent_data:/app/data` | Named volume for agent state (config, heartbeat pid file). |

### `docker-compose.yml` — `postgres` service (lines 233–235)

| Mount | Justification |
|---|---|
| `postgres_data:/var/lib/postgresql/data` | Named volume — database files. |
| `./deploy/tls:/usulnet-tls:ro` | **New in v26.5.1 (session 14).** Read-only bind of the TLS bootstrap entrypoint scripts (`postgres-entrypoint.sh`, cert generator helpers). Mount is `:ro`; the entrypoint script itself only writes to `/var/lib/postgresql/tls/` inside the container. When `USULNET_TLS_LOCAL_SERVICES=false` (default), the script just execs the stock postgres entrypoint and behaves identically to v26.5.0. |

### `docker-compose.yml` — `redis` service (lines 289–291)

| Mount | Justification |
|---|---|
| `redis_data:/data` | Named volume — Redis AOF + RDB. |
| `./deploy/tls:/usulnet-tls:ro` | **New in v26.5.1 (session 14).** Read-only TLS bootstrap, same pattern as postgres. |

### `docker-compose.yml` — `nats` service (lines 332–335)

| Mount | Justification |
|---|---|
| `nats_data:/data` | Named volume — JetStream state. |
| `./deploy/nats-server.conf:/etc/nats/nats-server.conf:ro` | Read-only mount of NATS server configuration. |
| `./deploy/tls:/usulnet-tls:ro` | **New in v26.5.1 (session 14).** Read-only TLS bootstrap. |

### `deploy/docker-compose.prod.yml` — `usulnet` service (lines 34–38)

| Mount | Justification |
|---|---|
| `/var/run/docker.sock:/var/run/docker.sock` | Same as above. |
| `./config.yaml:/app/config/config.yaml:ro` | Read-only operator-supplied config file. |
| `usulnet_data:/app/data` | Named volume. |
| `trivy_cache:/var/lib/usulnet/trivy` | Named volume. |

### `deploy/docker-compose.prod.yml` — `postgres` / `redis` / `nats` (lines 130, 170, 201–203)

| Mount | Justification |
|---|---|
| `postgres_data:/var/lib/postgresql/data` | Named volume. |
| `redis_data:/data` | Named volume. |
| `nats_data:/data` | Named volume. |
| `./nats-server.conf:/etc/nats/nats-server.conf:ro` | Read-only NATS config. |

**Result:** every bind mount documented. The Docker socket is mounted
into the usulnet container and the optional agent only — **never**
into a recon sandbox, a user-built image, or any new module's
container.

**Delta from v26.5.0 baseline:** three new read-only mounts of
`./deploy/tls:/usulnet-tls:ro` (postgres / redis / nats) from session
14's opt-in local-services TLS. All three are read-only and disabled
when `USULNET_TLS_LOCAL_SERVICES=false` (the default), in which case
the entrypoint scripts exec the stock service entrypoint and the
mount is harmless. No new privileged mount.

## 3. Outbound call audit

Enumerated via:

```sh
grep -rnE 'http\.Get|http\.Post|http\.NewRequest|net\.Dial' \
     internal/ | grep -v _test.go
```

Every destination is either operator-configured (the operator supplies
the URL or enables the integration via config / API) or a known
internal / recon sandbox channel.

### No call-home

A direct check for any `usulnet.com` endpoint in the binary returns
**zero call-home destinations.** The only `usulnet.com` references in
`internal/`:

| Location | Use |
|---|---|
| `internal/services/recon/connectors/hibp/connector.go:51` | HIBP `User-Agent` string `usulnet-recon/26.5.0 (+https://usulnet.com)`. HIBP requires a descriptive UA; the URL identifies the product to HIBP's operators. **No connection is made to usulnet.com** — the string is sent to HIBP only when the operator has explicitly enabled the HIBP connector and supplied their API key. |
| `internal/services/calendar/ics.go:34` | RFC 5545 §3.8.4.7 UID suffix in exported `.ics` files. Pure string — no network call. |
| `internal/gateway/server.go:172`, `internal/gateway/protocol/messages.go:57` | NATS subject prefixes (`usulnet.commands.*`). Internal NATS protocol — no HTTP. |

### Operator-configured outbound endpoints

Each row below corresponds to an HTTP / TCP destination only reachable
when the operator has explicitly configured the relevant integration
or supplied a target URL.

| Module | Default URL | Source | Operator-configurable | Opt-in mechanism |
|---|---|---|---|---|
| Docker registry — Docker Hub | `https://registry-1.docker.io/v2/...` | `internal/services/update/registry_dockerhub.go:165,215` | yes (per-registry) | `registries` table; operator adds a registry row |
| Docker registry — Docker Hub auth | `https://auth.docker.io/token` | `internal/services/update/registry_dockerhub.go:260` | yes | same as above |
| Docker registry — Docker Hub tags API | `https://hub.docker.com/v2/repositories/...` | `internal/services/update/registry_dockerhub.go:338` | yes | same as above |
| Docker registry — GHCR | `https://ghcr.io/v2/...` | `internal/services/update/registry_ghcr.go:130,172,217,518,558` | yes | same as above |
| GitHub release changelog | `https://api.github.com/...` | `internal/services/update/registry_ghcr.go:292,306,316`, `internal/services/update/changelog.go:247,271` | yes (overridable base URL) | only fires for image-update workflows the operator started |
| GitLab release changelog | `https://gitlab.com/api/v4/...` (overridable) | `internal/services/update/changelog.go:338-361` | yes | as above |
| GitHub API client | `https://api.github.com` (overridable) | `internal/integrations/github/client.go:33-37,64` | yes | operator creates a GitHub integration |
| GitLab API client | `https://gitlab.com` (overridable) | `internal/integrations/gitlab/client.go:34,68` | yes | operator creates a GitLab integration |
| Gitea API client | operator-supplied `baseURL` | `internal/integrations/gitea/client.go:660-1121` | yes (no default) | operator-configured per integration |
| NPM (Nginx Proxy Manager) | operator-supplied `baseURL` | `internal/integrations/npm/client.go:93,163,1118` | yes (no default) | operator-configured per integration |
| Cloudflare DNS | `https://api.cloudflare.com/client/v4` | `internal/services/dns/providers/cloudflare/cloudflare.go:27,291` | yes | DNS provider record + API token |
| DigitalOcean DNS | `https://api.digitalocean.com/v2` | `internal/services/dns/providers/digitalocean/digitalocean.go:26,283` | yes | DNS provider record + API token |
| OAuth / OIDC `userinfo` | operator-supplied URL | `internal/services/auth/oauth/provider.go:305-310` | yes (no default) | operator configures provider |
| Slack notification webhook | operator-supplied webhook URL | `internal/services/notification/channels/slack.go:160` | yes (no default) | operator creates channel |
| Discord notification webhook | operator-supplied webhook URL | `internal/services/notification/channels/discord.go:160` | yes (no default) | operator creates channel |
| Generic notification webhook | operator-supplied URL + method | `internal/services/notification/channels/webhook.go:231` | yes (no default) | operator creates channel |
| Telegram bot API | `https://api.telegram.org/bot<token>/...` | `internal/services/notification/channels/telegram.go:91,124` | yes (bot token) | operator creates channel |
| ntfy notification | `https://ntfy.sh` (overridable) | `internal/services/notification/channels/ntfy.go:64,111` | yes | operator creates channel |
| Gotify notification | operator-supplied URL | `internal/services/notification/channels/gotify.go:107` | yes (no default) | operator creates channel |
| PagerDuty Events API | `https://events.pagerduty.com/v2/enqueue` (PagerDuty-fixed) | `internal/services/notification/channels/pagerduty.go:42,130` | yes (channel enable) | operator creates channel + integration key |
| Opsgenie API | `https://api.opsgenie.com` (overridable) | `internal/services/notification/channels/opsgenie.go:75,145` | yes | operator creates channel |
| SMTP (email channel) | operator-supplied server | `internal/services/notification/channels/email.go:261` | yes (no default) | operator creates channel |
| Generic favicon fetch | operator-supplied bookmark URL | `internal/services/shortcuts/service.go:191-205` | yes (per-shortcut) | operator adds a shortcut; favicon fetch is opt-in via UI |
| Google favicon fallback | `https://www.google.com/s2/favicons?domain=...` | `internal/services/shortcuts/service.go:205` | yes (triggered by favicon fetch) | only fires when the bookmarked host's own favicon paths fail; the operator-bookmarked host is sent to Google. **No usulnet account or installation ID is sent.** |
| Crontab HTTP execution | operator-supplied URL | `internal/services/crontab/service.go:625` | yes (no default) | operator creates HTTP crontab entry |
| Caddy admin API (proxy) | operator-supplied AdminURL (default `http://localhost:2019` inside the proxy container) | `internal/services/proxy/caddy/client.go:71,97,131,153,172,189` | yes | only used when the proxy module is configured to drive Caddy |
| SSL Observatory TLS dial | operator-supplied scan target hostname:port | `internal/services/sslobservatory/service.go:483-499` | yes | operator creates a scan target |
| Connection-test TCP dial | operator-supplied host:port | `internal/web/handler_connections_ext.go:1231` | yes | only fires on operator-triggered "test" |
| RDP TCP dial | operator-supplied host:port | `internal/services/rdp/service.go:137` | yes | operator opens an RDP session |
| Guacamole guacd dial | `${GUACD_HOST}:${GUACD_PORT}` (default `guacd:4822`, same backend network) | `internal/web/handler_rdp_terminal.go:124` | env-configurable | local-only via Docker network |
| SSH transport | operator-supplied host:port | `internal/services/ssh/service.go:570,1050` | yes | operator-managed host |
| Webhook dispatch worker | operator-supplied URL | `internal/scheduler/workers/webhook_dispatch.go:200` | yes (no default) | operator creates webhook subscription |
| Runbook HTTP step | operator-supplied URL | `internal/scheduler/workers/runbook_execute.go:537-564`, `internal/web/handler_runbooks.go:696-724` | yes (no default) | step config drives the URL |
| RDAP ownership verifier | `https://rdap.org` (IANA bootstrap) | `internal/services/recon/rdap.go:29,121` | overridable | only fires when recon is enabled and an operator runs ownership verification |
| HIBP breach lookup | `https://haveibeenpwned.com/api/v3` (overridable) | `internal/services/recon/connectors/hibp/connector.go:46,308` | yes (`recon.connectors.hibp.enabled` + API key) | recon must be enabled AND HIBP key supplied |
| SpiderFoot recon engine | sandbox-private URL returned by the launcher | `internal/services/recon/engine/spiderfoot/client.go:81-95,154-280` | n/a — internal | private `usulnet-recon` Docker network |
| Docker daemon dial | operator-supplied `DOCKER_HOST` (or Unix socket) | `internal/docker/client.go:203` | yes | bound to the docker.sock bind-mount |
| Local DNS resolver | resolver per operator host config | `internal/services/dns/resolver.go:34` | host-resolv.conf | DNS for outbound integrations above |
| LDAP / Active Directory | operator-supplied LDAP server | `internal/services/auth/ldap/client.go:132`, `internal/services/ldapbrowser/service.go:206,221`, `internal/web/handler_ldap_admin.go:398` | yes | optional auth backend |

**Result:** every outbound endpoint is operator-configured or
operator-triggered (or, for the recon sandbox, scoped to a private
Docker network). **No call-home in the binary.**

**Delta from v26.5.0 baseline:** the new outbound endpoints introduced
by sessions 01–14 are:

- DNS providers (Cloudflare, DigitalOcean) — opt-in DNS-01 ACME
  provider, gated by operator config (session 10).
- SSL Observatory TLS dials — operator scan targets (session 05).
- Crontab HTTP execution — operator-defined HTTP cron jobs (session 02).
- Caddy admin API — only invoked when the proxy module is configured
  to drive Caddy (session 09).
- Marketplace catalog fetch — **offline catalog only.** No HTTP call
  was added (session 12).

All operator-configured. None hit `usulnet.com`.

## 4. Container user audit

| Image | User | Source |
|---|---|---|
| `usulnet` (production runtime) | `usulnet:1000` after entrypoint drops via `su-exec` | `Dockerfile:123-124`, `docker-entrypoint.sh:9,86` |
| `usulnet-agent` | inherits the same Dockerfile pattern (non-root) | `Dockerfile.agent` (mirrors main Dockerfile) |
| `recon-spiderfoot` sandbox | `USER 65534:65534` (`nobody:nogroup`) | `deploy/recon/spiderfoot/Dockerfile:53` |
| `recon-toolkit` sandbox | `USER 65534:65534` | `deploy/recon/toolkit/Dockerfile:144` |
| Recon launcher container spec | `User: "65534:65534"` enforced at create time | `internal/services/recon/sandbox/spec.go:27,131` |

The Dockerfile entrypoint runs as root only long enough to (a)
auto-detect the host Docker socket's GID and add the `usulnet` user
to a matching group, and (b) `chown -R usulnet:usulnet /app/data`.
Then it `exec su-exec usulnet "$@"`. Once the binary is running, it
is UID 1000 with the supplementary docker group.

**Delta from v26.5.0 baseline:** none. No module session changes the
container user.

## 5. Capability audit

| Container | `cap_add` | `cap_drop` | Justification |
|---|---|---|---|
| `usulnet` (root + agent) | `SYS_PTRACE`, `SYS_ADMIN` | (default + the kernel-default drop set) | Host terminal feature requires nsenter into the host PID/MNT namespaces; container process inspection requires PTRACE. Documented at `docker-compose.yml:58-60` and `internal/web/handler_host_terminal.go:234`. |
| `usulnet-agent` | (none) | (default) | Agent only needs Docker socket access; no host-terminal feature. |
| `guacd` | (none) | (default) | Guacamole daemon for RDP/VNC sessions; needs no extra capabilities. |
| `postgres` / `redis` / `nats` | (none) | (default) | Standard service containers. |
| Recon sandbox containers (`recon-spiderfoot`, `recon-toolkit`) | (none ever) | **`ALL`** | All Linux capabilities dropped at create time. Anything the engine needs must be added back via CapAdd in a follow-up RFC; the current code does not. Source: `internal/services/recon/sandbox/spec.go:78,133`. |

**No new module adds `NET_ADMIN`, `NET_RAW`, or `SYS_ADMIN` to the
usulnet container.** The two existing additions (`SYS_PTRACE`,
`SYS_ADMIN`) are unchanged from the v26.5.0 baseline and are required
for the pre-existing host-terminal feature.

The WireGuard module (session 07) operates through the host's `wg` /
`wg-quick` binaries via the existing host-management SSH transport
(principle §4). It does **not** request `NET_ADMIN` on the usulnet
container. A UI warning at `internal/web/handler_wireguard.go:61`
informs operators that running WireGuard in a container deployment
would need `NET_ADMIN + /sys/class/net`, but the AGPL usulnet build
does not enable that path.

The firewall module (session 01) shells out to `iptables` / `nftables`
on the operator's host via the SSH transport — again, no capability
changes inside usulnet itself.

The image-builder module (session 08) builds images by driving
`docker build` through the already-mounted Docker socket; no
additional capability is needed.

**Delta from v26.5.0 baseline:** none. All cap_add / cap_drop entries
in the v26.5.1 compose files are byte-for-byte identical to v26.5.0
(verified via `git diff main..HEAD -- docker-compose.yml deploy/docker-compose.prod.yml`).

## 6. Static analysis — gosec

`gosec -severity high -confidence medium ./...` was run on both the
v26.5.0 baseline and the v26.5.1 branch. Summary:

| Severity | v26.5.0 baseline | v26.5.1 | Delta |
|---|---:|---:|---:|
| HIGH | 98 | 100 | **+2** |

Rule breakdown:

| Rule | v26.5.0 | v26.5.1 | Delta | Notes |
|---|---:|---:|---:|---|
| G115 (integer overflow uint64→int64) | 62 | 62 | 0 | All are Docker SDK stat conversions (memory/network/pid counters → int64 for protobuf/JSON). Bounded by physical container limits. Pre-existing. |
| G402 (TLS InsecureSkipVerify) | 8 | **9** | **+1** | New: SSL Observatory `internal/services/sslobservatory/service.go:492` (session 05). Annotated `//nolint:gosec // intentional — see comment`: the observatory scans operator-chosen targets and must accept invalid certs in order to analyze them. The existing 8 baseline G402s are operator-configurable insecure modes (LDAP, SMTP, Docker daemon, agent connection). |
| G704 (SSRF taint) | 1 | 1 | 0 | Pre-existing connection-test TCP dial. |
| G101 (hardcoded credentials) | 6 | 6 | 0 | Error-code constants flagged as credential names. Excluded in `.golangci.yml`. |
| G703 (path traversal taint) | 9 | 9 | 0 | Pre-existing operator-supplied paths (admin-only routes: nvim editor, log management, session replay, packet capture). The session-09 proxy `nginx/client.go:112` finding existed in v26.5.0; sessions 01–14 did not add a new one. |
| G118 (goroutine context.Background) | 9 | **10** | **+1** | New: crontab `internal/services/crontab/service.go:395` (session 02). The `RunNow` API spawns a fire-and-forget execution goroutine; using the request context would cancel the cron run when the API call returns. Same pattern as the existing 9 baseline workers (gitea, audit, capture, etc.). |
| G122 (filepath.Walk TOCTOU) | 1 | 1 | 0 | Pre-existing backup archive walker. |
| G702 (command injection taint) | 2 | 2 | 0 | Pre-existing nvim editor websocket — admin-only and the command is whitelist-controlled. |

**Triage of the two new findings:**

1. **SSL Observatory `G402` (`InsecureSkipVerify=true`).** Intentional
   and annotated. The whole point of the observatory is to evaluate
   the cert that the target presents — even when invalid. Verification
   is performed in-band against the returned chain so the report can
   still classify trust. **No code change.**

2. **Crontab `G118` (`context.Background()` in goroutine).** Necessary
   for fire-and-forget execution. The execution has its own
   `HTTPRequestTimeout` budget inside `executeEntry`. Same pattern as
   the existing 9 baseline G118 findings — none of which are flagged
   as exploitable. **No code change.**

**Result:** the two new HIGH findings are documented, annotated where
appropriate, and consistent with patterns already accepted in the
v26.5.0 baseline. No new exploitable issue introduced.

## 7. Dependency vulnerability scanning — govulncheck

`govulncheck ./...` could not fetch the Go vulnerability index in the
hardened sandbox where this audit was originally run
(`https://vuln.go.dev` returned 403 due to the sandbox's host
allow-list). The follow-up sub-PR
(`claude/release-s15-2-readiness`) wires the check into CI on
GitHub-hosted runners, which can reach `vuln.go.dev` directly. The
workflow lives at `.github/workflows/govulncheck.yml` and runs on every
push to `main` and every PR; the script behind it is
[`scripts/govulncheck.sh`](../../scripts/govulncheck.sh).

After bumping every direct dependency to its latest patched release
(Go toolchain `go1.25.10`, `golang.org/x/{crypto,net,sys,text,mod,tools}`,
`coreos/go-oidc v3.18.0`, `docker/docker v28.5.2`,
`go-chi/chi/v5 v5.2.5`, `go-ldap/ldap/v3 v3.4.13`,
`golang-jwt/jwt/v5 v5.3.1`, `jackc/pgx/v5 v5.9.2`,
`nats-io/nats.go v1.52.0`, `redis/go-redis/v9 v9.19.0`) the first
clean CI run reports **two reachable findings that are documented
false positives**:

| OSV ID | CVE | Module | Status in our usage | Allowlisted? |
|---|---|---|---|---|
| `GO-2026-4883` | CVE-2026-33997 | `github.com/docker/docker` | Server-side off-by-one in the Moby daemon's plugin privilege validation. usulnet only uses `github.com/docker/docker/client.*` to talk to a remote daemon; the only contact with the AuthZ plugin surface is serialising the `authorization-plugins` string list to `/etc/docker/daemon.json` (`internal/services/dockerconfig/service.go:293`). No plugin runtime is linked into the binary. Fixed in `github.com/moby/moby/v2 v2.0.0-beta.8`; legacy module still "Fixed in: N/A". | Yes — `scripts/govulncheck.sh` ALLOWED_OSV_IDS |
| `GO-2026-4887` | CVE-2026-34040 | `github.com/docker/docker` | Server-side AuthZ plugin bypass on oversized request bodies. Same scope: daemon-side defect, irrelevant to a Docker client. usulnet ships no AuthZ plugin. Fixed in `moby/v2 v2.0.0-beta.8`; legacy module still "N/A". | Yes — `scripts/govulncheck.sh` ALLOWED_OSV_IDS |

The allowlist is encoded in `scripts/govulncheck.sh` with inline
justifications and links to the upstream advisories. Every entry is
revisited on each dep audit and must be dropped as soon as a fixed
upstream release lands in `go.mod`. Any new reachable finding outside
the allowlist still fails the workflow.

govulncheck's informational tally — "1 vulnerability in packages you
import and 0 vulnerabilities in modules you require, but your code
doesn't appear to call these vulnerabilities" — is unchanged from the
first scan; these are unreachable from the binary's call graph and
the CI gate ignores them by design.

**Action item for session 16 / release engineering:** monitor whether
`github.com/docker/docker` ships a v28-series backport of CVE-2026-33997
and CVE-2026-34040, or whether the migration to
`github.com/moby/moby/v2` becomes viable. Either path lets us drop the
two allowlist entries.

## 8. golangci-lint

`golangci-lint run ./...` summary:

| Linter | v26.5.0 baseline | v26.5.1 | Delta |
|---|---:|---:|---:|
| errcheck | 467 | 467 | 0 |
| errorlint | 119 | 119 | 0 |
| gocritic | 127 | 126 | −1 |
| gofmt | 208 | 193 | −15 |
| goimports | 22 | 21 | −1 |
| gosec | 112 | 112 | 0 |
| govet | 94 | 94 | 0 |
| ineffassign | 6 | 6 | 0 |
| misspell | 148 | 151 | +3 |
| nilerr | 26 | 26 | 0 |
| prealloc | 80 | 80 | 0 |
| staticcheck | 109 | 109 | 0 |
| unconvert | 9 | 9 | 0 |
| unused | 56 | 56 | 0 |
| whitespace | 2 | 2 | 0 |
| **Total** | **1585** | **1571** | **−14** |

**Delta:** the v26.5.1 branch is net **−14 issues** vs the v26.5.0
baseline (mostly gofmt cleanups from the eleven port sessions). The
three new misspell hits are documentation strings inside new module
help text and are tracked separately — they do not affect runtime
behaviour.

The aggregate count is a long-standing project state, not a regression
introduced by this audit. Per `.golangci.yml`, gosec G101, G104, G304
are intentionally excluded (false-positive prone). Reducing the
baseline count is a separate cleanup track.

### `make quality` state

`make quality` (== `lint vet check-naming test-check-coverage`) is
pre-existing **red** on both the v26.5.0 baseline (commit `f2cc6f6`)
and this v26.5.1 branch:

- `make vet` — green on both.
- `make check-naming` — green on both.
- `make lint` — red on both (1585 issues on baseline, **1571** on
  v26.5.1; net −14). The session 15 audit reduces the lint count, it
  does not raise it.
- `make test-check-coverage` — red on both. The 40 % threshold is not
  met because a long tail of `internal/web/` handlers and templ
  packages report ≤ 5 % coverage. Reproduced on `f2cc6f6` with the
  same toolchain.

Three test packages also fail on both trees:

- `internal/api/handlers` — `TestRouter_PublicRoutes/version_endpoint`
  and `TestSystemHandler_Version` expect a version stamp the bare
  test binary does not link in. Pre-existing.
- `internal/services/container` — `TestHostEventWatcher_ContextCancel`
  panics on a nil `dockerClient.Events`. Pre-existing.
- `internal/services/notification` — fixture-dependent assertions.
  Pre-existing.

The audit acknowledges these gate failures as **pre-existing
baseline state**. They are not introduced by sessions 01–14 and are
not in scope for this session (session 15 is a read-only audit + one
audit doc). Fixing them is a separate engineering track and is
called out as a release-engineering action item for session 16.

## 9. Combined hardening matrix (mirrors v26.5.0 baseline §11)

| # | Control | Status | Citation | Verified by |
|---|---|---|---|---|
| v26.5.0/1 | Recon sandbox flags enforced on every container start. | [x] | `internal/services/recon/sandbox/spec.go:100-145` | `internal/services/recon/sandbox/launcher_test.go:208` |
| v26.5.0/2 | No recon tool runs on the host filesystem; mounts forced `:ro`. | [x] | `internal/services/recon/sandbox/spec.go:112-117,135-139` | `internal/services/recon/sandbox/launcher_test.go:281` |
| v26.5.0/3 | PII never appears in info-level logs. | [x] | `internal/services/recon/connectors/hibp/connector.go:88-103`, `internal/services/recon/hash.go` | `connector_test.go::TestLookup_NoSecretInError` |
| v26.5.0/4 | Recon ownership verification cannot be bypassed. | [x] | `internal/services/recon/ownership.go:80-81`, `internal/api/handlers/recon.go:775` | `internal/api/handlers/recon_test.go` |
| v26.5.0/5 | Recon acknowledgement middleware blocks every recon route. | [x] | `internal/api/middleware/recon.go:48-65`, `internal/api/router.go:419-433` | `recon_test.go::TestRecon_AckRequired_*` |
| v26.5.0/6 | Recon feature flag off → routes 404 and no goroutines. | [x] | `internal/api/middleware/recon.go:26-37`, `internal/services/recon/wiring/wiring.go:88-91` | `wiring_test.go::TestBuild_DisabledShortCircuits` |
| v26.5.0/7 | HIBP key never appears in API responses. | [x] | `internal/api/handlers/recon.go:38-43`, `internal/services/recon/connectors/hibp/connector.go:271-293` | `connector_test.go::TestLookup_NoSecretInError` |
| v26.5.0/8 | Recon raw payloads encrypted at rest. | [x] | `internal/repository/postgres/recon_repo.go:33-46,511-515` | `recon_repo_test.go::TestReconRepo_UpsertFinding_EncryptsRawPayload` |
| v26.5.0/9 | Recon retention worker deletes only its own tables. | [x] | `internal/scheduler/workers/recon_retention.go:34-46`, `internal/repository/postgres/recon_retention_repo.go:54-94` | `recon_retention_test.go` |
| v26.5.0/10 | `recon_audit_log` is append-only. | [x] | `internal/repository/postgres/recon_repo.go:766-793` | `recon_audit_append_only_test.go::TestReconAuditLog_NoMutationStatements` |
| v26.5.1/11 | External port surface limited to 8080 (internal) + 7443 (public); NATS 4222 stays on `usulnet-backend`. | [x] | `Dockerfile:172`, `docker-compose.yml:44-48`, `deploy/docker-compose.prod.yml:29-33` | §1 above |
| v26.5.1/12 | All Docker socket bind mounts limited to the usulnet container and optional agent. | [x] | `docker-compose.yml:51,136`, `deploy/docker-compose.prod.yml:35` | §2 above |
| v26.5.1/13 | No binary call-home. | [x] | `grep -rnE 'http\\.Get\|http\\.Post\|http\\.NewRequest\|net\\.Dial' internal/` cross-checked against `grep -rnE 'usulnet\\.(com\|dev)'` | §3 above |
| v26.5.1/14 | usulnet runtime user is non-root `usulnet:1000`; recon sandboxes `nobody:nogroup` (65534). | [x] | `Dockerfile:123-124`, `docker-entrypoint.sh:86`, `deploy/recon/{spiderfoot,toolkit}/Dockerfile`, `internal/services/recon/sandbox/spec.go:27,131` | §4 above |
| v26.5.1/15 | `cap_add` limited to `SYS_PTRACE`, `SYS_ADMIN` on the usulnet container; recon containers drop `ALL`. | [x] | `docker-compose.yml:58-60`, `deploy/docker-compose.prod.yml:40-42`, `internal/services/recon/sandbox/spec.go:78,133` | §5 above |
| v26.5.1/16 | Opt-in local-services TLS (session 14) keeps plain-TCP defaults; the entrypoint scripts are read-only and inert when the flag is off. | [x] | `docker-compose.yml:81,207,267,323`, `deploy/tls/*.sh` | session 14 unit tests |
| v26.5.1/17 | New module outbound endpoints (DNS providers, SSL Observatory, crontab HTTP) are operator-configured or operator-triggered. | [x] | rows in §3 | §3 above |
| v26.5.1/18 | No new exploitable HIGH gosec finding introduced; both new findings are documented and consistent with the v26.5.0 pattern. | [x] | §6 | §6 above |
| v26.5.1/19 | The marketplace module ships offline catalog only — no outbound HTTP added by session 12. | [x] | `grep -rnE 'http\\.|net\\.Dial' internal/services/marketplace/ | grep -v _test.go` returns no matches outside the operator-supplied URL paths. | §3 above |

## Sign-off

- Implementer: claude — Session 15 (security hardening), 2026-05-14.
- Reviewer: _pending — see PR._

**Sign-off statement.** I confirm the citations above accurately
reflect the controls in the v26.5.1 codebase. The eleven new module
sessions did not introduce a call-home endpoint, did not open a new
external port, did not request a new privileged mount, and did not
elevate the usulnet container's capability set. The two new HIGH
gosec findings (SSL Observatory `G402`, crontab `G118`) are
documented, annotated, and consistent with the v26.5.0 baseline.
`govulncheck` was originally deferred to release-engineering CI
because the audit environment is sandboxed away from `vuln.go.dev`;
the follow-up sub-PR `claude/release-s15-2-readiness` wires the check
into `.github/workflows/govulncheck.yml`, bumps every reachable
dependency to its patched release, and documents the two remaining
server-side Moby false positives (CVE-2026-33997, CVE-2026-34040) in
the allowlist of [`scripts/govulncheck.sh`](../../scripts/govulncheck.sh).

Future revisions of this checklist must be appended, never
overwritten, when a v26.5.x or v26.6 change reshapes a control.
