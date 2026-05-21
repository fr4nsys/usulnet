# usulnet v26.5.2 — release notes

> **Status: DRAFT — unreleased.** The last shipped release is v26.5.1.
> Sections below describe the polish increment originally drafted on
> top of v26.5.1; the full v26.5.2 scope additionally absorbs the 14
> sessions documented in [`plan/`](plan/README.md). This document will
> be finalised at release time; the planned tag date is
> intentionally not set yet.

**Headline (provisional):** Shodan recon connector, CLI / agent refresh,
web-a11y landmarks, plus the v26.5.2 development plan (CI smoke E2E +
coverage gate, host-side CLI, sidebar / onboarding rewrite,
empty-states, L7 egress, Tor egress, container forensics, YARA +
trufflehog, BlackArch recon-toolkit, honeypots in marketplace, light
theme, animations).

The polish work captured here adds the Shodan recon connector to the
AGPL build as the second bring-your-own-key external integration after
HIBP, lands the CLI / agent / web-a11y refresh that came out of the
session-19 audit (global `--quiet` and `--json` flags, JSON error
envelope, `usulnet-agent` ported to Cobra with
`run` / `version` / `validate-config` subcommands, canonical
`USULNET_AGENT_DOCKER_HOST` env var, header / sidebar / modal / flash
a11y landmarks), bakes shell tab-completion into both production
Docker images, and ships a new operator-facing CLI reference at
[`docs/cli.md`](../cli.md). PR #142 also folds in two release-blocker
bugfixes against v26.5.1 (chi panic in `internal/web/routes_dns.go`,
`/recon/*` always 404 from missing web wiring).

**No database migration in the polish work above.** v26.5.2 reuses
every v26.5.1 table; the `recon_connectors` row that holds the Shodan
key uses the same schema v26.5.0 introduced for HIBP. **No new
external port, no new bind mount, no new container capability, no
call-home.** New sessions in [`plan/`](plan/README.md) may introduce
their own migrations — those are scoped per session and documented in
each session doc's "Files" table.

## v26.5.2 development plan

The 14-session plan is at [`plan/README.md`](plan/README.md). High
level:

- **Tier 0 (must land in v26.5.2):** smoke E2E in CI + image-publish
  gate; coverage 15 % → 25 %.
- **Tier 1:** host-side CLI binary; sidebar reorg + first-run wizard;
  empty-states across every module.
- **Tier 2 (differentiation):** L7 egress firewall; Tor egress; container
  forensics; YARA + trufflehog scans; recon-toolkit on Arch + BlackArch;
  honeypots in marketplace.
- **Tier 3 (polish):** CLI help polish; end-to-end light theme;
  micro-animations.

Per-feature changelog in [`CHANGELOG.md`](../../CHANGELOG.md) under
the `[v26.5.2]` heading at release time.

## What's new

### Recon: Shodan connector (BYO key)

![Recon connectors — Shodan card](../screenshots/recon-shodan-card.png)

Second external connector after HIBP. Operators supply their own API
key — the binary still ships zero credentials. Three target kinds
covered:

| Target kind | Shodan endpoint | Use |
|---|---|---|
| `ip` | `GET /shodan/host/{ip}` | Banner / vuln / open-port enrichment for a single host. |
| `domain` | `GET /dns/resolve` | DNS resolution lookup as a cheap pre-pass. |
| `ip_range` | `GET /shodan/host/search?query=net:<cidr>` | Range-level survey. |

Findings land in `recon_findings` under the `sfp_shodan` module bucket
so the dashboard groups them with whatever SpiderFoot emits from the
same module. Severity ladder: any CVE in vulns → high; sensitive port
(SSH / RDP / DB / Docker) → medium; otherwise → low (info for plain
DNS resolutions).

Health check pings `GET /api-info` and asserts a 200 carrying
`query_credits` — operators see the connector go green on the
`/recon/connectors` card the moment the key is valid.

**Secrecy.** Shodan only accepts the API key in the query string, so
every transport failure surfaces a `url.Error` that quotes the full
request URL. The connector scrubs the key out of every error before
returning it; a full-cycle secrecy test
(`internal/services/recon/connectors/shodan/connector_test.go:549`,
`TestSecrecyInvariant_FullCycle`) pins that the configured key never
appears in any log line, returned error string, or `url.Error` text.

Wired alongside HIBP at startup behind
`recon.connectors.shodan.enabled`. Credentials are AES-256-GCM
encrypted at rest in `recon_connectors`. Operator docs in
[`docs/recon.md`](../recon.md) §13.1.

### CLI: global `--quiet` and `--json` flags

`--quiet` (short `-q`) suppresses informational summaries (e.g.
`stripped: foo -> bar`, `Configuration is valid`). Errors and primary
data still print. `--json` is a shortcut for `--output json` and wins
over an explicit `--output`. Both flags are persistent on the root
command and inherited by every subcommand.

```
usulnet --quiet config check                # only errors / final state
usulnet --json meta info /tmp/photo.jpg     # machine-readable output
usulnet --json admin reset-password alice   # JSON error on failure
```

### CLI: structured JSON error envelope

With `--json` set, errors are emitted as a single-record envelope on
stderr:

```json
{"error": "config: USULNET_DATABASE_URL is required", "code": 64}
```

The `code` field matches the process exit code. The plain formatter
prefixes the line with `usulnet:`; Cobra's own usage dump is
suppressed via `SilenceUsage` + `SilenceErrors` on `rootCmd`, so a
typo'd flag now prints only the error rather than the full help text.

Exit codes are stable across the binary:

| Code | Meaning |
|---:|---|
| 0 | Success |
| 64 | Usage (bad flag, missing arg) |
| 70 | Infra (config / unreachable dep) |
| 71 | Server unreachable |
| 72 | Auth failure |

### CLI: `migrate` subtree (`up` / `down [N]` / `status`)

`migrate` is now a parent command. The three leaf subcommands:

```
usulnet migrate up         # apply pending migrations
usulnet migrate down [N]   # roll back the last N (default 1)
usulnet migrate status     # one line per migration with applied/pending state
```

Bare `usulnet migrate` prints help instead of failing with Cobra's
default error — matches the shape of every other parent command
(`config`, `admin`, `meta`, `recon`).

### CLI: `meta strip --output` → `--output-file`

The destination-path flag on `usulnet meta strip` previously shadowed
the global `--output table|json|yaml` format flag (same name, two
meanings on the same line). The destination flag is now
`--output-file`; the `-o` short form is preserved so most one-liner
operators stay unchanged. Scripts using the long `--output cleaned.jpg`
form must update — no alias is shipped. Migration note in
[`docs/cli.md`](../cli.md#meta-strip---output-file-migration-note).

### CLI: shared `apiclient` sub-package

The HTTP client used by `recon` and `meta` is now extracted to
`cmd/usulnet/internal/apiclient/`. Same behaviour, single
constructor — typed errors (`ErrConfig` / `ErrNetwork` / `ErrAuth` /
`ErrStatus`) drive the documented exit codes (71 / 72 / 70).

### Agent: Cobra command tree

`usulnet-agent` is now a Cobra binary with three subcommands:

```
usulnet-agent run               # default — same behaviour as bare usulnet-agent
usulnet-agent version           # build info, matches usulnet
usulnet-agent validate-config   # parse the resolved config, run the required-field check
```

Bare `usulnet-agent` remains equivalent to `usulnet-agent run` — no
breaking change for existing systemd units or compose specs.
Persistent flags (`--config`, `--gateway`, `--token`, `--docker`,
`--hostname`, `--log-level`, `--log-format`, `--data-dir`) work on
every subcommand.

`validate-config` is the recommended pre-flight before restarting an
agent in production:

```bash
usulnet-agent validate-config --config /etc/usulnet-agent/config.yaml
echo $?   # 0 only when a startable config can be assembled
```

The YAML schema is unchanged — existing `config.agent.yaml` files
keep working without edits. Internally, the agent now unmarshals
directly into `agent.Config` rather than through a parallel
`agentFileConfig` mirror struct.

### Agent: `USULNET_AGENT_DOCKER_HOST` env var

Canonical source for `--docker`; falls through to `$DOCKER_HOST` (for
parity with Docker tooling) and then the unix-socket default.
Resolves the prior mixed-prefix confusion (every other agent env var
was `USULNET_*`-prefixed). **No breaking change** — `DOCKER_HOST` and
the YAML / flag forms still work.

### Web: a11y landmarks on header, sidebar, modal, flash

Pure semantic markup — no visual change. Screen readers and keyboard
users get the same affordances as the visible UI.

| Element | Change |
|---|---|
| `<main role="main">` | Wraps the page body so AT users can jump straight to content. |
| Collapsible sidebar groups | Carry `aria-expanded` reflecting the Alpine state. |
| Mobile sidebar toggle | Carries `aria-label` + `aria-controls`. |
| Modal partial | Renders as `role="dialog" aria-modal="true"` with the heading wired via `aria-labelledby`. |
| Flash messages | Live in an `aria-live="polite"` region. |

A per-page sweep (form labels, table headers, focus management on
modal open/close) is tracked separately — see **Known limitations**
below.

### CLI: shell tab-completion

Both binaries register Cobra's `completion <shell>` for `bash`, `zsh`,
`fish`, and `powershell` (auto-wired by the framework). Three install
paths:

```bash
# Operator-side helper (auto-detects shell, writes per-user)
deploy/install-completions.sh

# Same, system-wide
sudo deploy/install-completions.sh --system

# Makefile target (delegates to the script)
make install-completions

# Docker image — both production images bake the four scripts so
# operators can copy them out without running the binary on the host
docker cp usulnet:/app/completions/bash/usulnet /etc/bash_completion.d/usulnet
```

The pre-baked completions live at
`/app/completions/{bash,zsh,fish,powershell}/<binary>` inside the
runtime image. Reference: [`docs/cli.md#tab-completion`](../cli.md#tab-completion).

### Docs: new CLI reference at `docs/cli.md`

One-stop operator reference for the CLI surface:

- Subcommand table (all 16 leaves, grouped by parent)
- Global flags (`--quiet`, `--json`, `--output`, `--config`)
- Exit codes (0 / 64 / 70 / 71 / 72)
- Error formats (plain `usulnet:` prefix + JSON envelope)
- The `meta strip --output-file` migration note
- Tab-completion install reference

Linked from the [README](../../README.md) and from
[`docs/agents.md`](../agents.md).

## Upgrade procedure

v26.5.1 → v26.5.2 is **migration-additive only — and in this release,
nothing additive runs.** No table is created, no destructive `ALTER`
runs against an existing v26.5.1 table.

Roll forward by pulling the new image and restarting:

```bash
docker compose pull
docker compose up -d
```

`scripts/verify-migrations.sh` (part of `make quality`) continues to
assert no gap, no duplicate, no orphan `up.sql` / `down.sql`. After
restart, `usulnet migrate status` should report the v26.5.1 set
(046–056) still applied and nothing pending.

No application config key is removed. No config key is renamed. The
only optional new keys are the Shodan connector toggle
(`recon.connectors.shodan.enabled`, default `false`) and the
canonical agent Docker-host env var (`USULNET_AGENT_DOCKER_HOST`,
falls through to the existing `$DOCKER_HOST` / unix-socket default).

### CLI scripting

One script change is required: any operator script using
`usulnet meta strip --output cleaned.jpg` must switch to
`--output-file cleaned.jpg`. The `-o` short form is preserved, so
short-form invocations are unchanged.

If you script around the CLI's stderr output, the new
`--json` envelope is opt-in; the plain formatter keeps the
`usulnet: <message>` prefix it had in v26.5.1, just without Cobra's
usage dump after it. Scripts that grep for `Error:` should grep for
`usulnet:` instead, or pass `--json` and parse the envelope.

## Rollback

If you need to revert to v26.5.1, simply redeploy the v26.5.1 image —
no migration to roll back. The `recon_connectors` Shodan row (if
present) is harmless to v26.5.1: that build reads `kind` from a
strict allow-list and ignores any row whose `kind` it does not
recognise. Optionally clean it up first:

```sql
DELETE FROM recon_connectors WHERE kind = 'shodan';
```

The agent rollback is the same — `usulnet-agent` v26.5.1 reads the
same `config.agent.yaml` and the same env vars. Operators who already
flipped to `USULNET_AGENT_DOCKER_HOST` on their managed nodes can
leave the env var in place; v26.5.1 ignores it and falls back to
`$DOCKER_HOST` / the unix-socket default.

## Known limitations

The following work was tracked under v26.5.2 but is **deferred to a
follow-up release**:

- **Per-shell automated tab-completion install hooks** (apk / apt
  postinstall) — `deploy/install-completions.sh` covers the manual
  per-user / system-wide flow; package-manager integration is a
  follow-up.
- **Automated a11y CI gate** (axe-core / pa11y as part of `make test`)
  — the v26.5.2 a11y work was validated by manual review and the
  per-page sweep below; an automated gate that fails CI on contrast
  / landmark / labelling regressions is a v26.6 item.
- **Profile-guided optimization** (`-pgo` builds against a captured
  workload trace) — out of scope for the v26.5.2 cycle; tracked for
  v26.6.
- **Light theme — full per-page audit** (plan session 13). The theme
  toggle is wired in `internal/web/preferences.go` and surfaced from
  the profile page, but several module pages still hard-code dark
  Tailwind palette classes. v26.6 will land the per-page sweep
  (estimated ~40 files in `internal/web/templates/pages/`).
- **Frontend animations** (plan session 14): HTMX swap fade-in,
  sidebar accordion transition, toast slide-in, hover
  micro-interactions. Tracked for v26.6 — the CSS / Alpine plumbing
  is in place but the animation styles never landed in
  `web/static/src/input.css`.
- **trufflehog volume secrets scanner** (plan session 09 — second
  half). Session 09's YARA half shipped in
  [#159](https://github.com/fran-olivares/usulnetdevbeta04/pull/159);
  the matching trufflehog `secrets_volume` analyzer that walks a
  Docker volume looking for leaked credentials remains deferred.
  Operators who want this today can deploy the upstream
  `trufflesecurity/trufflehog` container directly via the marketplace
  and point it at a host bind mount; the in-product integration
  lands in v26.6.
- **BlackArch overlay + full OSINT toolset for recon-toolkit**. The
  recon-toolkit image rebase landed in
  [#160](https://github.com/fran-olivares/usulnetdevbeta04/pull/160)
  on Arch + pip (mat2, exiftool, yara, holehe, h8mail, oletools,
  pdfid). The wider BlackArch overlay and Go-binary set
  (phoneinfoga, subfinder, katana, amass, nuclei, etc.) is tracked
  for v26.6 — three CI attempts to bootstrap BlackArch on top of
  `archlinux:latest` failed in the PR build job in <60s without a
  recoverable log; the follow-up lands them once the log path is
  reachable from the CI environment.

Work originally tracked as "deferred" but completed in-cycle before
tag:

- **Per-page accessibility sweep.** The chrome-level landmarks
  (header / sidebar / modal / flash) shipped at the release cut; the
  per-page sweep then landed across the full
  `internal/web/templates/` tree — every Font Awesome icon picked up
  `aria-hidden="true"` (~1914 sites), every `<th>` in `<thead>` got
  `scope="col"` (~670 sites), single-line `<input placeholder=…>`
  picked up `aria-label="…"`, multi-line `<input>` declarations did
  the same in a per-template manual pass, and the modal component
  now manages focus on open/close (stores the trigger element,
  focuses the first focusable child on open, returns focus on close).
- **Performance / optimization pass.** Three perf-pass landings
  reduce hot-path latency and allocation:
    - **Frontend gzip + batched alert event resolution + request-id
      `strconv`.** `chimiddleware.NewCompressor` cuts ~70 % off the
      vendor JS / CSS bundles served by `/static/*`. The compressor
      is scoped to non-CSRF routes only — see the §"Security recap"
      below. `internal/repository/postgres/alert_repo.go::ResolveActiveEvents`
      collapses N per-alert UPDATE round-trips into one parameterised
      statement. `strconv.FormatInt` replaces `fmt.Sprintf("%d", …)`
      in the per-request request-id middleware (−56 % ns/op on a
      hot path that runs on every frontend request).
    - **Host summary fan-out.** `host.Service.ListSummaries` no
      longer serialises per-host `client.Info()` calls; the
      enrichment runs across a goroutine pool capped at 16 so an
      N-host install pays `max(T)` latency instead of `N × T`.
    - **Container reconciliation fan-out.** The periodic
      `container.Service.syncAllHosts` worker (default tick: 5 min,
      configurable via `containers.sync_interval`) no longer
      serialises per-host `SyncHost` calls. The list-online-hosts
      result is fanned out across a goroutine pool capped at 8
      (lower than the 16 used by the host-summary fan-out because
      `SyncHost` issues a list + N inspect + N upsert sequence per
      host, and 8 is the conservative limit against the default 25-
      connection PostgreSQL pool). For large installs the safety-net
      reconciliation no longer risks overrunning its own tick
      interval. Per-host error handling is unchanged: failures are
      logged at warn and skipped, exactly as the previous serial
      loop did.
    - **Shared WebSocket JSON encoder pool.** Both hot text-frame
      writers — the nvim editor's pty → browser goroutine in
      `internal/web/ws_editor_nvim.go` and the SSH terminal's
      stdout / stderr → browser goroutines in
      `internal/web/handler_ssh_terminal.go` — now encode through
      a single shared `wsJSONEncoder` (paired `bytes.Buffer` +
      `json.Encoder`) recycled via `sync.Pool` in
      `internal/web/ws_json_pool.go`. The pool replaces both the
      per-call `json.Marshal` in the editor and the per-call
      `ws.WriteJSON` in the SSH handler. The change is byte-
      identical to the previous wire format on both paths — pinned
      by `TestEncodeWSJSONInto_ByteIdenticalToJSONMarshal` with 18
      sub-cases covering every concrete shape (editor `output` /
      `error` / `committed` / `resize`; SSH `output` /
      `credential_request` / `resize` / `connected`).
      `TestEncodeWSJSONInto_AcrossMessageShapes` separately
      pins that recycling the same pool entry across the two
      concrete struct types does not bleed bytes between them.
      The benchmark in the same file reports ~36 % less wall time
      and ~99 % less garbage per message (4914 B/op → 48 B/op).
- **CLI walk-the-tree tests.** T1 / T2 / T3 from the session-19
  audit (`Long:` populated on every leaf, `RunE` (not `Run`) on
  every leaf, parent → child invariants) are now pinned by
  `TestCommandTree_LeafContract` / `TestCommandTree_ParentContract`
  in `cmd/usulnet/main_test.go`, and the corresponding
  `TestCommandTree_LeafContract` / `TestCommandTree_RootContract`
  in `cmd/usulnet-agent/main_test.go`. Both walk the live Cobra
  tree at test time, so a future leaf added without `Long:` /
  `Example:` / `RunE` fails CI before it can ship.

None of the above blocks a v26.5.1 → v26.5.2 upgrade; they are tracked
in the development backlog under the v26.6 milestone.

## Module-by-module summary

| Area | Change |
|---|---|
| **recon** | Shodan connector added (BYO key); HIBP unchanged. Full-cycle secrecy test pins that the key never leaks into logs, errors, or `url.Error` text. |
| **CLI (`usulnet`)** | Global `--quiet` / `--json` flags; JSON error envelope; `migrate up` / `down [N]` / `status` subcommands; `meta strip --output` renamed to `--output-file`; shared `apiclient` sub-package; help-text polish (`Example:` + `Long:`) on every leaf; `SilenceUsage` + `SilenceErrors` on root. |
| **agent (`usulnet-agent`)** | Cobra command tree (`run` / `version` / `validate-config`); canonical `USULNET_AGENT_DOCKER_HOST` env var; direct YAML unmarshal into `agent.Config` (no parallel mirror struct). Bare `usulnet-agent` continues to behave as `usulnet-agent run`. |
| **web (a11y)** | `<main role="main">`; `aria-expanded` on sidebar groups; `aria-label` + `aria-controls` on mobile sidebar toggle; `role="dialog" aria-modal="true"` + `aria-labelledby` on modal partial; `aria-live="polite"` on flash region. |
| **docs** | New CLI reference at `docs/cli.md`. Agent + installation pages refreshed for the new env var and `validate-config` subcommand. |
| **deploy** | Shell tab-completion install script (`deploy/install-completions.sh`); `make install-completions` target; both production Docker images bake `/app/completions/{bash,zsh,fish,powershell}/<binary>`. |

## Security recap

v26.5.2's hardening posture against the v26.5.1 baseline:

- **External port surface unchanged.** HTTPS (`7443`) is the only
  port published by default; HTTP (`8080`) is commented out and used
  internally for health checks. NATS (`4222`) stays on the private
  `usulnet-backend` Docker network.
- **No new bind mount.** v26.5.2 introduces no new bind mount.
  The Docker socket is still mounted only into the usulnet container
  and the optional `usulnet-agent` container.
- **No new container capability.** No module added `NET_ADMIN`,
  `NET_RAW`, or any new entry to `cap_add`. The pre-existing
  `SYS_PTRACE` / `SYS_ADMIN` on the usulnet container are unchanged.
- **No call-home.** The repo-wide grep for `usulnet.com` endpoints
  still returns the same three matches as v26.5.1 (HIBP `User-Agent`
  string, iCal UID suffix per RFC 5545, NATS subject prefixes) plus
  one new match: the Shodan connector's `User-Agent` string follows
  the HIBP pattern (`usulnet-recon/26.5.2 (+https://usulnet.com)`).
  As with HIBP, the URL is a product identifier sent to Shodan only
  when the operator has explicitly enabled the connector and supplied
  their API key. **No connection is made to usulnet.com.**
- **Shodan key secrecy.** The Shodan API key is sent in the query
  string (Shodan's only supported auth method). The connector scrubs
  the key out of every transport error before returning it, including
  `url.Error` text. Pinned by
  `internal/services/recon/connectors/shodan/connector_test.go:549`
  (`TestSecrecyInvariant_FullCycle`).
- **JSON error envelope.** `--json` errors are produced via
  `encoding/json.Marshal` of a fixed-shape struct (no reflection over
  internal state); no stack trace, no file path, no internal
  identifier reaches stderr.
- **govulncheck CI.** `.github/workflows/govulncheck.yml` continues
  to run on every push to `main` and every PR; the two server-side
  Moby false positives (`GO-2026-4883`, `GO-2026-4887`) remain in the
  allowlist of `scripts/govulncheck.sh` with the same inline
  justifications as v26.5.1 (both are daemon-side defects in plugin
  install paths that usulnet does not exercise).

A full signed audit document mirroring
[`docs/v26.5/security-review-v26.5.1.md`](../v26.5/security-review-v26.5.1.md)
lands as
[`docs/v26.5/security-review-v26.5.2.md`](../v26.5/security-review-v26.5.2.md).
The audit reports **0 new exploitable vectors and 0 open advisories**
across the v26.5.2 code changes (Shodan, agent Cobra port,
`USULNET_AGENT_DOCKER_HOST`, CLI tab-completion script, web a11y
landmarks, JSON error envelope, route-scoped frontend gzip, batched
alert event resolution, request-id `strconv` swap). The two advisories
raised during the audit were both resolved before tag:

- The BREACH-class risk on compressed CSRF-bearing pages is closed by
  scoping `chimiddleware.NewCompressor` to two sub-groups in
  `internal/web/routes_frontend.go` — static assets and unauthenticated
  HTML (login, OAuth, health, `/docs/api`) — and removing it entirely
  from the authenticated route group. The protected response body no
  longer travels over the wire compressed, so the CSRF token in
  `<meta name="csrf-token">` and in hidden form fields is no longer
  exposed to compression-ratio side-channels. Pinned by
  `routes_frontend_perf_test.go::TestProtectedRouteNotCompressed`,
  which also keeps the static + public sub-groups gzipped as positive
  controls.
- The earlier `eval` advisory in `deploy/install-completions.sh` was
  resolved in the same release cycle — the install script now invokes
  operations through dedicated `run_mkdir` / `run_completion` helpers
  with no `eval`.

## No breaking changes

- No removed API endpoint.
- No removed config key.
- No removed CLI subcommand.
- No removed permission key.
- No removed database table or column.

Two CLI surface adjustments are worth calling out for scripts:

- `usulnet meta strip --output cleaned.jpg` is replaced by
  `usulnet meta strip --output-file cleaned.jpg`. The `-o` short
  form is preserved.
- Cobra's full-help dump after a `RunE` error is gone. Plain errors
  print only `usulnet: <message>`; `--json` errors print the
  envelope. `--help` still works on demand.

Both are surface-level and do not change the underlying behaviour of
any command.

## Capability requirements

Unchanged from v26.5.1. The v26.5.1 module matrix
([`docs/installation.md#capability-requirements-v2651-modules`](../installation.md#capability-requirements-v2651-modules))
applies as-is — no new module in v26.5.2 needs a capability the
default compose stack does not already provide.

The Shodan connector needs outbound HTTPS to `api.shodan.io` when
enabled (operator-configured, like every other recon connector). No
other v26.5.2 module touches the network.

## Acknowledgements

The CLI / agent / web-a11y refresh was scoped from the session-19
audit (`dev/0526/x/screenshots/session-19-cli-audit.md`) and the
session-18 frontend audit
(`dev/0526/x/screenshots/session-18-frontend-audit.md`). The Shodan
connector follows the HIBP connector pattern from v26.5.0; both
share the encrypted-at-rest `recon_connectors` schema introduced by
migration `045_recon_connectors.up.sql`.
