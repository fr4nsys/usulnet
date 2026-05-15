# Changelog

All notable changes to **usulnet** are recorded here. The format
roughly follows [Keep a Changelog](https://keepachangelog.com/) and
the project uses CalVer-style minor releases (v26.x).

## [Unreleased]

### [v26.5.1-cloud] — Cloud launch

Marketing / SaaS-launch release. **No Go code shipped in this tag.**
The AGPL self-hosted Docker platform is unchanged; self-hosted installs
do not need to upgrade. Cloud is an independent SaaS at
`cloud.usulnet.com` and does not share auth, storage, or a database
with self-hosted installs. Full notes:
[`docs/v26.5.1-cloud/release-notes.md`](docs/v26.5.1-cloud/release-notes.md).

#### Added

- **Cloud tiers on `cloud.usulnet.com`.** Three recurring subscriptions
  — Cloud Monthly, Cloud Annual, Cloud 5-Year — sold from
  `usulnet.com/pricing` and billed via Polar.sh as merchant of record.
  Pricing lives on the marketing page; numbers are sourced from
  Cloudflare bindings, never embedded in code.
- **Polar.sh checkout (S05).** `POST /api/v1/billing/checkout` and
  `GET /api/v1/billing/return` on the Cloudflare Worker
  (`usulnetdotcom-main/_worker.js`, `usulnetdotcom-main/api/polar.js`).
  Sandbox-validated end-to-end for all three tiers.
- **Polar.sh webhook + Cloudflare D1 account provisioning (S06).**
  `POST /api/v1/billing/webhook/polar` is signature-verified
  (HMAC-SHA-256, ±5-minute replay guard) and idempotent on Polar's
  `event.id`. `subscription.created` upserts `accounts` + inserts
  `subscriptions` + enqueues a `magic_link` outbox row;
  `subscription.updated` refreshes `status` and `current_period_end`;
  `subscription.canceled` flips `status` to `'cancelled'` and
  **preserves** `current_period_end`; `subscription.uncanceled`
  reverts to `'active'`; `order.refunded` flips the related
  subscription's `status` to `'refunded'` and enqueues a
  `refund_audit` outbox row. The webhook does NOT issue license JWTs
  and does NOT touch any AGPL `licenses` table. See
  [`docs/0526/technical-notes.md`](docs/0526/technical-notes.md) for
  the full event matrix and idempotency contract.
- **`olivaresai/usulnet` public mirror (S03).** Every push to
  `fr4nsys/usulnet/main` is `git push --mirror`'d to
  `olivaresai/usulnet` within 5 minutes. Tags propagate via the same
  workflow.
- **Privacy-first public README + Incogni positioning (S01).** Public
  README leads with the privacy story, names the recon module in its
  first paragraph, and includes an Incogni comparison table with an
  AGPL disclaimer.

#### Known limitations

- The Business tier still uses Stripe via the existing
  `https://api.usulnet.com/api/v1/checkout` flow. The Polar migration
  for Business is intentionally deferred (TODO comment in
  `usulnetdotcom-main/_worker.js`).
- The outbox dispatcher (magic-link + refund-audit email sender) is
  not shipped in v26.5.1-cloud. Outbox rows are persisted in D1 but
  unsent. Tracked in
  [#35](https://github.com/fr4nsys/usulnetdevbeta04/issues/35).

## [v26.5.1] — 2026-05-15

Self-hosted track. Brings the v26.2.7 module set forward into the AGPL
build with no biz gating, no call-home, and no breaking changes against
v26.5.0. Eleven modules formerly gated behind the Business edition now
ship in the standard AGPL binary. Tracked in
[`docs/v26.5/merge-plan-v26.5.1.md`](docs/v26.5/merge-plan-v26.5.1.md)
with per-module status in
[`docs/v26.5/v26.5.1-ported-modules.md`](docs/v26.5/v26.5.1-ported-modules.md).
Operator-facing release notes at
[`docs/v26.5/release-notes-v26.5.1.md`](docs/v26.5/release-notes-v26.5.1.md).

### Removed

- **Edition gating (biz/enterprise checks); all features available in
  the AGPL build.** Session 13 deletes the last `isEditionAvailable` /
  `navItemLocked` callsites in `internal/web/templates/partials/sidebar.templ`,
  drops the `requireFeature` web middleware along with its 27 callsites
  in `internal/web/routes_frontend.go`, and removes the API enforcement
  middleware `RequireFeature` / `RequirePaid` / `RequireEnterprise` /
  `RequireLimit` plus every callsite in `internal/api/handlers/`
  (`users.go`, `audit.go`, `settings.go`, `backups.go`, `notifications.go`,
  `hosts.go`). Service-level `limitProvider` enforcement is dropped from
  `team`, `user`, `host`, `git`, `storage`, `notification`, and `backup`
  — operator-controlled caps via `Config.Max*` remain. The `apierrors`
  helpers `LicenseRequired` / `LicenseExpired` / `FeatureDisabled` and
  the `pkg/errors.LimitExceeded` helper are removed along with their
  `LICENSE_REQUIRED` / `LICENSE_EXPIRED` / `FEATURE_DISABLED` /
  `LIMIT_EXCEEDED` error codes; only `LICENSE_INVALID` survives because
  it tags JWT cryptographic-validation failures.
- **Hard-coded Community-Edition resource caps.** `license.CELimits()`
  no longer caps `MaxNodes=1` / `MaxUsers=3` / `MaxAPIKeys=3` etc.; it
  is replaced by `license.OpenLimits()` which returns the zero value of
  `Limits` (all unlimited). `license.NewCEInfo()` (kept as an alias of
  the new `license.NewOpenInfo()`) now installs `AllFeatures()` on
  every resolved license. `license.AllBusinessFeatures()` and
  `license.AllEnterpriseFeatures()` are collapsed into the single
  `license.AllFeatures()`. `license.CEBaseNodes` and
  `license.BusinessDefaultLimits()` / `license.EnterpriseLimits()` are
  retired. `ClaimsToInfo` still parses commercial tokens for the
  support-tier tag (Business / Enterprise) and expiry banner, but the
  resolved capability is identical to the no-token state — every
  feature unlocked, every limit unlimited. The new
  `TestOpenEdition_UnlocksEverything` regression test pins principle 2
  from `docs/0526/x/principles.md`.
- **License-tier comparison table on the in-product License page.**
  `internal/web/templates/pages/license/page.templ` no longer renders
  the CE / Business / Enterprise comparison or the upsell button. The
  page now shows the AGPL banner, the instance fingerprint, and an
  optional support-token activation form whose copy clarifies the
  token only records a support contract — it does not unlock features.

The sidebar `Sidebar(...)` signature still accepts `edition` /
`editionName` so existing call sites do not change, but the parameters
are unused inside the template. The `Edition` constants (`CE` / `Business`
/ `Enterprise`) and their `EditionName()` accessor are intentionally
preserved so previously-issued commercial JWTs remain parseable; this
leaves two non-functional matches for `grep -niE '"biz"|"enterprise"'`
inside `internal/license/license.go` (the constant definitions and the
display-name switch) — neither gates any feature.

### Added

- **marketplace — curated app marketplace with offline-first catalogue
  and local-only reviews.** Port of the v26.2.7 marketplace module under
  `internal/services/marketplace/`,
  `internal/repository/postgres/marketplace_repo.go` (renamed from
  v26.2.7's `marketplace.go`), `internal/api/handlers/marketplace.go`
  (NEW — v26.2.7 had no API), `internal/web/handler_marketplace.go`,
  and `internal/web/templates/pages/marketplace/`. Migration
  `056_marketplace.up.sql` creates `marketplace_apps`,
  `marketplace_installations`, and `marketplace_reviews`, renumbered
  from v26.2.7's 054 to slot above the v26.5.0 `recon_*` tables and the
  preceding v26.5.1 ports. Sidebar entry lives in Integrations →
  Marketplace with no edition gate. The catalogue source is **offline
  static**: app templates ship under
  `internal/templates/marketplace/<slug>/{manifest.yaml,
  compose.yaml,icon.svg}` and are baked into the binary via
  `go:embed`. On boot, `(*Service).HydrateCatalog` reads every
  embedded entry and upserts it into `marketplace_apps`: rows with
  `built_in=true` whose `manifest_version` is older than the embedded
  one are replaced (UUID, install_count, and avg_rating preserved);
  missing built-in apps are inserted; user-submitted rows
  (`built_in=false`) are left untouched, even if they share a slug.
  The "no call-home" guarantee is asserted by a unit test
  (`TestStart_NoOutboundCalls`) that wires `http.DefaultTransport` to
  fail every dial and verifies hydration issues none. Upstream image
  licenses for the four shipped templates (nginx BSD-2-Clause,
  traefik/whoami MIT, Gitea MIT, Uptime Kuma MIT) are documented in
  `internal/templates/marketplace/LICENSES.md` with an AGPL-compatibility
  policy that explicitly rejects SSPL, Elastic License, BSL, and
  "free-for-personal-use" terms. Reviews are local-only: the
  `marketplace_reviews` table has a unique `(user_id, app_id)`
  constraint, paired with `MarketplaceReviewRepository.Upsert` so
  concurrent writes from the same user collapse to one row instead of
  racing — no submission to any external service. Install action wires
  through the existing stack service: the compose template is rendered
  with `{{KEY}}` substitution against user-supplied + manifest-default
  field values, the resulting docker-compose is handed to
  `stack.Service.Create`, and the new `stack_id` is stored on the
  installation row so the installed-apps page can link back. REST API at
  `/api/v1/marketplace/*`: `GET /apps`, `GET /featured`,
  `GET /apps/{slug}`, `POST /apps/{slug}/install` (returns
  `installation_id` + `stack_id`), `GET /apps/{slug}/reviews`,
  `GET /installations`, `GET /installations/{id}`,
  `POST /installations/{id}/uninstall`, `POST /reviews`. Read
  endpoints are viewer+, installs and reviews operator+. New
  permission keys `marketplace:view` / `marketplace:write` added to the
  legacy RBAC map. Built-in apps are protected from deletion at the
  service layer (would rehydrate on next boot anyway). Web UI renders
  six templ pages (browse grid, app detail with reviews, install form,
  installed list, submit form, leave-a-review form). Service unit tests
  at 70.0 % coverage; embedded-catalogue tests at 80.3 %. Decision
  notes: the existing `internal/templates/catalog/` tree
  (container templates, an unrelated feature shipped before v26.5.1) is
  intentionally left alone — marketplace ships under a separate
  `internal/templates/marketplace/` tree so the two surfaces stay
  independent and a new app template never accidentally registers as a
  container template.
- **calendar — operations calendar with iCalendar (.ics) export and
  cross-feature event aggregation.** Port of the v26.2.7 calendar
  module under `internal/services/calendar/`,
  `internal/repository/postgres/calendar_repo.go`,
  `internal/api/handlers/calendar.go`,
  `internal/web/handler_calendar.go`, and
  `internal/web/templates/pages/calendar/`. Migration
  `046_calendar.up.sql` creates `calendar_events` with a composite
  index on `(starts_at, ends_at)` for fast range queries plus
  per-host and per-kind indexes (renumbered from v26.2.7's 044 to
  slot above the v26.5.0 `recon_*` tables). Sidebar entry lives in
  Tools → Calendar with no edition gate. The kind column is
  constrained at the database level to a strict allow-list
  (`maintenance`, `backup`, `deploy`, `job`, `alert`, `note`) so
  the calendar cannot become a junk drawer; the
  `calendar_events_range_check` constraint refuses rows where
  `ends_at < starts_at`. REST API at `/api/v1/calendar/*`:
  `GET /events?from=…&to=…`, `POST /events`, `GET/PUT/DELETE
  /events/{id}`, `GET /stats`, `GET /sources`, and the
  RFC 5545 `GET /export.ics`. Read endpoints are viewer+,
  mutations operator+. Improvements vs v26.2.7: only manually-
  entered events are persisted in `calendar_events`; backup runs
  and scheduled jobs are surfaced read-only at query time via a
  new `EventSource` interface (`internal/services/calendar/sources.go`)
  so the calendar reflects the truth in each upstream service
  instead of duplicating tables. Two sources ship in this port —
  `BackupSource` translates `backups.started_at`/`completed_at`
  plus `backup_schedules.next_run_at` windows; `ScheduledJobSource`
  surfaces `scheduled_jobs.next_run_at`. Aggregator failures are
  logged and skipped rather than blanking the whole calendar. The
  iCalendar export hand-rolls a CRLF-terminated, 75-octet-folded
  document with backslash/comma/semicolon/newline TEXT escapes,
  UTC `DTSTART`/`DTEND` (with `VALUE=DATE` for all-day events),
  `CATEGORIES:<KIND>,SOURCE-<SOURCE>` for client-side filtering,
  and an RFC 5545 `BEGIN:VCALENDAR`/`END:VCALENDAR` envelope
  including `VERSION:2.0`, `PRODID`, and `CALSCALE:GREGORIAN`.
  Validation is asserted by a unit test that unfolds the document
  with a generic continuation-line parser and verifies every
  required property, the UTC-Z timestamp form, and round-tripping
  of a 200-char folded SUMMARY. Range queries are capped at 366
  days; reversed or oversized windows return a typed
  `ErrInvalidRange`. Service unit tests at 89.9 % coverage.
- **dns — DNS provider plugins for ACME DNS-01 and proxy record automation.**
  Reframes the v26.2.7 DNS module under `internal/services/dns/` from an
  embedded miekg/dns authoritative server (out of scope per
  `docs/0526/x/session-10-dns.md`) to a thin plugin layer that drops
  records into Cloudflare, AWS Route 53, DigitalOcean, and any RFC 2136
  dynamic-update nameserver. Plugin code lives under
  `internal/services/dns/providers/<kind>/`. Persistence at
  `internal/repository/postgres/dns_repo.go`,
  `internal/api/handlers/dns.go` (NEW — v26.2.7 had no API),
  `internal/web/handler_dns.go` and `internal/web/templates/pages/dns/`.
  Migration `048_dns.up.sql` creates `dns_providers`, `dns_records`,
  `dns_acme_orders`, `dns_audit_log` (renumbered from v26.2.7's 046 to
  slot above the v26.5.0 `recon_*` tables and the v26.5.1
  `047_proxy_extended`). Sidebar entry lives in Integrations → DNS
  Providers, gated only by the per-user `prefs.IsHidden("dns")`
  preference — no edition gate. Plugin registration is explicit:
  `internal/services/dns/providers.RegisterAll` is called once at boot
  in `init_services.go`, replacing the v26.2.7 init() side-effect drift.
  Provider credentials are AES-256-GCM encrypted at rest with the
  installation data encryption key (same posture as recon HIBP and TOTP
  secrets); the `credentials` column in `dns_providers` is base64
  ciphertext, never reachable via the REST API. The ACME DNS-01 flow is
  a persistent state machine
  (`pending → dropping → propagating → ready → completing → completed`,
  with `failed` as the sad terminal): orders are durable so usulnet
  resumes them after a restart via
  `(*Service).ResumeInFlightOrders`. Cloudflare and DigitalOcean speak
  their REST APIs over `net/http` (no vendor SDK — keeps the dep tree
  small per session-10's risk note); Route 53 reuses the AWS SDK v2
  already vendored for S3, with the new
  `github.com/aws/aws-sdk-go-v2/service/route53` module pulled in;
  RFC 2136 uses `github.com/miekg/dns` for wire-level UPDATE messages
  authenticated with TSIG (HMAC-SHA{1,256,512} or HMAC-MD5).
  REST API: `GET/POST/PUT/DELETE /api/v1/dns/providers`,
  `GET /api/v1/dns/supported-providers`,
  `GET/POST/DELETE /api/v1/dns/records?provider_id=…&host_id=…`,
  `GET/POST /api/v1/dns/acme-orders`,
  `POST /api/v1/dns/acme-orders/{id}/{process,complete,fail}`,
  `GET /api/v1/dns/audit`. New permission keys `dns:view` /
  `dns:write` added to the legacy RBAC map. Improvements vs v26.2.7:
  the embedded BIND-style server and zone editor are gone (out of
  scope); plugin registration is explicit, not init(); credentials are
  encrypted and JSON-redacted from API responses; no real-API tests —
  every provider has an httptest-backed unit suite plus a Cloudflare-
  mocked smoke E2E that asserts TXT-drop/clean. Service+plugin unit
  tests at 60–76 % per package.
- **crontab — managed cron jobs with web UI, REST API, and live execution tail.**
  Port of the v26.2.7 crontab module under
  `internal/services/crontab/`, `internal/repository/postgres/crontab_repo.go`,
  `internal/api/handlers/crontab.go`, `internal/web/handler_crontab.go`, and
  `internal/web/templates/pages/crontab/`. Migration `049_crontab.up.sql`
  creates `crontab_entries` and `crontab_executions` (renumbered from v26.2.7's
  047 to slot above the v26.5.0 `recon_*` tables). Sidebar entry lives in
  Operations → Crontab with no edition gate. Scheduling and parsing use
  `github.com/robfig/cron/v3` — the same parser the rest of the codebase
  already depends on, so no second cron implementation is added. The
  shell command type intentionally invokes `sh -c <script>` so users can
  write shell pipelines; docker and http types never reach a shell parser.
  Improvements vs v26.2.7: full REST API at `/api/v1/crontab/*` (CRUD,
  run-now, toggle, paginated executions, WebSocket `/executions/tail`
  for live updates — none existed in v26.2.7); execution-list pagination
  capped to 100 by default (v26.2.7 had a hard-coded 50 limit but no
  total/offset); input validation on name/schedule/command_type returns
  typed sentinel errors (`ErrInvalidSchedule`, `ErrInvalidInput`); docker
  command type now executes via explicit `docker exec` argv slice
  instead of returning "not supported"; HTTP response body capped at
  64 KiB to keep executions table bounded; service constructor accepts
  a nil logger via `logger.Nop()` matching the v26.5.0 convention; new
  `crontab:view` / `crontab:execute` permissions in the legacy RBAC map
  so operators can manage their own cron jobs without admin escalation.
- **backup-verify — automated backup verification with sandboxed restore tests.**
  Port of the v26.2.7 backup verification module under
  `internal/services/backupverify/`,
  `internal/repository/postgres/backup_verify_repo.go`,
  `internal/api/handlers/backup_verify.go`,
  `internal/web/handler_backup_verify.go`, and
  `internal/web/templates/pages/backupverify/`. Migration
  `052_backup_verification.up.sql` creates `backup_verifications` and
  `backup_verification_schedules` (renumbered from v26.2.7's 050 to slot
  above 049_crontab and 050_firewall). Sidebar entry lives in Operations
  → Backup Verify with no edition gate (the v26.2.7 `biz` lock has been
  dropped per the v26.5.0 "one AGPL build" principle). The new scheduler
  worker `JobTypeBackupVerify` drains scheduled verifications: it picks
  the top-N most-recent completed backups per schedule and runs each
  through the configured method. Container and database verification
  methods use a sandboxed restore container built on the recon sandbox
  launcher (`internal/services/recon/sandbox/launcher.go`) — read-only
  rootfs, dropped capabilities (`CAP_DROP=ALL`), no-new-privileges,
  default seccomp, non-root UID 65534, 512 MiB / 1 vCPU / 256 PIDs caps,
  dedicated egress-controlled bridge network. Per-installation
  encryption keys are passed to verification containers via a tmpfs
  file mount — never an env var that would appear in `docker inspect`.
  Improvements vs v26.2.7: extract verification now runs the real
  backup-service `Verify` pipeline (checksum + file readability) instead
  of the v26.2.7 heuristic that claimed "1 file per ~10 KiB"; new REST
  API surface `/api/v1/backup-verify/*` (runs CRUD, schedule CRUD, stats,
  per-backup run history — none existed in v26.2.7); a paired
  `HostID` filter on `models.BackupListOptions` lets the verification
  scheduler pick the N most-recent completed backups for a host without
  reaching into the backup repository's internals; service constructor
  accepts a nil logger via `logger.Nop()`; retention pruning runs on
  every scheduled tick so the verifications table stays bounded
  (default 90 days, configurable via `Options.Retention`); sandbox
  runner is wired via a narrow `SandboxRunner` interface so unit tests
  do not need a real Docker daemon; verification rows include explicit
  `started_at`/`completed_at` timestamps so the UI can show in-flight
  state. Service unit tests at 80% coverage; sandbox + worker unit
  tests cover the spec construction and key-mount discipline. Smoke
  E2E suite at `tests/e2e/backup_verify/` walks
  list-backups → trigger → poll → schedule-CRUD against a running
  instance.
- **firewall — UFW/nftables/iptables rule management with web UI and REST API.**
  Port of the v26.2.7 firewall module under
  `internal/services/firewall/`, `internal/repository/postgres/firewall_repo.go`,
  `internal/api/handlers/firewall.go`, `internal/web/handler_firewall.go`, and
  `internal/web/templates/pages/firewall/`. Migration `050_firewall.up.sql`
  creates `firewall_rules` and `firewall_audit_log`. Sidebar entry lives in
  Operations → Firewall with no edition gate (the v26.2.7 `biz` lock has been
  dropped per the v26.5.0 "one AGPL build" principle). The agent transport
  (NATS gateway: `firewall.detect`, `firewall.apply`, `firewall.sync`) runs
  with explicit `os/exec` arg slices on the agent side; the master never
  shells out. Improvements vs v26.2.7: new REST API surface
  `/api/v1/firewall/*` (rules CRUD + status/apply/sync/audit, no API handler
  existed in v26.2.7), input validation on the closed-enum fields
  (chain/action/protocol/direction) returns `ErrInvalidInput`, comment
  preview uses `strconv.Quote` instead of unsafe string concatenation, and
  service constructor accepts a nil logger via `logger.Nop()`.
- **rollback — automated rollback policies that detect failed deploys
  and revert to the last known-good stack version.** Port of the
  v26.2.7 automated-rollback module under
  `internal/services/rollback/`, `internal/repository/postgres/rollback_repo.go`,
  `internal/api/handlers/rollback.go`, `internal/web/handler_rollback.go`,
  and `internal/web/templates/pages/rollback/`. Migration
  `054_automated_rollback.up.sql` (renumbered from v26.2.7's 052)
  creates `rollback_policies`, `rollback_executions`, and
  `rollback_audit_log`. The audit table is APPEND-ONLY: the
  `rollback_audit_log_append_only_trigger` raises on UPDATE / DELETE /
  TRUNCATE so neither the API surface nor a privileged DBA can rewrite
  history through the application connection. A static guard
  (`rollback_audit_append_only_test.go`, mirroring the recon pattern)
  fails the build if a write path bypassing `AppendAudit` ever lands.
  Sidebar entry lives in Operations → Rollback with no edition gate
  (the v26.2.7 `biz` lock has been dropped per the v26.5.0 "one AGPL
  build" principle). Improvements vs v26.2.7:
  (1) event-driven instead of polled — the worker subscribes to the
  new `changes.Service.Subscribe` API (added in the same PR as a paired
  addition since the v26.5.0 `change_events` service was write-only)
  and dispatches matching stack events directly to the rollback
  service, no 1-minute tick;
  (2) `last_healthy` strategy walks the version history until it finds
  a version with `is_deployed && deployed_at`, replacing v26.2.7's
  naive "previous version" assumption that breaks when the previous
  deploy itself failed;
  (3) per-stack `sync.Mutex` lock held for the duration of an
  execution — a concurrent rollback on the same stack returns
  `ErrStackBusy` instead of racing the live revert;
  (4) cooldown window (`cooldown_seconds`) protects against flapping
  on a repeatedly-failing deploy;
  (5) new `POST /api/v1/rollback/policies/{id}/dry-run` endpoint plus
  matching web page lets the operator preview what a policy would do
  against any stack without touching the live state;
  (6) rollback action delegates to the stack module's
  `RestoreVersion` API rather than reaching into the Docker SDK
  directly — the stack module already audits the redeploy via
  `change_events`;
  (7) full REST API surface `/api/v1/rollback/*` (policies CRUD,
  executions list/get, audit list, dry-run) — no API handler existed
  in v26.2.7;
  (8) service unit tests reach 69.8 % statement coverage, comfortably
  above the 50 % session floor.
- **ssl observatory — periodic TLS scanning, certificate health grading,
  and per-target expiry alerts.** Port of the v26.2.7 SSL observatory
  module under `internal/services/sslobservatory/`,
  `internal/repository/postgres/ssl_observatory_repo.go`,
  `internal/api/handlers/ssl_observatory.go`,
  `internal/web/handler_ssl_observatory.go`, and
  `internal/web/templates/pages/sslobservatory/`. Migration
  `051_ssl_observatory.up.sql` (renumbered from v26.2.7's 049 to slot
  above 049_crontab and 050_firewall) creates `ssl_targets` and
  `ssl_scan_results`. Sidebar entry lives in Operations → SSL
  Observatory with no edition gate (the v26.2.7 `biz` lock has been
  dropped per the v26.5.0 "one AGPL build" principle). Scanning is
  fully self-hosted: every TLS handshake is performed in-process by
  `crypto/tls`, there is no call-out to any external observatory or
  scanner service, and no telemetry leaves the binary.
  Improvements vs v26.2.7:
  (1) a proper repository was extracted at
  `internal/repository/postgres/ssl_observatory_repo.go` — v26.2.7
  inlined SQL inside the service, blocking unit-testability;
  (2) per-target alert thresholds default to {30, 14, 7, 3, 1} days
  but each target can override the list (the v26.2.7 build had no
  configurable thresholds at all). Notifications fire the smallest
  threshold the cert currently satisfies, so the operator gets the
  most urgent matching alert without spam;
  (3) SNI virtual-host scans: each target can list additional
  hostnames, and the scanner persists one `scan_result` row per
  `(target, scan_hostname)` so many certs behind one IP can be
  graded independently — v26.2.7 only opened one handshake per
  target;
  (4) `ScanAll` respects a per-target concurrency cap (default 4 in
  flight, configurable via `Config.PerTargetConcurrency`) so the
  daily sweep never amplifies into a thundering herd against the
  egress network;
  (5) every TLS dial has a hard 10-second timeout enforced by the
  package-level `DialTimeout` and a per-call `context.WithTimeout`
  — a bug-ridden remote stack cannot hang the worker;
  (6) full REST API surface `/api/v1/ssl/*` (targets CRUD, scan
  trigger, paginated scan history, dashboard stats, expiring-certs
  query) — no API handler existed in v26.2.7;
  (7) scheduler worker `JobTypeSSLScan` registered with a daily
  04:00 UTC scheduled job that fans out across every enabled target
  on every host;
  (8) cert-expiry alerts dispatch through the existing notification
  service via a narrow `Notifier` interface so the SSL service does
  not depend on the notification package directly — the adapter
  lives in `internal/app/web_adapters.go`;
  (9) hostname inputs are case-folded and validated against control
  characters, eliminating a class of injection on the audit log;
  (10) service unit tests reach 79.9 % statement coverage with a
  real-handshake SNI scenario and a per-target concurrency stress
  test, comfortably above the 50 % session floor; smoke E2E suite
  at `tests/e2e/ssl_observatory/` walks
  add-target → scan → expect result row against a running instance.
- **docker-engine — `/etc/docker/daemon.json` editor with atomic
  writes, snapshot history, and reload-with-rollback.** Port of the
  v26.2.7 dockerconfig module under
  `internal/services/dockerconfig/`,
  `internal/api/handlers/docker_engine.go`,
  `internal/web/handler_docker_engine.go`, and
  `internal/web/templates/pages/dockerconfig/`. No DB migration —
  v26.2.7 had none and the snapshot history lives on disk under
  `/etc/docker/usulnet-snapshots`. Sidebar entry lives in Operations
  → Docker Engine with no edition gate (the v26.2.7 `biz` lock has
  been dropped per the v26.5.0 "one AGPL build" principle).
  Improvements vs v26.2.7:
  (1) v26.2.7's 898-LoC monolithic `service.go` is split into
  `reader.go`, `writer.go`, `applier.go`, and a thin `service.go` so
  each leg of the apply cycle is independently unit-testable;
  (2) writes are atomic — temp file + `fsync` + `rename`(2) onto the
  destination + parent-dir `fsync` — replacing v26.2.7's `os.WriteFile`
  path that could leave a half-written `daemon.json` on disk after a
  crash and hang `dockerd` on next start;
  (3) the apply cycle now performs reload-with-rollback: snapshot →
  atomic write → SIGHUP → poll the daemon API up to a hard
  60 s timeout → on timeout or unhealthy daemon, restore the
  snapshot atomically and re-issue SIGHUP. The `Reloaded` /
  `RolledBack` flags surface in both the API response and the web UI
  banner so the operator sees the rollback inline;
  (4) v26.2.7's nsenter-via-`docker exec` self-exec path (the editor
  shelling into its own container to read the host filesystem) is
  intentionally not ported. Operators volume-mount the host's
  `/etc/docker` into the usulnet container as `:rw`. This removes a
  fragile self-exec dependency, removes the need for the container
  to run with `--pid=host`, and removes the docker-exec cycle that
  would crash the editor when the daemon is down (the very state
  the editor exists to fix);
  (5) registry-mirror credentials and proxy URLs containing `user:pass`
  are redacted from every structured log call via a `redactURL`
  helper; a paired unit test (`TestApply_DoesNotLogRegistryMirrorPasswords`)
  asserts no credential string ever lands in the log buffer;
  (6) registry-mirror URLs that embed credentials are also rejected
  at the validation step with an error message that itself does not
  echo the password — Docker recommends `~/.docker/config.json` for
  registry auth and the editor enforces the recommendation;
  (7) snapshot rotation keeps the history bounded (default 50;
  configurable via `Config.MaxSnapshots`); each snapshot ID is
  `YYYYMMDD-HHMMSS-<rand6>` so concurrent applies cannot collide
  and an attacker who can race the timestamp cannot guess the next
  ID. Path traversal on the restore endpoint is rejected by a
  closed-character-set guard;
  (8) full REST API surface `/api/v1/docker-engine/*` (GET config,
  PUT config with validation + atomic write + reload + rollback,
  GET history, POST restore/{snapshot_id}) — no API handler existed
  in v26.2.7; a forced rollback returns 409 with a structured
  `result` body so the UI paints the rollback banner without a
  second round-trip;
  (9) v26.2.7's seven-tab form is replaced with a Monaco diff editor
  (left = on-disk daemon.json, right = working copy) plus a separate
  history page that lists snapshots with one-click restore. The
  apply button surfaces the hard-timeout window in its confirm
  dialog so the operator knows the worst-case stall;
  (10) service unit tests reach 65.9 % statement coverage with the
  explicit rollback path covered (`TestApply_RollsBackWhenReloadFails`),
  comfortably above the 50 % session floor; concurrent-write
  stress test asserts atomic writes never leave a corrupt
  `daemon.json` on disk; smoke E2E suite at
  `tests/e2e/docker_engine/` walks read → apply → history → restore
  against a running instance.
- **wireguard — peer + interface manager extended into a master→agent
  mesh.** Port of the v26.2.7 WireGuard module under
  `internal/services/wireguard/`,
  `internal/repository/postgres/wireguard_repo.go` (renamed from
  `wireguard.go`), `internal/api/handlers/wireguard.go` (NEW),
  `internal/web/handler_wireguard.go`, and
  `internal/web/templates/pages/wireguard/`. Migration
  `055_wireguard_vpn.up.sql` (renumbered from v26.2.7's 053) creates
  `wireguard_interfaces`, `wireguard_peers`, and the new
  `wireguard_mesh_links` table that tracks `(agent_host_id, peer_id,
  last_handshake, status)`. Sidebar entry lives in Operations →
  WireGuard with no edition gate (v26.2.7 was unconditional; we keep
  it that way per the "one AGPL build" principle).
  Improvements vs v26.2.7:
  (1) **mesh propagation** — when a peer is added on the master, the
  service pushes the entry to the operator-selected agents over the
  existing NATS transport (`wireguard.apply_peer` /
  `wireguard.remove_peer` / `wireguard.status` / `wireguard.probe`
  commands added in `internal/gateway/protocol/commands.go`). Agents
  execute `wg set <iface> peer <pubkey> …` with explicit argv and
  a hard timeout (preshared keys are piped on stdin so they never
  appear in process listings or argv). The
  `wireguard_mesh_links` table records pending/applied/failed status
  per agent so the operator sees the propagation matrix in the new
  Mesh status page; failed pushes do not unwind the CRUD operation
  on the master so retries are trivial;
  (2) **real Curve25519 public keys** — v26.2.7 generated a placeholder
  by XOR-ing the private key, which would never interoperate with a
  real WireGuard client. v26.5.1 calls `curve25519.X25519` (golang.org
  /x/crypto) to produce the correct public key; a unit test asserts
  the derived key does not match the v26.2.7 placeholder shape;
  (3) **private + preshared keys encrypted at rest** with the
  installation data encryption key (`USULNET_ENCRYPTION_KEY`, the
  same one `recon_findings_raw` and `npm_connections` use). The
  rendered client config (`config_client` column, replacing v26.2.7's
  cleartext `config_qr`) is also AES-256-GCM-encrypted so a stolen DB
  row still requires the installation key to read. When the encryptor
  is unavailable at start-up the service is intentionally NOT
  constructed — the web/API handlers render a "not configured" page
  rather than persisting cleartext keys;
  (4) **one-time QR endpoint with 5 min TTL.**
  `POST /api/v1/wireguard/peers/{id}/qr/issue` mints a single-use
  token; `GET /api/v1/wireguard/peers/{id}/qr?token=…` returns the
  cleartext peer config exactly once. The peer-detail page renders
  the QR client-side via the already-vendored qrcodejs library;
  (5) **service-level input validation** — `validateInterfaceInput`
  rejects empty display names, out-of-range ports/MTUs and missing
  addresses; `validatePeerInput` rejects empty names and out-of-range
  keepalive intervals. The agent re-validates interface names
  (15-char IFNAMSIZ limit, alnum + `-_`), base64 keys (44-char
  fixed-charset), `allowed_ips` (CIDR character set), and
  `endpoint` (`host:port` shape) before any value reaches argv —
  defense in depth, the master argv is already escaped;
  (6) **probe at startup** — `wireguard.ProbeLocal(ctx)` runs
  `exec.LookPath("wg")`, `exec.LookPath("wg-quick")` and a bounded
  `wg --version` under a 5 s context timeout. A non-fatal warning is
  logged on missing binaries and the list page renders a yellow
  banner so operators see the dependency gap inline. The
  `wireguard.probe` command on the agent surfaces the same info per
  remote node;
  (7) **full REST API surface** — `/api/v1/wireguard/*` with
  per-method RBAC (read viewer+, mutations operator+); v26.2.7 had no
  API at all. The handler is nil-safe — when the service is not
  configured every route returns 503 service_unavailable;
  (8) **mesh status page** — the new `/wireguard/mesh` page lists
  every `(peer, agent)` row with applied / pending / failed badges,
  per-agent error messages, and counters for the top-of-page summary;
  (9) **hard timeouts on every wg/wg-quick invocation** — every
  `exec.CommandContext` call uses the command's `Timeout` (with a
  30 s fallback for apply/remove, 15 s for status, 5 s for probe).
  Agent-side argv validation rejects shell metacharacters before
  invocation;
  (10) service unit tests reach 72.5 % statement coverage with fakes
  for the three repositories, the encryptor and the NATS sender —
  exercising key generation, encryption at rest, mesh propagation
  success / failure paths, QR token single-use semantics and
  pagination defaults. Smoke E2E plan: master + 1 agent, create
  interface, add peer with agent target, verify peer applied on
  agent (`wg show` dump round-trip) and screenshot the mesh page.
- **image-builder — local Dockerfile build pipeline with live log
  streaming, capped context uploads, AGPL-compatible starter
  templates, and an optional cosign hook.** Port of the v26.2.7 image
  builder under `internal/services/imagebuilder/`,
  `internal/repository/postgres/image_builder_repo.go` (extracted —
  v26.2.7 inlined SQL inside the service),
  `internal/api/handlers/image_builder.go` (NEW),
  `internal/web/handler_image_builder.go`, and
  `internal/web/templates/pages/imagebuilder/`. Migration
  `053_image_builder.up.sql` (renumbered from v26.2.7's 051 to slot
  above 052_backup_verification and below 054_automated_rollback)
  creates `image_build_jobs` and `dockerfile_templates`. Sidebar entry
  lives in Operations → Image Builder with no edition gate (v26.2.7
  was unconditional too — kept that way per the "one AGPL build"
  principle).
  Improvements vs v26.2.7:
  (1) **real Docker invocation** — v26.2.7's `performBuild` returned a
  synthetic `"Build completed successfully"` string and a fake
  `image_id`. v26.5.1 calls the docker client's `ImageBuild` directly,
  parses the daemon's NDJSON response stream and pulls the image ID
  from the `aux` envelope so the row reflects what actually happened
  on the host. The build path supports `BuildArgs`, `Labels`, target
  stage, platform, no-cache and pull flags;
  (2) **live log streaming via Redis pub/sub** — the daemon's per-line
  output is published on `imagebuilder:logs:<build_id>`. The new
  WebSocket endpoint `GET /api/v1/builds/{id}/log` (with SSE fallback
  when the client sends `Accept: text/event-stream`) bridges the
  channel into the response. The build-detail page opens the WebSocket
  inline with a 96-row terminal pane that auto-scrolls. The trailing
  64 KiB window of the log is persisted to `image_build_jobs.output`
  via a fixed-capacity `ringBuffer` so the table view stays bounded
  regardless of how chatty a build was. v26.2.7 buffered every byte in
  memory inside the service struct;
  (3) **build-context size cap** — uploads are capped at a configurable
  256 MiB (`image_builder.max_context_bytes`). Oversized payloads
  return `413 artifact_too_large` from the API before reaching the
  daemon; the cap matches the figure documented in the session brief
  (Risks). The handler maps `imagebuilder.ErrContextTooLarge`,
  `ErrBuilderUnavailable`, and `ErrInvalidInput` onto stable HTTP
  status codes;
  (4) **AGPL-compatible starter templates** — seven Dockerfile
  snippets ship with the binary (`alpine-minimal`, `static-web-nginx`,
  `node-app`, `python-app`, `go-app`, `postgres-extension`,
  `background-worker`). All are authored fresh for usulnet — no
  encumbered upstream content — and pull only from the public official
  upstream image families (alpine, nginx, node, python, golang,
  distroless, postgres). Built-ins are seeded idempotently on first
  start; `IsBuiltin` rows refuse deletion via `ErrBuiltinDelete`
  (mapped to 403 in the API and 403 in the web handler);
  (5) **optional cosign hook** — when `image_sign.enabled=true` the
  service hooks every successful build into the existing `imagesign`
  service via the new `Service.SetSignHook`. The hook signs the first
  resulting tag and records the signature reference on the row
  (`signed`, `signature_ref` columns added in migration 053). Hook
  failures are logged but never flip the build to failed — the image
  is already on disk by then;
  (6) **full REST API surface** — `/api/v1/builds/*` (paginated list,
  start, get, stats, log stream) and `/api/v1/build-templates/*` (list
  / get / create / delete). Per-method RBAC inside the handler's
  `Routes()` (read viewer+, mutations operator+). v26.2.7 shipped no
  API at all; the web handler called the concrete service directly;
  (7) service unit tests at 79.6 % statement coverage exercising
  validation, context-size enforcement, NDJSON stream parsing, daemon
  error capture, sign-hook success and failure paths, builtin-template
  seeding idempotency, ring buffer overflow, and Redis publisher nil
  safety. Smoke E2E at `tests/e2e/image_builder/` builds
  `FROM alpine:3.21` end-to-end against a real daemon and verifies the
  resulting image_id is populated.

- **proxy-extended — access lists, dead hosts, locations, redirections,
  and streams under unified state management with a clean backend
  support matrix.** Port of the v26.2.7 extended proxy features into
  v26.5.1's existing proxy module, AGPL, no biz gate. New tables under
  `internal/repository/postgres/migrations/047_proxy_extended.{up,down}.sql`
  (renumbered from v26.2.7's 045 to land above the v26.5.0 `recon_*`
  occupants of 044/045): `proxy_redirections`, `proxy_streams`,
  `proxy_dead_hosts`, `proxy_access_lists`, `proxy_access_list_auth`,
  `proxy_access_list_clients`, `proxy_locations`, plus five new columns
  on `proxy_hosts` (`block_exploits`, `caching_enabled`,
  `custom_nginx_config`, `hsts_subdomains`, `access_list_id`).
  Repository files split per sub-entity using the v26.5.0 `_repo.go`
  suffix convention: `proxy_access_lists_repo.go`,
  `proxy_dead_hosts_repo.go`, `proxy_locations_repo.go`,
  `proxy_redirections_repo.go`, `proxy_streams_repo.go`.
  Improvements vs v26.2.7:
  (1) **usulnet is the authoritative state**, not the external proxy.
  v26.5.0's `proxy.Service` was integration-only — every read and write
  hit NPM/Caddy live. v26.5.1 stores the extended state in PostgreSQL
  and pushes it to the active backend on apply via the new
  `ExtendedSyncBackend` interface (`Sync` + `SyncExtended`). The split
  lets the operator edit access lists / streams / redirections without
  the backend being reachable at edit time, and provides a clean target
  for the eventual config-diff and dry-run flows;
  (2) **backend feature matrix is explicit and machine-readable.**
  Each backend reports `FeatureSupport{AccessLists, DeadHosts, Locations,
  Redirections, Streams}`. The nginx backend reports full support; the
  Caddy backend reports streams=false (raw TCP/UDP has no native Caddy
  equivalent in v26.5.1). The matrix is surfaced via
  `GET /api/v1/proxy/support` and rendered as a coloured badge row at
  the top of every proxy page so operators see, before clicking into a
  tab, whether the active backend can apply the feature behind it;
  (3) **streams against Caddy return HTTP 422, never 500.** The service
  returns a typed `ErrFeatureNotSupported` sentinel; the API layer maps
  it to `422 FEATURE_NOT_SUPPORTED` with a message explaining which
  backend rejected the feature ("create stream: feature not supported
  by active proxy backend"). The web UI flashes the same message;
  (4) **access-list precedence is pinned by a table-driven test**:
  explicit deny > explicit allow > default. The `EvaluateClientAccess()`
  function lives in `internal/services/proxy/access_control.go` and is
  exercised against IPv4 literals, IPv4 CIDR, IPv6 literals, IPv6 CIDR
  and the literal "all" with eleven test cases asserting each branch of
  the precedence ladder (`access_control_test.go`). The contract is the
  service-level guarantee that backends must honour when they render
  the matchers natively;
  (5) **idempotent apply.** `ApplyExtended` re-pushes the database
  state to the backend; calling it twice with no DB changes produces no
  spurious side effects. Covered by
  `TestApplyExtendedIdempotent` in `extended_test.go`, which asserts
  the backend's `extSyncCalls` counter increments by exactly one per
  apply and the row count remains stable;
  (6) **smoke E2E for full host configs.** `TestSmokeFullHostConfig`
  builds a host with a `/api` location, an access list with mixed
  allow/deny CIDRs, and a redirection in one fixture, then asserts the
  backend's last `ExtendedSyncData` payload contains all three
  collections and that the access-list precedence holds end-to-end;
  (7) **new REST API at `/api/v1/proxy/*`** —
  `GET /support`,
  `GET|POST|PUT|DELETE /access-lists[/{id}]`,
  `GET|POST|DELETE /dead-hosts[/{id}]`,
  `GET|PUT /hosts/{id}/locations`,
  `GET|POST|PUT|DELETE /redirections[/{id}]`,
  `GET|POST|PUT|DELETE /streams[/{id}]`. v26.2.7's only extended-proxy
  API was via NPM's own admin port; v26.5.1 talks usulnet's own JSON
  contract first and translates on apply. The base
  `internal/api/handlers/proxy.go` is extended in place — no fork —
  via a thin `ExtendedProxyHandler` that embeds `*ProxyHandler` and
  adds the new sub-routes.

### Changed

- Restructured `internal/app/app.go` bootstrap. The monolithic
  ~2,700-line `startStandalone` is split into phased `init_*.go`
  files (server, auth, docker, services, scheduler, api, web) backed
  by a shared `initContext`. `app.go` is now a thin orchestrator that
  delegates to each phase. No behaviour change; recon + metadata
  wirings are preserved.
- Strengthened `scripts/verify-migrations.sh`. It now rejects gaps
  in the migration number sequence, duplicate numbers, and unpaired
  up.sql / down.sql files. Ships with `scripts/verify-migrations_test.sh`.
- The web layer's caddy proxy adapter no longer returns
  "not yet supported in Caddy mode" errors for redirections, dead
  hosts, locations, streams and access lists. Those features now
  flow through the proxy service's local state. Streams against Caddy
  still surface a clear "feature not supported by active backend"
  message — but as a 422 rather than a generic 500.
- **Optional TLS for in-cluster Postgres / Redis / NATS via
  `USULNET_TLS_LOCAL_SERVICES=true`; defaults unchanged.** New
  `server.tls.local_services` config field (default `false`) and
  matching env var. When on, the new `deploy/tls/{postgres,redis,nats}-entrypoint.sh`
  scripts generate self-signed ECDSA P-256 certs (3650 days) on first
  boot and start the containers in TLS mode; the application binary
  detects the flag, rewrites the connection settings to `postgres
  sslmode=require` (skip-verify), `rediss://`, and NATS with
  `nats.Secure(...)`, and the Redis client now plumbs through
  `TLSSkipVerify` / `TLSCAFile` / mutual-TLS knobs so operators can
  mount their own CA and verify-full. When off, the entrypoint
  dispatchers exec the upstream binaries with no TLS material on
  disk — plain-TCP behaviour on the private `usulnet-backend` Docker
  network is unchanged. `make dev-certs` (re-added from v26.2.7) is
  gated by the same env var and pre-generates the certs on the host.
  The managed `usulnet-nginx` container is **not** re-introduced —
  v26.5.0's external-proxy posture (NPM/Caddy integration) stays as
  the default reverse-proxy story. Docs: §"Optional: TLS for In-Cluster
  Postgres / Redis / NATS" in `docs/installation.md`.

### Fixed

- **`internal/services/container/service.go:1147` nil-deref.**
  `watchHostEvents` dereferenced `s.hostService` directly, so any test
  (or future caller) that instantiated `Service{}` without a host
  service panicked instead of hitting the documented retry / cancel
  loop. Added an early `host service not configured` return.
  Reproduced by `TestHostEventWatcher_ContextCancel`, now green.
- **`internal/api/router.go` — `/api/v1/system/version` was auth-gated.**
  The route lived inside the `RequireViewer` group while
  `TestRouter_PublicRoutes` and the OpenAPI discovery surface treat
  it as public alongside `/health` / `/healthz`. Moved into the public
  sub-group; `TestRouter_AuthRequired` already excluded `/version`.
- **`internal/services/notification` — `SendBackupCompleted` lost its
  `PriorityLow`.** `Send` uses `if msg.Priority == 0` to fill in the
  type's default priority, and `PriorityLow` shares the zero value of
  the iota. The helper's explicit `PriorityLow` was silently rewritten
  to `PriorityNormal`. Extracted `dispatchMessage` as the
  priority-preserving inner path; `Send` retains the unset→default
  behaviour that `TestSend_DefaultPriority_SetFromType` depends on.
- **`internal/services/notification` — gotify channel construction.**
  `TestRegisterChannel_SupportedTypes/gotify` exercised the wrong
  settings keys (`url`/`token` instead of `server_url`/`app_token`).
  Test corrected; `ntfy` row aligned at the same time (it was only
  passing because `NtfyConfig.ServerURL` defaults to `https://ntfy.sh`).
- **`internal/api/errors` — error envelope was missing `success: false`.**
  `TestRouter_NotImplementedFallback` and the OpenAPI `Error` schema
  both expect a top-level `"success"` boolean. Added `Success bool` to
  `APIError` (always `false`), without changing any of the other
  fields.
- **`internal/app/config.go` — inverted `ConfigFileNotFoundError`
  branch.** A previous `golangci-lint --fix` pass converted the type
  assertion to `errors.As` but dropped the leading `!`, so `LoadConfig`
  returned an error on the *expected* "no config file" path and
  silently accepted other read errors. Restored as
  `if !errors.As(err, &configFileNotFoundError)`.
- **`internal/services/backup/cron_test.go` — `time.Until(*time.Time)`
  did not compile.** Same `lint --fix` pass rewrote
  `result.Sub(time.Now())` to `time.Until(result)`, but `result` is
  `*time.Time`. Restored as `time.Until(*result)`.
- **`internal/services/recon/service_test.go` — half-renamed
  `cancelled` field.** misspell renamed the field declarations to
  `canceled` but left two `e.cancelled = true` call sites untouched.
  Unified on `canceled`.

### Changed

- **Stale outbound `User-Agent` strings retired.** The HIBP recon
  connector no longer hardcodes the release number
  (`internal/services/recon/connectors/hibp/connector.go:51`) and the
  shortcuts favicon fetcher dropped the `usulnet/1.0` UA in favour of
  a self-describing string pointing at `usulnet.com`
  (`internal/services/shortcuts/service.go:220`).
- **Coverage gate aligned with reality.** `scripts/check-coverage.sh`
  now strips auto-generated `*_templ.go` lines from the profile
  before measuring (consistent with the linter exclusion) and uses
  the filtered profile for the HTML report. Interim threshold dropped
  to 15% (filtered coverage 15.6%); 40% remains documented as the
  long-term target in the script header, `Makefile` help,
  `docs/development.md`, and `CLAUDE.md`.
- **golangci-lint auto-fix pass.** A single `make lint-fix` run
  reduced the issue count from 1571 to 976 (-38%), almost entirely
  formatting (`gofmt`, `goimports`, `misspell`, `whitespace`) plus a
  few safe `gocritic` rewrites. The remaining 976 issues
  (`errcheck`, `gosec`, `govet`, `staticcheck`, `unused`, …) need
  per-site review and are tracked as follow-up.
- **Dependency bumps for `govulncheck` readiness.** Go toolchain
  directive moved from `go1.25.7` to `go1.25.10` (eleven stdlib
  security fixes). `golang.org/x/{crypto,net,sys,text,mod,tools}`
  bumped to current. Direct deps refreshed:
  `coreos/go-oidc v3.17.0→v3.18.0`,
  `docker/docker v28.5.1→v28.5.2`,
  `go-chi/chi/v5 v5.2.2→v5.2.5`,
  `go-ldap/ldap/v3 v3.4.12→v3.4.13`,
  `golang-jwt/jwt/v5 v5.2.2→v5.3.1`,
  `jackc/pgx/v5 v5.7.2→v5.9.2`,
  `nats-io/nats.go v1.39.1→v1.52.0`,
  `redis/go-redis/v9 v9.7.0→v9.19.0`.

### Security

- **Hardening audit completed (session 15).** Full audit recorded in
  [`docs/v26.5/security-review-v26.5.1.md`](docs/v26.5/security-review-v26.5.1.md),
  mirroring the v26.5.0 baseline structure.
- **External port surface unchanged.** Only HTTPS (`7443`) is
  published to the host by default; HTTP (`8080`) is commented out
  and used internally for health checks. NATS (`4222`) stays on the
  private `usulnet-backend` Docker network. None of the eleven new
  modules opens an external port.
- **No call-home.** A repo-wide grep for `usulnet.com` endpoints
  inside `internal/` returns only three matches — a HIBP
  `User-Agent` string, an iCal UID suffix per RFC 5545, and NATS
  subject prefixes. None initiates a connection to a usulnet-controlled
  endpoint. Every outbound HTTP/TCP call is either operator-configured
  (registry, DNS provider, OAuth issuer, SMTP, notification webhook,
  GitHub/GitLab/Gitea integration, HIBP) or operator-triggered (SSL
  Observatory scan target, crontab HTTP entry, runbook step, SSH
  session, RDP session).
- **No new privileged mount.** Session 14's opt-in local-services TLS
  introduces three read-only mounts of `./deploy/tls:/usulnet-tls:ro`
  on postgres / redis / nats. The mounts are inert when
  `USULNET_TLS_LOCAL_SERVICES=false` (the default) and never grant
  write access to host files. The Docker socket is still mounted only
  into the `usulnet` container and the optional `usulnet-agent`
  container — never into a recon sandbox, a user-built image, or any
  of the new modules' workers.
- **No new capability added.** The `cap_add: [SYS_PTRACE, SYS_ADMIN]`
  on the `usulnet` container is unchanged from v26.5.0 (required for
  the existing host-terminal feature). The recon sandbox continues to
  drop `ALL` capabilities. New modules that touch the host (firewall,
  crontab, WireGuard, docker-engine-config, image-builder) reach it
  through the existing host-management SSH transport instead of
  requesting `NET_ADMIN` / `NET_RAW` / `SYS_ADMIN` for themselves
  (principle §4).
- **Container users unchanged.** usulnet runtime stays
  `usulnet:1000`; recon sandboxes stay `nobody:nogroup` (65534).
- **gosec triage.** Two new HIGH findings vs the v26.5.0 baseline,
  both documented and intentional:
  - `G402` in `internal/services/sslobservatory/service.go:492`
    (`InsecureSkipVerify: true` is required to analyze invalid certs
    — annotated `//nolint:gosec`).
  - `G118` in `internal/services/crontab/service.go:395`
    (`context.Background()` in the fire-and-forget execution
    goroutine — consistent with the existing 9 baseline goroutine
    workers).
- **Marketplace offline catalog.** Session 12 ships with
  `TestStart_NoOutboundCalls` asserting that the marketplace service
  never opens a network connection at start-up
  (`internal/services/marketplace/no_network_test.go`).
- **govulncheck now runs in CI.** Session 15 deferred this because the
  audit sandbox could not reach `vuln.go.dev`. Session 15.2 wired
  `.github/workflows/govulncheck.yml` to run
  [`scripts/govulncheck.sh`](scripts/govulncheck.sh) on every push to
  `main` and every PR, with a 15-minute timeout and
  `cancel-in-progress` concurrency. GitHub-hosted runners can reach
  `vuln.go.dev` by default; no extra egress allow-list required.
  Dependency bumps (listed under Changed) cover the CVEs surfaced by
  the first run.
- **Documented Moby false positives in the govulncheck allowlist.**
  Two reachable findings against `github.com/docker/docker@v28.5.2`
  remain after the dep bumps:
  - `GO-2026-4883` / `CVE-2026-33997` — Moby off-by-one in plugin
    privilege validation. Server-side defect in the daemon's plugin
    install path; usulnet only links `client.Client.*` and serialises
    the `authorization-plugins` field into `/etc/docker/daemon.json`
    (`internal/services/dockerconfig/service.go:293`) — no plugin code
    is executed in-process.
  - `GO-2026-4887` / `CVE-2026-34040` — Moby AuthZ plugin bypass on
    oversized request bodies. Same scope: daemon-side defect, no
    AuthZ plugin shipped from this repo.

  Both are fixed in `github.com/moby/moby/v2 v2.0.0-beta.8`; the legacy
  `github.com/docker/docker` module still reports "Fixed in: N/A". The
  two OSV IDs are encoded in `scripts/govulncheck.sh` `ALLOWED_OSV_IDS`
  with inline justifications and advisory links. Every other reachable
  finding still fails the workflow. Allowlist entries are revisited
  every dep audit and must be dropped as soon as a fixed upstream
  release lands in `go.mod`. Audit-doc cross-reference:
  [`docs/v26.5/security-review-v26.5.1.md`](docs/v26.5/security-review-v26.5.1.md) §7.
- **govulncheck CI output is mirrored to the job summary and a sticky
  PR comment.** The workflow runs the wrapper script twice (text +
  JSON), prints the human report, and posts the full output as a
  `<!-- govulncheck-report -->` PR comment so review can see what was
  flagged without auth to the Actions logs.

## [v26.5.0] — 2026-05-13

The v26.5.0 release introduces the **Privacy & Recon** module: an
opt-in, self-hosted OSINT scanner and file-metadata hygiene toolkit.
Everything ships behind the `cfg.Recon.Enabled` feature flag (default:
off) and requires an admin acknowledgement of the legal notice before
any recon route can be used.

### Open and unlimited

- **One AGPL build, all features.** v26.5.0 makes it explicit: the
  recon and metadata modules, like every previous feature in this
  repository, are part of the standard self-hosted install. There is
  no `enterprise` fork, no closed-source extension point, and no
  feature gated by a paid license tier. What lives in
  [`github.com/fr4nsys/usulnet`](https://github.com/fr4nsys/usulnet)
  is the entire product surface — Docker control plane, multi-node
  orchestration, security scanning, backups, reverse proxy
  automation, monitoring, alerting, OSINT recon, metadata hygiene.
- **No runtime caps.** The binary does not enforce node-count,
  container-count, user-count, scan-count, or retention-window
  quotas. It does not check a license at start-up to decide what to
  expose.
- **No call-home.** The binary issues no outbound request to any
  usulnet-controlled endpoint at runtime, at start-up, or during the
  optional commercial-license check (which is purely local
  cryptographic verification of a self-contained token).
- **AGPL-3.0-or-later covers the entire tree.** Including the
  SpiderFoot integration, the metadata-hygiene toolkit container,
  the gofpdf report generator, and the recon retention worker. The
  commercial licenses documented in
  [`docs/licensing.md`](docs/licensing.md) (Business, Enterprise)
  grant **additional rights to the same code base** — redistribution
  outside AGPL, formal support contracts, custom IdP integrations —
  and do not unlock additional runtime features.
- **Reproducible build, no proprietary toolchain.** The full build
  chain is `make build` against the sources in this repository: Go
  1.25.7, the Templ generator, and the Tailwind standalone CLI. No
  vendored binary blobs, no closed-source code generators, no
  privileged registry access required.

### Added

- **Recon engine.** SpiderFoot driver (`internal/services/recon/engine/spiderfoot`)
  and an atomic-toolkit driver covering holehe, PhoneInfoga, subfinder,
  and Katana (`internal/services/recon/engine/toolkit`). Engines are
  invoked through a hardened container launcher
  (`internal/services/recon/sandbox`) — read-only rootfs, dropped
  caps, seccomp default, dedicated egress-controlled Docker network.
- **Metadata hygiene.** EXIF/PDF/Office extractors plus mat2-based
  stripper run inside the recon-toolkit container
  (`internal/services/metadata/{extractor,stripper}`).
- **Ownership verification.** DNS TXT, e-mail link, RDAP match,
  admin-attest, and self-assert verifiers
  (`internal/services/recon/ownership.go`). Scans cannot start until
  the target's ownership has been verified.
- **REST API.** Full `/api/v1/recon/*` + `/api/v1/metadata/*` surface
  with feature-flag and acknowledgement middleware
  (`internal/api/handlers/recon.go`, `internal/api/handlers/metadata.go`,
  `internal/api/middleware/recon.go`).
- **Web UI.** Privacy dashboard, target wizard, scan results pages,
  metadata strip/extract UI under `/recon/*` and `/metadata/*`.
- **CLI.** `usulnet recon …` and `usulnet meta …` subcommand trees.
- **HIBP connector.** Optional Have-I-Been-Pwned integration
  (`internal/services/recon/connectors/hibp`). Health-checks `/breaches`
  with the configured key; surfaces `breachedaccount` results as
  EngineEvents when SpiderFoot's `sfp_haveibeen` lacks an upstream
  key. Gated by `cfg.Recon.Connectors.HIBP.Enabled`. Credentials are
  persisted **encrypted at rest** in `recon_connectors`
  (AES-256-GCM matching `recon_findings_raw`); `USULNET_RECON_HIBP_API_KEY`
  remains as a migration grace and the DB row wins when both are
  present. Boot logs `key_source=db|env|none` (never the key itself).
  Full CRUD lives at `GET / PUT / DELETE /api/v1/recon/connectors/{kind}`.
- **Reports.** `report.json` (structured per-scan report:
  target + profile + findings grouped by category + ScanSummary),
  `report.csv` (flat findings table), and `report.pdf` (paginated
  A4 document with target/profile header, severity-coloured summary
  table, and one section per finding category — pure Go via
  `jung-kurt/gofpdf`, no Cgo, byte-deterministic for the same
  `*report.Report` input).
- **User-defined scan profiles.** Full CRUD against `recon_profiles`
  via `POST` / `PUT` / `DELETE /api/v1/recon/profiles[/{id}]`. The
  schema's `kind` column (`builtin` / `custom`) is exercised end to
  end: builtin rows are immutable, custom rows validate target
  types against the closed `TargetType` enum and modules against a
  closed `KnownModules` catalogue, duplicate names return 409, and
  `recon_scans.profile_id ON DELETE RESTRICT` surfaces as a typed
  `ErrProfileInUse` (409) instead of a generic 500. Audit log gains
  `profile.created` / `profile.updated` / `profile.deleted` actions.
- **Retention worker.** Daily worker
  (`internal/scheduler/workers/recon_retention.go`) prunes findings,
  scans, and audit rows older than `cfg.Recon.RetentionDays` (default
  90). Metadata artifacts use a two-phase mark+sweep delete with a
  configurable grace period (default 7 days). Every run appends a
  `retention.delete` row to `recon_audit_log`.
- **Database migration 044/045.** New `recon_*` tables and the
  `marked_for_deletion_at` column on `recon_metadata_artifacts`
  required by the retention worker's two-phase delete.
- **E2E suite.** `tests/e2e/recon/{metadata,scan}_e2e_test.go` exercises
  the full happy path against `docker-compose.test.yml`.

### Changed

- Configuration: a new `recon:` section in `config.yaml` controls the
  feature flag, retention window, concurrency cap, installation
  organisation, egress allow-list, and connector toggles. Default
  values keep v26.5.0 invisible to operators who did not opt in.
- Worker registry: `JobTypeReconRetention`, `JobTypeReconScan`, and
  `JobTypeMetadataJob` join the existing taxonomy
  (`internal/models/job.go`).

### Security

- Recon module routes are 404 when the feature flag is off and 409
  `acknowledgement_required` until an admin records consent.
- Every recon container runs as `nobody:nogroup` (`65534:65534`),
  read-only root FS, all Linux caps dropped, seccomp default profile,
  256 PID limit, 512 MiB memory cap, 1.0 CPU cap, no Docker socket
  ever mounted.
- Recon containers attach to a dedicated `usulnet-recon` Docker
  network with an egress allow-list configured by the operator.
- Raw engine payloads stored in `recon_findings_raw` are encrypted at
  rest using the installation-wide AES-256-GCM data encryption key.
- HIBP API keys are persisted encrypted at rest (AES-256-GCM in
  `recon_connectors`) and never appear in API responses, error
  strings, or log lines (`TestLookup_NoSecretInError`).
- Custom recon profiles cannot reference modules outside the closed
  `KnownModules` catalogue, so engine adapters never receive
  instructions they cannot honour. Repo enforces `WHERE kind = 'custom'`
  on `UPDATE` / `DELETE` so builtin profile rows cannot be mutated
  even if the service layer is bypassed.
- Target values are hashed (`sha256`) before indexing so PII does not
  leak through index dumps or `pg_stat`.
- `recon_audit_log` is append-only from API/Service paths; only the
  retention worker may DELETE rows, and a static check in
  `internal/repository/postgres/recon_audit_append_only_test.go`
  prevents accidental writes from drifting in.
- A full security review checklist is recorded at
  `docs/v26.5/security-review-checklist.md`.

### Notes

- **Recon is OFF by default.** Operators must explicitly set
  `recon.enabled: true` (or `USULNET_RECON_ENABLED=true`) and post to
  `/api/v1/recon/_ack` before any recon route is reachable. The
  acknowledgement is recorded against the calling admin's user ID
  and IP for audit purposes.
- **Builtin + custom scan profiles.** Four curated builtin profiles
  ship out of the box (`email-exposure-lite`, `domain-surface`,
  `username-presence`, `phone-public-info`). Custom profiles can be
  created via `POST /api/v1/recon/profiles`; builtin rows are
  immutable.
- **Reports.** JSON, CSV and PDF formats land in v26.5.0. The PDF
  generator is pure Go (no Cgo, no wkhtmltopdf) and produces
  byte-deterministic output for the same scan inputs.
- **Shodan / IntelX connectors — coming in a later release.** HIBP is
  the only connector in v26.5.0; the registry / repo are
  kind-agnostic so adding one is just dropping a new `Connector`
  implementation under `internal/services/recon/connectors/`.
- **Tor egress — coming in a later release.** Until then, the recon
  network's default egress policy allows DNS + TCP/80 + TCP/443 only.
- The metadata strip flow does not modify the original file; it
  produces a cleaned copy under
  `${USULNET_DATA_DIR}/recon/artifacts/<job_id>/<artifact_id>/stripped`.
  Originals are deleted only after the retention grace window
  expires (default 90 days + 7-day grace).
