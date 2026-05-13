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
