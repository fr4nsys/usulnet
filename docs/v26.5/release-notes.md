# usulnet v26.5.0 — Privacy & Recon

**Release date:** 2026-05-12
**Highlights:** opt-in OSINT scanner, file-metadata hygiene toolkit,
HIBP connector, JSON/CSV reports, retention worker, hardened container
sandbox.

This is the first release of the **Privacy & Recon** module. It is
shipped *off by default*: an existing v26.4.x install upgraded to
v26.5.0 picks up exactly the same operational surface as before,
unless an admin explicitly turns the module on, acknowledges the
legal notice, and configures the optional HIBP connector.

## What's new

### Recon engine (opt-in)

- **SpiderFoot** in an isolated container drives passive OSINT
  (subdomains, certificate transparency, breach disclosures,
  public profile sniffing).
- **Custom toolkit** container bundles the atomic tools
  SpiderFoot doesn't fold in cleanly: `holehe`, `phoneinfoga`,
  `subfinder`, `katana`.
- **Hardened sandbox:** read-only rootfs, all Linux caps dropped,
  seccomp default, 256 PID limit, 512 MiB memory cap, dedicated
  `usulnet-recon` Docker network with a strict egress allow-list.
- **Ownership gating:** scans cannot start until the target's
  ownership has been verified via DNS TXT, e-mail link, RDAP match,
  admin-attest, or self-assert.

### Metadata hygiene

- Upload arbitrary files (JPEG/PDF/Office formats) and let the
  recon-toolkit container surface their hidden metadata via
  `exiftool` / `pdfid` / `oletools`.
- Strip the file in place with `mat2` and download a cleaned copy.
- All processing happens inside an isolated container; nothing
  touches the host filesystem.

### HIBP connector

- Opt-in Have-I-Been-Pwned integration.
- Configured via `cfg.Recon.Connectors.HIBP.Enabled` and the
  `USULNET_RECON_HIBP_API_KEY` environment variable.
- Health-checks `/api/v3/breaches` on every startup and surfaces
  the result in `GET /api/v1/recon/connectors`.
- API keys never appear in responses, error strings, or log lines.

### Reports

- `GET /api/v1/recon/scans/{id}/report.json` — structured per-scan
  report (target + profile + findings grouped by category + summary).
- `GET …/report.csv` — flat findings table for spreadsheet drops.
- `GET …/report.pdf` — paginated A4 document with target/profile
  header, severity-coloured summary table, and one section per
  finding category. Pure Go (no Cgo, no wkhtmltopdf); byte-deterministic
  for the same scan inputs.

### Retention worker

- New daily worker (`recon_retention`) prunes findings, scans,
  and audit log rows older than `cfg.Recon.RetentionDays`
  (default 90).
- Metadata artifacts use a **two-phase delete**: the worker first
  marks `recon_metadata_artifacts.marked_for_deletion_at`, then
  sweeps after a configurable grace period (default 7 days). The
  on-disk file survives the mark phase so a misconfigured retention
  window is recoverable by clearing the column.
- Every retention run appends a `retention.delete` row to
  `recon_audit_log`.

### Web UI + CLI

- `/recon/*` and `/metadata/*` pages give a target wizard, scan
  status views, report downloads, and an upload UI for the metadata
  toolkit.
- `usulnet recon …` and `usulnet meta …` Cobra subcommand trees
  cover the same surface from the terminal.

## Configuration

```yaml
recon:
  enabled: false        # <-- flip to enable
  retention_days: 90
  max_concurrent_scans: 2
  installation_org: "Acme, Inc."
  base_url: "https://usulnet.example.com"
  egress:
    allowlist: []
  connectors:
    hibp:
      enabled: false
```

`USULNET_RECON_HIBP_API_KEY` (env) is a migration grace; the
canonical home for the HIBP API key is the encrypted
`recon_connectors.credentials_encrypted` column, populated via
`PUT /api/v1/recon/connectors/hibp`. The DB value wins when both are
present. Boot logs `key_source=db|env|none` (never the key itself).

## Upgrade notes

- **Migrations 044 and 045 run automatically** on the first start
  with v26.5.0. They are forward-only; the `down.sql` files exist
  for development convenience but production rollbacks should restore
  from backup.
- If you are running with `recon.enabled: false` (the default), no
  goroutines start, no Docker network is created, and `/api/v1/recon/*`
  + `/api/v1/metadata/*` return 404.
- Once `recon.enabled` is flipped, an admin must POST to
  `/api/v1/recon/_ack` (or click "I understand" in the Privacy
  dashboard) before any other recon route returns 200.

## Known limitations (v26.5.0)

- **Four builtin profiles plus custom CRUD.** The seeded profiles
  cover `email-exposure-lite`, `domain-surface`,
  `username-presence`, and `phone-public-info`. Operators can add
  their own via `POST /api/v1/recon/profiles`; builtin rows are
  immutable. Phone (PhoneInfoga) and deep-crawl (katana/subfinder)
  profile expansions ship in a later release.
- **HIBP only.** Shodan and IntelX connectors land in a later
  release.
- **No Tor egress.** A later release introduces an optional Tor
  relay for outbound recon traffic; until then the recon network
  egress is DNS + TCP/80 + TCP/443 only, gated by the configured
  allow-list.

## Security

A full security review checklist is recorded at
[`docs/v26.5/security-review-checklist.md`](./security-review-checklist.md).
Every control is cited with `file:line` references and a pointer to
the test that exercises it.

## Thanks

The Privacy & Recon module took twelve sessions to land. Thanks to
everyone who reviewed the RFC at `docs/recon.md`, the prior session
PRs (#11 – #22 on `fr4nsys/usulnetdevbeta04`), and to the upstream
projects we lean on: SpiderFoot, mat2, exiftool, oletools, pdfid,
holehe, PhoneInfoga, subfinder, Katana.
