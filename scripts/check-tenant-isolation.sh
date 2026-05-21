#!/usr/bin/env bash
# =============================================================================
# usulnet cloud — tenant isolation static guard (S04)
#
# Fail the build if any code under `cloud-private/` calls D1 directly,
# bypassing the `tenant()` wrapper in `cloud-private/db/tenant.js`.
#
# Forgetting `account_id = ?` is the single biggest tenancy bug class
# in any SaaS. The wrapper makes it structurally impossible — this
# script keeps it that way by refusing to let raw `env.DB.prepare(...)`
# (or sibling `.batch(...)`, `.exec(...)`, `.dump(...)`) appear anywhere
# the wrapper does not live.
#
# Scope:
#   - `cloud-private/**/*.{js,mjs,ts}` is checked.
#   - `usulnetdotcom-main/` is NOT checked (S01-S03 billing code is
#     grandfathered public + non-tenant scoped per decision 3 / S04).
#   - Test files are NOT exempt — if a test in cloud-private/ needs
#     setup queries it uses the same wrapper, or it builds a local
#     SQLite handle (not `env.DB`).
#
# Exits 0 on clean. Exits 1 with file:line listings on violation.
#
# Wire-up: `make check-tenant-isolation` runs this directly. It is
# also surfaced by `make publish-public-check` so a publish dry run
# refuses to ship if the invariant is broken.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${CHECK_TENANT_ISOLATION_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
TARGET="${ROOT}/cloud-private"

if [ ! -d "$TARGET" ]; then
    echo "check-tenant-isolation: $TARGET not found, nothing to check"
    exit 0
fi

# Allow-list of files exempt from the check. The wrapper itself uses
# `db.prepare(...)` against the param it was handed (NOT `env.DB.*`),
# so the pattern below already lets it pass; the list is here in case
# a future file (e.g. an integration test) needs an explicit exemption
# and we want one place to write it down.
#
# Entries are repo-relative paths. Use this exemption ONLY for code that
# legitimately needs CROSS-TENANT access (background workers operating
# over all accounts) — never as a shortcut to skip the tenant() wrapper
# for a per-tenant query.
ALLOW=(
  # cloud-private/scheduler/db.js
  #   The scan scheduler (S09) picks due rows from recon_scan_schedule
  #   across all accounts and counts in-flight scans cluster-wide. Both
  #   are inherently cross-tenant operations — the tenant() wrapper's
  #   account_id = ? pin is the wrong shape for "pick which tenant runs
  #   next". Per-tenant writes (INSERT recon_scans, UPDATE schedule)
  #   still go through tenant() inside scheduler/core.js; only the
  #   cross-tenant SELECT / COUNT live in this file.
  "cloud-private/scheduler/db.js"
  # cloud-private/retention/core.js
  #   The S10 daily retention worker enumerates accounts with stale
  #   rows (cross-tenant SELECT) and runs tenant-scoped DELETEs whose
  #   predicate the tenant() wrapper does not express (`created_at < ?`
  #   plus a status filter). Every DELETE pins account_id = ?1 as the
  #   FIRST clause, and the audit-row INSERT still goes through
  #   tenant() — only the predicate-bearing DELETE and the cross-tenant
  #   account enumeration land here.
  "cloud-private/retention/core.js"
  # cloud-private/pdf-builder/db.js
  #   The S12 pdf-builder Worker polls the outbox for pdf_generate rows
  #   cross-tenant (the cron does not know which tenant's row is next).
  #   Every UPDATE narrows by (id, account_id) as a defense-in-depth pin
  #   against a stray account-id mix-up; the per-tenant reads
  #   (recon_targets, recon_scans, recon_findings, recon_findings_raw)
  #   and per-tenant writes (recon_audit_log) still go through tenant()
  #   inside cloud-private/pdf-builder/core.js.
  "cloud-private/pdf-builder/db.js"
  # cloud-private/weekly-digest/db.js
  #   The S13 weekly-digest Worker enumerates accounts with an active
  #   Polar subscription (cross-tenant SELECT against `subscriptions`)
  #   and reads `accounts` to resolve the customer email for the
  #   outbox row's `to` field. Per-tenant reads (recon_targets,
  #   recon_findings, recon_scans) still go through tenant() inside
  #   cloud-private/weekly-digest/core.js — via computeTargetDelta(),
  #   which itself uses the tenant() wrapper. Only the cross-tenant
  #   subscription enumeration + account email lookup live in db.js.
  "cloud-private/weekly-digest/db.js"
  # cloud-private/cloud-app/admin/queries.js
  #   The S18 operational dashboard aggregates state across every
  #   tenant: subscription counts by status, MRR roll-up, scan / outbox
  #   health, D1 row counts per table. Pinning account_id = ? is
  #   exactly the wrong shape — the operator's job here is precisely
  #   to see the cross-tenant totals. The route is operator-only,
  #   read-only (no INSERT / UPDATE / DELETE), and gated by the
  #   hardcoded OPERATOR_EMAILS list before any query runs.
  "cloud-private/cloud-app/admin/queries.js"
  # cloud-private/lib/health.js
  #   The S19 health endpoints expose two read-only D1 probes:
  #     - SELECT 1 AS ok                   (liveness)
  #     - SELECT MIN(created_at) FROM outbox WHERE sent_at IS NULL
  #                                        (dispatcher dispatch lag)
  #   Both are inherently cross-tenant: the probe answers "is the DB
  #   reachable" and "is the outbox cron alive", neither scoped to an
  #   account. The endpoints are GET-only, read-only, and the response
  #   body never includes row payloads or account ids — only literal
  #   status strings and a lag-in-seconds integer. See
  #   dev/0526/cloud/operations.md.
  "cloud-private/lib/health.js"
  # cloud-private/support-inbox/core.js
  #   The S20 support inbox Email Worker enqueues a `support_ack`
  #   outbox row for every inbound message that clears the per-sender
  #   1-ack-per-hour throttle. The row has `account_id IS NULL` —
  #   inbound senders are not paying customers in the general case,
  #   and the dispatcher reads `payload.to` to route the reply. The
  #   tenant() wrapper would pin account_id = ?, which is the wrong
  #   shape for this kind. The single INSERT INTO outbox here is the
  #   only D1 touch in the file and never references a tenant table.
  "cloud-private/support-inbox/core.js"
)

# Match `<x>.DB.prepare(`, `<x>.DB.batch(`, `<x>.DB.exec(`, `<x>.DB.dump(`.
# Matches the D1 binding access pattern regardless of the receiver name
# (env.DB / ctx.DB / etc.). `tenant.js` does not touch `.DB.` — it uses
# the `db` param the caller passes — so this pattern lets it through.
PATTERN='\.DB\.(prepare|batch|exec|dump)[[:space:]]*\('

# grep -rEn: recursive, extended regex, line numbers. --include filters
# by file extension so we don't grep through PDFs, SQL, etc.
#
# The second grep strips comment lines that merely DOCUMENT the
# forbidden pattern (the wrapper's doc-comment cites `env.DB.prepare`
# as the thing it abstracts away). A line where the match is preceded
# by `//` or by a JSDoc-style `*` at the line start is documentation,
# not code. The rule remains strict for non-comment lines.
matches="$(
    grep -rEn "$PATTERN" "$TARGET" \
        --include='*.js' --include='*.mjs' --include='*.ts' \
        2>/dev/null \
    | grep -vE ':[[:space:]]*(//|\*).*\.DB\.(prepare|batch|exec|dump)' \
    || true
)"

if [ -z "$matches" ]; then
    file_count="$(find "$TARGET" \
        \( -name '*.js' -o -name '*.mjs' -o -name '*.ts' \) | wc -l | tr -d ' ')"
    echo "check-tenant-isolation: OK (${file_count} files scanned)"
    exit 0
fi

# Apply allow-list, if any. Currently empty; kept for future use.
filtered=""
while IFS= read -r line; do
    [ -z "$line" ] && continue
    rel="${line#${ROOT}/}"
    file_only="${rel%%:*}"
    skip=0
    for a in "${ALLOW[@]}"; do
        if [ "$file_only" = "$a" ]; then
            skip=1
            break
        fi
    done
    if [ "$skip" -eq 0 ]; then
        filtered="${filtered}${rel}"$'\n'
    fi
done <<< "$matches"

# Trim trailing newline.
filtered="${filtered%$'\n'}"

if [ -z "$filtered" ]; then
    file_count="$(find "$TARGET" \
        \( -name '*.js' -o -name '*.mjs' -o -name '*.ts' \) | wc -l | tr -d ' ')"
    echo "check-tenant-isolation: OK (${file_count} files scanned, allow-list applied)"
    exit 0
fi

cat <<'MSG' >&2
check-tenant-isolation: FAIL

  Found raw D1 access (.DB.prepare / .DB.batch / .DB.exec / .DB.dump)
  under cloud-private/ that bypasses the tenant() wrapper. Every
  tenant-scoped query MUST go through cloud-private/db/tenant.js so the
  account_id filter cannot be forgotten.

  Offending lines:
MSG

while IFS= read -r v; do
    echo "    ${v}" >&2
done <<< "$filtered"

cat <<'MSG' >&2

  Fix: replace the raw D1 call with the appropriate tenant() method
  (select, selectFirst, insert, update, delete). If you genuinely need
  a non-tenant query against D1 from cloud-private/ — typically only
  for shared schema / migration plumbing — add the file to the ALLOW
  list at the top of scripts/check-tenant-isolation.sh in the same PR
  and explain why in the commit message.
MSG

exit 1
