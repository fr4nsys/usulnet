#!/usr/bin/env bash
# =============================================================================
# usulnet cloud — recon_audit_log append-only static guard (S08)
#
# Fail the build if any code under `cloud-private/` carries a SQL string
# that mentions UPDATE / DELETE / TRUNCATE against `recon_audit_log`.
#
# The append-only invariant is enforced twice on purpose:
#
#   1. SQLite triggers in cloud-private/cloud-migrations/0002_recon_verification.up.sql
#      abort UPDATE / DELETE at the engine layer. Belt.
#   2. This script grep-asserts no offending SQL string ever lands in
#      cloud-private/ code. Suspenders. A reviewer should not have to
#      reason "the trigger will catch it" — the string never compiled in
#      the first place.
#
# Mirrors the AGPL guard at
# internal/repository/postgres/recon_audit_append_only_test.go.
#
# Scope:
#   - cloud-private/**/*.{js,mjs,ts} is checked.
#   - usulnetdotcom-main/ is NOT checked (the verifier modules under that
#     tree do not talk to D1 at all; the static guard at
#     scripts/check-tenant-isolation.sh forbids raw env.DB.* under
#     cloud-private/ which is the only place D1 lookups can hit the
#     audit table).
#   - Test files (`*.test.js` / `*.test.mjs` / `*.test.ts`) ARE exempt.
#     The append-only invariant has a dedicated test that fires raw
#     UPDATE/DELETE statements through node:sqlite to prove the trigger
#     aborts them — those strings must exist in source for the test to
#     compile. The AGPL guard at
#     internal/repository/postgres/recon_audit_append_only_test.go uses
#     the same exemption (`strings.HasSuffix(path, "_test.go")`).
#
# Exits 0 on clean, 1 with file:line listings on violation.
#
# Wire-up: `make check-recon-audit-append-only` runs this directly. It is
# also called from `make publish-public-check` so a publish dry run
# refuses to ship if the invariant is broken.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${CHECK_RECON_AUDIT_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
TARGET="${ROOT}/cloud-private"

if [ ! -d "$TARGET" ]; then
    echo "check-recon-audit-append-only: $TARGET not found, nothing to check"
    exit 0
fi

# The forbidden patterns. `(?i)` is a perl-regex flag; grep -E does not
# support it, so we use grep -Ei with the case-insensitive flag and
# inline the keyword forms.
#
# Three patterns:
#   UPDATE recon_audit_log
#   DELETE FROM recon_audit_log
#   TRUNCATE recon_audit_log     (SQLite has no TRUNCATE but D1 might
#                                  one day; we forbid it for symmetry
#                                  with the AGPL guard.)
PATTERN='(UPDATE[[:space:]]+recon_audit_log|DELETE[[:space:]]+FROM[[:space:]]+recon_audit_log|TRUNCATE[[:space:]]+recon_audit_log)'

matches="$(
    grep -rEni "$PATTERN" "$TARGET" \
        --include='*.js' --include='*.mjs' --include='*.ts' \
        --exclude='*.test.js' --exclude='*.test.mjs' --exclude='*.test.ts' \
        2>/dev/null \
    | grep -vE ':[[:space:]]*(//|\*).*(UPDATE|DELETE|TRUNCATE).*recon_audit_log' \
    || true
)"

if [ -z "$matches" ]; then
    file_count="$(find "$TARGET" \
        \( -name '*.js' -o -name '*.mjs' -o -name '*.ts' \) | wc -l | tr -d ' ')"
    echo "check-recon-audit-append-only: OK (${file_count} files scanned)"
    exit 0
fi

cat <<'MSG' >&2
check-recon-audit-append-only: FAIL

  Found UPDATE / DELETE / TRUNCATE against recon_audit_log under
  cloud-private/. The audit log is append-only — the engine layer (a
  SQLite trigger installed by 0002_recon_verification.up.sql) refuses
  the statement, but the string must not exist in source at all so
  there is no risk a future code path bypasses the trigger.

  Offending lines:
MSG

while IFS= read -r v; do
    rel="${v#${ROOT}/}"
    echo "    ${rel}" >&2
done <<< "$matches"

cat <<'MSG' >&2

  Fix: drop the offending statement. Audit rows are written ONLY
  through cloud-private/recon/audit.js (appendAudit), and never
  updated or deleted by anyone — not even retention. If you need to
  prune rows, add a separate retention module + update this guard's
  allow-list (mirroring the AGPL recon_audit_append_only_test.go
  exemption for recon_retention_repo.go).
MSG

exit 1
