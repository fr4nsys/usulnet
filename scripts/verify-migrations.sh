#!/usr/bin/env bash
# verify-migrations.sh - CI script to validate migration integrity.
#
# Checks (each failure mode causes a non-zero exit):
#   1. Every up.sql has a matching down.sql and vice versa (no orphans).
#   2. No duplicate migration numbers across up.sql / down.sql files.
#   3. No gaps in the migration number sequence (001..NNN must be contiguous).
#   4. Down migrations are not empty (warning only).
#   5. Go-level migration rollback tests pass when Go is available.
#
# An optional MIGRATIONS_DIR env var overrides the default location (used by
# the test harness in scripts/verify-migrations_test.sh).
#
# Exit codes:
#   0  all checks pass
#   1  orphan up/down detected
#   2  duplicate migration number detected
#   3  gap in migration sequence detected
#   4  Go-level migration tests failed
#
# Usage:
#   ./scripts/verify-migrations.sh
#   VERBOSE=1 ./scripts/verify-migrations.sh
#   MIGRATIONS_DIR=/tmp/fixture ./scripts/verify-migrations.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-${PROJECT_ROOT}/internal/repository/postgres/migrations}"

# Quiet mode mutes the human-readable banner so the test harness can grep
# stderr/exit codes deterministically.
QUIET="${QUIET:-0}"

log() {
    if [ "${QUIET}" = "0" ]; then
        echo "$@"
    fi
}

log "=== Migration Integrity Verification ==="
log "Migrations dir: ${MIGRATIONS_DIR}"
log ""

if [ ! -d "${MIGRATIONS_DIR}" ]; then
    echo "ERROR: migrations directory does not exist: ${MIGRATIONS_DIR}" >&2
    exit 1
fi

# Collect migration numbers (zero-padded 3 digits) from filenames.
# Filenames look like: NNN_description.up.sql / NNN_description.down.sql.
mapfile -t up_files < <(find "${MIGRATIONS_DIR}" -maxdepth 1 -type f -name '*.up.sql' | sort)
mapfile -t down_files < <(find "${MIGRATIONS_DIR}" -maxdepth 1 -type f -name '*.down.sql' | sort)

UP_COUNT=${#up_files[@]}
DOWN_COUNT=${#down_files[@]}
log "Found ${UP_COUNT} up migrations, ${DOWN_COUNT} down migrations"
log ""

# Helper: pull the NNN number prefix from a filename.
migration_number() {
    local f
    f="$(basename "$1")"
    echo "${f%%_*}"
}

# Helper: pull the full base name (NNN_description) from a filename.
migration_base() {
    local f="$1"
    local b
    b="$(basename "$f")"
    b="${b%.up.sql}"
    b="${b%.down.sql}"
    echo "${b}"
}

# -----------------------------------------------------------------------------
# Check 1: orphan up.sql / down.sql files.
# -----------------------------------------------------------------------------
ORPHANS=0
for up in "${up_files[@]}"; do
    base="$(migration_base "${up}")"
    if [ ! -f "${MIGRATIONS_DIR}/${base}.down.sql" ]; then
        echo "ERROR: missing rollback: ${base}.down.sql" >&2
        ORPHANS=$((ORPHANS + 1))
    fi
done
for dn in "${down_files[@]}"; do
    base="$(migration_base "${dn}")"
    if [ ! -f "${MIGRATIONS_DIR}/${base}.up.sql" ]; then
        echo "ERROR: orphan rollback: ${base}.down.sql (no matching up migration)" >&2
        ORPHANS=$((ORPHANS + 1))
    fi
done
if [ "${ORPHANS}" -gt 0 ]; then
    echo "FAIL: ${ORPHANS} unpaired migration file(s)" >&2
    exit 1
fi
log "[ok] every up.sql has a matching down.sql"

# -----------------------------------------------------------------------------
# Check 2: duplicate migration numbers across up.sql files (and across
# down.sql files independently — both must form a distinct set).
# -----------------------------------------------------------------------------
DUPES=0
declare -A seen_up=()
for up in "${up_files[@]}"; do
    num="$(migration_number "${up}")"
    if [ -n "${seen_up[${num}]:-}" ]; then
        echo "ERROR: duplicate up migration number ${num}: ${seen_up[${num}]} and $(basename "${up}")" >&2
        DUPES=$((DUPES + 1))
    fi
    seen_up[${num}]="$(basename "${up}")"
done
declare -A seen_down=()
for dn in "${down_files[@]}"; do
    num="$(migration_number "${dn}")"
    if [ -n "${seen_down[${num}]:-}" ]; then
        echo "ERROR: duplicate down migration number ${num}: ${seen_down[${num}]} and $(basename "${dn}")" >&2
        DUPES=$((DUPES + 1))
    fi
    seen_down[${num}]="$(basename "${dn}")"
done
if [ "${DUPES}" -gt 0 ]; then
    echo "FAIL: ${DUPES} duplicate migration number(s)" >&2
    exit 2
fi
log "[ok] no duplicate migration numbers"

# -----------------------------------------------------------------------------
# Check 3: gaps in the migration sequence. The sequence must start at 001
# and be contiguous up to the highest observed number.
# -----------------------------------------------------------------------------
if [ "${UP_COUNT}" -gt 0 ]; then
    # Build a sorted list of unique numbers from up files (sufficient since
    # check 1 proved up/down are paired).
    mapfile -t numbers < <(printf '%s\n' "${!seen_up[@]}" | sort)
    expected=1
    GAPS=0
    for num in "${numbers[@]}"; do
        # Strip leading zeros for arithmetic. (10#NN forces base-10 parsing.)
        n=$((10#${num}))
        if [ "${n}" -ne "${expected}" ]; then
            echo "ERROR: gap in migration sequence: expected $(printf '%03d' "${expected}"), found ${num}" >&2
            GAPS=$((GAPS + 1))
            # Advance expected so we can report subsequent gaps individually
            # if the user wants to fix them in one pass.
            expected="${n}"
        fi
        expected=$((expected + 1))
    done
    if [ "${GAPS}" -gt 0 ]; then
        echo "FAIL: ${GAPS} gap(s) in migration sequence" >&2
        exit 3
    fi
fi
log "[ok] migration sequence is contiguous"

# -----------------------------------------------------------------------------
# Check 4: empty down migrations (warning only — sometimes intentional for
# data-only forward migrations, but the maintainer should review).
# -----------------------------------------------------------------------------
EMPTY=0
for dn in "${down_files[@]}"; do
    content="$(grep -v '^--' "${dn}" | grep -v '^[[:space:]]*$' || true)"
    if [ -z "${content}" ]; then
        log "WARNING: empty rollback file: $(basename "${dn}")"
        EMPTY=$((EMPTY + 1))
    fi
done
if [ "${EMPTY}" -gt 0 ]; then
    log "WARNING: ${EMPTY} down migration(s) appear empty"
fi

# -----------------------------------------------------------------------------
# Check 5: Go-level integrity tests (skipped if MIGRATIONS_DIR was overridden
# for fixture testing, since the Go tests target the project's real path).
# -----------------------------------------------------------------------------
if [ "${MIGRATIONS_DIR}" = "${PROJECT_ROOT}/internal/repository/postgres/migrations" ] \
   && command -v go &> /dev/null; then
    log ""
    log "Running migration integrity tests..."
    VERBOSE_FLAG=""
    if [ "${VERBOSE:-0}" = "1" ]; then
        VERBOSE_FLAG="-v"
    fi

    cd "${PROJECT_ROOT}"
    if ! go test ./internal/repository/postgres/ \
        -run "TestMigrationRollback|TestMigrationDependencyOrder" \
        ${VERBOSE_FLAG} \
        -count=1 \
        -timeout 60s; then
        echo "FAIL: Go-level migration tests failed" >&2
        exit 4
    fi
    log ""
    log "[ok] Go migration tests passed"
elif [ "${MIGRATIONS_DIR}" = "${PROJECT_ROOT}/internal/repository/postgres/migrations" ]; then
    log ""
    log "Go not available — skipping Go test execution (file checks passed)"
fi

log ""
log "=== Migration verification complete ==="
exit 0
