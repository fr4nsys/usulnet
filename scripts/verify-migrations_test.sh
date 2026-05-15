#!/usr/bin/env bash
# verify-migrations_test.sh - Unit tests for scripts/verify-migrations.sh.
#
# Each test builds a temporary fixture directory containing fake migration
# files and runs verify-migrations.sh against it via MIGRATIONS_DIR. The
# script's exit code is asserted against the expected value for that
# failure mode.
#
# Run:
#   ./scripts/verify-migrations_test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY_SCRIPT="${SCRIPT_DIR}/verify-migrations.sh"

if [ ! -x "${VERIFY_SCRIPT}" ]; then
    chmod +x "${VERIFY_SCRIPT}" || true
fi

PASS=0
FAIL=0
FAILURES=()

# make_pair <dir> <number> <name>
make_pair() {
    local dir="$1"
    local num="$2"
    local name="$3"
    cat > "${dir}/${num}_${name}.up.sql" <<EOF
-- up migration ${num}_${name}
CREATE TABLE IF NOT EXISTS test_${name} (id INT);
EOF
    cat > "${dir}/${num}_${name}.down.sql" <<EOF
-- down migration ${num}_${name}
DROP TABLE IF EXISTS test_${name};
EOF
}

# assert_exit <expected> <actual> <test_name> <captured_stderr>
assert_exit() {
    local expected="$1"
    local actual="$2"
    local test_name="$3"
    local stderr="$4"
    if [ "${actual}" -eq "${expected}" ]; then
        echo "[PASS] ${test_name} (exit=${actual})"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] ${test_name}: expected exit ${expected}, got ${actual}"
        echo "       stderr: ${stderr}"
        FAILURES+=("${test_name}")
        FAIL=$((FAIL + 1))
    fi
}

run_case() {
    local name="$1"
    local dir="$2"
    local expected="$3"
    local stderr
    local rc=0
    stderr="$(MIGRATIONS_DIR="${dir}" QUIET=1 "${VERIFY_SCRIPT}" 2>&1 >/dev/null)" || rc=$?
    assert_exit "${expected}" "${rc}" "${name}" "${stderr}"
}

# -----------------------------------------------------------------------------
# Test 1: happy path — 3 sequential paired migrations should exit 0.
# -----------------------------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
HAPPY="${TMP}/happy"
mkdir -p "${HAPPY}"
make_pair "${HAPPY}" 001 foundation
make_pair "${HAPPY}" 002 hosts
make_pair "${HAPPY}" 003 docker
run_case "happy-path" "${HAPPY}" 0

# -----------------------------------------------------------------------------
# Test 2: orphan up.sql with no matching down.sql → exit 1.
# -----------------------------------------------------------------------------
ORPHAN_UP="${TMP}/orphan-up"
mkdir -p "${ORPHAN_UP}"
make_pair "${ORPHAN_UP}" 001 foundation
echo "-- up only" > "${ORPHAN_UP}/002_orphan.up.sql"
run_case "orphan-up-missing-down" "${ORPHAN_UP}" 1

# -----------------------------------------------------------------------------
# Test 3: orphan down.sql with no matching up.sql → exit 1.
# -----------------------------------------------------------------------------
ORPHAN_DOWN="${TMP}/orphan-down"
mkdir -p "${ORPHAN_DOWN}"
make_pair "${ORPHAN_DOWN}" 001 foundation
echo "-- down only" > "${ORPHAN_DOWN}/002_orphan.down.sql"
run_case "orphan-down-missing-up" "${ORPHAN_DOWN}" 1

# -----------------------------------------------------------------------------
# Test 4: duplicate migration number across up.sql files → exit 2.
# -----------------------------------------------------------------------------
DUPE="${TMP}/dupe"
mkdir -p "${DUPE}"
make_pair "${DUPE}" 001 foundation
make_pair "${DUPE}" 002 hosts
# Add a second migration also numbered 002, paired correctly so the orphan
# check does not trigger first.
make_pair "${DUPE}" 002 also_hosts
run_case "duplicate-number" "${DUPE}" 2

# -----------------------------------------------------------------------------
# Test 5: gap in sequence (missing 002) → exit 3.
# -----------------------------------------------------------------------------
GAP="${TMP}/gap"
mkdir -p "${GAP}"
make_pair "${GAP}" 001 foundation
make_pair "${GAP}" 003 docker
run_case "gap-in-sequence" "${GAP}" 3

# -----------------------------------------------------------------------------
# Test 6: gap at start (sequence starts at 002, not 001) → exit 3.
# -----------------------------------------------------------------------------
GAP_START="${TMP}/gap-start"
mkdir -p "${GAP_START}"
make_pair "${GAP_START}" 002 hosts
make_pair "${GAP_START}" 003 docker
run_case "gap-at-start" "${GAP_START}" 3

# -----------------------------------------------------------------------------
# Test 7: empty directory → exit 0 (vacuously valid).
# -----------------------------------------------------------------------------
EMPTY="${TMP}/empty"
mkdir -p "${EMPTY}"
run_case "empty-directory" "${EMPTY}" 0

# -----------------------------------------------------------------------------
# Test 8: real project migrations dir → exit 0 (sanity check).
# Skipped if the migrations dir does not exist (e.g. shallow checkout).
# -----------------------------------------------------------------------------
PROJECT_MIGRATIONS="$(cd "${SCRIPT_DIR}/.." && pwd)/internal/repository/postgres/migrations"
if [ -d "${PROJECT_MIGRATIONS}" ]; then
    # Run with VERBOSE=0 + skip the Go test branch by pointing at a copy. The
    # script auto-skips Go tests when MIGRATIONS_DIR is overridden — we exploit
    # that to keep the test harness fast and DB-free.
    REAL_COPY="${TMP}/real"
    mkdir -p "${REAL_COPY}"
    cp "${PROJECT_MIGRATIONS}"/*.sql "${REAL_COPY}/"
    run_case "real-project-migrations" "${REAL_COPY}" 0
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo "=== verify-migrations.sh test summary ==="
echo "Passed: ${PASS}"
echo "Failed: ${FAIL}"
if [ "${FAIL}" -gt 0 ]; then
    echo "Failing tests:"
    for t in "${FAILURES[@]}"; do
        echo "  - ${t}"
    done
    exit 1
fi
exit 0
