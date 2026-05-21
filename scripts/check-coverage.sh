#!/usr/bin/env bash
# =============================================================================
# usulnet - Test Coverage Threshold Checker
# =============================================================================
# Usage: ./scripts/check-coverage.sh [threshold]
#
# Default threshold history:
#   - v26.5.1 and earlier: 15% (initial gate)
#   - v26.5.2 (this commit): 16% — bumped after PR adding routes_
#     register tests + recon wiring tests. Empirical measurement after
#     those tests was 16.5%, so 16% gives ~0.5% margin to flake.
#
# Long-term targets are 25% (v26.5.3) and 40% (v26.6). Reaching 25%
# requires meaningful handler / service tests beyond the cheap
# structural tests added in v26.5.2; tracked in
# docs/v26.5.2/plan/sessions/02-coverage-uplift.md.
#
# Auto-generated templ files (*_templ.go) are excluded to match
# .golangci.yml — testing generated code is not meaningful.
# =============================================================================

set -euo pipefail

THRESHOLD="${1:-16}"
COVERAGE_FILE="coverage.out"
COVERAGE_FILTERED="coverage.filtered.out"

echo "=== usulnet Test Coverage Check ==="
echo "Minimum threshold: ${THRESHOLD}%"
echo ""

# Run tests with coverage
echo "Running tests with coverage..."
go test -race -coverprofile="${COVERAGE_FILE}" -covermode=atomic ./... 2>&1 | tail -20

if [ ! -f "${COVERAGE_FILE}" ]; then
    echo "ERROR: Coverage file not generated"
    exit 1
fi

# Strip auto-generated _templ.go lines so the percentage reflects
# hand-written code only. Keep the mode line as the first record.
{
    head -1 "${COVERAGE_FILE}"
    grep -v "_templ\.go:" "${COVERAGE_FILE}" | tail -n +2
} > "${COVERAGE_FILTERED}"

# Calculate total coverage from the filtered profile.
TOTAL_COVERAGE=$(go tool cover -func="${COVERAGE_FILTERED}" | grep "^total:" | awk '{print $3}' | sed 's/%//')

echo ""
echo "=== Coverage Results ==="
echo "Total coverage: ${TOTAL_COVERAGE}%"
echo "Threshold:      ${THRESHOLD}%"
echo ""

# Show per-package coverage summary (filtered — hand-written code only).
# head closes the pipe after 30 lines; swallow the resulting SIGPIPE so
# `pipefail` does not fail the script on a successful summary print.
echo "=== Per-Package Coverage (excluding _templ.go) ==="
go tool cover -func="${COVERAGE_FILTERED}" 2>/dev/null | grep -E "^total:|^github" | head -30 || true
echo ""

# Check threshold
if [ "$(echo "${TOTAL_COVERAGE} < ${THRESHOLD}" | bc -l 2>/dev/null || python3 -c "print(1 if ${TOTAL_COVERAGE} < ${THRESHOLD} else 0)")" = "1" ]; then
    echo "FAIL: Coverage ${TOTAL_COVERAGE}% is below threshold ${THRESHOLD}%"
    exit 1
else
    echo "PASS: Coverage ${TOTAL_COVERAGE}% meets threshold ${THRESHOLD}%"
fi

# Generate HTML report from the filtered profile (templ excluded).
echo ""
echo "Generating HTML coverage report..."
go tool cover -html="${COVERAGE_FILTERED}" -o coverage.html
echo "Report saved to coverage.html"
