#!/usr/bin/env bash
# =============================================================================
# usulnet - Test Coverage Threshold Checker
# =============================================================================
# Usage: ./scripts/check-coverage.sh [threshold]
# Default threshold: 40%
# =============================================================================

set -euo pipefail

THRESHOLD="${1:-40}"
COVERAGE_FILE="coverage.out"

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

# Calculate total coverage
TOTAL_COVERAGE=$(go tool cover -func="${COVERAGE_FILE}" | grep "^total:" | awk '{print $3}' | sed 's/%//')

echo ""
echo "=== Coverage Results ==="
echo "Total coverage: ${TOTAL_COVERAGE}%"
echo "Threshold:      ${THRESHOLD}%"
echo ""

# Show per-package coverage summary
echo "=== Per-Package Coverage ==="
go tool cover -func="${COVERAGE_FILE}" | grep -E "^total:|^github" | head -30
echo ""

# Check threshold
if [ "$(echo "${TOTAL_COVERAGE} < ${THRESHOLD}" | bc -l 2>/dev/null || python3 -c "print(1 if ${TOTAL_COVERAGE} < ${THRESHOLD} else 0)")" = "1" ]; then
    echo "FAIL: Coverage ${TOTAL_COVERAGE}% is below threshold ${THRESHOLD}%"
    exit 1
else
    echo "PASS: Coverage ${TOTAL_COVERAGE}% meets threshold ${THRESHOLD}%"
fi

# Generate HTML report
echo ""
echo "Generating HTML coverage report..."
go tool cover -html="${COVERAGE_FILE}" -o coverage.html
echo "Report saved to coverage.html"
