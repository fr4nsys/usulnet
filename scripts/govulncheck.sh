#!/usr/bin/env bash
# =============================================================================
# usulnet - govulncheck wrapper with documented OSV allowlist
# =============================================================================
# Runs govulncheck against ./..., parses the JSON stream, filters out OSV IDs
# in ALLOWED_OSV_IDS, and fails if any unfiltered reachable vulnerability
# remains. The full report (excluded ids included) is teed to
# govulncheck.txt for the workflow's sticky PR comment + step summary.
#
# Allowlist policy: every entry must have an inline justification AND a link
# to the upstream advisory. The list is small on purpose — if a future
# release patches an entry, drop it from the allowlist instead of carrying
# stale exclusions.
# =============================================================================
set -euo pipefail

OUT_TXT="${OUT_TXT:-govulncheck.txt}"
OUT_JSON="${OUT_JSON:-govulncheck.json}"

# ---------------------------------------------------------------------------
# Allowed (false-positive) OSV IDs — documented exceptions
# ---------------------------------------------------------------------------
#
# GO-2026-4883 / CVE-2026-33997  Moby off-by-one in plugin privilege
#                                validation. Server-side defect inside the
#                                Docker daemon's plugin install path. usulnet
#                                links the github.com/docker/docker/client
#                                subpackages to talk to a remote daemon — we
#                                do not embed Moby's plugin runtime. The
#                                daemon config editor only serialises the
#                                `authorization-plugins` string list into
#                                /etc/docker/daemon.json
#                                (internal/services/dockerconfig/service.go:293);
#                                it never executes plugin code in-process.
#                                Fixed in github.com/moby/moby/v2 v2.0.0-beta.8
#                                — the legacy github.com/docker/docker module
#                                we depend on has "Fixed in: N/A".
#                                Advisory: https://github.com/moby/moby/security/advisories/GHSA-pxq6-2prw-chj9
#
# GO-2026-4887 / CVE-2026-34040  Moby AuthZ plugin bypass via oversized
#                                request bodies. Same scope — daemon-side,
#                                impacts hosts that run AuthZ plugins.
#                                usulnet ships no AuthZ plugin and runs no
#                                Moby daemon code path; the import is
#                                client.Client.*  for remote container/image
#                                management. Fixed in moby/v2 v2.0.0-beta.8;
#                                legacy github.com/docker/docker still "N/A".
#                                Advisory: https://github.com/moby/moby/security/advisories/GHSA-x744-4wpc-v9h2
#
# The two entries are revisited every time the dep audit runs. When
# github.com/docker/docker (or moby/v2) ships a fixed release usable from
# this repo, both lines drop out of the allowlist.
ALLOWED_OSV_IDS=(
  "GO-2026-4883"
  "GO-2026-4887"
)

# ---------------------------------------------------------------------------
# Run govulncheck twice: once for human-readable report, once for JSON.
# ---------------------------------------------------------------------------
echo "Running govulncheck (text output)..."
set +e
govulncheck -show traces ./... > "${OUT_TXT}" 2>&1
set -e

echo "Running govulncheck (JSON output)..."
set +e
govulncheck -format json ./... > "${OUT_JSON}" 2>/dev/null
json_exit=$?
set -e

# ---------------------------------------------------------------------------
# Always print the text report so the CI log + sticky PR comment + step
# summary keep their full content.
# ---------------------------------------------------------------------------
cat "${OUT_TXT}"

# ---------------------------------------------------------------------------
# Sanity: distinguish a clean "no findings" run from a failure to reach
# the vulnerability database (vuln.go.dev unreachable, malformed module,
# etc.). govulncheck's JSON stream always emits the config message even on
# a clean run, so an empty file is unambiguous evidence the scan never
# really ran.
# ---------------------------------------------------------------------------
if [ ! -s "${OUT_JSON}" ]; then
    echo
    echo "FAIL — govulncheck produced no JSON output (exit ${json_exit})."
    echo "Likely cause: vuln.go.dev unreachable or scan aborted before any"
    echo "messages were emitted. Cannot apply the allowlist; failing closed."
    exit 1
fi

# ---------------------------------------------------------------------------
# Extract reachable findings from the JSON stream. Each `finding` entry with
# a non-empty trace[0].function field is a reachable callsite. Map the OSV
# ID via the `osv` field; collect the unique set.
# ---------------------------------------------------------------------------
REACHED_IDS=$(jq -sr '
    [.[] | select(.finding != null)
          | select(.finding.trace[0].function != null)
          | .finding.osv]
    | unique
    | .[]
' "${OUT_JSON}" 2>/dev/null || true)

if [ -z "${REACHED_IDS}" ]; then
    echo
    echo "govulncheck: 0 reachable vulnerabilities."
    exit 0
fi

echo
echo "Reachable vulnerabilities reported: ${REACHED_IDS//$'\n'/, }"

# ---------------------------------------------------------------------------
# Drop allowlisted IDs.
# ---------------------------------------------------------------------------
ALLOWED_REGEX="^($(IFS='|'; echo "${ALLOWED_OSV_IDS[*]}"))$"
UNHANDLED=$(echo "${REACHED_IDS}" | grep -Ev "${ALLOWED_REGEX}" || true)

if [ -n "${UNHANDLED}" ]; then
    echo
    echo "FAIL — unhandled reachable vulnerabilities:"
    echo "${UNHANDLED}" | sed 's/^/  - /'
    echo
    echo "Either bump the offending dep or add the ID to ALLOWED_OSV_IDS in"
    echo "scripts/govulncheck.sh with a documented justification."
    exit 1
fi

echo
echo "PASS — every reachable finding is on the documented allowlist:"
echo "${REACHED_IDS}" | sed 's/^/  - /'
echo
echo "Note: allowlist entries are revisited every dep audit. Drop them as"
echo "soon as a fixed upstream release lands in go.mod."
exit 0
