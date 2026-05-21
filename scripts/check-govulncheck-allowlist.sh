#!/usr/bin/env bash
# =============================================================================
# usulnet - govulncheck allowlist assertion
# =============================================================================
# Pins the claim that the two docker/docker advisories on the govulncheck
# allowlist (GO-2026-4883, GO-2026-4887) remain unreachable from usulnet
# code paths. Runs in CI alongside govulncheck so a future commit that
# introduces one of the disallowed API calls fails the build with a clear
# pointer to the allowlist policy.
#
# This complements scripts/govulncheck.sh: that script enforces the
# allowlist against the dependency graph; this one enforces the
# justification embedded in the allowlist text.
#
# Policy: if a real callsite for any of the forbidden symbols below lands,
# either remove the corresponding entry from ALLOWED_OSV_IDS in
# scripts/govulncheck.sh (no longer a false positive — bump the dep or
# accept the finding) or add a documented carve-out here.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# ----------------------------------------------------------------------------
# GO-2026-4883 — Moby off-by-one in plugin privilege validation.
#
# The advisory affects daemon-side plugin install / enable / upgrade paths.
# usulnet uses github.com/docker/docker/client only for container, image,
# volume, network, exec, and swarm management — never the plugin API. If
# any code path here calls one of the plugin client methods below, the
# allowlist justification stops being true.
# ----------------------------------------------------------------------------
forbidden_plugin_calls=(
    "client.PluginInstall"
    "client.PluginEnable"
    "client.PluginDisable"
    "client.PluginRemove"
    "client.PluginUpgrade"
    "client.PluginCreate"
    "client.PluginPrivileges"
    "client.PluginPush"
    "client.PluginSet"
    "Client.PluginInstall"
    "Client.PluginEnable"
    "Client.PluginDisable"
    "Client.PluginRemove"
    "Client.PluginUpgrade"
    "Client.PluginCreate"
    "Client.PluginPrivileges"
    "Client.PluginPush"
    "Client.PluginSet"
)

for symbol in "${forbidden_plugin_calls[@]}"; do
    # Search in production code only — tests can stub these freely.
    hits=$(grep -rn --include="*.go" --exclude="*_test.go" \
        -F "${symbol}" internal/ cmd/ 2>/dev/null || true)
    if [ -n "${hits}" ]; then
        echo "FAIL: ${symbol} is reachable in production code:"
        echo "${hits}" | sed 's/^/  /'
        echo
        echo "GO-2026-4883 was allowlisted on the explicit ground that usulnet"
        echo "does not exercise Moby's plugin install path. Drop the allowlist"
        echo "entry in scripts/govulncheck.sh or document a carve-out."
        echo
        fail=1
    fi
done

# ----------------------------------------------------------------------------
# GO-2026-4887 — Moby AuthZ plugin bypass via oversized request bodies.
#
# Daemon-side defect. usulnet's only contact with the "authorization-plugins"
# concept is serialising the operator-configured string list into
# /etc/docker/daemon.json (the dockerconfig editor). It never executes plugin
# code, never proxies AuthZ-decorated request bodies, and runs no Moby
# daemon code in-process.
#
# The allowlist justification stops being true if any of the symbols below
# appear, or if the dockerconfig editor stops being the sole owner of the
# "authorization-plugins" string.
# ----------------------------------------------------------------------------
forbidden_authz_imports=(
    "github.com/docker/docker/pkg/authorization"
    "github.com/docker/docker/plugin/v2"
    "github.com/docker/docker/daemon"
)

for path in "${forbidden_authz_imports[@]}"; do
    hits=$(grep -rn --include="*.go" --exclude="*_test.go" \
        -F "\"${path}" internal/ cmd/ 2>/dev/null || true)
    if [ -n "${hits}" ]; then
        echo "FAIL: import of ${path} found in production code:"
        echo "${hits}" | sed 's/^/  /'
        echo
        echo "GO-2026-4887 was allowlisted on the explicit ground that usulnet"
        echo "links only docker/docker/client (remote daemon API) — not any"
        echo "in-process daemon, plugin runtime, or authorization layer."
        echo
        fail=1
    fi
done

# Whitelist of files allowed to mention "authorization-plugins" (the
# dockerconfig editor's JSON serialiser). Any new occurrence outside this
# list is a regression in the allowlist justification.
authz_string_owners_regex='^(internal/services/dockerconfig/(service\.go|types\.go)|scripts/check-govulncheck-allowlist\.sh|scripts/govulncheck\.sh)$'

stray=$(grep -rln --include="*.go" --include="*.sh" \
    "authorization-plugins" internal/ cmd/ scripts/ 2>/dev/null \
    | grep -Ev "${authz_string_owners_regex}" || true)
if [ -n "${stray}" ]; then
    echo "FAIL: 'authorization-plugins' string found outside the dockerconfig editor:"
    echo "${stray}" | sed 's/^/  /'
    echo
    echo "The GO-2026-4887 allowlist justification pins the dockerconfig editor as"
    echo "the only owner of this configuration key. A new owner means the AuthZ"
    echo "exposure surface widened; revisit the allowlist."
    echo
    fail=1
fi

if [ "${fail}" -ne 0 ]; then
    exit 1
fi

echo "OK — govulncheck allowlist justifications hold:"
echo "  GO-2026-4883: 0 plugin-API callsites in production code."
echo "  GO-2026-4887: 0 daemon/authz imports; authorization-plugins string scoped"
echo "                to internal/services/dockerconfig/."
exit 0
