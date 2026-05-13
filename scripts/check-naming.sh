#!/usr/bin/env bash
# =============================================================================
# usulnet — naming convention check
# =============================================================================
# The product name is always lowercase: "usulnet".
# The canonical domain is "usulnet.com".
#
# The only allowed uppercase form is the Viper environment variable prefix
# "USULNET_" (e.g., USULNET_DATABASE_URL, USULNET_RECON_ENABLED). Database,
# backend, and configuration env vars use this prefix; that is intentional
# and stays uppercase.
#
# Everything else — code identifiers, comments, doc strings, user-facing
# UI copy, logs, notifications, emails, marketing, the website — must be
# lowercase "usulnet".
#
# This script fails the build if it finds incorrect casing anywhere in the
# tracked source tree.
# =============================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

INCLUDES=(
    "--include=*.go"
    "--include=*.md"
    "--include=*.templ"
    "--include=*.yaml"
    "--include=*.yml"
    "--include=*.sql"
    "--include=*.sh"
    "--include=*.js"
    "--include=*.css"
    "--include=*.html"
    "--include=Makefile"
    "--include=Dockerfile*"
)

EXCLUDE_DIRS=(
    "--exclude-dir=.git"
    "--exclude-dir=node_modules"
    "--exclude-dir=vendor"
    "--exclude-dir=bin"
    "--exclude-dir=coverage"
    "--exclude-dir=usulnetdotcom-main"
)

# A line is allowed if it matches any of these patterns:
#   - contains USULNET_  (env var prefix usage, the only valid uppercase form)
#   - contains SetEnvPrefix("USULNET")  (the Viper call that defines the prefix)
#   - contains the marker  <!-- naming-rule-example -->  (CLAUDE.md anti-examples)
#   - is this script itself
ALLOWED='USULNET_|SetEnvPrefix\("USULNET"\)|<!-- naming-rule-example -->|scripts/check-naming\.sh'

matches="$(
    grep -REn "Usulnet|USULNET" "${INCLUDES[@]}" "${EXCLUDE_DIRS[@]}" . 2>/dev/null \
        | grep -Ev "${ALLOWED}" \
        || true
)"

if [ -n "${matches}" ]; then
    echo "naming check failed: 'usulnet' must always be lowercase."
    echo "The only allowed uppercase form is the env var prefix USULNET_"
    echo "(e.g., USULNET_DATABASE_URL). See CLAUDE.md > Naming."
    echo
    echo "Offending lines:"
    printf '%s\n' "${matches}"
    exit 1
fi

echo "naming check passed: 'usulnet' is consistently lowercase."
exit 0
