#!/usr/bin/env bash
# =============================================================================
# usulnet — publish-public split
# =============================================================================
# Builds a curated copy of this dev repo at build/public/ matching the
# allow-list in dev/PUBLIC_FILES.md. The output is the input to the
# mirror workflow (S03) and the website build (S04+).
#
# Guarantees:
#   - idempotent: running it twice produces the same tree;
#   - read-only against the source tree (writes only under build/);
#   - offline: no git, no curl, no gh, no network of any kind.
#
# See dev/0526/sessions/02-public-split-allowlist.md.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Hooks for the test harness. Operators do not set these.
ROOT="${PUBLISH_PUBLIC_ROOT:-${DEFAULT_ROOT}}"
ALLOW_LIST="${PUBLISH_PUBLIC_ALLOW_LIST:-${ROOT}/dev/PUBLIC_FILES.md}"
BUILD_DIR="${PUBLISH_PUBLIC_BUILD_DIR:-${ROOT}/build}"
STAGING="${BUILD_DIR}/public"
PREVIOUS="${BUILD_DIR}/public-previous"

# Overlay directory: files under ${ROOT}/${OVERLAY_DIR}/<x> are republished
# to ${STAGING}/<x> with the prefix stripped. This lets us author public-repo
# artefacts (such as .github/workflows/mirror-olivaresai.yml) inside this
# dev repo without leaking the dev repo's own .github/. See S03.
OVERLAY_DIR="${PUBLISH_PUBLIC_OVERLAY_DIR:-usulnet-public-overlays}"

ALLOW_RULES=()
DENY_RULES=()

usage() {
    cat <<'EOF'
publish-public — build the curated public-repo staging tree.

Usage:
    scripts/publish-public.sh <mode>

Modes:
    --dry-run        Build build/public/ and print a summary.
    --check-denied   Build build/public/ and fail if any denied path leaked in.
    --diff           Build build/public/ and diff against build/public-previous/.
    --clean          Remove build/public/ and exit.
    -h, --help       Print this help.

The script never makes network calls and never modifies anything outside
build/.
EOF
}

log() { printf 'publish-public: %s\n' "$*"; }
die() { printf 'publish-public: error: %s\n' "$*" >&2; exit 1; }

# Strip leading and trailing ASCII whitespace from a single argument.
trim() {
    local s="$1"
    # Trim leading.
    while [[ "${s}" == [[:space:]]* ]]; do s="${s#?}"; done
    # Trim trailing.
    while [[ "${s}" == *[[:space:]] ]]; do s="${s%?}"; done
    printf '%s' "${s}"
}

load_rules() {
    [[ -f "${ALLOW_LIST}" ]] || die "allow-list not found: ${ALLOW_LIST}"

    local in_block=0
    local raw
    local line
    while IFS= read -r raw || [[ -n "${raw}" ]]; do
        if [[ "${in_block}" -eq 0 ]]; then
            if [[ "${raw}" == '```rules' ]]; then
                in_block=1
            fi
            continue
        fi
        if [[ "${raw}" == '```' ]]; then
            in_block=0
            continue
        fi
        line="$(trim "${raw}")"
        [[ -z "${line}" ]] && continue
        case "${line}" in
            \#*) continue ;;
            !*)
                local rule="${line#!}"
                rule="$(trim "${rule}")"
                [[ -z "${rule}" ]] && continue
                validate_rule "${rule}"
                DENY_RULES+=("${rule}")
                ;;
            *)
                validate_rule "${line}"
                ALLOW_RULES+=("${line}")
                ;;
        esac
    done < "${ALLOW_LIST}"

    if [[ "${in_block}" -ne 0 ]]; then
        die "unterminated \`\`\`rules block in ${ALLOW_LIST}"
    fi
    if [[ "${#ALLOW_RULES[@]}" -eq 0 ]]; then
        die "no allow rules parsed from ${ALLOW_LIST}"
    fi
}

# Reject rules with path traversal or unsupported glob metacharacters.
# The only wildcard supported is a trailing /** on a directory path.
validate_rule() {
    local rule="$1"
    case "${rule}" in
        /*|*..*) die "invalid rule (absolute or traversal): ${rule}" ;;
    esac
    local stripped="${rule%/\*\*}"
    case "${stripped}" in
        *\**|*\?*|*\[*) die "invalid rule (unsupported glob): ${rule}" ;;
    esac
}

# matches_rule <path> <rule>
matches_rule() {
    local path="$1"
    local rule="$2"
    if [[ "${rule}" == *"/**" ]]; then
        local prefix="${rule%/\*\*}"
        [[ "${path}" == "${prefix}" || "${path}" == "${prefix}/"* ]]
    else
        [[ "${path}" == "${rule}" ]]
    fi
}

# is_denied <path>
is_denied() {
    local path="$1"
    local rule
    for rule in "${DENY_RULES[@]}"; do
        if matches_rule "${path}" "${rule}"; then
            return 0
        fi
    done
    return 1
}

# is_allowed <path>
# A path is allowed iff at least one allow rule matches and no deny does.
is_allowed() {
    local path="$1"
    local rule
    local hit=1
    for rule in "${ALLOW_RULES[@]}"; do
        if matches_rule "${path}" "${rule}"; then
            hit=0
            break
        fi
    done
    [[ "${hit}" -eq 0 ]] || return 1
    if is_denied "${path}"; then
        return 1
    fi
    return 0
}

# Emit every regular file in the source tree as a repo-relative path,
# excluding:
#   - our own output (build/) and the git data dir;
#   - the dev repo's own .github/ — it contains AI-agent prompts and
#     dev-repo CI that must stay private. The public-repo .github/ is
#     authored under ${OVERLAY_DIR}/.github/ and is published by the
#     overlay pass below;
#   - the overlay subtree itself — it is processed by apply_overlay
#     with the prefix stripped.
enumerate_source() {
    ( cd "${ROOT}" && find . \
            \( -path './.git' \
               -o -path './build' \
               -o -path './.github' \
               -o -path "./${OVERLAY_DIR}" \) -prune -o \
            -type f -print
    ) | sed 's|^\./||' | LC_ALL=C sort
}

# Emit every regular file under the overlay directory as a path RELATIVE
# to the overlay root. The caller treats the emitted path as both the
# allow-list lookup key and the destination path under STAGING.
# Empty output if the overlay directory does not exist.
enumerate_overlay() {
    [[ -d "${ROOT}/${OVERLAY_DIR}" ]] || return 0
    ( cd "${ROOT}/${OVERLAY_DIR}" && find . -type f -print
    ) | sed 's|^\./||' | LC_ALL=C sort
}

# Copy the overlay subtree on top of the main staging tree, applying the
# usulnet-public-overlays/<x> -> <x> path-rewrite.
#
# A rewritten path is published only if it satisfies the same allow/deny
# rules as a regular source path. The raw overlay subtree itself should
# be denied (`!usulnet-public-overlays/**`) so files cannot leak under
# their pre-rewrite path through the main pass.
apply_overlay() {
    if [[ ! -d "${ROOT}/${OVERLAY_DIR}" ]]; then
        log "overlay directory ${OVERLAY_DIR}/ not present; skipping"
        return 0
    fi

    local copied=0
    local skipped=0
    local rel src dest
    while IFS= read -r rel; do
        [[ -z "${rel}" ]] && continue
        if is_allowed "${rel}"; then
            src="${ROOT}/${OVERLAY_DIR}/${rel}"
            dest="${STAGING}/${rel}"
            mkdir -p "$(dirname "${dest}")"
            cp -p "${src}" "${dest}"
            copied=$((copied + 1))
        else
            skipped=$((skipped + 1))
        fi
    done < <(enumerate_overlay)

    log "overlay rewrite: ${OVERLAY_DIR}/<x> -> <x>"
    log "overlay copied:  ${copied}"
    log "overlay skipped: ${skipped}"
}

build_staging() {
    log "loading rules from ${ALLOW_LIST#"${ROOT}/"}"
    load_rules
    log "allow rules: ${#ALLOW_RULES[@]}; deny rules: ${#DENY_RULES[@]}"

    rm -rf "${STAGING}"
    mkdir -p "${STAGING}"

    local copied=0
    local skipped_deny=0
    local skipped_no_allow=0
    local path
    local dest
    while IFS= read -r path; do
        if is_denied "${path}"; then
            skipped_deny=$((skipped_deny + 1))
            continue
        fi
        if is_allowed "${path}"; then
            dest="${STAGING}/${path}"
            mkdir -p "$(dirname "${dest}")"
            cp -p "${ROOT}/${path}" "${dest}"
            copied=$((copied + 1))
        else
            skipped_no_allow=$((skipped_no_allow + 1))
        fi
    done < <(enumerate_source)

    log "copied ${copied} files"
    log "skipped (denied):       ${skipped_deny}"
    log "skipped (not in allow): ${skipped_no_allow}"

    apply_overlay
}

mode_dry_run() {
    build_staging
    log "staging tree at ${STAGING}"
    log "top-level entries:"
    ( cd "${STAGING}" && find . -mindepth 1 -maxdepth 1 \
            \( -printf '  %y %P\n' \) ) | LC_ALL=C sort -k2
    log "byte size:"
    du -sh "${STAGING}" | awk '{print "  " $1}'
}

mode_check_denied() {
    if [[ "${PUBLISH_PUBLIC_NO_BUILD:-0}" != "1" ]]; then
        build_staging
    else
        log "PUBLISH_PUBLIC_NO_BUILD=1 — scanning existing staging only"
        load_rules
    fi

    [[ -d "${STAGING}" ]] || die "staging missing: ${STAGING}"

    log "scanning ${STAGING#"${ROOT}/"} for denied paths..."
    local offending=()
    local path
    while IFS= read -r path; do
        if is_denied "${path}"; then
            offending+=("${path}")
        fi
    done < <( cd "${STAGING}" && find . -type f -print \
                | sed 's|^\./||' | LC_ALL=C sort )

    if [[ "${#offending[@]}" -gt 0 ]]; then
        printf 'publish-public: error: %d denied path(s) leaked into staging:\n' \
            "${#offending[@]}" >&2
        local p
        for p in "${offending[@]}"; do
            printf '  %s\n' "${p}" >&2
        done
        exit 1
    fi
    log "ok — no denied paths in staging"
}

mode_diff() {
    build_staging
    if [[ ! -d "${PREVIOUS}" ]]; then
        log "no previous build at ${PREVIOUS} — snapshot the current"
        log "staging with: mv ${STAGING} ${PREVIOUS}"
        return 0
    fi
    log "diff -rq ${PREVIOUS#"${ROOT}/"} ${STAGING#"${ROOT}/"}:"
    diff -rq "${PREVIOUS}" "${STAGING}" || true
}

mode_clean() {
    if [[ -d "${STAGING}" ]]; then
        rm -rf "${STAGING}"
        log "removed ${STAGING}"
    else
        log "nothing to clean at ${STAGING}"
    fi
}

main() {
    if [[ $# -eq 0 ]]; then
        usage >&2
        exit 1
    fi
    if [[ $# -gt 1 ]]; then
        die "expected one mode flag, got: $*"
    fi
    case "$1" in
        --dry-run)      mode_dry_run ;;
        --check-denied) mode_check_denied ;;
        --diff)         mode_diff ;;
        --clean)        mode_clean ;;
        -h|--help)      usage ;;
        *)              usage >&2; exit 1 ;;
    esac
}

main "$@"
