#!/usr/bin/env bash
# =============================================================================
# usulnet — publish-public_test.sh
# =============================================================================
# Bash test harness for scripts/publish-public.sh. Exercises the allow /
# deny / glob logic by:
#
#   1. Running --dry-run against the real repo and asserting representative
#      files land where expected.
#   2. Running --check-denied in a self-contained fixture that simulates a
#      leak, and asserting the script exits non-zero and names every
#      offending path.
#
# The harness is offline, idempotent, and does not modify the real
# build/public/ directory beyond what publish-public.sh would.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PUBLISH="${SCRIPT_DIR}/publish-public.sh"
STAGING="${ROOT}/build/public"

PASS=0
FAIL=0
FAILED_NAMES=()

pass() {
    printf '  PASS  %s\n' "$1"
    PASS=$((PASS + 1))
}
fail() {
    printf '  FAIL  %s\n' "$1" >&2
    FAIL=$((FAIL + 1))
    FAILED_NAMES+=("$1")
}

assert_file() {
    local name="$1"
    local path="$2"
    if [[ -f "${STAGING}/${path}" ]]; then
        pass "${name}"
    else
        fail "${name}: expected file present: ${path}"
    fi
}

assert_no_file() {
    local name="$1"
    local path="$2"
    if [[ ! -e "${STAGING}/${path}" ]]; then
        pass "${name}"
    else
        fail "${name}: unexpected file present: ${path}"
    fi
}

assert_eq() {
    local name="$1"
    local expected="$2"
    local actual="$3"
    if [[ "${expected}" == "${actual}" ]]; then
        pass "${name}"
    else
        fail "${name}: expected '${expected}', got '${actual}'"
    fi
}

echo "=== publish-public_test.sh ==="
echo

# ---------------------------------------------------------------------------
# Section 1 — dry-run against the real repo.
# ---------------------------------------------------------------------------
echo "[1] --dry-run sweep"
bash "${PUBLISH}" --dry-run > /dev/null

# Allow rule cmd/** admits Go entry points.
assert_file "allow cmd/** admits cmd/usulnet/main.go" \
    "cmd/usulnet/main.go"
assert_file "allow cmd/** admits cmd/usulnet-agent/main.go" \
    "cmd/usulnet-agent/main.go"

# Allow rule internal/** admits internals.
assert_file "allow internal/** admits internal/app/app.go" \
    "internal/app/app.go"

# Allow rule docs/v26.5/** admits its public files. The release-notes /
# security-review / status-board sit here. Internal v26.5 docs (merge plan,
# context, technical notes, sessions/) moved to dev/v26.5/ as of 2026-05-15
# and are denied below.
v265_pub="docs/v26.5/release-notes-v26.5.1.md"
if [[ -f "${ROOT}/${v265_pub}" ]]; then
    assert_file "allow docs/v26.5/** admits ${v265_pub}" "${v265_pub}"
else
    pass "allow docs/v26.5/** (no public file present — skipped)"
fi

# Top-level literal allows.
assert_file "literal LICENSE is published"        "LICENSE"
assert_file "literal Makefile is published"       "Makefile"
assert_file "literal README.md is published"      "README.md"
assert_file "literal CHANGELOG.md is published"   "CHANGELOG.md"
assert_file "literal go.mod is published"         "go.mod"
assert_file "literal .gitignore is published"     ".gitignore"

# Allowed single-file doc.
assert_file "literal docs/recon.md is published"  "docs/recon.md"

# ---------- Denies ----------

# Deny !CLAUDE.md blocks the top-level CLAUDE.md.
assert_no_file "deny !CLAUDE.md blocks CLAUDE.md" \
    "CLAUDE.md"

# Deny !dev/** blocks the entire dev folder (planning, sessions, internal
# notes, source-zip snapshots). This is the primary defense-in-depth deny
# since 2026-05-15; obsolete !docs/0526/** and !docs/v26.5/sessions/**
# entries are kept in PUBLIC_FILES.md for paths that may reappear.
assert_no_file "deny !dev/** blocks the cloud session prompts" \
    "dev/0526/cloud/README.md"
assert_no_file "deny !dev/** blocks the v26.5.1 merge plan" \
    "dev/v26.5/merge-plan-v26.5.1.md"
assert_no_file "deny !dev/** blocks PUBLIC_FILES.md itself" \
    "dev/PUBLIC_FILES.md"
assert_no_file "deny !dev/** blocks May-2026 pivot technical notes" \
    "dev/0526/technical-notes.md"
assert_no_file "deny !dev/** blocks the v26.2.7 source zip" \
    "dev/0526/usulnet-26.2.7-17621d7848828b531b92e43cb6cc11286a2bf2c3.zip"

# Deny !scripts/publish-public.sh blocks the script from publishing itself.
assert_no_file "deny !scripts/publish-public.sh blocks the script" \
    "scripts/publish-public.sh"
assert_no_file "deny !scripts/publish-public_test.sh blocks the test" \
    "scripts/publish-public_test.sh"

# Deny on internal-only docs.
assert_no_file "deny !PROJECT_STATUS.md blocks PROJECT_STATUS.md" \
    "PROJECT_STATUS.md"
assert_no_file "deny !issues.md blocks issues.md" \
    "issues.md"
assert_no_file "deny !docs/portainer-gap-analysis.md blocks it" \
    "docs/portainer-gap-analysis.md"
assert_no_file "deny !docker_swarm_vs_kubernetes.pdf blocks the PDF" \
    "docker_swarm_vs_kubernetes.pdf"

# Sibling scripts that are NOT denied should be published.
assert_file "sibling scripts/check-naming.sh IS published" \
    "scripts/check-naming.sh"
assert_file "sibling scripts/pre-commit IS published" \
    "scripts/pre-commit"

# ---------- Overlay path-rewrite (S03) ----------

# usulnet-public-overlays/<x> rewrites to <x> in the staging tree.
assert_file "overlay rewrite: .github/workflows/mirror-olivaresai.yml" \
    ".github/workflows/mirror-olivaresai.yml"
assert_file "overlay rewrite: .github/CODEOWNERS" \
    ".github/CODEOWNERS"

# The raw overlay subtree must not be copied verbatim under its
# pre-rewrite path.
assert_no_file "deny !usulnet-public-overlays/** blocks the raw overlay tree" \
    "usulnet-public-overlays/.github/workflows/mirror-olivaresai.yml"
assert_no_file "deny !usulnet-public-overlays/** blocks the raw CODEOWNERS" \
    "usulnet-public-overlays/.github/CODEOWNERS"

echo

# ---------------------------------------------------------------------------
# Section 2 — --check-denied happy path on the real repo.
# ---------------------------------------------------------------------------
echo "[2] --check-denied happy path"
if bash "${PUBLISH}" --check-denied > /tmp/publish_public_check.out 2>&1; then
    pass "--check-denied exits 0 on a clean build"
else
    fail "--check-denied unexpectedly failed on a clean build"
    cat /tmp/publish_public_check.out >&2 || true
fi
echo

# ---------------------------------------------------------------------------
# Section 3 — --check-denied failure path against a self-contained fixture.
# ---------------------------------------------------------------------------
echo "[3] --check-denied failure path (fixture-driven leak)"

FIXTURE="$(mktemp -d)"
trap 'rm -rf "${FIXTURE}"' EXIT

mkdir -p "${FIXTURE}/repo/docs/0526" "${FIXTURE}/repo/cmd/usulnet"
cat > "${FIXTURE}/repo/docs/0526/PUBLIC_FILES.md" <<'EOF'
# Fixture allow-list for publish-public_test.sh.

```rules
cmd/**
README.md
!CLAUDE.md
!docs/0526/**
!secret.md
```
EOF
echo 'package main' > "${FIXTURE}/repo/cmd/usulnet/main.go"
echo '# Fixture README' > "${FIXTURE}/repo/README.md"

mkdir -p "${FIXTURE}/build/public/cmd/usulnet"
echo 'package main' > "${FIXTURE}/build/public/cmd/usulnet/main.go"
echo '# Fixture README' > "${FIXTURE}/build/public/README.md"
mkdir -p "${FIXTURE}/build/public/docs/0526"
echo 'leak'  > "${FIXTURE}/build/public/docs/0526/PRIVATE_LEAK.md"
echo 'leak'  > "${FIXTURE}/build/public/CLAUDE.md"
echo 'leak'  > "${FIXTURE}/build/public/secret.md"

set +e
PUBLISH_PUBLIC_ROOT="${FIXTURE}/repo" \
PUBLISH_PUBLIC_ALLOW_LIST="${FIXTURE}/repo/docs/0526/PUBLIC_FILES.md" \
PUBLISH_PUBLIC_BUILD_DIR="${FIXTURE}/build" \
PUBLISH_PUBLIC_NO_BUILD=1 \
    bash "${PUBLISH}" --check-denied > "${FIXTURE}/check.out" 2>&1
rc=$?
set -e

assert_eq "--check-denied fixture exits 1 when denied paths leak" \
    "1" "${rc}"

leak_output="$(cat "${FIXTURE}/check.out")"
for leaked in \
    "docs/0526/PRIVATE_LEAK.md" \
    "CLAUDE.md" \
    "secret.md"
do
    if printf '%s' "${leak_output}" | grep -Fq "${leaked}"; then
        pass "--check-denied names offending path: ${leaked}"
    else
        fail "--check-denied did not name: ${leaked}"
    fi
done

# Now clean the leaked files and re-check — should pass.
rm -f "${FIXTURE}/build/public/CLAUDE.md" \
      "${FIXTURE}/build/public/secret.md" \
      "${FIXTURE}/build/public/docs/0526/PRIVATE_LEAK.md"
rmdir "${FIXTURE}/build/public/docs/0526" "${FIXTURE}/build/public/docs" 2>/dev/null || true

set +e
PUBLISH_PUBLIC_ROOT="${FIXTURE}/repo" \
PUBLISH_PUBLIC_ALLOW_LIST="${FIXTURE}/repo/docs/0526/PUBLIC_FILES.md" \
PUBLISH_PUBLIC_BUILD_DIR="${FIXTURE}/build" \
PUBLISH_PUBLIC_NO_BUILD=1 \
    bash "${PUBLISH}" --check-denied > "${FIXTURE}/check2.out" 2>&1
rc2=$?
set -e
assert_eq "--check-denied fixture exits 0 once leaks are removed" \
    "0" "${rc2}"

echo

# ---------------------------------------------------------------------------
# Section 3b — overlay path-rewrite (S03) against a self-contained fixture.
# ---------------------------------------------------------------------------
echo "[3b] overlay path-rewrite (fixture)"

OV_FIXTURE="$(mktemp -d)"
trap 'rm -rf "${FIXTURE}" "${OV_FIXTURE}"' EXIT

mkdir -p \
    "${OV_FIXTURE}/repo/docs/0526" \
    "${OV_FIXTURE}/repo/cmd/usulnet" \
    "${OV_FIXTURE}/repo/usulnet-public-overlays/.github/workflows"

cat > "${OV_FIXTURE}/repo/docs/0526/PUBLIC_FILES.md" <<'EOF'
# Overlay fixture allow-list.

```rules
cmd/**
README.md
.github/**

!CLAUDE.md
!usulnet-public-overlays/**
```
EOF
echo 'package main'    > "${OV_FIXTURE}/repo/cmd/usulnet/main.go"
echo '# Fixture'       > "${OV_FIXTURE}/repo/README.md"
echo 'name: mirror'    > "${OV_FIXTURE}/repo/usulnet-public-overlays/.github/workflows/mirror.yml"
echo '* @fr4nsys'      > "${OV_FIXTURE}/repo/usulnet-public-overlays/.github/CODEOWNERS"

PUBLISH_PUBLIC_ROOT="${OV_FIXTURE}/repo" \
PUBLISH_PUBLIC_ALLOW_LIST="${OV_FIXTURE}/repo/docs/0526/PUBLIC_FILES.md" \
PUBLISH_PUBLIC_BUILD_DIR="${OV_FIXTURE}/build" \
    bash "${PUBLISH}" --dry-run > "${OV_FIXTURE}/out" 2>&1

OV_STAGING="${OV_FIXTURE}/build/public"

if [[ -f "${OV_STAGING}/.github/workflows/mirror.yml" ]]; then
    pass "overlay rewrites <overlay>/.github/workflows/mirror.yml -> .github/workflows/mirror.yml"
else
    fail "overlay rewrite did not land mirror.yml at .github/workflows/"
    cat "${OV_FIXTURE}/out" >&2 || true
fi

if [[ -f "${OV_STAGING}/.github/CODEOWNERS" ]]; then
    pass "overlay rewrites <overlay>/.github/CODEOWNERS -> .github/CODEOWNERS"
else
    fail "overlay rewrite did not land CODEOWNERS at .github/"
fi

if [[ ! -e "${OV_STAGING}/usulnet-public-overlays" ]]; then
    pass "raw overlay subtree is not republished verbatim"
else
    fail "raw overlay subtree leaked into staging"
fi

# Re-running must be idempotent.
PUBLISH_PUBLIC_ROOT="${OV_FIXTURE}/repo" \
PUBLISH_PUBLIC_ALLOW_LIST="${OV_FIXTURE}/repo/docs/0526/PUBLIC_FILES.md" \
PUBLISH_PUBLIC_BUILD_DIR="${OV_FIXTURE}/build" \
    bash "${PUBLISH}" --dry-run > "${OV_FIXTURE}/out2" 2>&1

if [[ -f "${OV_STAGING}/.github/workflows/mirror.yml" ]]; then
    pass "overlay rewrite is idempotent on a second run"
else
    fail "second --dry-run lost the overlay-rewritten file"
fi

# --check-denied on the overlay fixture must succeed (no denied paths
# leak — the overlay was rewritten, not copied verbatim).
set +e
PUBLISH_PUBLIC_ROOT="${OV_FIXTURE}/repo" \
PUBLISH_PUBLIC_ALLOW_LIST="${OV_FIXTURE}/repo/docs/0526/PUBLIC_FILES.md" \
PUBLISH_PUBLIC_BUILD_DIR="${OV_FIXTURE}/build" \
    bash "${PUBLISH}" --check-denied > "${OV_FIXTURE}/check.out" 2>&1
ov_rc=$?
set -e
assert_eq "--check-denied passes on a fresh overlay build" "0" "${ov_rc}"

echo

# ---------------------------------------------------------------------------
# Section 4 — usage and error handling.
# ---------------------------------------------------------------------------
echo "[4] usage and error handling"

set +e
bash "${PUBLISH}" > /dev/null 2>&1
rc3=$?
set -e
assert_eq "no args prints usage and exits 1" "1" "${rc3}"

set +e
bash "${PUBLISH}" --bogus-flag > /dev/null 2>&1
rc4=$?
set -e
assert_eq "unknown flag exits 1" "1" "${rc4}"

set +e
bash "${PUBLISH}" --dry-run --check-denied > /dev/null 2>&1
rc5=$?
set -e
assert_eq "multiple flags exits 1" "1" "${rc5}"

echo

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '=== %d passed, %d failed ===\n' "${PASS}" "${FAIL}"
if [[ "${FAIL}" -gt 0 ]]; then
    printf '\nfailed tests:\n' >&2
    for name in "${FAILED_NAMES[@]}"; do
        printf '  - %s\n' "${name}" >&2
    done
    exit 1
fi
exit 0
