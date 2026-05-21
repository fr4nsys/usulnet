#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2024-2026 usulnet contributors
# https://github.com/fr4nsys/usulnet
#
# Install shell tab-completion for the usulnet and usulnet-agent CLIs.
#
# Both binaries are Cobra-based and expose `<binary> completion <shell>`;
# this script wraps that with shell auto-detection and writes the output
# to the conventional path for each shell.
#
# Usage: deploy/install-completions.sh [--shell SHELL] [--binary NAME]
#                                       [--system] [--dry-run] [-h]

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Install shell tab-completion for usulnet and usulnet-agent.

Options:
  --shell SHELL      Override the auto-detected shell. One of:
                     bash, zsh, fish, powershell.
  --binary NAME      Install only for this binary. One of:
                     usulnet, usulnet-agent, both (default: both).
  --bin PATH         Use PATH as the binary to run "completion" against.
                     Implies --binary inferred from \$(basename PATH).
                     May be repeated to cover both binaries.
  --system           Write to system-wide paths (needs sudo).
                     Default: per-user paths under \$HOME / \$XDG_*.
  --dry-run          Print the actions, do not write anything.
  -h, --help         Show this help and exit.

Examples:
  # Auto-detect shell, install both binaries for the current user
  ${SCRIPT_NAME}

  # System-wide (root); both binaries, auto-detected shell
  sudo ${SCRIPT_NAME} --system

  # Only zsh, only the main binary
  ${SCRIPT_NAME} --shell zsh --binary usulnet

  # Override the binary path (e.g. a non-PATH build)
  ${SCRIPT_NAME} --bin ./bin/usulnet --shell bash

Reload the shell (or "source" the file) after install.
EOF
}

SHELL_OVERRIDE=""
BINARY_FILTER="both"
SYSTEM=0
DRY_RUN=0
BIN_PATHS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --shell)    SHELL_OVERRIDE="${2:?--shell needs a value}"; shift 2 ;;
        --binary)   BINARY_FILTER="${2:?--binary needs a value}"; shift 2 ;;
        --bin)      BIN_PATHS+=("${2:?--bin needs a value}"); shift 2 ;;
        --system)   SYSTEM=1; shift ;;
        --dry-run)  DRY_RUN=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        *)          echo "${SCRIPT_NAME}: unknown flag $1" >&2; usage >&2; exit 64 ;;
    esac
done

# Resolve which shell to target.
detect_shell() {
    if [[ -n "${SHELL_OVERRIDE}" ]]; then
        echo "${SHELL_OVERRIDE}"
        return
    fi
    case "$(basename "${SHELL:-}")" in
        bash) echo bash ;;
        zsh)  echo zsh ;;
        fish) echo fish ;;
        pwsh|powershell) echo powershell ;;
        *)    echo "${SCRIPT_NAME}: cannot auto-detect shell (\$SHELL=${SHELL:-unset}); pass --shell" >&2
              exit 64 ;;
    esac
}

# Resolve binaries to operate on.
# Returns a list of "name|path" pairs.
resolve_binaries() {
    local -a out=()
    if [[ ${#BIN_PATHS[@]} -gt 0 ]]; then
        local p
        for p in "${BIN_PATHS[@]}"; do
            [[ -x "${p}" ]] || { echo "${SCRIPT_NAME}: not executable: ${p}" >&2; exit 70; }
            out+=("$(basename "${p}")|${p}")
        done
        printf '%s\n' "${out[@]}"
        return
    fi

    local want_main=0 want_agent=0
    case "${BINARY_FILTER}" in
        usulnet)       want_main=1 ;;
        usulnet-agent) want_agent=1 ;;
        both)          want_main=1; want_agent=1 ;;
        *) echo "${SCRIPT_NAME}: invalid --binary ${BINARY_FILTER}" >&2; exit 64 ;;
    esac

    local p
    if [[ ${want_main} -eq 1 ]]; then
        if p=$(command -v usulnet 2>/dev/null); then
            out+=("usulnet|${p}")
        else
            echo "${SCRIPT_NAME}: usulnet not on \$PATH; skipping (use --bin to override)" >&2
        fi
    fi
    if [[ ${want_agent} -eq 1 ]]; then
        if p=$(command -v usulnet-agent 2>/dev/null); then
            out+=("usulnet-agent|${p}")
        else
            echo "${SCRIPT_NAME}: usulnet-agent not on \$PATH; skipping (use --bin to override)" >&2
        fi
    fi

    if [[ ${#out[@]} -eq 0 ]]; then
        echo "${SCRIPT_NAME}: no installable binaries found" >&2
        exit 70
    fi
    printf '%s\n' "${out[@]}"
}

# Resolve the target file path for a (binary, shell, scope) tuple.
# Echoes the absolute path on stdout.
target_path() {
    local name="$1" shell="$2"
    case "${shell}" in
        bash)
            if [[ ${SYSTEM} -eq 1 ]]; then
                echo "/etc/bash_completion.d/${name}"
            else
                local dir="${XDG_DATA_HOME:-${HOME}/.local/share}/bash-completion/completions"
                echo "${dir}/${name}"
            fi ;;
        zsh)
            if [[ ${SYSTEM} -eq 1 ]]; then
                echo "/usr/local/share/zsh/site-functions/_${name}"
            else
                local dir="${HOME}/.local/share/zsh/site-functions"
                echo "${dir}/_${name}"
            fi ;;
        fish)
            if [[ ${SYSTEM} -eq 1 ]]; then
                echo "/etc/fish/completions/${name}.fish"
            else
                local dir="${XDG_CONFIG_HOME:-${HOME}/.config}/fish/completions"
                echo "${dir}/${name}.fish"
            fi ;;
        powershell)
            if [[ ${SYSTEM} -eq 1 ]]; then
                echo "/etc/powershell/completions/${name}.ps1"
            else
                local dir="${XDG_CONFIG_HOME:-${HOME}/.config}/powershell/completions"
                echo "${dir}/${name}.ps1"
            fi ;;
        *) echo "${SCRIPT_NAME}: unsupported shell: ${shell}" >&2; exit 64 ;;
    esac
}

# Print the post-install note for the chosen shell.
post_install_note() {
    local shell="$1" target="$2" dir
    case "${shell}" in
        bash) echo "  Restart bash or run: source \"${target}\"" ;;
        zsh)
            dir="$(dirname "${target}")"
            echo "  Add to ~/.zshrc (before \`compinit\`): fpath=(${dir} \$fpath)"
            echo "  Then restart zsh, or run: autoload -U compinit && compinit"
            ;;
        fish) echo "  Restart fish (or open a new shell)." ;;
        powershell) echo "  Add to \$PROFILE: . \"${target}\"" ;;
    esac
}

# run_mkdir creates DIR, honouring DRY_RUN. Replaces the previous
# generic eval-based run() — keeping each operation in its own helper
# means values flow as positional arguments rather than through a
# string passed to eval, so shell metacharacters in DIR (spaces,
# semicolons, dollar signs) can never be reinterpreted by the shell.
run_mkdir() {
    local dir="$1"
    if [[ ${DRY_RUN} -eq 1 ]]; then
        echo "[dry-run] mkdir -p \"${dir}\""
    else
        mkdir -p "${dir}"
    fi
}

# run_completion writes the Cobra completion script for SHELL produced
# by BIN to TARGET. Direct invocation — no eval — so BIN, SHELL, and
# TARGET are passed as ordinary positional arguments.
run_completion() {
    local bin="$1" shell="$2" target="$3"
    if [[ ${DRY_RUN} -eq 1 ]]; then
        echo "[dry-run] \"${bin}\" completion ${shell} > \"${target}\""
    else
        "${bin}" completion "${shell}" > "${target}"
    fi
}

main() {
    local shell
    shell="$(detect_shell)"
    echo "${SCRIPT_NAME}: shell=${shell} system=${SYSTEM} dry-run=${DRY_RUN}"

    local mapping name path target
    while IFS= read -r mapping; do
        name="${mapping%%|*}"
        path="${mapping#*|}"
        target="$(target_path "${name}" "${shell}")"

        run_mkdir "$(dirname "${target}")"
        run_completion "${path}" "${shell}" "${target}"
        echo "${SCRIPT_NAME}: installed ${name} ${shell} completion -> ${target}"
        post_install_note "${shell}" "${target}"
    done < <(resolve_binaries)
}

main "$@"
