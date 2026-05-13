#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2024-2026 usulnet contributors
#
# recon-toolkit dispatcher.
#
# Subcommands:
#   extract     --path <p> --mime <m> -> JSON metadata to stdout
#   pdfid       --path <p>            -> JSON pdfid summary (PDF-only)
#   oletools    --path <p>            -> JSON olemeta summary (Office docs)
#   strip       --path <p> --mime <m> -> writes /work/out/cleaned, prints
#                                        JSON {sha256, size, path}
#   holehe       --email <e>          -> JSON
#   phoneinfoga  --phone <p>          -> JSON (amd64 only)
#   subfinder    --domain <d>         -> JSON of subdomains
#   katana       --url <u>            -> JSON of crawled URLs
#
# Designed to run under: --read-only --tmpfs /tmp:exec --user 65534:65534
set -eu

export PATH="/opt/venv/bin:/usr/local/bin:/usr/bin:/bin"
export HOME="${HOME:-/tmp}"

err() {
    # Emit a structured JSON error to stdout and exit non-zero so the
    # caller can parse rather than scrape stderr.
    code="$1"; shift
    msg="$*"
    printf '{"error":"%s","message":"%s"}\n' "$code" "$msg"
    exit 2
}

require_arg() {
    # require_arg <name> <value>
    if [ -z "${2:-}" ]; then
        err invalid_args "missing value for --$1"
    fi
}

parse_kv() {
    # Parse "--key value" pairs from positional args.  Populates
    # underscore-prefixed shell vars (_path, _mime, _email, ...) so we
    # do not collide with anything the caller might set.
    _path=""; _mime=""; _email=""; _phone=""; _domain=""; _url=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --path)   _path="${2:-}";   shift 2 ;;
            --mime)   _mime="${2:-}";   shift 2 ;;
            --email)  _email="${2:-}";  shift 2 ;;
            --phone)  _phone="${2:-}";  shift 2 ;;
            --domain) _domain="${2:-}"; shift 2 ;;
            --url)    _url="${2:-}";    shift 2 ;;
            *) err invalid_args "unknown flag: $1" ;;
        esac
    done
}

# Read a file's path and report a JSON object combining exiftool + file(1)
# output.  mat2 itself does not have a clean "dump metadata as JSON" mode,
# so we rely on exiftool for general formats; PDF/Office artefacts get
# augmented data from pdfid / oletools at higher layers.
cmd_extract() {
    parse_kv "$@"
    require_arg path "$_path"
    require_arg mime "$_mime"
    if [ ! -f "$_path" ]; then
        err input_missing "no such file: $_path"
    fi

    # exiftool -json emits an array of one object; unwrap it so callers
    # always get an object.  Add the detected MIME for cross-checks.
    detected=$(file --brief --mime-type "$_path" 2>/dev/null || echo "application/octet-stream")
    exiftool_json=$(exiftool -json -groupNames "$_path" 2>/dev/null || echo "[{}]")

    printf '%s' "$exiftool_json" | jq -c --arg mime "$_mime" --arg detected "$detected" '
        (.[0] // {}) as $meta
        | {requested_mime: $mime, detected_mime: $detected, exiftool: $meta}
    '
}

# Strip metadata by copying to /work/out/cleaned and running mat2 on the
# copy (mat2 --inplace writes back to the same file).  /work/out is a
# tmpfs the launcher mounts on every recon container; the launcher
# copies the cleaned bytes back to the host with ContainerCopyFileStream
# after the container exits.
cmd_strip() {
    parse_kv "$@"
    require_arg path "$_path"
    require_arg mime "$_mime"
    if [ ! -f "$_path" ]; then
        err input_missing "no such file: $_path"
    fi

    out_dir="/work/out"
    mkdir -p "$out_dir"
    out="${out_dir}/cleaned"
    cp "$_path" "$out"
    if ! mat2 --inplace --no-backup "$out" >/dev/null 2>&1; then
        err strip_failed "mat2 could not process $_mime"
    fi

    sum=$(sha256sum "$out" | awk '{print $1}')
    size=$(stat -c '%s' "$out")
    printf '{"sha256":"%s","size":%s,"path":"%s"}\n' "$sum" "$size" "$out"
}

# Run Didier Stevens' pdfid against a PDF file and emit a structured
# JSON summary.  pdfid itself prints column-aligned text; we wrap the
# raw output so the caller has a single contract.
cmd_pdfid() {
    parse_kv "$@"
    require_arg path "$_path"
    if [ ! -f "$_path" ]; then
        err input_missing "no such file: $_path"
    fi
    raw=$(pdfid "$_path" 2>&1 || true)
    jq -Rn --arg raw "$raw" --arg path "$_path" '{
        path: $path,
        raw: $raw
    }'
}

# Run oletools olemeta for OLE / Office Open XML metadata and emit
# JSON.  olemeta does not have a native JSON mode; we capture its
# text output and pass it through so callers can audit it.
cmd_oletools() {
    parse_kv "$@"
    require_arg path "$_path"
    if [ ! -f "$_path" ]; then
        err input_missing "no such file: $_path"
    fi
    raw=$(olemeta "$_path" 2>&1 || true)
    jq -Rn --arg raw "$raw" --arg path "$_path" '{
        path: $path,
        raw: $raw
    }'
}

cmd_holehe() {
    parse_kv "$@"
    require_arg email "$_email"
    # holehe --no-clear --only-used streams plain text; we capture and
    # post-process into JSON so the caller has a single contract.
    raw=$(holehe --no-clear --only-used "$_email" 2>&1 || true)
    jq -Rn --arg raw "$raw" --arg email "$_email" '{
        email: $email,
        raw: $raw
    }'
}

cmd_phoneinfoga() {
    parse_kv "$@"
    require_arg phone "$_phone"
    if ! command -v phoneinfoga >/dev/null 2>&1; then
        err unsupported_arch "phoneinfoga is not available on this architecture"
    fi
    phoneinfoga scan -n "$_phone" --output json 2>/dev/null \
        || err tool_failed "phoneinfoga scan failed"
}

cmd_subfinder() {
    parse_kv "$@"
    require_arg domain "$_domain"
    # -silent suppresses banner; -json emits one JSON object per line, so
    # collect into an array.
    subfinder -d "$_domain" -silent -json 2>/dev/null \
        | jq -s --arg domain "$_domain" '{domain: $domain, subdomains: .}'
}

cmd_katana() {
    parse_kv "$@"
    require_arg url "$_url"
    katana -u "$_url" -silent -jsonl 2>/dev/null \
        | jq -s --arg url "$_url" '{seed: $url, urls: .}'
}

main() {
    if [ $# -eq 0 ]; then
        err invalid_args "no subcommand given"
    fi
    sub="$1"; shift
    case "$sub" in
        extract)      cmd_extract "$@" ;;
        pdfid)        cmd_pdfid "$@" ;;
        oletools)     cmd_oletools "$@" ;;
        strip)        cmd_strip "$@" ;;
        holehe)       cmd_holehe "$@" ;;
        phoneinfoga)  cmd_phoneinfoga "$@" ;;
        subfinder)    cmd_subfinder "$@" ;;
        katana)       cmd_katana "$@" ;;
        --help|-h|help)
            cat <<'USAGE'
recon-toolkit subcommands:
  extract      --path <p> --mime <m>
  pdfid        --path <p>
  oletools     --path <p>
  strip        --path <p> --mime <m>
  holehe       --email <e>
  phoneinfoga  --phone <p>
  subfinder    --domain <d>
  katana       --url <u>
USAGE
            ;;
        *) err invalid_args "unknown subcommand: $sub" ;;
    esac
}

main "$@"
