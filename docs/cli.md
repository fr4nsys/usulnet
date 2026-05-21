# usulnet CLI Reference

> **usulnet** — Docker Management Platform
> CLI reference for the `usulnet` main binary.
> The `usulnet-agent` companion binary lives in [`docs/agents.md`](agents.md).

---

## Table of Contents

1. [Overview](#overview)
2. [Global Flags](#global-flags)
3. [Subcommands](#subcommands)
4. [Examples](#examples)
5. [Error Format](#error-format)
6. [Exit Codes](#exit-codes)
7. [`meta strip --output-file` (Migration Note)](#meta-strip---output-file-migration-note)
8. [Tab Completion](#tab-completion)

---

## Overview

The `usulnet` binary is a Cobra-based command tree. Every leaf command
has an `Example:` field — run `usulnet <cmd> --help` for the full
text. The same binary serves the API and web UI (`usulnet serve`),
runs database migrations, validates the configuration, resets the
admin password, drives the recon and metadata-hygiene workflows, and
prints build info.

Parent commands (`migrate`, `config`, `admin`, `meta`, `recon`) print
their own help when invoked without a subcommand instead of failing
with the default Cobra error. Errors from any subcommand are routed
through a single formatter that prefixes plain output with `usulnet:`
and switches to a JSON envelope under `--json` — see [Error
Format](#error-format).

---

## Global Flags

The root command registers four persistent flags. Every subcommand
inherits them.

| Flag | Short | Default | Description |
|---|---|---|---|
| `--config <path>` | `-c` | `/etc/usulnet/config.yaml` or `./config.yaml` | Config file path |
| `--output <fmt>` |  | `table` | Output format: `table\|json\|yaml`. Applied by `recon` and `meta` data output. |
| `--json` |  | `false` | Shortcut for `--output json`. Wins over an explicit `--output`. Also switches the error formatter to a JSON envelope. |
| `--quiet` | `-q` | `false` | Suppress informational lines (e.g. `stripped: foo -> bar`, `Configuration is valid`). Errors and primary data still print. |

Precedence:

- `--json` always wins over `--output`. Setting `--json --output yaml`
  produces JSON, not YAML.
- `--quiet` only silences informational summaries. It does not
  suppress the primary data output of a list/get command and does
  not suppress error lines.

The `--output` format flag is honored everywhere `recon` and `meta`
call the shared `writeView` helper (every list/get/post subcommand in
those trees). `serve`, `migrate`, `config`, `admin`, and `version`
print directly via the logger or `infof` and so honor `--quiet` but
not `--output` (their output is already plain text by design).

---

## Subcommands

### Host-side client (v26.5.2)

The CLI binary doubles as a **host-side client**: from a laptop or CI
runner, you can drive any remote usulnet installation over HTTPS
without `docker exec`. The client subcommands reuse the same
`apiclient` package the in-container `recon` / `meta` subcommands use
and share the `--output table|json|yaml` formatter.

Auth model: one or more **contexts** saved at
`~/.config/usulnet/config.yaml` (mode 0600). Mint an API key in the
web UI under **Settings → API Keys** then:

```
usulnet login https://prod.example.com:7443 --token <key>
usulnet login https://localhost:7443 --token <key> --insecure --name local
USULNET_CONTEXT=local usulnet containers ls
```

| Command | Purpose |
|---|---|
| `usulnet login URL --token KEY [--insecure] [--name NAME]` | Save credentials for a usulnet installation. |
| `usulnet logout [NAME]` | Remove a saved context (defaults to the active one). |
| `usulnet whoami` | Print the active context + the authenticated user (`/api/v1/auth/me`). |
| `usulnet contexts list` | List configured contexts; default marked with `*`. |
| `usulnet contexts use NAME` | Switch the default context. |
| `usulnet contexts rm NAME` | Remove a context. |
| `usulnet containers ls` | List containers across every attached host. |
| `usulnet images ls` | List images across every attached host. |
| `usulnet hosts ls` | List Docker hosts attached to the active installation. |
| `usulnet stacks ls` | List deployed stacks. |
| `usulnet backups ls` | List recent backups. |

Context resolution per command:

1. `$USULNET_CONTEXT` env var.
2. `default_context:` line in `~/.config/usulnet/config.yaml`.
3. The single context, if exactly one is configured.

v26.5.2 ships the **headless** `--token` login flow only. A browser
callback flow (`usulnet login URL` with no token, opens browser, mints
a key automatically) is on the v26.5.3 plan. Mutating operations
(`containers restart`, `stacks deploy`, `backups restore`, etc.) are
also v26.5.3 — this release is the read-only foundation.

### Server

| Command | Purpose |
|---|---|
| `usulnet serve` | Start the server in the configured mode |
| `usulnet version` | Print version, commit, build date, Go runtime, OS/arch |

### Database

| Command | Purpose |
|---|---|
| `usulnet migrate up` | Apply every migration not yet recorded in `schema_migrations`. Idempotent. |
| `usulnet migrate down [N]` | Roll back the last N migrations (default `1`). Destructive — `down.sql` rollbacks may discard data. |
| `usulnet migrate status` | Print one line per migration with `applied`/`pending` and `applied_at`. |

### Config & admin

| Command | Purpose |
|---|---|
| `usulnet config check` | Validate the resolved config; exits 0 if every required field is set. |
| `usulnet config show` | Print the resolved config with secrets masked. |
| `usulnet admin reset-password [NEW_PASSWORD]` | Reset (or create) the `admin` user. Default password: `usulnet`. Account is also unlocked. |

### Metadata hygiene (`meta`)

Each `meta` subcommand runs in **server mode** when `--server` is
given or `$USULNET_API_URL` is set; otherwise it runs in **local
mode** against the host Docker daemon via the recon-toolkit
container.

| Command | Purpose |
|---|---|
| `usulnet meta extract <path>` | Print EXIF / PDF / OLE metadata for one file. |
| `usulnet meta strip <path>` | Write a cleaned copy. Default destination: `<path>.stripped`. Override with `-o` / `--output-file`. |
| `usulnet meta scan <dir>` | Walk a directory and extract metadata for every file. Add `--recursive` to descend into subdirectories. |

### Recon (`recon`)

Every `recon` subcommand speaks to the running usulnet server over the
local API. Set `$USULNET_API_URL` and `$USULNET_API_TOKEN` (or pass
`--server` / `--token`) so the CLI can reach it.

| Command | Purpose |
|---|---|
| `usulnet recon target add <type> <value>` | Register a recon target (`email\|phone\|username\|domain\|ip\|ip_range`). |
| `usulnet recon target list` | List registered targets. |
| `usulnet recon target verify <id>` | Start ownership verification (default method: `rdap_match`). |
| `usulnet recon profile list` | List built-in and custom scan profiles. |
| `usulnet recon scan start <target-id> --profile <name>` | Queue a scan. Add `--watch` to stream events. |
| `usulnet recon scan list` | List recent scans. |
| `usulnet recon scan status <id>` | Show one scan's current status. |
| `usulnet recon scan cancel <id>` | Cancel a running or queued scan. |
| `usulnet recon scan report <id>` | Download a report. Format: `--format json\|csv\|pdf` (default `json`). |
| `usulnet recon findings list` | List findings. Filter via `--target <id>` and `--severity <low\|medium\|high\|critical>`. |

---

## Examples

```bash
# Apply pending migrations
usulnet migrate up

# Roll back the last 3 migrations
usulnet migrate down 3

# Show migration state — one line per file
usulnet migrate status

# Validate the configuration in CI
usulnet config check --config /etc/usulnet/config.yaml

# Print resolved config (secrets masked)
usulnet config show

# Reset admin password and unlock the account
usulnet admin reset-password 'MyNewPass123'

# Quiet JSON for scripting
usulnet --json --quiet recon target list

# Strip metadata, override the destination path
usulnet meta strip photo.jpg -o cleaned.jpg

# Scan a directory recursively, JSON to stdout
usulnet meta scan ./photos --recursive --output json

# Start a recon scan and stream events
usulnet recon scan start 11111111-1111-1111-1111-111111111111 \
  --profile default --watch

# Download a PDF report
usulnet recon scan report aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
  --format pdf > report.pdf

# Print version info
usulnet version
```

---

## Error Format

Every error that escapes `rootCmd.Execute()` is routed through one
formatter. The format depends on the resolved output mode.

### Default (plain text)

```text
$ usulnet recon target add email bad@example
usulnet: HTTP 400 /api/v1/recon/targets: invalid target value
$ echo $?
70
```

The `usulnet:` prefix is fixed; the rest of the line is the wrapped
error chain. Cobra's own "usage" dump is suppressed so a typo'd flag
prints only the error line, not the full help text.

### JSON envelope

Setting `--json` (or `--output json`) on any subcommand switches the
formatter to a single-record JSON object printed on stderr:

```text
$ usulnet --json recon target add email bad@example
{"error":"HTTP 400 /api/v1/recon/targets: invalid target value","code":70}
$ echo $?
70
```

The envelope shape is fixed: `{"error":"<string>","code":<int>}`. The
`code` field matches the process exit code. Scripts piping stderr to
a JSON consumer should always set `--json` on the invocation — the
plain `usulnet: <message>` line is not machine-parseable.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Unclassified error (fallback when no typed exit hint is set) |
| `2` | Per-file failure during `meta scan` — full report is still printed |
| `64` | Usage error — bad arguments, unknown subcommand, invalid `--output` |
| `70` | Infrastructure error — Docker unavailable, sandbox launcher failure, API 5xx |
| `71` | Server unreachable — `--server` not set or transport failed |
| `72` | Authentication error — token rejected or missing |

Codes are defined in `cmd/usulnet/recon.go` (`exitOK` …
`exitAuth`). The semantics are exercised by `cmd/usulnet/recon_test.go`
and shared across the `recon` and `meta` subtrees via the
`hasReconError` / `metaExitCode` translators.

A script can switch on the code to distinguish a usage typo (64),
an unreachable server (71), and a real API error (70) without
parsing the message.

---

## `meta strip --output-file` (Migration Note)

Prior to v26.5.2, the destination flag on `usulnet meta strip` was
named `--output`, which collided with the global `--output
table|json|yaml` format flag declared on the root command. The
destination flag is now `--output-file`. The `-o` short form is
preserved.

```bash
# Before (broken — --output had two meanings on the same line)
usulnet meta strip photo.jpg --output cleaned.jpg

# After
usulnet meta strip photo.jpg --output-file cleaned.jpg
usulnet meta strip photo.jpg -o cleaned.jpg
```

Scripts that called the old flag must update; there is no alias.

---

## Tab Completion

Both binaries auto-register a `completion <shell>` subcommand that
prints a portable completion script. Supported shells: `bash`, `zsh`,
`fish`, `powershell`.

### Recommended: `deploy/install-completions.sh`

The helper script detects the current shell, writes the right file to
the conventional path, and covers both binaries in one invocation.
Defaults to per-user paths under `$XDG_DATA_HOME` / `$XDG_CONFIG_HOME`
so no sudo is required.

```bash
# Per-user, auto-detect shell, both binaries
./deploy/install-completions.sh

# System-wide (sudo)
sudo ./deploy/install-completions.sh --system

# Override the shell (useful in scripts / CI)
./deploy/install-completions.sh --shell zsh

# Only one binary, custom path
./deploy/install-completions.sh --bin /usr/local/bin/usulnet --shell bash
```

Or via the Makefile:

```bash
make install-completions                    # per-user, auto-detect
SYSTEM=1 make install-completions           # system-wide (needs sudo)
SHELL_OVERRIDE=zsh make install-completions # force shell
```

Reload the shell (or `source` the file) after install.

### Manual install per shell

If you prefer to run the binary directly:

| Shell | Per-user path | System-wide path |
|---|---|---|
| bash | `$XDG_DATA_HOME/bash-completion/completions/usulnet` (default `~/.local/share/...`) | `/etc/bash_completion.d/usulnet` |
| zsh | `~/.local/share/zsh/site-functions/_usulnet` (add the dir to `$fpath`) | `/usr/local/share/zsh/site-functions/_usulnet` |
| fish | `$XDG_CONFIG_HOME/fish/completions/usulnet.fish` (default `~/.config/...`) | `/etc/fish/completions/usulnet.fish` |
| powershell | `$XDG_CONFIG_HOME/powershell/completions/usulnet.ps1` (source from `$PROFILE`) | `/etc/powershell/completions/usulnet.ps1` |

```bash
# bash, system-wide
sudo usulnet completion bash       > /etc/bash_completion.d/usulnet
sudo usulnet-agent completion bash > /etc/bash_completion.d/usulnet-agent

# zsh, per-user (ensure $fpath contains the directory)
usulnet completion zsh       > ~/.local/share/zsh/site-functions/_usulnet
usulnet-agent completion zsh > ~/.local/share/zsh/site-functions/_usulnet-agent

# fish
usulnet completion fish       > ~/.config/fish/completions/usulnet.fish
usulnet-agent completion fish > ~/.config/fish/completions/usulnet-agent.fish
```

Bash requires the `bash-completion` package for `complete -F`-style
loaders to work; install via your distro's package manager.

### Docker installs

Both runtime images bake the four completion scripts at
`/app/completions/{bash,zsh,fish,powershell}/<binary>`. Operators can
copy them onto the host without running the binary locally:

```bash
# usulnet (main image)
docker cp usulnet-app:/app/completions/bash/usulnet \
  /etc/bash_completion.d/usulnet

# usulnet-agent
docker cp usulnet-agent:/app/completions/bash/usulnet-agent \
  /etc/bash_completion.d/usulnet-agent
```

Or pipe the binary's output through `docker exec`:

```bash
docker exec usulnet-app /app/usulnet completion bash \
  | sudo tee /etc/bash_completion.d/usulnet > /dev/null
```

---

*Server-side REST API reference: [`docs/api.md`](api.md). Agent
binary reference: [`docs/agents.md`](agents.md). Recon module design
and threat model: [`docs/recon.md`](recon.md).*
