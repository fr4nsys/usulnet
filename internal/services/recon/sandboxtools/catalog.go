// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package sandboxtools surfaces the recon-toolkit sandbox tool
// catalogue to the rest of the binary without requiring a live Docker
// dependency. The canonical manifest lives at
// images/recon-toolkit/tools.list and is copied into this package via
// `go generate` (and verified in lockstep by TestManifestInSync).
//
// The recon-toolkit container's own `list-tools.sh` produces the same
// catalogue augmented with pacman-reported versions for ad-hoc
// operator audits; this package returns the static names and
// categories so the web UI can render the panel at /recon/connectors
// without a Docker round-trip on every page load.
package sandboxtools

import (
	_ "embed"
	"sort"
	"strings"
)

// canonicalManifest is the embedded copy of images/recon-toolkit/tools.list.
// The Docker build COPYs the same file into the image, and
// TestManifestInSync asserts the two files do not drift.
//
//go:embed tools.list
var canonicalManifest []byte

// Tool is one entry in the sandbox tool catalogue.
type Tool struct {
	// Name is the pacman package name (e.g. "subfinder", "h8mail").
	Name string
	// Category is the section header from tools.list (e.g.
	// "osint-domain", "metadata"). Empty for the support packages
	// that ship with every Arch base.
	Category string
}

// Catalog returns the tools the recon-toolkit sandbox image exposes.
// Entries with the `# nocatalog` inline marker are omitted (these are
// support packages — coreutils, ca-certificates, etc. — that ship with
// every Arch base and are not meaningful to surface in the operator
// UI). The order is the order they appear in tools.list, which is the
// same order the smoke test probes them in.
//
// Result is computed once at package init (parseManifest runs over a
// ~1 KiB byte slice in microseconds) and returned as a fresh copy on
// every call so callers can mutate without poisoning the package
// state.
func Catalog() []Tool {
	out := make([]Tool, len(cached))
	copy(out, cached)
	return out
}

// Categories returns the distinct, alphabetically sorted set of
// categories surfaced in Catalog(). The empty category is omitted.
// Useful for grouping the tools in the /recon/connectors UI.
func Categories() []string {
	seen := make(map[string]struct{}, 8)
	for _, t := range cached {
		if t.Category != "" {
			seen[t.Category] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// cached holds the parsed catalogue. Populated by init() and read by
// Catalog() / Categories().
var cached []Tool

func init() {
	cached = parseManifest(canonicalManifest)
}

// parseManifest walks the bytes of a tools.list file and returns the
// catalogue. The rules are:
//
//   - Lines starting with `# category: <name>` set the current category
//     for every subsequent entry until the next category marker.
//   - Lines containing the literal `# nocatalog` are skipped.
//   - Other comment lines (`#`-prefixed) are skipped.
//   - The first whitespace-separated token of a non-comment line is the
//     pacman package name.
//
// Exported as a free function (not a method) so tests can exercise it
// against synthetic inputs without round-tripping through the embed.
func parseManifest(data []byte) []Tool {
	out := make([]Tool, 0, 32)
	current := ""
	for _, raw := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(raw)
		// Category marker has to be recognised before the blank/comment
		// skip below, otherwise the `# category: ...` line itself would
		// be discarded as a regular comment.
		if cat, ok := categoryFromLine(trimmed); ok {
			current = cat
			continue
		}
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "# nocatalog") {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Strip inline comments (anything after the first `#`).
		if i := strings.Index(trimmed, "#"); i >= 0 {
			trimmed = strings.TrimSpace(trimmed[:i])
		}
		// First whitespace-separated token is the package name.
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		out = append(out, Tool{Name: fields[0], Category: current})
	}
	return out
}

// categoryFromLine extracts the category name from a `# category: foo`
// comment. Returns ("", false) when the line is not a category marker.
func categoryFromLine(line string) (string, bool) {
	const marker = "# category:"
	if !strings.HasPrefix(line, marker) {
		return "", false
	}
	return strings.TrimSpace(line[len(marker):]), true
}
