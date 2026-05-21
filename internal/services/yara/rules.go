// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package yara

import (
	"errors"
	"io/fs"
	"sort"
	"strings"

	yararules "github.com/fr4nsys/usulnet/internal/templates/yara-rules"
)

// Ruleset is one named bundle of YARA rules. Source is the raw .yar
// text; the toolkit container writes it to a tmpfs file at scan time
// so yara can read it.
type Ruleset struct {
	Name        string
	Description string
	Source      []byte
}

// ErrUnknownRuleset is returned by the service when the caller asks
// for a ruleset that is not present in the embedded library.
var ErrUnknownRuleset = errors.New("yara: unknown ruleset")

// ListRulesets returns the names of every embedded ruleset, sorted.
// The UI uses this to render the dropdown without hard-coding any
// names — adding a new .yar bundle is a one-line change.
func ListRulesets() ([]string, error) {
	entries, err := fs.ReadDir(yararules.FS, ".")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".yar") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".yar"))
	}
	sort.Strings(out)
	return out, nil
}

// LookupRuleset returns the embedded ruleset bytes for the given name.
// Names map 1:1 to the .yar file stem.
func LookupRuleset(name string) (*Ruleset, error) {
	if name == "" {
		return nil, ErrUnknownRuleset
	}
	body, err := yararules.FS.ReadFile(name + ".yar")
	if err != nil {
		return nil, ErrUnknownRuleset
	}
	return &Ruleset{
		Name:        name,
		Description: describeRuleset(body),
		Source:      body,
	}, nil
}

// describeRuleset extracts the first prose-block of top-of-file
// comment lines as a human-readable description. Falls back to an
// empty string when no comment block is present.
//
// The SPDX header at the top of every file is intentionally skipped
// by walking past the first blank line — the description starts at
// the second comment block.
func describeRuleset(body []byte) string {
	var lines []string
	for _, line := range strings.Split(string(body), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "// ") {
			lines = append(lines, strings.TrimPrefix(trim, "// "))
			continue
		}
		if trim == "//" {
			lines = append(lines, "")
			continue
		}
		if len(lines) > 0 {
			break
		}
	}
	desc := strings.TrimSpace(strings.Join(lines, "\n"))
	if idx := strings.Index(desc, "\n\n"); idx >= 0 {
		desc = strings.TrimSpace(desc[idx+2:])
	}
	if idx := strings.Index(desc, "\n\n"); idx >= 0 {
		desc = strings.TrimSpace(desc[:idx])
	}
	return desc
}
