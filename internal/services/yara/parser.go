// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package yara

import (
	"bufio"
	"strings"
)

// Match is one YARA hit. Tags and Strings populate only when the
// scanner is invoked with -t and -s respectively; v1 invokes with
// -t so we capture tags but skip the string body to keep output
// volume bounded.
type Match struct {
	Rule      string   `json:"rule"`
	Namespace string   `json:"namespace,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Target    string   `json:"target"`
}

// parseYaraOutput parses the textual output of `yara` into a slice of
// matches. The default format yara emits with -t flag is:
//
//	<rule_name> [tag1,tag2] <target_path>
//
// or, without -t:
//
//	<rule_name> <target_path>
//
// Indented lines (string matches when invoked with -s) and blank
// lines are skipped — they belong to context, not to a new match.
//
// The function is forgiving: rows it cannot parse are dropped rather
// than failing the scan. yara emits the occasional warning to stdout
// that we don't want to surface as a "match".
func parseYaraOutput(raw string, scannedPath string) []Match {
	out := make([]Match, 0)
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '0' {
			// Empty, indented (string body), or `0x...:$var:` lines.
			continue
		}
		m, ok := parseMatchLine(line, scannedPath)
		if !ok {
			continue
		}
		out = append(out, m)
	}
	return out
}

// parseMatchLine parses a single non-indented yara output line.
// Returns (zero, false) when the line doesn't look like a match
// header.
func parseMatchLine(line, scannedPath string) (Match, bool) {
	// Strip a leading "rule_name" token. yara guarantees the rule
	// name has no whitespace.
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Match{}, false
	}
	m := Match{Rule: fields[0], Target: scannedPath}

	// Tags arrive bracketed like [reverse_shell,credential_access].
	idx := 1
	if strings.HasPrefix(fields[idx], "[") && strings.HasSuffix(fields[idx], "]") {
		tagStr := strings.TrimSuffix(strings.TrimPrefix(fields[idx], "["), "]")
		if tagStr != "" {
			m.Tags = strings.Split(tagStr, ",")
		}
		idx++
	}

	// Whatever remains is the path. yara never embeds spaces in the
	// path it reports — it echoes back the argv path verbatim — so we
	// can rejoin without worrying about quoting.
	if idx >= len(fields) {
		return Match{}, false
	}
	m.Target = strings.Join(fields[idx:], " ")
	// When the rule was authored inside a namespace, yara prints
	// "<namespace>:<rule>" instead of "<rule>". Split here so the
	// API contract stays clean.
	if colon := strings.Index(m.Rule, ":"); colon > 0 {
		m.Namespace = m.Rule[:colon]
		m.Rule = m.Rule[colon+1:]
	}
	return m, true
}
