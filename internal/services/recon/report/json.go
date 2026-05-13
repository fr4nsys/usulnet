// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// GenerateJSON renders a Report as indented JSON. The output is the
// canonical machine-readable shape: tools that need a single
// downloadable file consume it; the API's /report.json endpoint emits
// the same bytes verbatim.
func GenerateJSON(r *Report, w io.Writer) error {
	if r == nil {
		return fmt.Errorf("report: GenerateJSON: nil report")
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("report: encode json: %w", err)
	}
	return nil
}

// groupByCategory takes a flat finding list and returns one
// ReportCategory per Finding.Category, ordered alphabetically. Inside
// each category findings are sorted by severity desc, then first_seen
// asc, then ID asc — three keys are enough to make the output
// deterministic for tests.
func groupByCategory(in []recon.Finding) []ReportCategory {
	if len(in) == 0 {
		return nil
	}
	groups := map[string][]ReportFinding{}
	highest := map[string]recon.Severity{}
	for i := range in {
		f := &in[i]
		groups[f.Category] = append(groups[f.Category], ReportFinding{
			ID:         f.ID.String(),
			Module:     f.Module,
			Severity:   f.Severity,
			Value:      f.Value,
			Source:     f.Source,
			Confidence: f.Confidence,
			FirstSeen:  f.FirstSeen.UTC(),
			LastSeen:   f.LastSeen.UTC(),
		})
		if severityRank(f.Severity) > severityRank(highest[f.Category]) {
			highest[f.Category] = f.Severity
		}
	}

	cats := make([]string, 0, len(groups))
	for k := range groups {
		cats = append(cats, k)
	}
	sort.Strings(cats)

	out := make([]ReportCategory, 0, len(cats))
	for _, cat := range cats {
		findings := groups[cat]
		sort.SliceStable(findings, func(i, j int) bool {
			ri := severityRank(findings[i].Severity)
			rj := severityRank(findings[j].Severity)
			if ri != rj {
				return ri > rj
			}
			if !findings[i].FirstSeen.Equal(findings[j].FirstSeen) {
				return findings[i].FirstSeen.Before(findings[j].FirstSeen)
			}
			return findings[i].ID < findings[j].ID
		})
		out = append(out, ReportCategory{
			Category: cat,
			Severity: highest[cat],
			Findings: findings,
		})
	}
	return out
}
