// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package report produces per-scan recon reports. v26.5.1 ships JSON,
// CSV and PDF generators; each is a pure-Go function that consumes a
// *Report and writes to an io.Writer.
//
// The package is deliberately handler-agnostic so reports can also be
// rendered by CLI tooling or scheduled workers without dragging in the
// HTTP layer.
package report

import (
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// Report is the in-memory shape every generator consumes. It is
// produced once and rendered to JSON / CSV / PDF — so the data
// surfaces are identical across formats (no JSON-only fields).
type Report struct {
	ScanID      uuid.UUID        `json:"scan_id"`
	Target      ReportTarget     `json:"target"`
	Profile     ReportProfile    `json:"profile"`
	Summary     ReportSummary    `json:"summary"`
	Categories  []ReportCategory `json:"categories"`
	GeneratedAt time.Time        `json:"generated_at"`
}

// ReportTarget is the subset of the recon.Target safe to embed in a
// report. The raw value is included because the report is consumed
// by the operator who already owns the target — but the value_hash is
// dropped (it would leak nothing useful here and only confuses the
// reader).
type ReportTarget struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
}

// ReportProfile is the subset of recon.Profile a report needs.
type ReportProfile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Modules     []string `json:"modules,omitempty"`
}

// ReportSummary embeds the ScanSummary aggregated counts and grade.
// The correlations field is dropped from CSV but preserved in JSON
// (correlation rows are deeply nested by nature).
type ReportSummary struct {
	Counts       map[string]int   `json:"counts,omitempty"`
	Grade        string           `json:"grade,omitempty"`
	Correlations []map[string]any `json:"correlations,omitempty"`
	Total        int              `json:"total"`
}

// ReportCategory groups findings by Finding.Category. The grouping
// happens once, in Build, so every generator sees the same ordering.
type ReportCategory struct {
	Category string          `json:"category"`
	Severity recon.Severity  `json:"highest_severity"`
	Findings []ReportFinding `json:"findings"`
}

// ReportFinding is the per-row shape rendered into JSON and CSV.
// RawPayload is intentionally absent — raw payloads live in
// recon_findings_raw and are encrypted at rest; surfacing them in a
// downloadable report would defeat the encryption-at-rest control.
type ReportFinding struct {
	ID         string         `json:"id"`
	Module     string         `json:"module"`
	Severity   recon.Severity `json:"severity"`
	Value      string         `json:"value"`
	Source     string         `json:"source,omitempty"`
	Confidence int            `json:"confidence"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
}

// Build assembles a Report from the inputs the handler already has
// in hand: the scan/target/profile rows, the ScanSummary, and the
// flat findings list. The function is deterministic — same inputs
// produce identical bytes — so test fixtures can byte-compare the
// JSON output.
func Build(
	scan *recon.Scan,
	target *recon.Target,
	profile *recon.Profile,
	summary *recon.ScanSummary,
	findings []recon.Finding,
	now time.Time,
) *Report {
	r := &Report{
		ScanID:      scanID(scan),
		Target:      buildTarget(target),
		Profile:     buildProfile(profile),
		Summary:     buildSummary(summary, findings),
		Categories:  groupByCategory(findings),
		GeneratedAt: now.UTC(),
	}
	return r
}

func scanID(s *recon.Scan) uuid.UUID {
	if s == nil {
		return uuid.Nil
	}
	return s.ID
}

func buildTarget(t *recon.Target) ReportTarget {
	if t == nil {
		return ReportTarget{}
	}
	return ReportTarget{
		ID:    t.ID.String(),
		Type:  string(t.Type),
		Value: t.Value,
		Label: t.Label,
	}
}

func buildProfile(p *recon.Profile) ReportProfile {
	if p == nil {
		return ReportProfile{}
	}
	return ReportProfile{
		ID:          p.ID.String(),
		Name:        p.Name,
		Description: p.Description,
		Modules:     append([]string(nil), p.Modules...),
	}
}

func buildSummary(s *recon.ScanSummary, findings []recon.Finding) ReportSummary {
	out := ReportSummary{Total: len(findings)}
	if s == nil {
		return out
	}
	if len(s.Counts) > 0 {
		out.Counts = make(map[string]int, len(s.Counts))
		for k, v := range s.Counts {
			out.Counts[k] = v
		}
	}
	out.Grade = s.Grade
	if len(s.Correlations) > 0 {
		out.Correlations = append([]map[string]any(nil), s.Correlations...)
	}
	return out
}

// severityRank orders severities so groupByCategory can report the
// highest severity in each category and so CSV rows sort low→high.
func severityRank(s recon.Severity) int {
	switch s {
	case recon.SeverityCritical:
		return 4
	case recon.SeverityHigh:
		return 3
	case recon.SeverityMedium:
		return 2
	case recon.SeverityLow:
		return 1
	case recon.SeverityInfo:
		return 0
	}
	return -1
}

// AllFindings flattens a Report's grouped findings back to a single
// slice in stable order (category, then severity desc, then first_seen
// asc). Used by the CSV generator.
func (r *Report) AllFindings() []ReportFinding {
	total := 0
	for _, c := range r.Categories {
		total += len(c.Findings)
	}
	out := make([]ReportFinding, 0, total)
	for _, c := range r.Categories {
		out = append(out, c.Findings...)
	}
	return out
}
