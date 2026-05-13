// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"time"
)

// CSVHeader is the column order written by GenerateCSV. Stable — the
// E2E suite and any downstream tooling depend on these names.
var CSVHeader = []string{
	"scan_id",
	"target_id",
	"target_type",
	"target_value",
	"category",
	"module",
	"severity",
	"value",
	"source",
	"confidence",
	"first_seen",
	"last_seen",
}

// GenerateCSV renders the report's findings as a flat CSV table.
// One row per finding, sorted in the same order Report.AllFindings
// returns (category asc, then severity desc, then first_seen asc).
//
// The summary section is omitted: CSV consumers care about rows;
// JSON readers get the aggregated counts via the structured report.
func GenerateCSV(r *Report, w io.Writer) error {
	if r == nil {
		return fmt.Errorf("report: GenerateCSV: nil report")
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return fmt.Errorf("report: csv header: %w", err)
	}

	scanID := r.ScanID.String()
	targetID := r.Target.ID
	targetType := r.Target.Type
	targetValue := r.Target.Value

	for _, cat := range r.Categories {
		for _, f := range cat.Findings {
			row := []string{
				scanID,
				targetID,
				targetType,
				targetValue,
				cat.Category,
				f.Module,
				string(f.Severity),
				f.Value,
				f.Source,
				strconv.Itoa(f.Confidence),
				f.FirstSeen.UTC().Format(time.RFC3339),
				f.LastSeen.UTC().Format(time.RFC3339),
			}
			if err := cw.Write(row); err != nil {
				return fmt.Errorf("report: csv row: %w", err)
			}
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("report: csv flush: %w", err)
	}
	return nil
}
