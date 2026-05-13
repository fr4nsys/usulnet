// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package recon

import (
	"context"
	"strings"
	"testing"
)

func TestFindingsTable_Empty(t *testing.T) {
	var buf strings.Builder
	if err := FindingsTable(nil).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No findings match") {
		t.Errorf("expected empty-state message, got %q", out)
	}
}

func TestFindingsTable_WithRows(t *testing.T) {
	rows := []FindingRow{
		{
			ID:         "abc",
			Module:     "hibp",
			Category:   "breach",
			Severity:   "high",
			Value:      "alice@example.com",
			Confidence: 80,
			FirstSeen:  "2026-05-01 10:00",
		},
		{
			ID:        "def",
			Module:    "subfinder",
			Category:  "subdomain",
			Severity:  "info",
			Value:     "api.example.com",
			FirstSeen: "2026-05-02 11:00",
		},
	}
	var buf strings.Builder
	if err := FindingsTable(rows).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"hibp", "alice@example.com", "subfinder", "api.example.com", "high", "info"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing %q\n---\n%s", want, out)
		}
	}
}

func TestScanProgress_RendersStatusAndPct(t *testing.T) {
	data := ScanProgressData{
		ScanID:   "abc",
		Status:   "running",
		Progress: 73,
		Engine:   "spiderfoot",
	}
	var buf strings.Builder
	if err := ScanProgress(data).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "running") || !strings.Contains(out, "73%") || !strings.Contains(out, "spiderfoot") {
		t.Errorf("missing expected fields in rendered partial:\n%s", out)
	}
}
