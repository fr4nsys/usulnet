// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/services/recon"
)

func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parse uuid: %v", err)
	}
	return id
}

// sample assembles a deterministic Report so generator tests can
// byte-compare against fixtures.
func sample(t *testing.T) *Report {
	t.Helper()
	scanID := mustParseUUID(t, "11111111-1111-1111-1111-111111111111")
	targetID := mustParseUUID(t, "22222222-2222-2222-2222-222222222222")
	profileID := mustParseUUID(t, "33333333-3333-3333-3333-333333333333")
	tA := mustParseUUID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	tB := mustParseUUID(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	tC := mustParseUUID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc")
	tD := mustParseUUID(t, "dddddddd-dddd-dddd-dddd-dddddddddddd")
	ts := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)

	scan := &recon.Scan{ID: scanID, TargetID: targetID, ProfileID: profileID}
	target := &recon.Target{
		ID:    targetID,
		Type:  recon.TargetEmail,
		Value: "alice@example.com",
		Label: "primary",
	}
	profile := &recon.Profile{
		ID:          profileID,
		Name:        "email-exposure-lite",
		Description: "passive",
		Modules:     []string{"sfp_haveibeen", "toolkit:holehe"},
	}
	summary := &recon.ScanSummary{
		Counts: map[string]int{"high": 1, "medium": 1, "low": 1, "info": 1},
		Grade:  "C",
		Correlations: []map[string]any{
			{"kind": "weak_password", "modules": []string{"sfp_haveibeen", "toolkit:holehe"}},
		},
		GeneratedAt: ts,
	}
	findings := []recon.Finding{
		{
			ID: tA, ScanID: scanID, TargetID: targetID,
			Module: "sfp_haveibeen", Category: "data_breach",
			Severity: recon.SeverityHigh, Value: "Adobe",
			Source: "hibp", Confidence: 95,
			FirstSeen: ts, LastSeen: ts,
		},
		{
			ID: tB, ScanID: scanID, TargetID: targetID,
			Module: "sfp_haveibeen", Category: "data_breach",
			Severity: recon.SeverityMedium, Value: "ForumLeak",
			Source: "hibp", Confidence: 85,
			FirstSeen: ts.Add(time.Hour), LastSeen: ts.Add(time.Hour),
		},
		{
			ID: tC, ScanID: scanID, TargetID: targetID,
			Module: "toolkit:holehe", Category: "email_exposure",
			Severity: recon.SeverityMedium, Value: "site.com",
			Source: "alice@example.com", Confidence: 80,
			FirstSeen: ts, LastSeen: ts,
		},
		{
			ID: tD, ScanID: scanID, TargetID: targetID,
			Module: "sfp_gravatar", Category: "profile",
			Severity: recon.SeverityInfo, Value: "https://gravatar.com/u/abc",
			Source: "gravatar", Confidence: 50,
			FirstSeen: ts, LastSeen: ts,
		},
	}

	return Build(scan, target, profile, summary, findings, ts)
}

// ============================================================================
// Build
// ============================================================================

func TestBuild_GroupsByCategoryAndOrdersByHighestSeverity(t *testing.T) {
	r := sample(t)

	// Categories are sorted alphabetically.
	if got := []string{r.Categories[0].Category, r.Categories[1].Category, r.Categories[2].Category}; got[0] != "data_breach" || got[1] != "email_exposure" || got[2] != "profile" {
		t.Errorf("categories order = %v", got)
	}

	// First category's highest severity is high.
	if r.Categories[0].Severity != recon.SeverityHigh {
		t.Errorf("category[0].Severity = %q, want high", r.Categories[0].Severity)
	}
	// data_breach has two findings, sorted severity desc → high first.
	if r.Categories[0].Findings[0].Severity != recon.SeverityHigh ||
		r.Categories[0].Findings[1].Severity != recon.SeverityMedium {
		t.Errorf("findings not severity-sorted: %+v", r.Categories[0].Findings)
	}
}

func TestBuild_SummaryTotalIsFindingsCount(t *testing.T) {
	r := sample(t)
	if r.Summary.Total != 4 {
		t.Errorf("Summary.Total = %d, want 4", r.Summary.Total)
	}
	if r.Summary.Grade != "C" {
		t.Errorf("Summary.Grade = %q, want C", r.Summary.Grade)
	}
}

func TestBuild_NilSummaryYieldsTotal(t *testing.T) {
	r := Build(nil, nil, nil, nil, []recon.Finding{}, time.Now())
	if r.Summary.Total != 0 {
		t.Errorf("Summary.Total = %d, want 0", r.Summary.Total)
	}
	if r.Categories != nil {
		t.Errorf("Categories = %v, want nil", r.Categories)
	}
}

// ============================================================================
// JSON
// ============================================================================

func TestGenerateJSON_Roundtrip(t *testing.T) {
	r := sample(t)
	var buf bytes.Buffer
	if err := GenerateJSON(r, &buf); err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v: %s", err, buf.String())
	}
	cats, ok := decoded["categories"].([]any)
	if !ok || len(cats) != 3 {
		t.Fatalf("categories = %v", decoded["categories"])
	}
	if decoded["scan_id"] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("scan_id = %v", decoded["scan_id"])
	}
}

func TestGenerateJSON_NilReport(t *testing.T) {
	var buf bytes.Buffer
	if err := GenerateJSON(nil, &buf); err == nil {
		t.Error("expected error on nil report")
	}
}

// ============================================================================
// CSV
// ============================================================================

func TestGenerateCSV_HeaderAndRowsMatch(t *testing.T) {
	r := sample(t)
	var buf bytes.Buffer
	if err := GenerateCSV(r, &buf); err != nil {
		t.Fatalf("GenerateCSV: %v", err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if !equalSlice(rows[0], CSVHeader) {
		t.Errorf("header = %v, want %v", rows[0], CSVHeader)
	}
	if len(rows)-1 != 4 {
		t.Errorf("data rows = %d, want 4", len(rows)-1)
	}
	// First data row should be the high-severity data_breach finding.
	if rows[1][4] != "data_breach" || rows[1][6] != "high" {
		t.Errorf("first row = %v", rows[1])
	}
}

func TestGenerateCSV_EmptyReportWritesHeader(t *testing.T) {
	r := Build(nil, nil, nil, nil, nil, time.Now())
	var buf bytes.Buffer
	if err := GenerateCSV(r, &buf); err != nil {
		t.Fatalf("GenerateCSV: %v", err)
	}
	if !strings.HasPrefix(buf.String(), "scan_id,target_id") {
		t.Errorf("missing header: %q", buf.String())
	}
}

// ============================================================================
// PDF
// ============================================================================

// pdfMagic is the magic header every valid PDF file starts with. See
// the PDF 1.x spec §7.5.2 — the four ASCII bytes %PDF followed by a
// version. We do not pin the minor version because gofpdf may bump it
// across releases.
var pdfMagic = []byte("%PDF-")

func TestGeneratePDF_WritesPDFBytes(t *testing.T) {
	r := sample(t)
	var buf bytes.Buffer
	if err := GeneratePDF(r, &buf); err != nil {
		t.Fatalf("GeneratePDF: %v", err)
	}
	if buf.Len() < 200 {
		t.Errorf("PDF is suspiciously small: %d bytes", buf.Len())
	}
	if !bytes.HasPrefix(buf.Bytes(), pdfMagic) {
		t.Errorf("PDF magic missing, got prefix %q", buf.Bytes()[:8])
	}
	// gofpdf writes an EOF marker as the last non-trivial bytes.
	if !bytes.Contains(buf.Bytes(), []byte("%%EOF")) {
		t.Error("PDF tail EOF marker missing")
	}
}

func TestGeneratePDF_EmptyReportStillRenders(t *testing.T) {
	r := Build(nil, nil, nil, nil, nil, time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC))
	var buf bytes.Buffer
	if err := GeneratePDF(r, &buf); err != nil {
		t.Fatalf("GeneratePDF: %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), pdfMagic) {
		t.Errorf("PDF magic missing for empty report")
	}
}

func TestGeneratePDF_DeterministicAcrossCalls(t *testing.T) {
	// Same input → same output. gofpdf's CreationDate / ModDate are
	// pinned to r.GeneratedAt by the implementation, so two
	// back-to-back renders must produce identical bytes.
	r := sample(t)
	var a, b bytes.Buffer
	if err := GeneratePDF(r, &a); err != nil {
		t.Fatalf("first render: %v", err)
	}
	if err := GeneratePDF(r, &b); err != nil {
		t.Fatalf("second render: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Errorf("PDF bytes differ across calls (len %d vs %d)", a.Len(), b.Len())
	}
}

func TestGeneratePDF_NilReport(t *testing.T) {
	var buf bytes.Buffer
	if err := GeneratePDF(nil, &buf); err == nil {
		t.Error("expected error on nil report")
	}
}

func TestGeneratePDF_NilWriter(t *testing.T) {
	if err := GeneratePDF(sample(t), nil); err == nil {
		t.Error("expected error on nil writer")
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
