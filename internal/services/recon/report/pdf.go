// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"

	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// pdfPageSize is the A4 portrait layout the recon PDF uses. A4 keeps
// the document portable for both EU and US printing without an
// orientation flag.
const (
	pdfPageOrientation = "P"
	pdfPageSize        = "A4"
	pdfPageUnit        = "mm"

	pdfMarginLeft   = 15.0
	pdfMarginTop    = 15.0
	pdfMarginRight  = 15.0
	pdfMarginBottom = 18.0

	pdfHeaderFontSize = 18.0
	pdfSectionFontSize = 12.0
	pdfBodyFontSize    = 9.5

	// pdfFontFamily is bundled with gofpdf as a core PDF font, so the
	// binary needs no external font files. Adequate for an English /
	// Latin-1 report; non-Latin scripts would require a TTF embed.
	pdfFontFamily = "Helvetica"
)

// GeneratePDF renders the report as a PDF document to w. Layout:
//
//   1. Title bar (target value, scan ID, generated_at).
//   2. Profile + summary block: name, description, grade, total
//      findings, severity counts.
//   3. One section per category, listing findings as a small table
//      with a coloured severity cell so a reader scanning the page
//      can spot the high/critical rows immediately.
//
// The output is deterministic for the same Report value: gofpdf's
// CreationDate / ModDate are pinned to r.GeneratedAt and no
// engine-side randomness sneaks in.
func GeneratePDF(r *Report, w io.Writer) error {
	if r == nil {
		return fmt.Errorf("report: GeneratePDF: nil report")
	}
	if w == nil {
		return fmt.Errorf("report: GeneratePDF: nil writer")
	}

	pdf := gofpdf.New(pdfPageOrientation, pdfPageUnit, pdfPageSize, "")
	pdf.SetMargins(pdfMarginLeft, pdfMarginTop, pdfMarginRight)
	pdf.SetAutoPageBreak(true, pdfMarginBottom)

	// SetCatalogSort makes gofpdf emit resource catalogs in
	// alphabetical order rather than Go-map iteration order, which is
	// what lets two identical reports byte-compare equal. The cost is
	// a small sort; readers do not care.
	pdf.SetCatalogSort(true)

	// Pin the document timestamp so byte-deterministic tests work.
	// gofpdf writes both /CreationDate and /ModDate from this value.
	pdf.SetCreationDate(r.GeneratedAt.UTC())
	pdf.SetModificationDate(r.GeneratedAt.UTC())

	// usulnet branding lives in the title / producer fields so PDF
	// readers (and grep on the raw bytes) can identify the source.
	pdf.SetTitle("usulnet recon report — scan "+r.ScanID.String(), true)
	pdf.SetCreator("usulnet", true)
	pdf.SetAuthor("usulnet", true)

	pdf.AddPage()
	renderHeader(pdf, r)
	renderProfileBlock(pdf, r)
	renderSummaryBlock(pdf, r)
	renderCategories(pdf, r)

	if err := pdf.Output(w); err != nil {
		return fmt.Errorf("report: pdf output: %w", err)
	}
	return nil
}

// renderHeader writes the document title line plus the target/scan/
// timestamp triple in a compact two-line block.
func renderHeader(pdf *gofpdf.Fpdf, r *Report) {
	pdf.SetFont(pdfFontFamily, "B", pdfHeaderFontSize)
	pdf.Cell(0, 9, "usulnet — recon report")
	pdf.Ln(9)

	pdf.SetFont(pdfFontFamily, "", pdfBodyFontSize)
	pdf.SetTextColor(80, 80, 80)
	pdf.MultiCell(0, 5, fmt.Sprintf(
		"target: %s  (%s)\nscan id: %s\ngenerated: %s",
		safeText(r.Target.Value),
		safeText(r.Target.Type),
		r.ScanID.String(),
		r.GeneratedAt.UTC().Format(time.RFC3339),
	), "", "L", false)
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(3)
}

// renderProfileBlock writes the profile name + description in a small
// labelled box.
func renderProfileBlock(pdf *gofpdf.Fpdf, r *Report) {
	pdf.SetFont(pdfFontFamily, "B", pdfSectionFontSize)
	pdf.Cell(0, 7, "Profile")
	pdf.Ln(7)

	pdf.SetFont(pdfFontFamily, "", pdfBodyFontSize)
	pdf.MultiCell(0, 5, fmt.Sprintf(
		"name: %s\ndescription: %s",
		safeText(r.Profile.Name),
		safeText(defaultIfEmpty(r.Profile.Description, "(no description)")),
	), "", "L", false)
	pdf.Ln(2)
}

// renderSummaryBlock writes the grade + total + severity counts in a
// table the eye scans in one pass.
func renderSummaryBlock(pdf *gofpdf.Fpdf, r *Report) {
	pdf.SetFont(pdfFontFamily, "B", pdfSectionFontSize)
	pdf.Cell(0, 7, "Summary")
	pdf.Ln(7)

	pdf.SetFont(pdfFontFamily, "", pdfBodyFontSize)
	pdf.Cell(40, 5, fmt.Sprintf("Grade: %s", defaultIfEmpty(r.Summary.Grade, "-")))
	pdf.Cell(0, 5, fmt.Sprintf("Total findings: %d", r.Summary.Total))
	pdf.Ln(6)

	// Severity counts in a fixed order so screenshots and tests
	// always match. Zero buckets are still rendered for parity.
	severities := []recon.Severity{
		recon.SeverityCritical,
		recon.SeverityHigh,
		recon.SeverityMedium,
		recon.SeverityLow,
		recon.SeverityInfo,
	}
	for _, s := range severities {
		setSeverityFill(pdf, s)
		pdf.CellFormat(20, 6, strings.ToUpper(string(s)), "1", 0, "C", true, 0, "")
		pdf.SetFillColor(255, 255, 255)
		pdf.SetTextColor(0, 0, 0)
		pdf.CellFormat(15, 6, fmt.Sprintf("%d", r.Summary.Counts[string(s)]), "1", 0, "C", false, 0, "")
		pdf.Cell(3, 6, "")
	}
	pdf.Ln(9)
}

// renderCategories writes one block per category. Each block has a
// header row and a small finding table; gofpdf manages page breaks
// automatically thanks to SetAutoPageBreak.
func renderCategories(pdf *gofpdf.Fpdf, r *Report) {
	if len(r.Categories) == 0 {
		pdf.SetFont(pdfFontFamily, "I", pdfBodyFontSize)
		pdf.SetTextColor(120, 120, 120)
		pdf.MultiCell(0, 5, "No findings reported.", "", "L", false)
		pdf.SetTextColor(0, 0, 0)
		return
	}

	for _, cat := range r.Categories {
		pdf.SetFont(pdfFontFamily, "B", pdfSectionFontSize)
		pdf.MultiCell(0, 7, fmt.Sprintf("Category — %s (highest: %s)",
			safeText(cat.Category), strings.ToUpper(string(cat.Severity))),
			"", "L", false)

		// Findings table: severity | module | value | confidence.
		// Widths add to 180mm to fit inside the 15mm/15mm side
		// margins on A4 (210mm wide). The "value" column truncates
		// long strings — readers wanting the full value can drop the
		// JSON report.
		colW := []float64{22.0, 38.0, 90.0, 30.0}
		pdf.SetFont(pdfFontFamily, "B", pdfBodyFontSize)
		pdf.SetFillColor(230, 230, 230)
		pdf.SetTextColor(0, 0, 0)
		pdf.CellFormat(colW[0], 6, "Severity", "1", 0, "C", true, 0, "")
		pdf.CellFormat(colW[1], 6, "Module", "1", 0, "L", true, 0, "")
		pdf.CellFormat(colW[2], 6, "Value", "1", 0, "L", true, 0, "")
		pdf.CellFormat(colW[3], 6, "Confidence", "1", 0, "C", true, 0, "")
		pdf.Ln(6)

		// Stable sort within the category: severity desc, then
		// first_seen asc — matches AllFindings ordering.
		findings := append([]ReportFinding(nil), cat.Findings...)
		sort.SliceStable(findings, func(i, j int) bool {
			ri, rj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
			if ri != rj {
				return ri > rj
			}
			return findings[i].FirstSeen.Before(findings[j].FirstSeen)
		})

		pdf.SetFont(pdfFontFamily, "", pdfBodyFontSize)
		for _, f := range findings {
			setSeverityFill(pdf, f.Severity)
			pdf.CellFormat(colW[0], 6, strings.ToUpper(string(f.Severity)), "1", 0, "C", true, 0, "")
			pdf.SetFillColor(255, 255, 255)
			pdf.SetTextColor(0, 0, 0)
			pdf.CellFormat(colW[1], 6, safeText(truncate(f.Module, 28)), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colW[2], 6, safeText(truncate(f.Value, 70)), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colW[3], 6, fmt.Sprintf("%d", f.Confidence), "1", 0, "C", false, 0, "")
			pdf.Ln(6)
		}
		pdf.Ln(3)
	}
}

// setSeverityFill applies a fill colour for the severity badge cells.
// Colours are chosen for printability — they survive grayscale toner
// without all rows collapsing to the same shade. Text contrast is set
// alongside so light fills get black text and dark fills get white.
func setSeverityFill(pdf *gofpdf.Fpdf, s recon.Severity) {
	switch s {
	case recon.SeverityCritical:
		pdf.SetFillColor(140, 30, 30) // deep red
		pdf.SetTextColor(255, 255, 255)
	case recon.SeverityHigh:
		pdf.SetFillColor(210, 70, 30) // orange-red
		pdf.SetTextColor(255, 255, 255)
	case recon.SeverityMedium:
		pdf.SetFillColor(230, 170, 0) // amber
		pdf.SetTextColor(0, 0, 0)
	case recon.SeverityLow:
		pdf.SetFillColor(120, 170, 70) // muted green
		pdf.SetTextColor(0, 0, 0)
	case recon.SeverityInfo:
		pdf.SetFillColor(180, 180, 200) // light blue-grey
		pdf.SetTextColor(0, 0, 0)
	default:
		pdf.SetFillColor(220, 220, 220)
		pdf.SetTextColor(0, 0, 0)
	}
}

// safeText strips characters that gofpdf's core fonts cannot encode in
// the default Latin-1 code page. The recon module already sanitises
// engine output, but engine values can still contain stray bytes from
// scraping HTML; replacing them with '?' prevents the PDF writer from
// emitting unreadable runs.
func safeText(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t', r == '\n', r == '\r':
			b.WriteByte(' ')
		case r < 32:
			continue
		case r > 255:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// truncate caps a string at n runes, appending an ellipsis when it
// trims so the reader knows the value was cut. n includes the
// ellipsis.
func truncate(s string, n int) string {
	if n <= 1 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}

// defaultIfEmpty returns def when s is empty after trimming. Used for
// the "(no description)" placeholder so the layout never shows an
// empty colon-suffix.
func defaultIfEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
