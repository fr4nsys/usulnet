// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ReportFormat represents the format of a security report
type ReportFormat string

const (
	ReportFormatJSON     ReportFormat = "json"
	ReportFormatHTML     ReportFormat = "html"
	ReportFormatMarkdown ReportFormat = "markdown"
	ReportFormatText     ReportFormat = "text"
)

// ReportOptions holds options for report generation
type ReportOptions struct {
	Format          ReportFormat
	IncludeDetails  bool // Include full issue details
	IncludeTrends   bool // Include historical trends
	GroupByCategory bool // Group issues by category
	GroupBySeverity bool // Group issues by severity
	MinSeverity     models.IssueSeverity // Minimum severity to include
}

// DefaultReportOptions returns the default report options
func DefaultReportOptions() *ReportOptions {
	return &ReportOptions{
		Format:          ReportFormatJSON,
		IncludeDetails:  true,
		IncludeTrends:   false,
		GroupBySeverity: true,
		MinSeverity:     models.IssueSeverityLow,
	}
}

// ReportGenerator generates security reports
type ReportGenerator struct {
	templates map[ReportFormat]*template.Template
}

// NewReportGenerator creates a new report generator
func NewReportGenerator() *ReportGenerator {
	g := &ReportGenerator{
		templates: make(map[ReportFormat]*template.Template),
	}

	// Initialize templates
	g.initTemplates()

	return g
}

// Generate generates a security report
func (g *ReportGenerator) Generate(ctx context.Context, data *ReportData, opts *ReportOptions) ([]byte, error) {
	if opts == nil {
		opts = DefaultReportOptions()
	}

	// Filter issues by severity
	data = g.filterBySeverity(data, opts.MinSeverity)

	switch opts.Format {
	case ReportFormatJSON:
		return g.generateJSON(data)
	case ReportFormatHTML:
		return g.generateHTML(data)
	case ReportFormatMarkdown:
		return g.generateMarkdown(data)
	case ReportFormatText:
		return g.generateText(data)
	default:
		return g.generateJSON(data)
	}
}

// ReportData holds all data for a security report
type ReportData struct {
	// Report metadata
	ID          uuid.UUID `json:"id"`
	GeneratedAt time.Time `json:"generated_at"`
	Title       string    `json:"title"`

	// Scope
	HostID   *uuid.UUID `json:"host_id,omitempty"`
	HostName string     `json:"host_name,omitempty"`

	// Summary statistics
	TotalContainers   int     `json:"total_containers"`
	ScannedContainers int     `json:"scanned_containers"`
	AverageScore      float64 `json:"average_score"`
	LowestScore       int     `json:"lowest_score"`
	HighestScore      int     `json:"highest_score"`

	// Grade distribution
	GradeDistribution map[models.SecurityGrade]int `json:"grade_distribution"`

	// Issue summary
	TotalIssues   int                          `json:"total_issues"`
	SeverityCounts map[models.IssueSeverity]int `json:"severity_counts"`

	// Container details
	Containers []ContainerReportData `json:"containers"`

	// Top issues across all containers
	TopIssues []IssueReportData `json:"top_issues"`

	// Trends (if available)
	Trends *TrendsData `json:"trends,omitempty"`
}

// ContainerReportData holds data for a single container in a report
type ContainerReportData struct {
	ContainerID   string               `json:"container_id"`
	ContainerName string               `json:"container_name"`
	Image         string               `json:"image"`
	Score         int                  `json:"score"`
	Grade         models.SecurityGrade `json:"grade"`
	GradeColor    string               `json:"grade_color"`
	IssueCount    int                  `json:"issue_count"`
	CriticalCount int                  `json:"critical_count"`
	HighCount     int                  `json:"high_count"`
	MediumCount   int                  `json:"medium_count"`
	LowCount      int                  `json:"low_count"`
	Issues        []IssueReportData    `json:"issues,omitempty"`
	ScannedAt     time.Time            `json:"scanned_at"`
}

// IssueReportData holds data for a single issue in a report
type IssueReportData struct {
	ID             string               `json:"id"`
	ContainerName  string               `json:"container_name"`
	Severity       models.IssueSeverity `json:"severity"`
	SeverityColor  string               `json:"severity_color"`
	Category       models.IssueCategory `json:"category"`
	Title          string               `json:"title"`
	Description    string               `json:"description"`
	Recommendation string               `json:"recommendation"`
	FixCommand     string               `json:"fix_command,omitempty"`
	DocURL         string               `json:"doc_url,omitempty"`
	CVEID          string               `json:"cve_id,omitempty"`
	CVSSScore      float64              `json:"cvss_score,omitempty"`
}

// TrendsData holds historical trend data
type TrendsData struct {
	Period        string      `json:"period"`
	AverageScores []DataPoint `json:"average_scores"`
	IssueCounts   []DataPoint `json:"issue_counts"`
	Improvement   float64     `json:"improvement_percent"`
}

// DataPoint represents a data point in a trend
type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// filterBySeverity filters report data by minimum severity
func (g *ReportGenerator) filterBySeverity(data *ReportData, minSeverity models.IssueSeverity) *ReportData {
	severityOrder := map[models.IssueSeverity]int{
		models.IssueSeverityCritical: 5,
		models.IssueSeverityHigh:     4,
		models.IssueSeverityMedium:   3,
		models.IssueSeverityLow:      2,
		models.IssueSeverityInfo:     1,
	}

	minOrder := severityOrder[minSeverity]

	// Filter top issues
	var filteredTopIssues []IssueReportData
	for _, issue := range data.TopIssues {
		if severityOrder[issue.Severity] >= minOrder {
			filteredTopIssues = append(filteredTopIssues, issue)
		}
	}
	data.TopIssues = filteredTopIssues

	// Filter container issues
	for i := range data.Containers {
		var filteredIssues []IssueReportData
		for _, issue := range data.Containers[i].Issues {
			if severityOrder[issue.Severity] >= minOrder {
				filteredIssues = append(filteredIssues, issue)
			}
		}
		data.Containers[i].Issues = filteredIssues
	}

	return data
}

// generateJSON generates a JSON report
func (g *ReportGenerator) generateJSON(data *ReportData) ([]byte, error) {
	return json.MarshalIndent(data, "", "  ")
}

// generateText generates a plain text report
func (g *ReportGenerator) generateText(data *ReportData) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString("=" + strings.Repeat("=", 60) + "\n")
	buf.WriteString(fmt.Sprintf(" SECURITY REPORT: %s\n", data.Title))
	buf.WriteString(fmt.Sprintf(" Generated: %s\n", data.GeneratedAt.Format(time.RFC1123)))
	buf.WriteString("=" + strings.Repeat("=", 60) + "\n\n")

	// Summary
	buf.WriteString("SUMMARY\n")
	buf.WriteString(strings.Repeat("-", 40) + "\n")
	buf.WriteString(fmt.Sprintf("Total Containers:   %d\n", data.TotalContainers))
	buf.WriteString(fmt.Sprintf("Scanned:            %d\n", data.ScannedContainers))
	buf.WriteString(fmt.Sprintf("Average Score:      %.1f\n", data.AverageScore))
	buf.WriteString(fmt.Sprintf("Score Range:        %d - %d\n", data.LowestScore, data.HighestScore))
	buf.WriteString(fmt.Sprintf("Total Issues:       %d\n", data.TotalIssues))
	buf.WriteString("\n")

	// Grade Distribution
	buf.WriteString("GRADE DISTRIBUTION\n")
	buf.WriteString(strings.Repeat("-", 40) + "\n")
	for _, grade := range []models.SecurityGrade{
		models.SecurityGradeA,
		models.SecurityGradeB,
		models.SecurityGradeC,
		models.SecurityGradeD,
		models.SecurityGradeF,
	} {
		count := data.GradeDistribution[grade]
		bar := strings.Repeat("█", count)
		buf.WriteString(fmt.Sprintf("  %s: %3d %s\n", grade, count, bar))
	}
	buf.WriteString("\n")

	// Severity Counts
	buf.WriteString("ISSUES BY SEVERITY\n")
	buf.WriteString(strings.Repeat("-", 40) + "\n")
	buf.WriteString(fmt.Sprintf("  Critical: %d\n", data.SeverityCounts[models.IssueSeverityCritical]))
	buf.WriteString(fmt.Sprintf("  High:     %d\n", data.SeverityCounts[models.IssueSeverityHigh]))
	buf.WriteString(fmt.Sprintf("  Medium:   %d\n", data.SeverityCounts[models.IssueSeverityMedium]))
	buf.WriteString(fmt.Sprintf("  Low:      %d\n", data.SeverityCounts[models.IssueSeverityLow]))
	buf.WriteString("\n")

	// Top Issues
	if len(data.TopIssues) > 0 {
		buf.WriteString("TOP ISSUES\n")
		buf.WriteString(strings.Repeat("-", 40) + "\n")
		for i, issue := range data.TopIssues {
			if i >= 10 {
				break
			}
			buf.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, issue.Severity, issue.Title))
			buf.WriteString(fmt.Sprintf("   Container: %s\n", issue.ContainerName))
			buf.WriteString(fmt.Sprintf("   %s\n\n", issue.Description))
		}
	}

	// Container Details
	buf.WriteString("CONTAINER DETAILS\n")
	buf.WriteString(strings.Repeat("-", 40) + "\n")

	// Sort by score ascending (worst first)
	containers := make([]ContainerReportData, len(data.Containers))
	copy(containers, data.Containers)
	sort.Slice(containers, func(i, j int) bool {
		return containers[i].Score < containers[j].Score
	})

	for _, c := range containers {
		buf.WriteString(fmt.Sprintf("\n%s (Grade: %s, Score: %d)\n",
			c.ContainerName, c.Grade, c.Score))
		buf.WriteString(fmt.Sprintf("  Image: %s\n", c.Image))
		buf.WriteString(fmt.Sprintf("  Issues: %d (C:%d H:%d M:%d L:%d)\n",
			c.IssueCount, c.CriticalCount, c.HighCount, c.MediumCount, c.LowCount))
	}

	return buf.Bytes(), nil
}

// generateMarkdown generates a Markdown report
func (g *ReportGenerator) generateMarkdown(data *ReportData) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("# Security Report: %s\n\n", data.Title))
	buf.WriteString(fmt.Sprintf("*Generated: %s*\n\n", data.GeneratedAt.Format(time.RFC1123)))

	// Summary
	buf.WriteString("## Summary\n\n")
	buf.WriteString("| Metric | Value |\n")
	buf.WriteString("|--------|-------|\n")
	buf.WriteString(fmt.Sprintf("| Total Containers | %d |\n", data.TotalContainers))
	buf.WriteString(fmt.Sprintf("| Scanned | %d |\n", data.ScannedContainers))
	buf.WriteString(fmt.Sprintf("| Average Score | %.1f |\n", data.AverageScore))
	buf.WriteString(fmt.Sprintf("| Total Issues | %d |\n", data.TotalIssues))
	buf.WriteString("\n")

	// Grade Distribution
	buf.WriteString("## Grade Distribution\n\n")
	buf.WriteString("| Grade | Count | Description |\n")
	buf.WriteString("|-------|-------|-------------|\n")
	for _, grade := range []models.SecurityGrade{
		models.SecurityGradeA,
		models.SecurityGradeB,
		models.SecurityGradeC,
		models.SecurityGradeD,
		models.SecurityGradeF,
	} {
		count := data.GradeDistribution[grade]
		desc := GetGradeDescription(grade)
		buf.WriteString(fmt.Sprintf("| %s | %d | %s |\n", grade, count, desc))
	}
	buf.WriteString("\n")

	// Severity Summary
	buf.WriteString("## Issues by Severity\n\n")
	buf.WriteString("| Severity | Count |\n")
	buf.WriteString("|----------|-------|\n")
	buf.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", data.SeverityCounts[models.IssueSeverityCritical]))
	buf.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", data.SeverityCounts[models.IssueSeverityHigh]))
	buf.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", data.SeverityCounts[models.IssueSeverityMedium]))
	buf.WriteString(fmt.Sprintf("| 🔵 Low | %d |\n", data.SeverityCounts[models.IssueSeverityLow]))
	buf.WriteString("\n")

	// Top Issues
	if len(data.TopIssues) > 0 {
		buf.WriteString("## Top Issues\n\n")
		for i, issue := range data.TopIssues {
			if i >= 10 {
				break
			}
			emoji := severityEmoji(issue.Severity)
			buf.WriteString(fmt.Sprintf("### %d. %s %s\n\n", i+1, emoji, issue.Title))
			buf.WriteString(fmt.Sprintf("- **Container:** %s\n", issue.ContainerName))
			buf.WriteString(fmt.Sprintf("- **Severity:** %s\n", issue.Severity))
			buf.WriteString(fmt.Sprintf("- **Category:** %s\n", issue.Category))
			buf.WriteString(fmt.Sprintf("\n%s\n\n", issue.Description))
			if issue.Recommendation != "" {
				buf.WriteString(fmt.Sprintf("**Recommendation:** %s\n\n", issue.Recommendation))
			}
			if issue.FixCommand != "" {
				buf.WriteString("```bash\n")
				buf.WriteString(issue.FixCommand + "\n")
				buf.WriteString("```\n\n")
			}
		}
	}

	// Container Summary Table
	buf.WriteString("## Container Scores\n\n")
	buf.WriteString("| Container | Image | Grade | Score | Issues |\n")
	buf.WriteString("|-----------|-------|-------|-------|--------|\n")

	// Sort by score
	containers := make([]ContainerReportData, len(data.Containers))
	copy(containers, data.Containers)
	sort.Slice(containers, func(i, j int) bool {
		return containers[i].Score < containers[j].Score
	})

	for _, c := range containers {
		buf.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %d |\n",
			c.ContainerName, truncateString(c.Image, 30), c.Grade, c.Score, c.IssueCount))
	}

	return buf.Bytes(), nil
}

// generateHTML generates an HTML report
func (g *ReportGenerator) generateHTML(data *ReportData) ([]byte, error) {
	tmpl := g.templates[ReportFormatHTML]
	if tmpl == nil {
		// Fallback to basic HTML
		return g.generateBasicHTML(data)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// generateBasicHTML generates a professional HTML security report
func (g *ReportGenerator) generateBasicHTML(data *ReportData) ([]byte, error) {
	var buf bytes.Buffer

	// Sort containers by score (worst first)
	containers := make([]ContainerReportData, len(data.Containers))
	copy(containers, data.Containers)
	sort.Slice(containers, func(i, j int) bool {
		return containers[i].Score < containers[j].Score
	})

	criticalCount := data.SeverityCounts[models.IssueSeverityCritical]
	highCount := data.SeverityCounts[models.IssueSeverityHigh]
	mediumCount := data.SeverityCounts[models.IssueSeverityMedium]
	lowCount := data.SeverityCounts[models.IssueSeverityLow]

	buf.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
`)
	buf.WriteString(fmt.Sprintf("<title>Security Report - %s</title>\n", data.Title))
	buf.WriteString(`<style>
:root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --accent: #ff6b35; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 32px 24px; }
.header { text-align: center; margin-bottom: 40px; padding-bottom: 32px; border-bottom: 1px solid var(--border); }
.header h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
.header .subtitle { color: var(--muted); font-size: 14px; }
.header .logo { display: inline-flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.header .logo-icon { width: 40px; height: 40px; background: linear-gradient(135deg, #ff6b35, #e55a2b); border-radius: 12px; display: flex; align-items: center; justify-content: center; color: #000; font-weight: 800; font-size: 18px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }
.stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }
.stat-card .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
.stat-card .value { font-size: 28px; font-weight: 700; }
.stat-card .detail { font-size: 12px; color: var(--muted); margin-top: 4px; }
.section { margin-bottom: 32px; }
.section-title { font-size: 18px; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
.section-title .icon { width: 28px; height: 28px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; font-size: 13px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
table { width: 100%; border-collapse: collapse; }
th { background: rgba(255,255,255,0.03); padding: 12px 16px; text-align: left; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; border-bottom: 1px solid var(--border); }
td { padding: 12px 16px; border-bottom: 1px solid var(--border); font-size: 14px; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,0.02); }
.grade { display: inline-flex; align-items: center; justify-content: center; width: 32px; height: 32px; border-radius: 8px; font-weight: 700; font-size: 16px; }
.grade-A { background: rgba(34,197,94,0.15); color: #22c55e; }
.grade-B { background: rgba(132,204,22,0.15); color: #84cc16; }
.grade-C { background: rgba(234,179,8,0.15); color: #eab308; }
.grade-D { background: rgba(249,115,22,0.15); color: #f97316; }
.grade-F { background: rgba(239,68,68,0.15); color: #ef4444; }
.severity { display: inline-block; padding: 2px 10px; border-radius: 9999px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
.severity-critical { background: rgba(220,38,38,0.15); color: #ef4444; }
.severity-high { background: rgba(234,88,12,0.15); color: #f97316; }
.severity-medium { background: rgba(202,138,4,0.15); color: #eab308; }
.severity-low { background: rgba(37,99,235,0.15); color: #60a5fa; }
.severity-info { background: rgba(107,114,128,0.15); color: #9ca3af; }
.bar { display: flex; height: 8px; border-radius: 4px; overflow: hidden; background: rgba(255,255,255,0.05); }
.bar-segment { height: 100%; }
.bar-critical { background: #ef4444; }
.bar-high { background: #f97316; }
.bar-medium { background: #eab308; }
.bar-low { background: #60a5fa; }
.score-ring { display: inline-flex; align-items: center; justify-content: center; width: 56px; height: 56px; border-radius: 50%; border: 3px solid; font-size: 20px; font-weight: 700; }
.issue-card { padding: 16px; border-bottom: 1px solid var(--border); }
.issue-card:last-child { border-bottom: none; }
.issue-title { font-size: 14px; font-weight: 600; margin-bottom: 6px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.issue-desc { font-size: 13px; color: var(--muted); margin-bottom: 8px; }
.issue-meta { display: flex; gap: 16px; flex-wrap: wrap; font-size: 12px; color: var(--muted); }
.issue-meta span { display: inline-flex; align-items: center; gap: 4px; }
.cve-badge { display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; font-family: monospace; background: rgba(255,107,53,0.15); color: #ff6b35; }
.cvss { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
.cvss-critical { background: rgba(220,38,38,0.2); color: #ef4444; }
.cvss-high { background: rgba(234,88,12,0.2); color: #f97316; }
.cvss-medium { background: rgba(202,138,4,0.2); color: #eab308; }
.cvss-low { background: rgba(37,99,235,0.2); color: #60a5fa; }
.fix-cmd { background: rgba(255,255,255,0.05); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; color: #7ee787; margin-top: 8px; word-break: break-all; }
.recommendation { background: rgba(34,197,94,0.08); border-left: 3px solid #22c55e; padding: 8px 12px; font-size: 13px; color: #7ee787; margin-top: 8px; border-radius: 0 6px 6px 0; }
.empty { padding: 40px; text-align: center; color: var(--muted); }
.footer { text-align: center; padding: 24px 0; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 40px; }
@media print { body { background: #fff; color: #1a1a1a; } .card, .stat-card { border-color: #e5e7eb; background: #fff; } th { background: #f9fafb; } .header { border-color: #e5e7eb; } td { border-color: #e5e7eb; } }
@media (max-width: 768px) { .grid { grid-template-columns: repeat(2, 1fr); } .container { padding: 16px; } }
</style>
</head>
<body>
<div class="container">
`)

	// Header
	buf.WriteString(`<div class="header">
<div class="logo"><div class="logo-icon">U</div><span style="font-size:20px;font-weight:700">usulnet</span></div>
`)
	buf.WriteString(fmt.Sprintf("<h1>%s</h1>\n", data.Title))
	buf.WriteString(fmt.Sprintf("<div class=\"subtitle\">Generated on %s</div>\n", data.GeneratedAt.Format("January 2, 2006 at 15:04 UTC")))
	buf.WriteString("</div>\n")

	// Summary Stats Grid
	buf.WriteString("<div class=\"grid\">\n")

	// Average Score
	scoreColor := "#22c55e"
	if data.AverageScore < 50 {
		scoreColor = "#ef4444"
	} else if data.AverageScore < 70 {
		scoreColor = "#f97316"
	} else if data.AverageScore < 85 {
		scoreColor = "#eab308"
	}
	buf.WriteString(fmt.Sprintf(`<div class="stat-card"><div class="label">Average Score</div><div class="score-ring" style="border-color:%s;color:%s">%.0f</div><div class="detail">Range: %d - %d</div></div>`, scoreColor, scoreColor, data.AverageScore, data.LowestScore, data.HighestScore))

	buf.WriteString(fmt.Sprintf(`<div class="stat-card"><div class="label">Containers Scanned</div><div class="value">%d</div><div class="detail">of %d total</div></div>`, data.ScannedContainers, data.TotalContainers))

	buf.WriteString(fmt.Sprintf(`<div class="stat-card"><div class="label">Total Issues</div><div class="value">%d</div><div class="detail">across all containers</div></div>`, data.TotalIssues))

	buf.WriteString(fmt.Sprintf(`<div class="stat-card"><div class="label">Critical / High</div><div class="value" style="color:#ef4444">%d / %d</div><div class="detail">require immediate attention</div></div>`, criticalCount, highCount))

	buf.WriteString("</div>\n")

	// Severity Distribution Bar
	if data.TotalIssues > 0 {
		buf.WriteString(`<div class="section"><div class="section-title">Issue Severity Distribution</div><div class="card" style="padding:20px">`)
		buf.WriteString(`<div class="bar" style="height:12px;margin-bottom:16px">`)
		total := float64(data.TotalIssues)
		if criticalCount > 0 {
			buf.WriteString(fmt.Sprintf(`<div class="bar-segment bar-critical" style="width:%.1f%%"></div>`, float64(criticalCount)/total*100))
		}
		if highCount > 0 {
			buf.WriteString(fmt.Sprintf(`<div class="bar-segment bar-high" style="width:%.1f%%"></div>`, float64(highCount)/total*100))
		}
		if mediumCount > 0 {
			buf.WriteString(fmt.Sprintf(`<div class="bar-segment bar-medium" style="width:%.1f%%"></div>`, float64(mediumCount)/total*100))
		}
		if lowCount > 0 {
			buf.WriteString(fmt.Sprintf(`<div class="bar-segment bar-low" style="width:%.1f%%"></div>`, float64(lowCount)/total*100))
		}
		buf.WriteString("</div>\n")

		buf.WriteString(`<div style="display:flex;gap:24px;flex-wrap:wrap;font-size:13px">`)
		buf.WriteString(fmt.Sprintf(`<span><span class="severity severity-critical">Critical</span> %d</span>`, criticalCount))
		buf.WriteString(fmt.Sprintf(`<span><span class="severity severity-high">High</span> %d</span>`, highCount))
		buf.WriteString(fmt.Sprintf(`<span><span class="severity severity-medium">Medium</span> %d</span>`, mediumCount))
		buf.WriteString(fmt.Sprintf(`<span><span class="severity severity-low">Low</span> %d</span>`, lowCount))
		buf.WriteString("</div></div></div>\n")
	}

	// Grade Distribution
	buf.WriteString(`<div class="section"><div class="section-title">Grade Distribution</div><div class="card" style="padding:20px">`)
	buf.WriteString(`<div style="display:flex;gap:16px;flex-wrap:wrap;justify-content:center">`)
	for _, grade := range []models.SecurityGrade{
		models.SecurityGradeA, models.SecurityGradeB, models.SecurityGradeC,
		models.SecurityGradeD, models.SecurityGradeF,
	} {
		count := data.GradeDistribution[grade]
		gradeClass := fmt.Sprintf("grade-%s", grade)
		buf.WriteString(fmt.Sprintf(`<div style="text-align:center;min-width:80px"><div class="grade %s" style="width:48px;height:48px;font-size:20px;margin:0 auto 8px">%s</div><div style="font-size:24px;font-weight:700">%d</div><div style="font-size:11px;color:var(--muted)">%s</div></div>`,
			gradeClass, grade, count, GetGradeDescription(grade)))
	}
	buf.WriteString("</div></div></div>\n")

	// Container Scores Table
	buf.WriteString(`<div class="section"><div class="section-title">Container Security Scores</div><div class="card">`)
	if len(containers) == 0 {
		buf.WriteString(`<div class="empty">No containers scanned yet</div>`)
	} else {
		buf.WriteString(`<table><thead><tr><th>Container</th><th>Image</th><th>Grade</th><th>Score</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr></thead><tbody>`)
		for _, c := range containers {
			gradeClass := fmt.Sprintf("grade-%s", c.Grade)
			buf.WriteString(fmt.Sprintf(`<tr><td><strong>%s</strong></td><td style="font-family:monospace;font-size:12px;color:var(--muted)">%s</td><td><span class="grade %s">%s</span></td><td>%d</td>`,
				c.ContainerName, truncateString(c.Image, 40), gradeClass, c.Grade, c.Score))
			buf.WriteString(fmt.Sprintf(`<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td></tr>`,
				countBadge(c.CriticalCount, "critical"), countBadge(c.HighCount, "high"),
				countBadge(c.MediumCount, "medium"), countBadge(c.LowCount, "low"), c.IssueCount))
		}
		buf.WriteString("</tbody></table>")
	}
	buf.WriteString("</div></div>\n")

	// Detailed Issues per Container
	for _, c := range containers {
		if len(c.Issues) == 0 {
			continue
		}

		// Sort issues by severity
		issues := make([]IssueReportData, len(c.Issues))
		copy(issues, c.Issues)
		sort.Slice(issues, func(i, j int) bool {
			return severityOrder(issues[i].Severity) > severityOrder(issues[j].Severity)
		})

		gradeClass := fmt.Sprintf("grade-%s", c.Grade)
		buf.WriteString(fmt.Sprintf(`<div class="section"><div class="section-title"><span class="grade %s" style="width:24px;height:24px;font-size:12px">%s</span> %s <span style="font-size:13px;color:var(--muted);font-weight:400">(%d issues)</span></div><div class="card">`,
			gradeClass, c.Grade, c.ContainerName, len(issues)))

		for _, issue := range issues {
			sevClass := fmt.Sprintf("severity-%s", issue.Severity)
			buf.WriteString(fmt.Sprintf(`<div class="issue-card"><div class="issue-title"><span class="severity %s">%s</span>%s`,
				sevClass, issue.Severity, issue.Title))

			// CVE badge
			if issue.CVEID != "" {
				buf.WriteString(fmt.Sprintf(` <a href="https://nvd.nist.gov/vuln/detail/%s" target="_blank" rel="noopener" class="cve-badge" style="text-decoration:none">%s</a>`, issue.CVEID, issue.CVEID))
			}

			// CVSS score
			if issue.CVSSScore > 0 {
				cvssClass := "cvss-low"
				if issue.CVSSScore >= 9.0 {
					cvssClass = "cvss-critical"
				} else if issue.CVSSScore >= 7.0 {
					cvssClass = "cvss-high"
				} else if issue.CVSSScore >= 4.0 {
					cvssClass = "cvss-medium"
				}
				buf.WriteString(fmt.Sprintf(` <span class="cvss %s">CVSS %.1f</span>`, cvssClass, issue.CVSSScore))
			}

			buf.WriteString("</div>\n")

			if issue.Description != "" {
				buf.WriteString(fmt.Sprintf(`<div class="issue-desc">%s</div>`, issue.Description))
			}

			buf.WriteString(`<div class="issue-meta">`)
			buf.WriteString(fmt.Sprintf(`<span>Category: %s</span>`, issue.Category))
			if issue.DocURL != "" {
				buf.WriteString(fmt.Sprintf(`<span><a href="%s" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none">Documentation</a></span>`, issue.DocURL))
			}
			buf.WriteString("</div>\n")

			if issue.Recommendation != "" {
				buf.WriteString(fmt.Sprintf(`<div class="recommendation">%s</div>`, issue.Recommendation))
			}
			if issue.FixCommand != "" {
				buf.WriteString(fmt.Sprintf(`<div class="fix-cmd">$ %s</div>`, issue.FixCommand))
			}

			buf.WriteString("</div>\n")
		}

		buf.WriteString("</div></div>\n")
	}

	// Footer
	buf.WriteString(fmt.Sprintf(`<div class="footer">Generated by usulnet Security Scanner &middot; Report ID: %s</div>`, data.ID.String()[:8]))

	buf.WriteString("</div>\n</body>\n</html>")

	return buf.Bytes(), nil
}

func countBadge(count int, severity string) string {
	if count == 0 {
		return `<span style="color:var(--muted)">0</span>`
	}
	return fmt.Sprintf(`<span class="severity severity-%s">%d</span>`, severity, count)
}

func severityOrder(s models.IssueSeverity) int {
	switch s {
	case models.IssueSeverityCritical:
		return 5
	case models.IssueSeverityHigh:
		return 4
	case models.IssueSeverityMedium:
		return 3
	case models.IssueSeverityLow:
		return 2
	default:
		return 1
	}
}

// initTemplates initializes report templates
func (g *ReportGenerator) initTemplates() {
	// Templates would be loaded from files in production
	// For now, we use the basic generators
}

// Helper functions

func severityEmoji(severity models.IssueSeverity) string {
	switch severity {
	case models.IssueSeverityCritical:
		return "🔴"
	case models.IssueSeverityHigh:
		return "🟠"
	case models.IssueSeverityMedium:
		return "🟡"
	case models.IssueSeverityLow:
		return "🔵"
	default:
		return "⚪"
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
