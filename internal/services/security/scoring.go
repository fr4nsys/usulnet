// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package security

import (
	"sort"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ScoreConfig holds the penalty values for different security issues
type ScoreConfig struct {
	// Base score starts at 100
	BaseScore int

	// Individual check penalties (can be overridden)
	Penalties map[string]int

	// Severity multipliers (applied after individual penalties)
	SeverityMultipliers map[models.IssueSeverity]float64

	// Maximum penalties per category to prevent single category domination
	MaxPenaltyPerCategory map[models.IssueCategory]int

	// Minimum score (floor)
	MinScore int

	// Maximum score (ceiling)
	MaxScore int
}

// DefaultScoreConfig returns the default scoring configuration
func DefaultScoreConfig() *ScoreConfig {
	return &ScoreConfig{
		BaseScore: 100,
		MinScore:  0,
		MaxScore:  100,
		Penalties: map[string]int{
			models.CheckHealthcheck:        15,
			models.CheckRootUser:           20,
			models.CheckPrivileged:         25,
			models.CheckCapabilities:       10,
			models.CheckResourceLimits:     10,
			models.CheckReadOnlyFS:         5,
			models.CheckNetworkMode:        15,
			models.CheckPortExposure:       5,
			models.CheckPortDangerous:      10,
			models.CheckSecretsInEnv:       20,
			models.CheckImageVulnerability: 15,
			models.CheckLoggingDriver:      5,
			models.CheckRestartPolicy:      5,
		},
		SeverityMultipliers: map[models.IssueSeverity]float64{
			models.IssueSeverityCritical: 1.5,
			models.IssueSeverityHigh:     1.2,
			models.IssueSeverityMedium:   1.0,
			models.IssueSeverityLow:      0.8,
			models.IssueSeverityInfo:     0.5,
		},
		MaxPenaltyPerCategory: map[models.IssueCategory]int{
			models.IssueCategorySecurity:      60,
			models.IssueCategoryReliability:   30,
			models.IssueCategoryPerformance:   20,
			models.IssueCategoryBestPractice:  20,
			models.IssueCategoryVulnerability: 50,
		},
	}
}

// ScoreResult holds the calculated score and breakdown
type ScoreResult struct {
	// Final score (0-100)
	Score int

	// Grade (A-F)
	Grade models.SecurityGrade

	// Breakdown by category
	CategoryBreakdown map[models.IssueCategory]CategoryScore

	// Total penalties applied
	TotalPenalty int

	// Number of issues by severity
	SeverityCounts map[models.IssueSeverity]int

	// Top issues (sorted by penalty)
	TopIssues []Issue
}

// CategoryScore holds score breakdown for a category
type CategoryScore struct {
	Issues       int
	TotalPenalty int
	CappedAt     int  // If penalty was capped
	WasCapped    bool // Whether capping was applied
}

// Calculator handles security score calculation
type Calculator struct {
	config *ScoreConfig
}

// NewCalculator creates a new score calculator
func NewCalculator(config *ScoreConfig) *Calculator {
	if config == nil {
		config = DefaultScoreConfig()
	}
	return &Calculator{config: config}
}

// Calculate computes the security score from a list of issues
func (c *Calculator) Calculate(issues []Issue) *ScoreResult {
	result := &ScoreResult{
		CategoryBreakdown: make(map[models.IssueCategory]CategoryScore),
		SeverityCounts:    make(map[models.IssueSeverity]int),
		TopIssues:         make([]Issue, 0),
	}

	// Initialize category breakdown
	for _, cat := range []models.IssueCategory{
		models.IssueCategorySecurity,
		models.IssueCategoryReliability,
		models.IssueCategoryPerformance,
		models.IssueCategoryBestPractice,
		models.IssueCategoryVulnerability,
	} {
		result.CategoryBreakdown[cat] = CategoryScore{}
	}

	// Initialize severity counts
	for _, sev := range []models.IssueSeverity{
		models.IssueSeverityCritical,
		models.IssueSeverityHigh,
		models.IssueSeverityMedium,
		models.IssueSeverityLow,
		models.IssueSeverityInfo,
	} {
		result.SeverityCounts[sev] = 0
	}

	// Calculate penalties per category
	categoryPenalties := make(map[models.IssueCategory]int)

	for _, issue := range issues {
		// Count by severity
		result.SeverityCounts[issue.Severity]++

		// Get base penalty
		penalty := issue.Penalty
		if p, ok := c.config.Penalties[issue.CheckID]; ok {
			penalty = p
		}

		// Apply severity multiplier
		if multiplier, ok := c.config.SeverityMultipliers[issue.Severity]; ok {
			penalty = int(float64(penalty) * multiplier)
		}

		// Add to category
		categoryPenalties[issue.Category] += penalty

		// Update category breakdown
		cs := result.CategoryBreakdown[issue.Category]
		cs.Issues++
		cs.TotalPenalty += penalty
		result.CategoryBreakdown[issue.Category] = cs

		// Track for top issues
		issueWithPenalty := issue
		issueWithPenalty.Penalty = penalty
		result.TopIssues = append(result.TopIssues, issueWithPenalty)
	}

	// Apply category caps and calculate total
	for cat, penalty := range categoryPenalties {
		cappedPenalty := penalty
		wasCapped := false

		if maxPenalty, ok := c.config.MaxPenaltyPerCategory[cat]; ok {
			if penalty > maxPenalty {
				cappedPenalty = maxPenalty
				wasCapped = true
			}
		}

		// Update breakdown with capping info
		cs := result.CategoryBreakdown[cat]
		if wasCapped {
			cs.CappedAt = cappedPenalty
			cs.WasCapped = true
		}
		result.CategoryBreakdown[cat] = cs

		result.TotalPenalty += cappedPenalty
	}

	// Calculate final score
	result.Score = c.config.BaseScore - result.TotalPenalty

	// Apply floor and ceiling
	if result.Score < c.config.MinScore {
		result.Score = c.config.MinScore
	}
	if result.Score > c.config.MaxScore {
		result.Score = c.config.MaxScore
	}

	// Determine grade
	result.Grade = models.GradeFromScore(result.Score)

	// Sort top issues by penalty (descending)
	sort.Slice(result.TopIssues, func(i, j int) bool {
		return result.TopIssues[i].Penalty > result.TopIssues[j].Penalty
	})

	// Limit top issues to 10
	if len(result.TopIssues) > 10 {
		result.TopIssues = result.TopIssues[:10]
	}

	return result
}

// CalculateSimple computes just the score and grade without detailed breakdown
func CalculateSimple(issues []Issue) (int, models.SecurityGrade) {
	calc := NewCalculator(nil)
	result := calc.Calculate(issues)
	return result.Score, result.Grade
}

// CountIssuesBySeverity counts issues by severity level
func CountIssuesBySeverity(issues []Issue) map[models.IssueSeverity]int {
	counts := map[models.IssueSeverity]int{
		models.IssueSeverityCritical: 0,
		models.IssueSeverityHigh:     0,
		models.IssueSeverityMedium:   0,
		models.IssueSeverityLow:      0,
		models.IssueSeverityInfo:     0,
	}

	for _, issue := range issues {
		counts[issue.Severity]++
	}

	return counts
}

// FilterIssuesBySeverity returns issues at or above the given severity
func FilterIssuesBySeverity(issues []Issue, minSeverity models.IssueSeverity) []Issue {
	severityOrder := map[models.IssueSeverity]int{
		models.IssueSeverityCritical: 5,
		models.IssueSeverityHigh:     4,
		models.IssueSeverityMedium:   3,
		models.IssueSeverityLow:      2,
		models.IssueSeverityInfo:     1,
	}

	minOrder := severityOrder[minSeverity]
	var filtered []Issue

	for _, issue := range issues {
		if severityOrder[issue.Severity] >= minOrder {
			filtered = append(filtered, issue)
		}
	}

	return filtered
}

// FilterIssuesByCategory returns issues in the given category
func FilterIssuesByCategory(issues []Issue, category models.IssueCategory) []Issue {
	var filtered []Issue
	for _, issue := range issues {
		if issue.Category == category {
			filtered = append(filtered, issue)
		}
	}
	return filtered
}

// SortIssuesBySeverity sorts issues by severity (critical first)
func SortIssuesBySeverity(issues []Issue) []Issue {
	severityOrder := map[models.IssueSeverity]int{
		models.IssueSeverityCritical: 5,
		models.IssueSeverityHigh:     4,
		models.IssueSeverityMedium:   3,
		models.IssueSeverityLow:      2,
		models.IssueSeverityInfo:     1,
	}

	sorted := make([]Issue, len(issues))
	copy(sorted, issues)

	sort.Slice(sorted, func(i, j int) bool {
		return severityOrder[sorted[i].Severity] > severityOrder[sorted[j].Severity]
	})

	return sorted
}

// HasCriticalIssues returns true if there are any critical severity issues
func HasCriticalIssues(issues []Issue) bool {
	for _, issue := range issues {
		if issue.Severity == models.IssueSeverityCritical {
			return true
		}
	}
	return false
}

// HasHighOrAboveIssues returns true if there are high or critical severity issues
func HasHighOrAboveIssues(issues []Issue) bool {
	for _, issue := range issues {
		if issue.Severity == models.IssueSeverityCritical ||
			issue.Severity == models.IssueSeverityHigh {
			return true
		}
	}
	return false
}

// GetGradeDescription returns a description for a grade
func GetGradeDescription(grade models.SecurityGrade) string {
	switch grade {
	case models.SecurityGradeA:
		return "Excellent - Container follows security best practices"
	case models.SecurityGradeB:
		return "Good - Minor improvements recommended"
	case models.SecurityGradeC:
		return "Fair - Several security issues should be addressed"
	case models.SecurityGradeD:
		return "Poor - Significant security concerns"
	case models.SecurityGradeF:
		return "Critical - Immediate attention required"
	default:
		return "Unknown grade"
	}
}

// GetGradeColor returns the color code for a grade (for UI)
func GetGradeColor(grade models.SecurityGrade) string {
	switch grade {
	case models.SecurityGradeA:
		return "#22c55e" // green-500
	case models.SecurityGradeB:
		return "#84cc16" // lime-500
	case models.SecurityGradeC:
		return "#eab308" // yellow-500
	case models.SecurityGradeD:
		return "#f97316" // orange-500
	case models.SecurityGradeF:
		return "#ef4444" // red-500
	default:
		return "#6b7280" // gray-500
	}
}

// GetSeverityColor returns the color code for a severity (for UI)
func GetSeverityColor(severity models.IssueSeverity) string {
	switch severity {
	case models.IssueSeverityCritical:
		return "#dc2626" // red-600
	case models.IssueSeverityHigh:
		return "#ea580c" // orange-600
	case models.IssueSeverityMedium:
		return "#ca8a04" // yellow-600
	case models.IssueSeverityLow:
		return "#2563eb" // blue-600
	case models.IssueSeverityInfo:
		return "#6b7280" // gray-500
	default:
		return "#6b7280" // gray-500
	}
}
