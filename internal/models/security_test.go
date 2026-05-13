// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"testing"
)

// ============================================================================
// SecurityGrade
// ============================================================================

func TestSecurityGradeConstants(t *testing.T) {
	grades := []SecurityGrade{
		SecurityGradeA, SecurityGradeB, SecurityGradeC,
		SecurityGradeD, SecurityGradeF,
	}
	expected := []string{"A", "B", "C", "D", "F"}

	for i, g := range grades {
		if string(g) != expected[i] {
			t.Errorf("SecurityGrade = %q, want %q", g, expected[i])
		}
	}
}

// ============================================================================
// GradeFromScore
// ============================================================================

func TestGradeFromScore(t *testing.T) {
	tests := []struct {
		score int
		want  SecurityGrade
	}{
		{100, SecurityGradeA},
		{95, SecurityGradeA},
		{90, SecurityGradeA},
		{89, SecurityGradeB},
		{85, SecurityGradeB},
		{80, SecurityGradeB},
		{79, SecurityGradeC},
		{75, SecurityGradeC},
		{70, SecurityGradeC},
		{69, SecurityGradeD},
		{65, SecurityGradeD},
		{60, SecurityGradeD},
		{59, SecurityGradeF},
		{50, SecurityGradeF},
		{0, SecurityGradeF},
	}

	for _, tt := range tests {
		got := GradeFromScore(tt.score)
		if got != tt.want {
			t.Errorf("GradeFromScore(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

// ============================================================================
// IssueSeverity constants
// ============================================================================

func TestIssueSeverityConstants(t *testing.T) {
	severities := map[IssueSeverity]string{
		IssueSeverityCritical: "critical",
		IssueSeverityHigh:     "high",
		IssueSeverityMedium:   "medium",
		IssueSeverityLow:      "low",
		IssueSeverityInfo:     "info",
	}

	for severity, expected := range severities {
		if string(severity) != expected {
			t.Errorf("IssueSeverity = %q, want %q", severity, expected)
		}
	}
}

// ============================================================================
// IssueCategory constants
// ============================================================================

func TestIssueCategoryConstants(t *testing.T) {
	categories := map[IssueCategory]string{
		IssueCategorySecurity:      "security",
		IssueCategoryReliability:   "reliability",
		IssueCategoryPerformance:   "performance",
		IssueCategoryBestPractice:  "best_practice",
		IssueCategoryVulnerability: "vulnerability",
		IssueCategoryNetwork:       "network",
	}

	for cat, expected := range categories {
		if string(cat) != expected {
			t.Errorf("IssueCategory = %q, want %q", cat, expected)
		}
	}
}

// ============================================================================
// IssueStatus constants
// ============================================================================

func TestIssueStatusConstants(t *testing.T) {
	statuses := map[IssueStatus]string{
		IssueStatusOpen:          "open",
		IssueStatusAcknowledged:  "acknowledged",
		IssueStatusResolved:      "resolved",
		IssueStatusIgnored:       "ignored",
		IssueStatusFalsePositive: "false_positive",
	}

	for status, expected := range statuses {
		if string(status) != expected {
			t.Errorf("IssueStatus = %q, want %q", status, expected)
		}
	}
}

// ============================================================================
// DefaultSecurityChecks
// ============================================================================

func TestDefaultSecurityChecks(t *testing.T) {
	checks := DefaultSecurityChecks()

	if len(checks) == 0 {
		t.Fatal("DefaultSecurityChecks() returned empty")
	}

	// The number of default checks is allowed to grow as new ones land.
	// The check below catches a regression where the seed list is gutted
	// entirely or shrinks unexpectedly, without locking the exact count
	// (which would force a test edit every time a check is added).
	const minChecks = 13
	if len(checks) < minChecks {
		t.Errorf("DefaultSecurityChecks() count = %d, want >= %d", len(checks), minChecks)
	}

	// All checks should have required fields
	for _, check := range checks {
		if check.ID == "" {
			t.Error("check ID should not be empty")
		}
		if check.Name == "" {
			t.Errorf("check %s Name should not be empty", check.ID)
		}
		if check.Description == "" {
			t.Errorf("check %s Description should not be empty", check.ID)
		}
		if check.Category == "" {
			t.Errorf("check %s Category should not be empty", check.ID)
		}
		if check.Severity == "" {
			t.Errorf("check %s Severity should not be empty", check.ID)
		}
		if check.ScoreImpact <= 0 {
			t.Errorf("check %s ScoreImpact = %d, should be positive", check.ID, check.ScoreImpact)
		}
		if !check.IsEnabled {
			t.Errorf("check %s should be enabled by default", check.ID)
		}
	}
}

func TestDefaultSecurityChecks_ContainsKnownChecks(t *testing.T) {
	checks := DefaultSecurityChecks()
	checkIDs := make(map[string]bool)
	for _, c := range checks {
		checkIDs[c.ID] = true
	}

	expectedIDs := []string{
		CheckHealthcheck, CheckRootUser, CheckPrivileged,
		CheckCapabilities, CheckResourceLimits, CheckReadOnlyFS,
		CheckNetworkMode, CheckPortExposure, CheckPortDangerous,
		CheckSecretsInEnv, CheckImageVulnerability,
		CheckLoggingDriver, CheckRestartPolicy,
	}

	for _, id := range expectedIDs {
		if !checkIDs[id] {
			t.Errorf("DefaultSecurityChecks missing check %s", id)
		}
	}
}

func TestDefaultSecurityChecks_PrivilegedIsCritical(t *testing.T) {
	checks := DefaultSecurityChecks()
	for _, c := range checks {
		if c.ID == CheckPrivileged {
			if c.Severity != IssueSeverityCritical {
				t.Errorf("Privileged check severity = %q, want 'critical'", c.Severity)
			}
			return
		}
	}
	t.Error("Privileged check not found")
}

func TestDefaultSecurityChecks_SecretsInEnvIsHigh(t *testing.T) {
	checks := DefaultSecurityChecks()
	for _, c := range checks {
		if c.ID == CheckSecretsInEnv {
			if c.Severity != IssueSeverityHigh {
				t.Errorf("SecretsInEnv check severity = %q, want 'high'", c.Severity)
			}
			return
		}
	}
	t.Error("SecretsInEnv check not found")
}

// ============================================================================
// Security check ID constants
// ============================================================================

func TestSecurityCheckIDConstants(t *testing.T) {
	ids := []string{
		CheckHealthcheck, CheckRootUser, CheckPrivileged,
		CheckCapabilities, CheckResourceLimits, CheckReadOnlyFS,
		CheckNetworkMode, CheckPortExposure, CheckPortDangerous,
		CheckSecretsInEnv, CheckImageVulnerability,
		CheckLoggingDriver, CheckRestartPolicy,
	}

	seen := make(map[string]bool)
	for _, id := range ids {
		if id == "" {
			t.Error("security check ID constant should not be empty")
		}
		if seen[id] {
			t.Errorf("duplicate security check ID: %s", id)
		}
		seen[id] = true
	}
}
