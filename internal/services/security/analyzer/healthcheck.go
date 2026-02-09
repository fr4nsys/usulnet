// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package analyzer provides individual security analyzers for container inspection.
// Each analyzer focuses on a specific security aspect and returns issues found.
package analyzer

import (
	"context"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/security"
)

// HealthcheckAnalyzer checks if containers have proper healthcheck configuration
type HealthcheckAnalyzer struct {
	security.BaseAnalyzer
}

// NewHealthcheckAnalyzer creates a new healthcheck analyzer
func NewHealthcheckAnalyzer() *HealthcheckAnalyzer {
	return &HealthcheckAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"healthcheck",
			"Checks if container has healthcheck configured for automatic failure detection",
		),
	}
}

// Analyze checks the container for healthcheck issues
func (a *HealthcheckAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	var issues []security.Issue

	// Get the check definition
	checks := models.DefaultSecurityChecks()
	var healthCheck models.SecurityCheck
	for _, c := range checks {
		if c.ID == models.CheckHealthcheck {
			healthCheck = c
			break
		}
	}

	// Check if healthcheck is configured
	if data.Healthcheck == nil {
		issues = append(issues, security.NewIssue(healthCheck,
			"Container has no healthcheck configured. Without a healthcheck, "+
				"Docker cannot automatically detect and recover from application failures.").
			WithDetail("container", data.Name).
			WithDetail("impact", "Failures may go undetected, causing service degradation"))
		return issues, nil
	}

	// Check if healthcheck is disabled (NONE)
	if len(data.Healthcheck.Test) > 0 && data.Healthcheck.Test[0] == "NONE" {
		issues = append(issues, security.NewIssue(healthCheck,
			"Container healthcheck is explicitly disabled (NONE). "+
				"This prevents automatic failure detection and recovery.").
			WithDetail("container", data.Name).
			WithDetail("test", data.Healthcheck.Test))
		return issues, nil
	}

	// Validate healthcheck configuration quality
	issues = append(issues, a.validateHealthcheckConfig(data, healthCheck)...)

	return issues, nil
}

// validateHealthcheckConfig checks if the healthcheck is well-configured
func (a *HealthcheckAnalyzer) validateHealthcheckConfig(data *security.ContainerData, check models.SecurityCheck) []security.Issue {
	var issues []security.Issue

	hc := data.Healthcheck

	// Check for very long intervals (> 5 minutes)
	if hc.Interval > 300_000_000_000 { // 5 minutes in nanoseconds
		// This is a low severity issue - not the main check
		issues = append(issues, security.Issue{
			CheckID:     models.CheckHealthcheck,
			Severity:    models.IssueSeverityLow,
			Category:    models.IssueCategoryReliability,
			Title:       "Long Healthcheck Interval",
			Description: "Healthcheck interval is longer than 5 minutes, which may delay failure detection.",
			Recommendation: "Consider reducing the healthcheck interval to 30-60 seconds for faster failure detection.",
			Penalty:     2,
		}.WithDetail("interval_seconds", hc.Interval/1_000_000_000))
	}

	// Check for very short timeout (< 5 seconds)
	if hc.Timeout > 0 && hc.Timeout < 5_000_000_000 { // 5 seconds
		issues = append(issues, security.Issue{
			CheckID:     models.CheckHealthcheck,
			Severity:    models.IssueSeverityInfo,
			Category:    models.IssueCategoryReliability,
			Title:       "Short Healthcheck Timeout",
			Description: "Healthcheck timeout is very short, which may cause false positives during load.",
			Recommendation: "Consider increasing timeout to at least 5-10 seconds.",
			Penalty:     1,
		}.WithDetail("timeout_seconds", hc.Timeout/1_000_000_000))
	}

	// Check for zero or low retries
	if hc.Retries < 2 {
		issues = append(issues, security.Issue{
			CheckID:     models.CheckHealthcheck,
			Severity:    models.IssueSeverityInfo,
			Category:    models.IssueCategoryReliability,
			Title:       "Low Healthcheck Retries",
			Description: "Healthcheck has few retries, which may cause unnecessary restarts on transient failures.",
			Recommendation: "Consider setting retries to 3 or more for better tolerance.",
			Penalty:     1,
		}.WithDetail("retries", hc.Retries))
	}

	return issues
}
