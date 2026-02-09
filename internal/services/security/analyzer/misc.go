// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package analyzer

import (
	"context"
	"strings"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/security"
)

// RestartPolicyAnalyzer checks for restart policy configuration
type RestartPolicyAnalyzer struct {
	security.BaseAnalyzer
}

// NewRestartPolicyAnalyzer creates a new restart policy analyzer
func NewRestartPolicyAnalyzer() *RestartPolicyAnalyzer {
	return &RestartPolicyAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"restart_policy",
			"Checks if container has an appropriate restart policy for reliability",
		),
	}
}

// Analyze checks the container for restart policy issues
func (a *RestartPolicyAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	var issues []security.Issue

	// Get the check definition
	checks := models.DefaultSecurityChecks()
	var restartCheck models.SecurityCheck
	for _, c := range checks {
		if c.ID == models.CheckRestartPolicy {
			restartCheck = c
			break
		}
	}

	policy := strings.ToLower(data.RestartPolicy)

	// Check for no restart policy
	if policy == "" || policy == "no" {
		issues = append(issues, security.NewIssue(restartCheck,
			"Container has no restart policy or restart policy is 'no'. "+
				"If the container crashes or the host reboots, it will not automatically restart.").
			WithDetail("container", data.Name).
			WithDetail("current_policy", data.RestartPolicy).
			WithDetail("recommendation", "Use 'unless-stopped' or 'always' for production services"))
	}

	// Check for 'always' policy (might restart crashed containers endlessly)
	if policy == "always" {
		issues = append(issues, security.Issue{
			CheckID:     models.CheckRestartPolicy,
			Severity:    models.IssueSeverityInfo,
			Category:    models.IssueCategoryReliability,
			Title:       "Restart Policy 'always'",
			Description: "Container uses 'always' restart policy. This will restart even after manual stops.",
			Recommendation: "Consider using 'unless-stopped' to respect manual stop commands.",
			Penalty:     1,
		}.WithDetail("container", data.Name))
	}

	return issues, nil
}

// LoggingAnalyzer checks for logging configuration
type LoggingAnalyzer struct {
	security.BaseAnalyzer
}

// NewLoggingAnalyzer creates a new logging analyzer
func NewLoggingAnalyzer() *LoggingAnalyzer {
	return &LoggingAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"logging",
			"Checks if container has appropriate logging configuration",
		),
	}
}

// Analyze checks the container for logging issues
func (a *LoggingAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	// Note: Logging driver info is not typically available in container inspect
	// This analyzer checks for labels or other indicators
	// The actual logging driver is often set at daemon level

	// For now, this is a placeholder that can be extended
	// when we have access to daemon logging configuration

	return nil, nil
}

// AllAnalyzers returns all available analyzers with default configuration
func AllAnalyzers() []security.Analyzer {
	return []security.Analyzer{
		NewHealthcheckAnalyzer(),
		NewUserAnalyzer(),
		NewPrivilegedAnalyzer(),
		NewCapabilitiesAnalyzer(),
		NewResourcesAnalyzer(),
		NewNetworkAnalyzer(),
		NewPortsAnalyzer(),
		NewEnvAnalyzer(),
		NewMountsAnalyzer(),
		NewRestartPolicyAnalyzer(),
		NewLoggingAnalyzer(),
		NewCISBenchmarkAnalyzer(),
	}
}

// AllAnalyzersWithCISStrict returns all analyzers with CIS strict mode
func AllAnalyzersWithCISStrict() []security.Analyzer {
	return []security.Analyzer{
		NewHealthcheckAnalyzer(),
		NewUserAnalyzer(),
		NewPrivilegedAnalyzer(),
		NewCapabilitiesAnalyzer(),
		NewResourcesAnalyzer(),
		NewNetworkAnalyzer(),
		NewPortsAnalyzer(),
		NewEnvAnalyzer(),
		NewMountsAnalyzer(),
		NewRestartPolicyAnalyzer(),
		NewLoggingAnalyzer(),
		NewCISBenchmarkAnalyzerStrict(),
	}
}

// AnalyzerByName returns an analyzer by its name
func AnalyzerByName(name string) security.Analyzer {
	for _, a := range AllAnalyzers() {
		if a.Name() == name {
			return a
		}
	}
	return nil
}

// EnabledAnalyzers returns only enabled analyzers
func EnabledAnalyzers(analyzers []security.Analyzer) []security.Analyzer {
	var enabled []security.Analyzer
	for _, a := range analyzers {
		if a.IsEnabled() {
			enabled = append(enabled, a)
		}
	}
	return enabled
}

// DisableAnalyzer disables an analyzer by name
func DisableAnalyzer(analyzers []security.Analyzer, name string) {
	for _, a := range analyzers {
		if a.Name() == name {
			a.SetEnabled(false)
			return
		}
	}
}

// EnableAnalyzer enables an analyzer by name
func EnableAnalyzer(analyzers []security.Analyzer, name string) {
	for _, a := range analyzers {
		if a.Name() == name {
			a.SetEnabled(true)
			return
		}
	}
}
