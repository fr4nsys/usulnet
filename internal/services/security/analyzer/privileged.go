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

// PrivilegedAnalyzer checks if containers run in privileged mode
type PrivilegedAnalyzer struct {
	security.BaseAnalyzer
}

// NewPrivilegedAnalyzer creates a new privileged mode analyzer
func NewPrivilegedAnalyzer() *PrivilegedAnalyzer {
	return &PrivilegedAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"privileged",
			"Checks if container runs in privileged mode which grants full host access",
		),
	}
}

// Analyze checks the container for privileged mode issues
func (a *PrivilegedAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	var issues []security.Issue

	// Get the check definition
	checks := models.DefaultSecurityChecks()
	var privCheck models.SecurityCheck
	for _, c := range checks {
		if c.ID == models.CheckPrivileged {
			privCheck = c
			break
		}
	}

	// Check if running in privileged mode
	if data.Privileged {
		issues = append(issues, security.NewIssue(privCheck,
			"Container is running in privileged mode. This grants the container "+
				"almost all capabilities of the host system, effectively disabling "+
				"container isolation. An attacker with access to the container can "+
				"easily escape to the host system.").
			WithDetail("container", data.Name).
			WithDetail("impact", "Complete container escape possible").
			WithDetail("risk_level", "critical"))
	}

	// Check for dangerous security options that effectively grant similar access
	issues = append(issues, a.checkDangerousSecurityOpts(data)...)

	return issues, nil
}

// checkDangerousSecurityOpts checks for security options that weaken container isolation
func (a *PrivilegedAnalyzer) checkDangerousSecurityOpts(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	for _, opt := range data.SecurityOpt {
		opt = strings.ToLower(opt)

		// Check for disabled AppArmor
		if strings.HasPrefix(opt, "apparmor=unconfined") {
			issues = append(issues, security.Issue{
				CheckID:     models.CheckPrivileged,
				Severity:    models.IssueSeverityHigh,
				Category:    models.IssueCategorySecurity,
				Title:       "AppArmor Disabled",
				Description: "AppArmor is set to unconfined, disabling mandatory access control protection.",
				Recommendation: "Remove apparmor:unconfined unless absolutely required for the workload.",
				Penalty:     15,
			}.WithDetail("security_opt", opt))
		}

		// Check for disabled seccomp
		if strings.Contains(opt, "seccomp=unconfined") || strings.Contains(opt, "seccomp:unconfined") {
			issues = append(issues, security.Issue{
				CheckID:     models.CheckPrivileged,
				Severity:    models.IssueSeverityHigh,
				Category:    models.IssueCategorySecurity,
				Title:       "Seccomp Disabled",
				Description: "Seccomp profile is set to unconfined, allowing all system calls.",
				Recommendation: "Use default seccomp profile or a custom restricted profile.",
				Penalty:     15,
			}.WithDetail("security_opt", opt))
		}

		// Check for no-new-privileges disabled
		if strings.Contains(opt, "no-new-privileges=false") || strings.Contains(opt, "no-new-privileges:false") {
			issues = append(issues, security.Issue{
				CheckID:     models.CheckPrivileged,
				Severity:    models.IssueSeverityMedium,
				Category:    models.IssueCategorySecurity,
				Title:       "No-New-Privileges Disabled",
				Description: "no-new-privileges is disabled, allowing processes to gain additional privileges.",
				Recommendation: "Enable no-new-privileges to prevent privilege escalation.",
				Penalty:     10,
			}.WithDetail("security_opt", opt))
		}

		// Check for label:disable (SELinux)
		if strings.HasPrefix(opt, "label=disable") || strings.HasPrefix(opt, "label:disable") {
			issues = append(issues, security.Issue{
				CheckID:     models.CheckPrivileged,
				Severity:    models.IssueSeverityMedium,
				Category:    models.IssueCategorySecurity,
				Title:       "SELinux Labeling Disabled",
				Description: "SELinux labeling is disabled for this container.",
				Recommendation: "Enable SELinux labeling for additional security isolation.",
				Penalty:     8,
			}.WithDetail("security_opt", opt))
		}
	}

	return issues
}
