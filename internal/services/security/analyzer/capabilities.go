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

// CapabilitiesAnalyzer checks for dangerous Linux capabilities
type CapabilitiesAnalyzer struct {
	security.BaseAnalyzer
}

// NewCapabilitiesAnalyzer creates a new capabilities analyzer
func NewCapabilitiesAnalyzer() *CapabilitiesAnalyzer {
	return &CapabilitiesAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"capabilities",
			"Checks for dangerous Linux capabilities and recommends minimal capability sets",
		),
	}
}

// Analyze checks the container for capability-related security issues
func (a *CapabilitiesAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	var issues []security.Issue

	// Get the check definition
	checks := models.DefaultSecurityChecks()
	var capCheck models.SecurityCheck
	for _, c := range checks {
		if c.ID == models.CheckCapabilities {
			capCheck = c
			break
		}
	}

	// Check if CAP_ALL is not dropped
	hasDropAll := hasCapability(data.CapDrop, "ALL")

	// Check for dangerous capabilities added
	dangerousCaps := a.findDangerousCapabilities(data.CapAdd)

	if len(dangerousCaps) > 0 {
		for _, cap := range dangerousCaps {
			risk := getCapabilityRisk(cap)
			issues = append(issues, security.Issue{
				CheckID:     models.CheckCapabilities,
				Severity:    risk.Severity,
				Category:    models.IssueCategorySecurity,
				Title:       "Dangerous Capability Added: " + cap,
				Description: risk.Description,
				Recommendation: risk.Recommendation,
				FixCommand:  "Remove cap_add: " + cap + " from container configuration",
				Penalty:     risk.Penalty,
			}.WithDetail("capability", cap).
				WithDetail("container", data.Name))
		}
	}

	// If not dropping all capabilities, suggest doing so
	if !hasDropAll && !data.Privileged {
		// Only add this as a suggestion if there are no other cap issues
		if len(dangerousCaps) == 0 {
			issues = append(issues, security.NewIssue(capCheck,
				"Container does not drop all capabilities. It is recommended "+
					"to drop all capabilities and only add the specific ones needed.").
				WithDetail("container", data.Name).
				WithDetail("current_cap_add", data.CapAdd).
				WithDetail("current_cap_drop", data.CapDrop))
		}
	}

	return issues, nil
}

// findDangerousCapabilities returns a list of dangerous capabilities from the added list
func (a *CapabilitiesAnalyzer) findDangerousCapabilities(capAdd []string) []string {
	var dangerous []string

	for _, cap := range capAdd {
		cap = normalizeCapability(cap)
		if isDangerousCapability(cap) {
			dangerous = append(dangerous, cap)
		}
	}

	return dangerous
}

// normalizeCapability normalizes capability names (removes CAP_ prefix, uppercases)
func normalizeCapability(cap string) string {
	cap = strings.ToUpper(strings.TrimSpace(cap))
	cap = strings.TrimPrefix(cap, "CAP_")
	return cap
}

// hasCapability checks if a capability is in the list
func hasCapability(caps []string, target string) bool {
	target = normalizeCapability(target)
	for _, cap := range caps {
		if normalizeCapability(cap) == target {
			return true
		}
	}
	return false
}

// isDangerousCapability checks if a capability is considered dangerous
func isDangerousCapability(cap string) bool {
	for _, dangerous := range security.DangerousCapabilities {
		if cap == dangerous {
			return true
		}
	}
	return false
}

// CapabilityRisk describes the risk of a specific capability
type CapabilityRisk struct {
	Severity       models.IssueSeverity
	Description    string
	Recommendation string
	Penalty        int
}

// getCapabilityRisk returns the risk information for a capability
func getCapabilityRisk(cap string) CapabilityRisk {
	risks := map[string]CapabilityRisk{
		"SYS_ADMIN": {
			Severity:       models.IssueSeverityCritical,
			Description:    "SYS_ADMIN grants a very wide range of capabilities including mounting filesystems, performing administrative operations, and can be used for container escape.",
			Recommendation: "This capability is almost never needed. Use more specific capabilities instead.",
			Penalty:        20,
		},
		"NET_ADMIN": {
			Severity:       models.IssueSeverityHigh,
			Description:    "NET_ADMIN allows network configuration changes including interfaces, firewall rules, and routing. Can be used to intercept traffic.",
			Recommendation: "Only use if the container needs to manage network configuration. Consider using --network=host instead if full network access is needed.",
			Penalty:        12,
		},
		"SYS_PTRACE": {
			Severity:       models.IssueSeverityCritical,
			Description:    "SYS_PTRACE allows tracing/debugging any process, including reading memory and registers. Can be used to escape container.",
			Recommendation: "Only use for debugging tools. Remove in production environments.",
			Penalty:        18,
		},
		"SYS_MODULE": {
			Severity:       models.IssueSeverityCritical,
			Description:    "SYS_MODULE allows loading and unloading kernel modules. This can completely compromise the host system.",
			Recommendation: "Never use this capability in containers. If needed, reconsider your architecture.",
			Penalty:        22,
		},
		"DAC_READ_SEARCH": {
			Severity:       models.IssueSeverityHigh,
			Description:    "DAC_READ_SEARCH bypasses file read permission checks and directory read/execute checks.",
			Recommendation: "Avoid using this capability. Set proper file permissions instead.",
			Penalty:        12,
		},
		"DAC_OVERRIDE": {
			Severity:       models.IssueSeverityHigh,
			Description:    "DAC_OVERRIDE bypasses file read, write, and execute permission checks.",
			Recommendation: "Avoid using this capability. Run as the appropriate user instead.",
			Penalty:        12,
		},
		"SETUID": {
			Severity:       models.IssueSeverityMedium,
			Description:    "SETUID allows changing the process UID. Can be used for privilege escalation.",
			Recommendation: "Only use if the application legitimately needs to switch users.",
			Penalty:        8,
		},
		"SETGID": {
			Severity:       models.IssueSeverityMedium,
			Description:    "SETGID allows changing the process GID. Can be used for privilege escalation.",
			Recommendation: "Only use if the application legitimately needs to switch groups.",
			Penalty:        8,
		},
		"NET_RAW": {
			Severity:       models.IssueSeverityMedium,
			Description:    "NET_RAW allows use of raw sockets and packet sockets. Can be used for network sniffing.",
			Recommendation: "Only use for network diagnostic tools. Remove for general applications.",
			Penalty:        8,
		},
		"SYS_CHROOT": {
			Severity:       models.IssueSeverityMedium,
			Description:    "SYS_CHROOT allows use of chroot() which can potentially be used in escape scenarios.",
			Recommendation: "Only use if application specifically needs chroot functionality.",
			Penalty:        6,
		},
		"MKNOD": {
			Severity:       models.IssueSeverityMedium,
			Description:    "MKNOD allows creation of special device files which could be used for attacks.",
			Recommendation: "Only use if application needs to create device nodes.",
			Penalty:        6,
		},
		"SYS_RAWIO": {
			Severity:       models.IssueSeverityCritical,
			Description:    "SYS_RAWIO allows raw I/O operations which can compromise the host system.",
			Recommendation: "Never use in containers. This grants near-full host access.",
			Penalty:        20,
		},
		"SYS_BOOT": {
			Severity:       models.IssueSeverityHigh,
			Description:    "SYS_BOOT allows rebooting the system and loading new kernels.",
			Recommendation: "Never use in containers. This can disrupt the entire host.",
			Penalty:        15,
		},
		"SYS_TIME": {
			Severity:       models.IssueSeverityMedium,
			Description:    "SYS_TIME allows changing the system clock which can affect other containers and services.",
			Recommendation: "Only use if application needs to set system time. Consider NTP instead.",
			Penalty:        6,
		},
		"AUDIT_CONTROL": {
			Severity:       models.IssueSeverityHigh,
			Description:    "AUDIT_CONTROL allows enabling/disabling kernel auditing and changing audit rules.",
			Recommendation: "Only use for dedicated audit management containers.",
			Penalty:        12,
		},
		"AUDIT_WRITE": {
			Severity:       models.IssueSeverityMedium,
			Description:    "AUDIT_WRITE allows writing records to kernel auditing log.",
			Recommendation: "Only use if application needs to log audit records.",
			Penalty:        6,
		},
	}

	if risk, ok := risks[cap]; ok {
		return risk
	}

	// Default risk for unknown dangerous capabilities
	return CapabilityRisk{
		Severity:       models.IssueSeverityMedium,
		Description:    "Capability " + cap + " is considered potentially dangerous.",
		Recommendation: "Review if this capability is actually needed for your application.",
		Penalty:        8,
	}
}
