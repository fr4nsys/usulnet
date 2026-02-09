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

// MountsAnalyzer checks for security issues with volume mounts
type MountsAnalyzer struct {
	security.BaseAnalyzer
}

// NewMountsAnalyzer creates a new mounts analyzer
func NewMountsAnalyzer() *MountsAnalyzer {
	return &MountsAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"mounts",
			"Checks for dangerous volume mounts and filesystem security",
		),
	}
}

// Analyze checks the container for mount-related security issues
func (a *MountsAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	var issues []security.Issue

	// Get the check definition for read-only filesystem
	checks := models.DefaultSecurityChecks()
	var readOnlyCheck models.SecurityCheck
	for _, c := range checks {
		if c.ID == models.CheckReadOnlyFS {
			readOnlyCheck = c
			break
		}
	}

	// Check for read-only root filesystem
	if !data.ReadonlyRootfs {
		issues = append(issues, security.NewIssue(readOnlyCheck,
			"Container filesystem is not read-only. A read-only filesystem "+
				"prevents attackers from modifying files or installing malware.").
			WithDetail("container", data.Name).
			WithDetail("recommendation", "Set read_only: true and use tmpfs or volumes for writable paths"))
	}

	// Check for dangerous bind mounts
	issues = append(issues, a.checkDangerousMounts(data)...)

	return issues, nil
}

// checkDangerousMounts checks for bind mounts that could be security risks
func (a *MountsAnalyzer) checkDangerousMounts(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	// Dangerous paths to check
	dangerousPaths := map[string]dangerousPathInfo{
		"/":         {severity: models.IssueSeverityCritical, description: "Root filesystem mounted - complete host access"},
		"/etc":      {severity: models.IssueSeverityCritical, description: "System configuration directory mounted"},
		"/root":     {severity: models.IssueSeverityHigh, description: "Root user home directory mounted"},
		"/home":     {severity: models.IssueSeverityMedium, description: "User home directories mounted"},
		"/var/run/docker.sock": {severity: models.IssueSeverityCritical, description: "Docker socket mounted - container escape possible"},
		"/run/docker.sock":     {severity: models.IssueSeverityCritical, description: "Docker socket mounted - container escape possible"},
		"/var/lib/docker": {severity: models.IssueSeverityCritical, description: "Docker data directory mounted"},
		"/proc":    {severity: models.IssueSeverityCritical, description: "Process filesystem mounted"},
		"/sys":     {severity: models.IssueSeverityHigh, description: "System filesystem mounted"},
		"/dev":     {severity: models.IssueSeverityCritical, description: "Device directory mounted - full device access"},
		"/boot":    {severity: models.IssueSeverityCritical, description: "Boot directory mounted - could modify kernel"},
		"/lib/modules": {severity: models.IssueSeverityCritical, description: "Kernel modules directory mounted"},
		"/etc/shadow":  {severity: models.IssueSeverityCritical, description: "Password shadow file mounted"},
		"/etc/passwd":  {severity: models.IssueSeverityHigh, description: "Password file mounted"},
		"/etc/sudoers": {severity: models.IssueSeverityCritical, description: "Sudoers file mounted"},
		"/etc/ssh":     {severity: models.IssueSeverityHigh, description: "SSH configuration mounted"},
	}

	// Check each mount
	allMounts := append(data.Mounts, a.parseBionds(data.Binds)...)

	for _, mount := range allMounts {
		if mount.Type != "bind" {
			continue
		}

		source := strings.TrimSuffix(mount.Source, "/")

		// Check against dangerous paths
		for dangerousPath, info := range dangerousPaths {
			// Exact match or parent directory match
			if source == dangerousPath || strings.HasPrefix(dangerousPath+"/", source+"/") {
				issue := security.Issue{
					CheckID:     "MOUNT_001",
					Severity:    info.severity,
					Category:    models.IssueCategorySecurity,
					Title:       "Dangerous Host Path Mounted",
					Description: info.description,
					Recommendation: "Avoid mounting sensitive host paths. Use named volumes or specific subdirectories instead.",
					Penalty:     a.penaltyForSeverity(info.severity),
				}.WithDetail("container", data.Name).
					WithDetail("source", mount.Source).
					WithDetail("destination", mount.Destination).
					WithDetail("mode", mount.Mode)

				// Higher penalty if mounted read-write
				if mount.RW {
					issue.Penalty += 5
					issue = issue.WithDetail("warning", "Mounted read-write - can modify host files")
				}

				issues = append(issues, issue)
				break // Don't report same mount multiple times
			}
		}

		// Check for paths containing sensitive keywords
		sourceLower := strings.ToLower(source)
		sensitiveKeywords := []string{"secret", "password", "credential", "key", "token", "cert", "ssl", "tls", "private"}
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(sourceLower, keyword) && mount.RW {
				issues = append(issues, security.Issue{
					CheckID:     "MOUNT_002",
					Severity:    models.IssueSeverityMedium,
					Category:    models.IssueCategorySecurity,
					Title:       "Sensitive Path Mounted Read-Write",
					Description: "A path containing sensitive keywords is mounted with write access.",
					Recommendation: "Mount sensitive paths read-only if the container doesn't need to modify them.",
					Penalty:     8,
				}.WithDetail("container", data.Name).
					WithDetail("source", mount.Source).
					WithDetail("keyword", keyword))
				break
			}
		}
	}

	return issues
}

// parseBionds parses bind mount strings into MountData
func (a *MountsAnalyzer) parseBionds(binds []string) []security.MountData {
	var mounts []security.MountData

	for _, bind := range binds {
		// Format: source:destination[:options]
		parts := strings.Split(bind, ":")
		if len(parts) < 2 {
			continue
		}

		mount := security.MountData{
			Type:        "bind",
			Source:      parts[0],
			Destination: parts[1],
			RW:          true,
			Mode:        "rw",
		}

		if len(parts) >= 3 {
			options := strings.Split(parts[2], ",")
			for _, opt := range options {
				if opt == "ro" {
					mount.RW = false
					mount.Mode = "ro"
				}
			}
		}

		mounts = append(mounts, mount)
	}

	return mounts
}

// penaltyForSeverity returns the penalty for a given severity
func (a *MountsAnalyzer) penaltyForSeverity(severity models.IssueSeverity) int {
	switch severity {
	case models.IssueSeverityCritical:
		return 20
	case models.IssueSeverityHigh:
		return 15
	case models.IssueSeverityMedium:
		return 10
	case models.IssueSeverityLow:
		return 5
	default:
		return 2
	}
}

// dangerousPathInfo holds information about a dangerous path
type dangerousPathInfo struct {
	severity    models.IssueSeverity
	description string
}
