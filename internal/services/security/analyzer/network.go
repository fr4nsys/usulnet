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

// NetworkAnalyzer checks for network-related security issues
type NetworkAnalyzer struct {
	security.BaseAnalyzer
}

// NewNetworkAnalyzer creates a new network analyzer
func NewNetworkAnalyzer() *NetworkAnalyzer {
	return &NetworkAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"network",
			"Checks for network mode security issues like host network mode",
		),
	}
}

// Analyze checks the container for network-related security issues
func (a *NetworkAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	var issues []security.Issue

	// Get the check definition
	checks := models.DefaultSecurityChecks()
	var netCheck models.SecurityCheck
	for _, c := range checks {
		if c.ID == models.CheckNetworkMode {
			netCheck = c
			break
		}
	}

	networkMode := strings.ToLower(data.NetworkMode)

	// Check for host network mode
	if networkMode == "host" {
		issues = append(issues, security.NewIssue(netCheck,
			"Container uses host network mode. This disables network isolation "+
				"and gives the container direct access to the host's network interfaces. "+
				"This can expose services and allow network sniffing.").
			WithDetail("container", data.Name).
			WithDetail("network_mode", data.NetworkMode).
			WithDetail("impact", "Network isolation disabled, services may be exposed"))
	}

	// Check PID mode
	if strings.ToLower(data.PidMode) == "host" {
		issues = append(issues, security.Issue{
			CheckID:     models.CheckNetworkMode,
			Severity:    models.IssueSeverityHigh,
			Category:    models.IssueCategorySecurity,
			Title:       "Host PID Namespace",
			Description: "Container shares the host's PID namespace. This allows seeing and potentially signaling all host processes.",
			Recommendation: "Avoid using PID namespace sharing unless absolutely required for monitoring tools.",
			Penalty:     15,
		}.WithDetail("container", data.Name).
			WithDetail("pid_mode", data.PidMode))
	}

	// Check IPC mode
	if strings.ToLower(data.IpcMode) == "host" {
		issues = append(issues, security.Issue{
			CheckID:     models.CheckNetworkMode,
			Severity:    models.IssueSeverityMedium,
			Category:    models.IssueCategorySecurity,
			Title:       "Host IPC Namespace",
			Description: "Container shares the host's IPC namespace. This allows access to shared memory segments.",
			Recommendation: "Avoid using IPC namespace sharing unless required for specific IPC communication.",
			Penalty:     10,
		}.WithDetail("container", data.Name).
			WithDetail("ipc_mode", data.IpcMode))
	}

	// Check for container network mode sharing
	if strings.HasPrefix(networkMode, "container:") {
		containerID := strings.TrimPrefix(networkMode, "container:")
		issues = append(issues, security.Issue{
			CheckID:     models.CheckNetworkMode,
			Severity:    models.IssueSeverityLow,
			Category:    models.IssueCategorySecurity,
			Title:       "Shared Container Network",
			Description: "Container shares network namespace with another container. Ensure this is intentional.",
			Recommendation: "Verify that network sharing is required and the target container is trusted.",
			Penalty:     3,
		}.WithDetail("container", data.Name).
			WithDetail("shared_with", containerID))
	}

	// Check for "none" network mode (could be intentional but worth noting)
	if networkMode == "none" {
		issues = append(issues, security.Issue{
			CheckID:     models.CheckNetworkMode,
			Severity:    models.IssueSeverityInfo,
			Category:    models.IssueCategorySecurity,
			Title:       "No Network",
			Description: "Container has no network connectivity. This is secure but may limit functionality.",
			Recommendation: "This is often desirable for batch jobs or security-sensitive workloads.",
			Penalty:     0, // This is actually good for security
		}.WithDetail("container", data.Name))
	}

	return issues, nil
}
