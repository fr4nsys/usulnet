// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package analyzer

import (
	"context"
	"fmt"
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
			CheckID:        models.CheckRestartPolicy,
			Severity:       models.IssueSeverityInfo,
			Category:       models.IssueCategoryReliability,
			Title:          "Restart Policy 'always'",
			Description:    "Container uses 'always' restart policy. This will restart even after manual stops.",
			Recommendation: "Consider using 'unless-stopped' to respect manual stop commands.",
			Penalty:        1,
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

	return nil, nil
}

// MiscSecurityAnalyzer performs miscellaneous security checks that don't fit
// neatly into other categories: namespace sharing, Docker socket mounts,
// latest tag usage, privileged ports, and missing healthchecks.
type MiscSecurityAnalyzer struct {
	security.BaseAnalyzer
}

// NewMiscSecurityAnalyzer creates a new miscellaneous security analyzer
func NewMiscSecurityAnalyzer() *MiscSecurityAnalyzer {
	return &MiscSecurityAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"misc_security",
			"Performs additional security checks: namespace sharing, Docker socket, image tags, privileged ports",
		),
	}
}

// Analyze runs all miscellaneous security checks on the container.
func (a *MiscSecurityAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	var issues []security.Issue

	issues = append(issues, a.checkNamespaceSharing(data)...)
	issues = append(issues, a.checkDockerSocket(data)...)
	issues = append(issues, a.checkLatestTag(data)...)
	issues = append(issues, a.checkPrivilegedPorts(data)...)
	issues = append(issues, a.checkNoHealthcheck(data)...)
	issues = append(issues, a.checkNoResourceLimits(data)...)

	return issues, nil
}

// checkNamespaceSharing checks if the container shares host PID, Network, or IPC namespaces.
func (a *MiscSecurityAnalyzer) checkNamespaceSharing(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	pidMode := strings.ToLower(data.PidMode)
	ipcMode := strings.ToLower(data.IpcMode)

	if pidMode == "host" {
		issues = append(issues, security.Issue{
			CheckID:        models.CheckNamespaceSharing,
			Severity:       models.IssueSeverityHigh,
			Category:       models.IssueCategorySecurity,
			Title:          "Host PID Namespace Shared",
			Description:    "Container shares the host PID namespace, allowing it to see and interact with all host processes.",
			Recommendation: "Remove pid: host unless the container specifically needs to monitor host processes.",
			Penalty:        15,
		}.WithDetail("container", data.Name).WithDetail("pid_mode", data.PidMode))
	}

	if ipcMode == "host" {
		issues = append(issues, security.Issue{
			CheckID:        models.CheckNamespaceSharing,
			Severity:       models.IssueSeverityMedium,
			Category:       models.IssueCategorySecurity,
			Title:          "Host IPC Namespace Shared",
			Description:    "Container shares the host IPC namespace, enabling shared memory attacks between container and host.",
			Recommendation: "Remove ipc: host unless the container needs shared memory with the host.",
			Penalty:        10,
		}.WithDetail("container", data.Name).WithDetail("ipc_mode", data.IpcMode))
	}

	return issues
}

// checkDockerSocket checks if the Docker socket is mounted into the container.
func (a *MiscSecurityAnalyzer) checkDockerSocket(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	socketPaths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/var/run/docker",
	}

	for _, mount := range data.Mounts {
		for _, socketPath := range socketPaths {
			if mount.Source == socketPath || mount.Destination == socketPath {
				issues = append(issues, security.Issue{
					CheckID:        models.CheckDockerSocket,
					Severity:       models.IssueSeverityCritical,
					Category:       models.IssueCategorySecurity,
					Title:          "Docker Socket Mounted",
					Description:    "The Docker socket is mounted into this container, granting full control over the Docker daemon. This is equivalent to root access on the host.",
					Recommendation: "Remove the Docker socket mount. Use Docker-in-Docker with proper isolation or a Docker API proxy with restricted permissions.",
					Penalty:        25,
				}.WithDetail("container", data.Name).
					WithDetail("mount_source", mount.Source).
					WithDetail("mount_destination", mount.Destination).
					WithDetail("read_write", mount.RW))
				break
			}
		}
	}

	// Also check bind mounts
	for _, bind := range data.Binds {
		for _, socketPath := range socketPaths {
			if strings.HasPrefix(bind, socketPath+":") || strings.Contains(bind, socketPath) {
				issues = append(issues, security.Issue{
					CheckID:        models.CheckDockerSocket,
					Severity:       models.IssueSeverityCritical,
					Category:       models.IssueCategorySecurity,
					Title:          "Docker Socket Bind Mount",
					Description:    "Docker socket is bind-mounted into the container via volume bind.",
					Recommendation: "Remove the Docker socket bind mount.",
					Penalty:        25,
				}.WithDetail("container", data.Name).WithDetail("bind", bind))
				break
			}
		}
	}

	return issues
}

// checkLatestTag checks if the container image uses the 'latest' tag.
func (a *MiscSecurityAnalyzer) checkLatestTag(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	image := data.Image
	if image == "" {
		return nil
	}

	// Check if image uses :latest or has no tag (defaults to latest)
	isLatest := false
	if strings.HasSuffix(image, ":latest") {
		isLatest = true
	} else if !strings.Contains(image, ":") && !strings.Contains(image, "@sha256:") {
		// No tag and no digest means implicit :latest
		isLatest = true
	}

	if isLatest {
		issues = append(issues, security.Issue{
			CheckID:        models.CheckLatestTag,
			Severity:       models.IssueSeverityMedium,
			Category:       models.IssueCategoryReliability,
			Title:          "Image Uses 'latest' Tag",
			Description:    "Container image uses the 'latest' tag or no specific tag. This can cause unexpected behavior when images are updated, as different deployments may run different versions.",
			Recommendation: "Pin the image to a specific version tag or SHA256 digest for reproducible deployments.",
			Penalty:        10,
		}.WithDetail("container", data.Name).WithDetail("image", image))
	}

	return issues
}

// checkPrivilegedPorts checks if the container exposes ports below 1024.
func (a *MiscSecurityAnalyzer) checkPrivilegedPorts(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	for _, port := range data.Ports {
		if port.HostPort > 0 && port.HostPort < 1024 {
			issues = append(issues, security.Issue{
				CheckID:        models.CheckPrivilegedPorts,
				Severity:       models.IssueSeverityLow,
				Category:       models.IssueCategorySecurity,
				Title:          "Privileged Port Exposed",
				Description:    fmt.Sprintf("Container maps to privileged host port %d (< 1024). Binding to privileged ports typically requires root privileges on the host.", port.HostPort),
				Recommendation: "Map to a non-privileged port (>= 1024) on the host if possible, or use a reverse proxy.",
				Penalty:        5,
			}.WithDetail("container", data.Name).
				WithDetail("host_port", port.HostPort).
				WithDetail("container_port", port.ContainerPort).
				WithDetail("protocol", port.Protocol))
		}
	}

	return issues
}

// checkNoHealthcheck reports containers without any healthcheck configured.
func (a *MiscSecurityAnalyzer) checkNoHealthcheck(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	if data.Healthcheck == nil || len(data.Healthcheck.Test) == 0 {
		if data.Health == "" || data.Health == "none" {
			issues = append(issues, security.Issue{
				CheckID:        models.CheckHealthcheck,
				Severity:       models.IssueSeverityMedium,
				Category:       models.IssueCategoryReliability,
				Title:          "No Healthcheck Configured",
				Description:    "Container has no healthcheck configured. Without a healthcheck, Docker cannot detect when the application inside the container becomes unhealthy.",
				Recommendation: "Add a HEALTHCHECK instruction to the Dockerfile or configure a healthcheck in the compose file.",
				Penalty:        10,
			}.WithDetail("container", data.Name).WithDetail("image", data.Image))
		}
	}

	return issues
}

// checkNoResourceLimits flags containers without CPU or memory limits.
func (a *MiscSecurityAnalyzer) checkNoResourceLimits(data *security.ContainerData) []security.Issue {
	var issues []security.Issue

	hasMemLimit := data.MemoryLimit > 0
	hasCPULimit := data.CPUQuota > 0 || data.NanoCPUs > 0 || data.CPUShares > 0

	if !hasMemLimit && !hasCPULimit {
		issues = append(issues, security.Issue{
			CheckID:        models.CheckResourceLimits,
			Severity:       models.IssueSeverityMedium,
			Category:       models.IssueCategoryReliability,
			Title:          "No CPU or Memory Limits",
			Description:    "Container has no CPU or memory limits configured. A runaway process could consume all available host resources and affect other containers.",
			Recommendation: "Set memory and CPU limits in the compose file (e.g., mem_limit: 512m, cpus: 1.0).",
			Penalty:        10,
		}.WithDetail("container", data.Name).
			WithDetail("memory_limit", data.MemoryLimit).
			WithDetail("cpu_quota", data.CPUQuota).
			WithDetail("nano_cpus", data.NanoCPUs))
	}

	return issues
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
		NewMiscSecurityAnalyzer(),
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
		NewMiscSecurityAnalyzer(),
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
