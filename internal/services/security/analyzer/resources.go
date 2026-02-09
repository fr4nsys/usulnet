// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package analyzer

import (
	"context"
	"fmt"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/security"
)

// ResourcesAnalyzer checks if containers have proper resource limits
type ResourcesAnalyzer struct {
	security.BaseAnalyzer

	// Configuration
	MinMemoryRecommended int64 // Minimum recommended memory limit (bytes)
	MaxMemoryWarning     int64 // Memory limit that triggers a warning (bytes)
}

// NewResourcesAnalyzer creates a new resources analyzer
func NewResourcesAnalyzer() *ResourcesAnalyzer {
	return &ResourcesAnalyzer{
		BaseAnalyzer: security.NewBaseAnalyzer(
			"resources",
			"Checks if container has CPU and memory limits configured to prevent resource exhaustion",
		),
		MinMemoryRecommended: 64 * 1024 * 1024,        // 64 MB
		MaxMemoryWarning:     32 * 1024 * 1024 * 1024, // 32 GB
	}
}

// Analyze checks the container for resource limit issues
func (a *ResourcesAnalyzer) Analyze(ctx context.Context, data *security.ContainerData) ([]security.Issue, error) {
	if !a.IsEnabled() {
		return nil, nil
	}

	var issues []security.Issue

	// Get the check definition
	checks := models.DefaultSecurityChecks()
	var resCheck models.SecurityCheck
	for _, c := range checks {
		if c.ID == models.CheckResourceLimits {
			resCheck = c
			break
		}
	}

	// Check memory limit
	hasMemoryLimit := data.MemoryLimit > 0
	hasCPULimit := data.NanoCPUs > 0 || data.CPUQuota > 0 || data.CPUShares > 0

	if !hasMemoryLimit && !hasCPULimit {
		issues = append(issues, security.NewIssue(resCheck,
			"Container has no resource limits configured. Without limits, "+
				"a container can consume all available host resources, "+
				"leading to denial of service for other containers and the host system.").
			WithDetail("container", data.Name).
			WithDetail("memory_limit", "none").
			WithDetail("cpu_limit", "none"))
		return issues, nil
	}

	// Check individual limits
	if !hasMemoryLimit {
		issues = append(issues, security.Issue{
			CheckID:     models.CheckResourceLimits,
			Severity:    models.IssueSeverityMedium,
			Category:    models.IssueCategoryReliability,
			Title:       "No Memory Limit",
			Description: "Container has no memory limit configured. A memory leak or spike could affect other workloads.",
			Recommendation: "Set a memory limit appropriate for your workload using mem_limit in compose or --memory flag.",
			FixCommand:  "docker update --memory 512m " + data.Name,
			Penalty:     5,
		}.WithDetail("container", data.Name))
	} else {
		// Check if memory limit is very low
		if data.MemoryLimit < a.MinMemoryRecommended {
			issues = append(issues, security.Issue{
				CheckID:     models.CheckResourceLimits,
				Severity:    models.IssueSeverityLow,
				Category:    models.IssueCategoryPerformance,
				Title:       "Very Low Memory Limit",
				Description: fmt.Sprintf("Memory limit (%s) is very low and may cause OOM kills.", formatBytes(data.MemoryLimit)),
				Recommendation: "Ensure the memory limit is appropriate for your application's needs.",
				Penalty:     2,
			}.WithDetail("memory_limit_bytes", data.MemoryLimit).
				WithDetail("memory_limit_human", formatBytes(data.MemoryLimit)))
		}

		// Check if memory limit is very high (potential misconfiguration)
		if data.MemoryLimit > a.MaxMemoryWarning {
			issues = append(issues, security.Issue{
				CheckID:     models.CheckResourceLimits,
				Severity:    models.IssueSeverityInfo,
				Category:    models.IssueCategoryPerformance,
				Title:       "Very High Memory Limit",
				Description: fmt.Sprintf("Memory limit (%s) is very high. Verify this is intentional.", formatBytes(data.MemoryLimit)),
				Recommendation: "Review if this high memory limit is actually needed.",
				Penalty:     1,
			}.WithDetail("memory_limit_bytes", data.MemoryLimit).
				WithDetail("memory_limit_human", formatBytes(data.MemoryLimit)))
		}
	}

	if !hasCPULimit {
		issues = append(issues, security.Issue{
			CheckID:     models.CheckResourceLimits,
			Severity:    models.IssueSeverityLow,
			Category:    models.IssueCategoryReliability,
			Title:       "No CPU Limit",
			Description: "Container has no CPU limit configured. A CPU-intensive process could starve other workloads.",
			Recommendation: "Set a CPU limit using cpus in compose or --cpus flag.",
			FixCommand:  "docker update --cpus 1.0 " + data.Name,
			Penalty:     3,
		}.WithDetail("container", data.Name))
	}

	// Check for PIDs limit
	if data.PidsLimit == 0 {
		issues = append(issues, security.Issue{
			CheckID:     models.CheckResourceLimits,
			Severity:    models.IssueSeverityLow,
			Category:    models.IssueCategoryReliability,
			Title:       "No PIDs Limit",
			Description: "Container has no PIDs limit. A fork bomb could exhaust process table entries.",
			Recommendation: "Set a PIDs limit to prevent fork bomb attacks.",
			FixCommand:  "docker update --pids-limit 200 " + data.Name,
			Penalty:     2,
		}.WithDetail("container", data.Name))
	}

	return issues, nil
}

// formatBytes formats bytes to human readable string
func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/TB)
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
