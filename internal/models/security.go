// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// SecurityGrade represents a security grade
type SecurityGrade string

const (
	SecurityGradeA SecurityGrade = "A"
	SecurityGradeB SecurityGrade = "B"
	SecurityGradeC SecurityGrade = "C"
	SecurityGradeD SecurityGrade = "D"
	SecurityGradeF SecurityGrade = "F"
)

// GradeFromScore returns the grade for a given score
func GradeFromScore(score int) SecurityGrade {
	switch {
	case score >= 90:
		return SecurityGradeA
	case score >= 80:
		return SecurityGradeB
	case score >= 70:
		return SecurityGradeC
	case score >= 60:
		return SecurityGradeD
	default:
		return SecurityGradeF
	}
}

// IssueSeverity represents the severity of a security issue
type IssueSeverity string

const (
	IssueSeverityCritical IssueSeverity = "critical"
	IssueSeverityHigh     IssueSeverity = "high"
	IssueSeverityMedium   IssueSeverity = "medium"
	IssueSeverityLow      IssueSeverity = "low"
	IssueSeverityInfo     IssueSeverity = "info"
)

// IssueCategory represents the category of a security issue
type IssueCategory string

const (
	IssueCategorySecurity      IssueCategory = "security"
	IssueCategoryReliability   IssueCategory = "reliability"
	IssueCategoryPerformance   IssueCategory = "performance"
	IssueCategoryBestPractice  IssueCategory = "best_practice"
	IssueCategoryVulnerability IssueCategory = "vulnerability"
	IssueCategoryNetwork       IssueCategory = "network"
)

// IssueStatus represents the status of a security issue
type IssueStatus string

const (
	IssueStatusOpen         IssueStatus = "open"
	IssueStatusAcknowledged IssueStatus = "acknowledged"
	IssueStatusResolved     IssueStatus = "resolved"
	IssueStatusIgnored      IssueStatus = "ignored"
	IssueStatusFalsePositive IssueStatus = "false_positive"
)

// SecurityScan represents a security scan result
type SecurityScan struct {
	ID              uuid.UUID       `json:"id" db:"id"`
	HostID          uuid.UUID       `json:"host_id" db:"host_id"`
	ContainerID     string          `json:"container_id" db:"container_id"`
	ContainerName   string          `json:"container_name" db:"container_name"`
	Image           string          `json:"image" db:"image"`
	Score           int             `json:"score" db:"score"`
	Grade           SecurityGrade   `json:"grade" db:"grade"`
	Issues          []SecurityIssue `json:"issues,omitempty" db:"-"`
	IssueCount      int             `json:"issue_count" db:"issue_count"`
	CriticalCount   int             `json:"critical_count" db:"critical_count"`
	HighCount       int             `json:"high_count" db:"high_count"`
	MediumCount     int             `json:"medium_count" db:"medium_count"`
	LowCount        int             `json:"low_count" db:"low_count"`
	CVECount        int             `json:"cve_count" db:"cve_count"`
	IncludeCVE      bool            `json:"include_cve" db:"include_cve"`
	ScanDuration    time.Duration   `json:"scan_duration" db:"scan_duration_ms"`
	CompletedAt     time.Time       `json:"completed_at" db:"completed_at"`
	CreatedAt       time.Time       `json:"created_at" db:"created_at"`
}

// SecurityIssue represents a security issue
type SecurityIssue struct {
	ID               int64         `json:"id" db:"id"`
	ScanID           uuid.UUID     `json:"scan_id" db:"scan_id"`
	ContainerID      string        `json:"container_id" db:"container_id"`
	HostID           uuid.UUID     `json:"host_id" db:"host_id"`
	Severity         IssueSeverity `json:"severity" db:"severity"`
	Category         IssueCategory `json:"category" db:"category"`
	CheckID          string        `json:"check_id" db:"check_id"`
	Title            string        `json:"title" db:"title"`
	Description      string        `json:"description" db:"description"`
	Recommendation   string        `json:"recommendation" db:"recommendation"`
	FixCommand       *string       `json:"fix_command,omitempty" db:"fix_command"`
	DocumentationURL *string       `json:"documentation_url,omitempty" db:"documentation_url"`
	CVEID            *string       `json:"cve_id,omitempty" db:"cve_id"`
	CVSSScore        *float64      `json:"cvss_score,omitempty" db:"cvss_score"`
	Status           IssueStatus   `json:"status" db:"status"`
	AcknowledgedBy   *uuid.UUID    `json:"acknowledged_by,omitempty" db:"acknowledged_by"`
	AcknowledgedAt   *time.Time    `json:"acknowledged_at,omitempty" db:"acknowledged_at"`
	ResolvedBy       *uuid.UUID    `json:"resolved_by,omitempty" db:"resolved_by"`
	ResolvedAt       *time.Time    `json:"resolved_at,omitempty" db:"resolved_at"`
	DetectedAt       time.Time     `json:"detected_at" db:"detected_at"`
}

// SecurityCheck represents a security check definition
type SecurityCheck struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Description  string        `json:"description"`
	Category     IssueCategory `json:"category"`
	Severity     IssueSeverity `json:"severity"`
	ScoreImpact  int           `json:"score_impact"`
	IsEnabled    bool          `json:"is_enabled"`
	FixCommand   string        `json:"fix_command,omitempty"`
	DocURL       string        `json:"doc_url,omitempty"`
}

// Security check IDs
const (
	CheckHealthcheck        = "HEALTH_001"
	CheckRootUser           = "USER_001"
	CheckPrivileged         = "PRIV_001"
	CheckCapabilities       = "CAP_001"
	CheckResourceLimits     = "RES_001"
	CheckReadOnlyFS         = "FS_001"
	CheckNetworkMode        = "NET_001"
	CheckPortExposure       = "PORT_001"
	CheckPortDangerous      = "PORT_002"
	CheckSecretsInEnv       = "SEC_001"
	CheckImageVulnerability = "CVE_001"
	CheckLoggingDriver      = "LOG_001"
	CheckRestartPolicy      = "REL_001"
)

// DefaultSecurityChecks returns the default security checks
func DefaultSecurityChecks() []SecurityCheck {
	return []SecurityCheck{
		{
			ID:          CheckHealthcheck,
			Name:        "Healthcheck Configuration",
			Description: "Container should have a healthcheck configured for automatic recovery",
			Category:    IssueCategoryReliability,
			Severity:    IssueSeverityMedium,
			ScoreImpact: 15,
			IsEnabled:   true,
			FixCommand:  "Add HEALTHCHECK instruction to Dockerfile or healthcheck config in compose",
			DocURL:      "https://docs.docker.com/engine/reference/builder/#healthcheck",
		},
		{
			ID:          CheckRootUser,
			Name:        "Non-Root User",
			Description: "Container should run as non-root user for security isolation",
			Category:    IssueCategorySecurity,
			Severity:    IssueSeverityHigh,
			ScoreImpact: 20,
			IsEnabled:   true,
			FixCommand:  "Add USER instruction in Dockerfile or user config in compose",
			DocURL:      "https://docs.docker.com/engine/security/#linux-kernel-capabilities",
		},
		{
			ID:          CheckPrivileged,
			Name:        "Privileged Mode",
			Description: "Container should not run in privileged mode unless absolutely necessary",
			Category:    IssueCategorySecurity,
			Severity:    IssueSeverityCritical,
			ScoreImpact: 25,
			IsEnabled:   true,
			FixCommand:  "Remove privileged: true from compose or --privileged flag",
			DocURL:      "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
		},
		{
			ID:          CheckCapabilities,
			Name:        "Minimal Capabilities",
			Description: "Container should drop all capabilities and only add required ones",
			Category:    IssueCategorySecurity,
			Severity:    IssueSeverityMedium,
			ScoreImpact: 10,
			IsEnabled:   true,
			FixCommand:  "Add cap_drop: [ALL] and only specific cap_add as needed",
			DocURL:      "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
		},
		{
			ID:          CheckResourceLimits,
			Name:        "Resource Limits",
			Description: "Container should have CPU and memory limits configured",
			Category:    IssueCategoryReliability,
			Severity:    IssueSeverityMedium,
			ScoreImpact: 10,
			IsEnabled:   true,
			FixCommand:  "Add mem_limit and cpus config in compose",
			DocURL:      "https://docs.docker.com/config/containers/resource_constraints/",
		},
		{
			ID:          CheckReadOnlyFS,
			Name:        "Read-Only Filesystem",
			Description: "Container filesystem should be read-only when possible",
			Category:    IssueCategorySecurity,
			Severity:    IssueSeverityLow,
			ScoreImpact: 5,
			IsEnabled:   true,
			FixCommand:  "Add read_only: true in compose",
			DocURL:      "https://docs.docker.com/engine/reference/run/#security-configuration",
		},
		{
			ID:          CheckNetworkMode,
			Name:        "Network Mode Host",
			Description: "Container should not use host network mode unless necessary",
			Category:    IssueCategorySecurity,
			Severity:    IssueSeverityHigh,
			ScoreImpact: 15,
			IsEnabled:   true,
			FixCommand:  "Use bridge network instead of network_mode: host",
			DocURL:      "https://docs.docker.com/network/drivers/host/",
		},
		{
			ID:          CheckPortExposure,
			Name:        "Port Exposure",
			Description: "Container should not expose ports to 0.0.0.0 unless necessary",
			Category:    IssueCategorySecurity,
			Severity:    IssueSeverityMedium,
			ScoreImpact: 5,
			IsEnabled:   true,
			FixCommand:  "Bind to 127.0.0.1 instead of 0.0.0.0 for internal services",
			DocURL:      "https://docs.docker.com/network/",
		},
		{
			ID:          CheckPortDangerous,
			Name:        "Dangerous Ports",
			Description: "Container exposes commonly attacked ports (22, 3306, 5432, 6379, 27017)",
			Category:    IssueCategorySecurity,
			Severity:    IssueSeverityHigh,
			ScoreImpact: 10,
			IsEnabled:   true,
			FixCommand:  "Use internal network or bind to localhost only",
		},
		{
			ID:          CheckSecretsInEnv,
			Name:        "Secrets in Environment",
			Description: "Container should not have plaintext secrets in environment variables",
			Category:    IssueCategorySecurity,
			Severity:    IssueSeverityHigh,
			ScoreImpact: 20,
			IsEnabled:   true,
			FixCommand:  "Use Docker secrets or encrypted config management",
			DocURL:      "https://docs.docker.com/engine/swarm/secrets/",
		},
		{
			ID:          CheckImageVulnerability,
			Name:        "Image Vulnerabilities",
			Description: "Container image has known CVE vulnerabilities",
			Category:    IssueCategoryVulnerability,
			Severity:    IssueSeverityHigh,
			ScoreImpact: 15,
			IsEnabled:   true,
			FixCommand:  "Update base image or apply security patches",
			DocURL:      "https://docs.docker.com/develop/security-best-practices/",
		},
		{
			ID:          CheckLoggingDriver,
			Name:        "Logging Configuration",
			Description: "Container should have logging driver configured",
			Category:    IssueCategoryReliability,
			Severity:    IssueSeverityLow,
			ScoreImpact: 5,
			IsEnabled:   true,
			FixCommand:  "Configure logging driver in compose",
			DocURL:      "https://docs.docker.com/config/containers/logging/",
		},
		{
			ID:          CheckRestartPolicy,
			Name:        "Restart Policy",
			Description: "Container should have appropriate restart policy",
			Category:    IssueCategoryReliability,
			Severity:    IssueSeverityLow,
			ScoreImpact: 5,
			IsEnabled:   true,
			FixCommand:  "Add restart: unless-stopped in compose",
			DocURL:      "https://docs.docker.com/config/containers/start-containers-automatically/",
		},
	}
}

// CVEInfo represents CVE vulnerability information
type CVEInfo struct {
	ID               string        `json:"id"`
	Title            string        `json:"title"`
	Description      string        `json:"description"`
	Severity         IssueSeverity `json:"severity"`
	CVSSScore        float64       `json:"cvss_score,omitempty"`
	CVSSVector       string        `json:"cvss_vector,omitempty"`
	Package          string        `json:"package"`
	InstalledVersion string        `json:"installed_version"`
	FixedVersion     string        `json:"fixed_version,omitempty"`
	Published        *time.Time    `json:"published,omitempty"`
	References       []string      `json:"references,omitempty"`
}

// SecurityReport represents a security report
type SecurityReport struct {
	ID              uuid.UUID          `json:"id"`
	HostID          *uuid.UUID         `json:"host_id,omitempty"`
	GeneratedAt     time.Time          `json:"generated_at"`
	TotalContainers int                `json:"total_containers"`
	ScannedCount    int                `json:"scanned_count"`
	AverageScore    float64            `json:"average_score"`
	GradeDistribution map[string]int   `json:"grade_distribution"`
	SeveritySummary   map[string]int   `json:"severity_summary"`
	TopIssues       []SecurityIssue    `json:"top_issues,omitempty"`
	ContainerScores []ContainerScore   `json:"container_scores,omitempty"`
	Trends          *SecurityTrends    `json:"trends,omitempty"`
}

// ContainerScore represents a container's security score
type ContainerScore struct {
	ContainerID   string        `json:"container_id"`
	ContainerName string        `json:"container_name"`
	Image         string        `json:"image"`
	Score         int           `json:"score"`
	Grade         SecurityGrade `json:"grade"`
	IssueCount    int           `json:"issue_count"`
	CriticalCount int           `json:"critical_count"`
}

// SecurityTrends represents security trends over time
type SecurityTrends struct {
	Period          string      `json:"period"` // daily, weekly, monthly
	AverageScores   []TrendPoint `json:"average_scores"`
	IssueCounts     []TrendPoint `json:"issue_counts"`
	Improvement     float64      `json:"improvement"` // Percentage improvement
}

// TrendPoint represents a data point in a trend
type TrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// UpdateIssueStatusInput represents input for updating issue status
type UpdateIssueStatusInput struct {
	Status  IssueStatus `json:"status" validate:"required,oneof=acknowledged resolved ignored false_positive"`
	Comment *string     `json:"comment,omitempty"`
}

// ScanOptions represents options for security scanning
type ScanOptions struct {
	IncludeCVE        bool     `json:"include_cve"`
	Severity          []string `json:"severity,omitempty"` // Filter by severity
	IgnoreUnfixed     bool     `json:"ignore_unfixed"`
	Timeout           *int     `json:"timeout,omitempty"` // In seconds
}
