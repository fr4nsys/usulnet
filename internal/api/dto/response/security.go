// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package response contains response DTOs for the API.
package response

import (
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Scan responses
// ============================================================================

// SecurityScan is the response for a completed security scan.
type SecurityScan struct {
	// ID is the unique scan identifier
	ID string `json:"id"`

	// ContainerID is the scanned container ID
	ContainerID string `json:"container_id"`

	// ContainerName is the container name
	ContainerName string `json:"container_name"`

	// Image is the container image
	Image string `json:"image"`

	// Score is the security score (0-100)
	Score int `json:"score"`

	// Grade is the letter grade (A-F)
	Grade string `json:"grade"`

	// IssueCount is the total number of issues found
	IssueCount int `json:"issue_count"`

	// CriticalCount is the number of critical issues
	CriticalCount int `json:"critical_count"`

	// HighCount is the number of high severity issues
	HighCount int `json:"high_count"`

	// MediumCount is the number of medium severity issues
	MediumCount int `json:"medium_count"`

	// LowCount is the number of low severity issues
	LowCount int `json:"low_count"`

	// CVECount is the number of CVEs found
	CVECount int `json:"cve_count"`

	// ScanDuration is the scan duration in milliseconds
	ScanDuration int64 `json:"scan_duration_ms"`

	// CompletedAt is when the scan completed
	CompletedAt time.Time `json:"completed_at"`
}

// SecurityScanDetail is the detailed response for a security scan including issues.
type SecurityScanDetail struct {
	// ID is the unique scan identifier
	ID string `json:"id"`

	// HostID is the host where the container runs
	HostID string `json:"host_id"`

	// ContainerID is the scanned container ID
	ContainerID string `json:"container_id"`

	// ContainerName is the container name
	ContainerName string `json:"container_name"`

	// Image is the container image
	Image string `json:"image"`

	// Score is the security score (0-100)
	Score int `json:"score"`

	// Grade is the letter grade (A-F)
	Grade string `json:"grade"`

	// IssueCount is the total number of issues found
	IssueCount int `json:"issue_count"`

	// CriticalCount is the number of critical issues
	CriticalCount int `json:"critical_count"`

	// HighCount is the number of high severity issues
	HighCount int `json:"high_count"`

	// MediumCount is the number of medium severity issues
	MediumCount int `json:"medium_count"`

	// LowCount is the number of low severity issues
	LowCount int `json:"low_count"`

	// CVECount is the number of CVEs found
	CVECount int `json:"cve_count"`

	// IncludeCVE indicates if CVE scanning was performed
	IncludeCVE bool `json:"include_cve"`

	// ScanDuration is the scan duration in milliseconds
	ScanDuration int64 `json:"scan_duration_ms"`

	// Issues is the list of security issues found
	Issues []*SecurityIssue `json:"issues,omitempty"`

	// CompletedAt is when the scan completed
	CompletedAt time.Time `json:"completed_at"`

	// CreatedAt is when the scan was created
	CreatedAt time.Time `json:"created_at"`
}

// SecurityScanSummary is a brief summary of a scan for lists.
type SecurityScanSummary struct {
	// ID is the unique scan identifier
	ID string `json:"id"`

	// ContainerID is the scanned container ID
	ContainerID string `json:"container_id"`

	// ContainerName is the container name
	ContainerName string `json:"container_name"`

	// Score is the security score (0-100)
	Score int `json:"score"`

	// Grade is the letter grade (A-F)
	Grade string `json:"grade"`

	// IssueCount is the total number of issues found
	IssueCount int `json:"issue_count"`

	// CriticalCount is the number of critical issues
	CriticalCount int `json:"critical_count"`

	// HighCount is the number of high severity issues
	HighCount int `json:"high_count"`

	// CompletedAt is when the scan completed
	CompletedAt time.Time `json:"completed_at"`
}

// ScanAllResponse is the response for scanning all containers.
type ScanAllResponse struct {
	// Scans is the list of completed scans
	Scans []*SecurityScan `json:"scans"`

	// Total is the total number of containers scanned
	Total int `json:"total"`

	// HostID is the host that was scanned
	HostID string `json:"host_id"`

	// Errors contains any containers that failed to scan
	Errors []ScanError `json:"errors,omitempty"`
}

// ScanError represents a failed scan for a container.
type ScanError struct {
	// ContainerID is the container that failed
	ContainerID string `json:"container_id"`

	// ContainerName is the container name
	ContainerName string `json:"container_name"`

	// Error is the error message
	Error string `json:"error"`
}

// ============================================================================
// Issue responses
// ============================================================================

// SecurityIssue is the response for a security issue.
type SecurityIssue struct {
	// ID is the unique issue identifier
	ID int64 `json:"id"`

	// ScanID is the scan that found this issue
	ScanID string `json:"scan_id"`

	// ContainerID is the affected container
	ContainerID string `json:"container_id"`

	// Severity is the issue severity (critical, high, medium, low, info)
	Severity string `json:"severity"`

	// Category is the issue category
	Category string `json:"category"`

	// CheckID is the security check identifier
	CheckID string `json:"check_id"`

	// Title is the issue title
	Title string `json:"title"`

	// Description is the detailed description
	Description string `json:"description"`

	// Recommendation is the suggested fix
	Recommendation string `json:"recommendation"`

	// FixCommand is a command to fix the issue (if available)
	FixCommand string `json:"fix_command,omitempty"`

	// DocumentationURL is a link to documentation
	DocumentationURL string `json:"documentation_url,omitempty"`

	// CVEID is the CVE identifier (for vulnerabilities)
	CVEID string `json:"cve_id,omitempty"`

	// CVSSScore is the CVSS score (for CVEs)
	CVSSScore float64 `json:"cvss_score,omitempty"`

	// Status is the current issue status
	Status string `json:"status"`

	// AcknowledgedAt is when the issue was acknowledged
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`

	// ResolvedAt is when the issue was resolved
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`

	// DetectedAt is when the issue was first detected
	DetectedAt time.Time `json:"detected_at"`
}

// SecurityIssueSummary is a brief summary of an issue.
type SecurityIssueSummary struct {
	// ID is the unique issue identifier
	ID int64 `json:"id"`

	// Severity is the issue severity
	Severity string `json:"severity"`

	// Category is the issue category
	Category string `json:"category"`

	// Title is the issue title
	Title string `json:"title"`

	// Status is the current status
	Status string `json:"status"`

	// ContainerName is the affected container name
	ContainerName string `json:"container_name,omitempty"`
}

// ============================================================================
// Summary and statistics responses
// ============================================================================

// SecuritySummary is the aggregated security summary.
type SecuritySummary struct {
	// TotalContainers is the total number of containers
	TotalContainers int `json:"total_containers"`

	// ScannedContainers is the number of containers with scans
	ScannedContainers int `json:"scanned_containers"`

	// AverageScore is the average security score
	AverageScore float64 `json:"average_score"`

	// TotalIssues is the total number of issues across all scans
	TotalIssues int `json:"total_issues"`

	// OpenIssues is the number of open (unresolved) issues
	OpenIssues int `json:"open_issues"`

	// GradeDistribution shows how many containers per grade
	GradeDistribution map[string]int `json:"grade_distribution"`

	// SeverityCounts shows issues by severity
	SeverityCounts map[string]int `json:"severity_counts"`

	// TopIssues shows the most common issues
	TopIssues []*SecurityIssueSummary `json:"top_issues,omitempty"`

	// RecentScans shows recent scan activity
	RecentScans []*SecurityScanSummary `json:"recent_scans,omitempty"`

	// LastScanAt is when the last scan was performed
	LastScanAt *time.Time `json:"last_scan_at,omitempty"`
}

// SecurityTrends represents security trends over time.
type SecurityTrends struct {
	// Period is the time period (7d, 30d, 90d)
	Period string `json:"period"`

	// ScoreHistory is the score over time
	ScoreHistory []TrendPoint `json:"score_history"`

	// IssueHistory is the issue count over time
	IssueHistory []TrendPoint `json:"issue_history"`

	// GradeHistory shows grade changes over time
	GradeHistory []GradeTrendPoint `json:"grade_history,omitempty"`

	// Improvement shows if security is improving
	Improvement *ImprovementStats `json:"improvement,omitempty"`
}

// TrendPoint is a single point in a trend line.
type TrendPoint struct {
	// Timestamp is the time of the measurement
	Timestamp time.Time `json:"timestamp"`

	// Value is the measured value
	Value float64 `json:"value"`
}

// GradeTrendPoint shows grade distribution at a point in time.
type GradeTrendPoint struct {
	// Timestamp is the time of the measurement
	Timestamp time.Time `json:"timestamp"`

	// Distribution shows grades at this time
	Distribution map[string]int `json:"distribution"`
}

// ImprovementStats shows improvement metrics.
type ImprovementStats struct {
	// ScoreChange is the score change (positive = improved)
	ScoreChange float64 `json:"score_change"`

	// IssuesFixed is the number of issues fixed
	IssuesFixed int `json:"issues_fixed"`

	// NewIssues is the number of new issues
	NewIssues int `json:"new_issues"`

	// NetChange is the net issue change
	NetChange int `json:"net_change"`
}

// ============================================================================
// Report responses
// ============================================================================

// SecurityReport is a full security report.
type SecurityReport struct {
	// ID is the report identifier
	ID string `json:"id"`

	// GeneratedAt is when the report was generated
	GeneratedAt time.Time `json:"generated_at"`

	// Title is the report title
	Title string `json:"title"`

	// HostID is the host covered (if specific)
	HostID string `json:"host_id,omitempty"`

	// Summary contains aggregate statistics
	Summary *SecuritySummary `json:"summary"`

	// Containers lists all scanned containers
	Containers []*ContainerSecurityReport `json:"containers,omitempty"`

	// TopIssues lists the most critical issues
	TopIssues []*SecurityIssue `json:"top_issues,omitempty"`

	// Trends shows security trends (if included)
	Trends *SecurityTrends `json:"trends,omitempty"`

	// Recommendations lists prioritized recommendations
	Recommendations []string `json:"recommendations,omitempty"`
}

// ContainerSecurityReport is security info for a single container.
type ContainerSecurityReport struct {
	// ContainerID is the container ID
	ContainerID string `json:"container_id"`

	// ContainerName is the container name
	ContainerName string `json:"container_name"`

	// Image is the container image
	Image string `json:"image"`

	// Score is the security score
	Score int `json:"score"`

	// Grade is the letter grade
	Grade string `json:"grade"`

	// IssueCount is the total issues
	IssueCount int `json:"issue_count"`

	// Issues lists all issues (if details included)
	Issues []*SecurityIssue `json:"issues,omitempty"`

	// ScannedAt is when it was last scanned
	ScannedAt time.Time `json:"scanned_at"`
}

// ============================================================================
// Configuration responses
// ============================================================================

// SecurityConfig is the current security configuration.
type SecurityConfig struct {
	// EnabledChecks lists enabled security checks
	EnabledChecks []SecurityCheckInfo `json:"enabled_checks"`

	// DisabledChecks lists disabled security checks
	DisabledChecks []SecurityCheckInfo `json:"disabled_checks"`

	// Penalties shows current penalty values
	Penalties map[string]int `json:"penalties"`

	// TrivyConfig shows Trivy configuration
	TrivyConfig *TrivyConfig `json:"trivy"`

	// ScheduleConfig shows scan schedule configuration
	ScheduleConfig *ScanScheduleConfig `json:"schedule"`

	// IgnorePatterns shows configured ignore patterns
	IgnorePatterns *IgnorePatterns `json:"ignore_patterns"`
}

// SecurityCheckInfo describes a security check.
type SecurityCheckInfo struct {
	// ID is the check identifier
	ID string `json:"id"`

	// Name is the human-readable name
	Name string `json:"name"`

	// Description describes what the check does
	Description string `json:"description"`

	// Category is the check category
	Category string `json:"category"`

	// DefaultPenalty is the default penalty
	DefaultPenalty int `json:"default_penalty"`

	// CurrentPenalty is the currently configured penalty
	CurrentPenalty int `json:"current_penalty"`

	// Enabled shows if the check is enabled
	Enabled bool `json:"enabled"`
}

// TrivyConfig shows Trivy configuration.
type TrivyConfig struct {
	// Enabled shows if Trivy is enabled
	Enabled bool `json:"enabled"`

	// Available shows if Trivy binary is available
	Available bool `json:"available"`

	// Version is the Trivy version
	Version string `json:"version,omitempty"`

	// Severities are the configured severities
	Severities []string `json:"severities"`

	// IgnoreUnfixed shows if unfixed CVEs are ignored
	IgnoreUnfixed bool `json:"ignore_unfixed"`

	// DBLastUpdate is when the DB was last updated
	DBLastUpdate *time.Time `json:"db_last_update,omitempty"`
}

// ScanScheduleConfig shows scan schedule configuration.
type ScanScheduleConfig struct {
	// Enabled shows if scheduled scanning is enabled
	Enabled bool `json:"enabled"`

	// IntervalHours is the scan interval
	IntervalHours int `json:"interval_hours"`

	// NextScanAt is when the next scan is scheduled
	NextScanAt *time.Time `json:"next_scan_at,omitempty"`

	// LastScanAt is when the last scheduled scan ran
	LastScanAt *time.Time `json:"last_scan_at,omitempty"`

	// IncludeCVE shows if CVE scanning is included
	IncludeCVE bool `json:"include_cve"`
}

// IgnorePatterns shows configured ignore patterns.
type IgnorePatterns struct {
	// Containers are ignored container patterns
	Containers []string `json:"containers"`

	// Images are ignored image patterns
	Images []string `json:"images"`

	// CVEs are ignored CVE IDs
	CVEs []string `json:"cves"`

	// ChecksByContainer maps containers to ignored checks
	ChecksByContainer map[string][]string `json:"checks_by_container"`
}

// ============================================================================
// Async operation responses
// ============================================================================

// ScanOperation represents an async scan operation.
type ScanOperation struct {
	// ID is the operation ID
	ID uuid.UUID `json:"id"`

	// Status is the operation status
	Status string `json:"status"`

	// Progress is the completion percentage (0-100)
	Progress int `json:"progress"`

	// TotalContainers is the total to scan
	TotalContainers int `json:"total_containers"`

	// CompletedContainers is how many are done
	CompletedContainers int `json:"completed_containers"`

	// CurrentContainer is currently being scanned
	CurrentContainer string `json:"current_container,omitempty"`

	// StartedAt is when the operation started
	StartedAt time.Time `json:"started_at"`

	// CompletedAt is when it finished (if done)
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Error is the error message if failed
	Error string `json:"error,omitempty"`
}
