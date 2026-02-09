// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package request contains request DTOs for the API.
package request

// ============================================================================
// Scan requests
// ============================================================================

// ScanContainerRequest is the request body for scanning a single container.
type ScanContainerRequest struct {
	// ContainerID is the Docker container ID or name to scan
	ContainerID string `json:"container_id" validate:"required"`

	// HostID is the host where the container is running (optional for local)
	HostID string `json:"host_id,omitempty"`

	// IncludeCVE enables CVE scanning via Trivy (slower but more thorough)
	IncludeCVE bool `json:"include_cve,omitempty"`
}

// ScanAllRequest is the request body for scanning all containers on a host.
type ScanAllRequest struct {
	// HostID is the host to scan all containers on
	HostID string `json:"host_id" validate:"required,uuid"`

	// IncludeCVE enables CVE scanning for all containers
	IncludeCVE bool `json:"include_cve,omitempty"`

	// ContainerFilter filters which containers to scan (optional)
	ContainerFilter *ContainerScanFilter `json:"filter,omitempty"`
}

// ContainerScanFilter filters containers for batch scanning.
type ContainerScanFilter struct {
	// Names filters by container name (supports wildcards)
	Names []string `json:"names,omitempty"`

	// Images filters by image name (supports wildcards)
	Images []string `json:"images,omitempty"`

	// Labels filters by container labels
	Labels map[string]string `json:"labels,omitempty"`

	// RunningOnly only scans running containers
	RunningOnly bool `json:"running_only,omitempty"`

	// ExcludeNames excludes containers by name
	ExcludeNames []string `json:"exclude_names,omitempty"`

	// ExcludeImages excludes containers by image
	ExcludeImages []string `json:"exclude_images,omitempty"`
}

// ScheduleScanRequest is the request body for scheduling automatic scans.
type ScheduleScanRequest struct {
	// HostID is the host to schedule scans for
	HostID string `json:"host_id" validate:"required,uuid"`

	// Enabled enables or disables scheduled scanning
	Enabled bool `json:"enabled"`

	// IntervalHours is the interval between scans in hours (default: 6)
	IntervalHours int `json:"interval_hours,omitempty" validate:"omitempty,min=1,max=168"`

	// IncludeCVE enables CVE scanning in scheduled scans
	IncludeCVE bool `json:"include_cve,omitempty"`

	// NotifyOnCritical sends notification when critical issues are found
	NotifyOnCritical bool `json:"notify_on_critical,omitempty"`

	// NotifyOnScoreDecrease sends notification when score decreases
	NotifyOnScoreDecrease bool `json:"notify_on_score_decrease,omitempty"`

	// MinScoreThreshold triggers notification if score falls below this
	MinScoreThreshold int `json:"min_score_threshold,omitempty" validate:"omitempty,min=0,max=100"`
}

// ============================================================================
// Issue requests
// ============================================================================

// UpdateIssueStatusRequest is the request body for updating issue status.
type UpdateIssueStatusRequest struct {
	// Status is the new status (open, acknowledged, resolved, ignored, false_positive)
	Status string `json:"status" validate:"required,oneof=open acknowledged resolved ignored false_positive"`

	// UserID is the user making the change (for audit)
	UserID string `json:"user_id,omitempty" validate:"omitempty,uuid"`

	// Comment is an optional comment explaining the status change
	Comment string `json:"comment,omitempty" validate:"omitempty,max=1000"`
}

// BulkUpdateIssuesRequest is the request body for bulk updating issues.
type BulkUpdateIssuesRequest struct {
	// IssueIDs are the issues to update
	IssueIDs []int64 `json:"issue_ids" validate:"required,min=1,max=100"`

	// Status is the new status for all issues
	Status string `json:"status" validate:"required,oneof=open acknowledged resolved ignored false_positive"`

	// UserID is the user making the change
	UserID string `json:"user_id,omitempty" validate:"omitempty,uuid"`

	// Comment is an optional comment for all issues
	Comment string `json:"comment,omitempty" validate:"omitempty,max=1000"`
}

// ============================================================================
// Report requests
// ============================================================================

// GenerateReportRequest is the request body for generating a security report.
type GenerateReportRequest struct {
	// HostID filters report to a specific host (optional)
	HostID string `json:"host_id,omitempty" validate:"omitempty,uuid"`

	// ContainerIDs filters report to specific containers (optional)
	ContainerIDs []string `json:"container_ids,omitempty"`

	// Format is the output format (json, html, markdown, text)
	Format string `json:"format,omitempty" validate:"omitempty,oneof=json html markdown text"`

	// IncludeDetails includes full issue details
	IncludeDetails bool `json:"include_details,omitempty"`

	// IncludeTrends includes score trend data
	IncludeTrends bool `json:"include_trends,omitempty"`

	// IncludeRecommendations includes fix recommendations
	IncludeRecommendations bool `json:"include_recommendations,omitempty"`

	// GroupBy groups issues (category, severity, container)
	GroupBy string `json:"group_by,omitempty" validate:"omitempty,oneof=category severity container"`

	// MinSeverity filters issues by minimum severity
	MinSeverity string `json:"min_severity,omitempty" validate:"omitempty,oneof=critical high medium low info"`

	// DateRange filters scans within a date range
	DateRange *DateRange `json:"date_range,omitempty"`
}

// DateRange specifies a date range for filtering.
type DateRange struct {
	// From is the start date (inclusive)
	From string `json:"from,omitempty" validate:"omitempty,datetime=2006-01-02"`

	// To is the end date (inclusive)
	To string `json:"to,omitempty" validate:"omitempty,datetime=2006-01-02"`
}

// ============================================================================
// Configuration requests
// ============================================================================

// UpdateScanConfigRequest is the request body for updating scan configuration.
type UpdateScanConfigRequest struct {
	// EnabledChecks is the list of enabled security checks
	EnabledChecks []string `json:"enabled_checks,omitempty"`

	// DisabledChecks is the list of disabled security checks
	DisabledChecks []string `json:"disabled_checks,omitempty"`

	// CustomPenalties overrides default penalties for checks
	CustomPenalties map[string]int `json:"custom_penalties,omitempty"`

	// TrivyConfig configures Trivy CVE scanning
	TrivyConfig *TrivyConfigRequest `json:"trivy,omitempty"`

	// IgnorePatterns are patterns to ignore in scans
	IgnorePatterns *IgnorePatternsRequest `json:"ignore_patterns,omitempty"`
}

// TrivyConfigRequest configures Trivy scanning.
type TrivyConfigRequest struct {
	// Enabled enables Trivy scanning
	Enabled bool `json:"enabled"`

	// Severities are the severities to report (CRITICAL, HIGH, MEDIUM, LOW)
	Severities []string `json:"severities,omitempty" validate:"omitempty,dive,oneof=CRITICAL HIGH MEDIUM LOW"`

	// IgnoreUnfixed ignores vulnerabilities without fixes
	IgnoreUnfixed bool `json:"ignore_unfixed,omitempty"`

	// SkipDBUpdate skips database update before scan
	SkipDBUpdate bool `json:"skip_db_update,omitempty"`

	// Timeout is the scan timeout in seconds
	Timeout int `json:"timeout,omitempty" validate:"omitempty,min=30,max=600"`
}

// IgnorePatternsRequest configures patterns to ignore in scans.
type IgnorePatternsRequest struct {
	// Containers are container names/patterns to ignore
	Containers []string `json:"containers,omitempty"`

	// Images are image names/patterns to ignore
	Images []string `json:"images,omitempty"`

	// CVEs are specific CVE IDs to ignore
	CVEs []string `json:"cves,omitempty"`

	// Checks are check IDs to ignore for specific containers
	Checks map[string][]string `json:"checks,omitempty"`
}

// ============================================================================
// Query parameter helpers
// ============================================================================

// ListScansQuery represents query parameters for listing scans.
type ListScansQuery struct {
	// HostID filters by host
	HostID string `query:"host_id" validate:"omitempty,uuid"`

	// ContainerID filters by container
	ContainerID string `query:"container_id"`

	// MinScore filters by minimum score
	MinScore int `query:"min_score" validate:"omitempty,min=0,max=100"`

	// MaxScore filters by maximum score
	MaxScore int `query:"max_score" validate:"omitempty,min=0,max=100"`

	// Grade filters by grade (A, B, C, D, F)
	Grade string `query:"grade" validate:"omitempty,oneof=A B C D F"`

	// Since filters scans after this timestamp
	Since string `query:"since" validate:"omitempty,datetime=2006-01-02T15:04:05Z07:00"`

	// Limit is the maximum number of results
	Limit int `query:"limit" validate:"omitempty,min=1,max=100"`

	// Offset is the pagination offset
	Offset int `query:"offset" validate:"omitempty,min=0"`
}

// ListIssuesQuery represents query parameters for listing issues.
type ListIssuesQuery struct {
	// HostID filters by host (required)
	HostID string `query:"host_id" validate:"required,uuid"`

	// ContainerID filters by container
	ContainerID string `query:"container_id"`

	// ScanID filters by specific scan
	ScanID string `query:"scan_id" validate:"omitempty,uuid"`

	// Severity filters by severity
	Severity string `query:"severity" validate:"omitempty,oneof=critical high medium low info"`

	// Category filters by category
	Category string `query:"category" validate:"omitempty,oneof=security reliability performance best_practice vulnerability"`

	// Status filters by status
	Status string `query:"status" validate:"omitempty,oneof=open acknowledged resolved ignored false_positive"`

	// CheckID filters by specific check
	CheckID string `query:"check_id"`

	// Limit is the maximum number of results
	Limit int `query:"limit" validate:"omitempty,min=1,max=100"`

	// Offset is the pagination offset
	Offset int `query:"offset" validate:"omitempty,min=0"`
}
