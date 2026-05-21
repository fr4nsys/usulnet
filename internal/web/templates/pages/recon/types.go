// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package recon contains server-side rendered templates for the
// v26.5.0 Privacy & Recon module.
package recon

import (
	"github.com/fr4nsys/usulnet/internal/web/templates/layouts"
)

// DashboardData backs /recon/dashboard.
type DashboardData struct {
	PageData       layouts.PageData
	Stats          DashboardStats
	RecentScans    []ScanView
	TopFindings    []FindingView
	Acknowledged   bool
	IsAcknowledged bool
	LegalNotice    string
	IsAdmin        bool
}

// DashboardStats is the small KPI bar at the top of the dashboard.
type DashboardStats struct {
	Targets       int
	Scans         int
	Running       int
	Completed     int
	Failed        int
	FindingsBySev map[string]int
	Critical      int
	High          int
	Medium        int
	Low           int
}

// TargetsListData backs /recon/targets.
type TargetsListData struct {
	PageData layouts.PageData
	Targets  []TargetView
	Profiles []ProfileView
	IsAdmin  bool
}

// TargetDetailData backs /recon/targets/{id}.
type TargetDetailData struct {
	PageData        layouts.PageData
	Target          TargetView
	OwnershipProofs []OwnershipProofView
	Scans           []ScanView
	Findings        []FindingView
}

// ScansListData backs /recon/scans.
type ScansListData struct {
	PageData     layouts.PageData
	Scans        []ScanView
	FilterStatus string
}

// ScanDetailData backs /recon/scans/{id}.
type ScanDetailData struct {
	PageData layouts.PageData
	Scan     ScanView
	Summary  *ScanSummaryView
	Findings []FindingView
	Modules  []string
}

// ConnectorsData backs /recon/connectors.
type ConnectorsData struct {
	PageData     layouts.PageData
	Connectors   []ConnectorView
	SandboxTools []SandboxToolGroup
}

// SandboxToolGroup is one labelled group on the /recon/connectors
// "Sandbox tools" panel.
type SandboxToolGroup struct {
	Category string
	Tools    []SandboxToolView
}

// SandboxToolView is one tool advertised inside the recon-toolkit
// sandbox image.
type SandboxToolView struct {
	Name string
}

// ReportsData backs /recon/reports.
type ReportsData struct {
	PageData layouts.PageData
	Reports  []ReportView
}

// TargetView is one identifier row.
type TargetView struct {
	ID              string
	Type            string
	Value           string
	ValueHashPrefix string
	Label           string
	OwnershipStatus string
	OwnershipMethod string
	OwnershipOK     bool
	LastScanAt      string
	ScanCount       int
	CreatedAt       string
}

// OwnershipProofView shows one verification record.
type OwnershipProofView struct {
	ID         string
	Method     string
	Status     string
	Challenge  string
	VerifiedAt string
	CreatedAt  string
}

// ScanView is one scan-run row.
type ScanView struct {
	ID          string
	TargetID    string
	TargetValue string
	TargetType  string
	ProfileID   string
	ProfileName string
	Status      string
	Engine      string
	Error       string
	StartedAt   string
	FinishedAt  string
	Duration    string
	Progress    int
	CreatedAt   string
}

// ScanSummaryView aggregates a completed scan.
type ScanSummaryView struct {
	Grade       string
	Counts      map[string]int
	GeneratedAt string
}

// FindingView is one normalized finding.
type FindingView struct {
	ID         string
	ScanID     string
	TargetID   string
	Module     string
	Category   string
	Severity   string
	Value      string
	Source     string
	Confidence int
	FirstSeen  string
	LastSeen   string
}

// ProfileView lists a built-in scan profile.
type ProfileView struct {
	ID          string
	Name        string
	Description string
	Kind        string
	TargetTypes []string
	Modules     []string
}

// ConnectorView is one optional external API integration.
type ConnectorView struct {
	Kind        string
	Name        string
	Enabled     bool
	Configured  bool
	Description string
	DocsURL     string
}

// ReportView is one generated export.
type ReportView struct {
	ID          string
	ScanID      string
	TargetValue string
	Format      string
	SizeBytes   int64
	CreatedAt   string
	DownloadURL string
}

// SeverityClass returns Tailwind classes for the colored severity badge,
// reusing the same palette as the security and vulnerability pages.
func SeverityClass(severity string) string {
	switch severity {
	case "critical":
		return "text-red-400 bg-red-500/10 border-red-500/20"
	case "high":
		return "text-orange-400 bg-orange-500/10 border-orange-500/20"
	case "medium":
		return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
	case "low":
		return "text-blue-400 bg-blue-500/10 border-blue-500/20"
	case "info":
		return "text-gray-400 bg-gray-500/10 border-gray-500/20"
	default:
		return "text-gray-400 bg-gray-500/10 border-gray-500/20"
	}
}

// StatusClass returns Tailwind classes for scan status badges.
func StatusClass(status string) string {
	switch status {
	case "completed":
		return "text-green-400 bg-green-500/10 border-green-500/20"
	case "running":
		return "text-primary-400 bg-primary-500/10 border-primary-500/20"
	case "queued":
		return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
	case "failed":
		return "text-red-400 bg-red-500/10 border-red-500/20"
	case "canceled":
		return "text-gray-400 bg-gray-500/10 border-gray-500/20"
	default:
		return "text-gray-400 bg-gray-500/10 border-gray-500/20"
	}
}
