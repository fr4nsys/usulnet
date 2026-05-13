// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"strconv"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	securitysvc "github.com/fr4nsys/usulnet/internal/services/security"
)

type securityAdapter struct {
	svc          *securitysvc.Service
	hostSvc      *hostsvc.Service
	containerSvc *containersvc.Service
	hostID       uuid.UUID
}

func (a *securityAdapter) IsTrivyAvailable() bool {
	if a.svc == nil {
		return false
	}
	return a.svc.IsTrivyAvailable()
}

func (a *securityAdapter) GetOverview(ctx context.Context) (*SecurityOverviewData, error) {
	if a.svc == nil {
		return nil, nil
	}

	hostID := resolveHostID(ctx, a.hostID)
	summary, err := a.svc.GetSecuritySummary(ctx, &hostID)
	if err != nil {
		return nil, err
	}

	// Convert severity counts
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	if summary.SeverityCounts != nil {
		criticalCount = summary.SeverityCounts[models.IssueSeverityCritical]
		highCount = summary.SeverityCounts[models.IssueSeverityHigh]
		mediumCount = summary.SeverityCounts[models.IssueSeverityMedium]
		lowCount = summary.SeverityCounts[models.IssueSeverityLow]
	}

	// Convert grade distribution
	gradeA := 0
	gradeB := 0
	gradeC := 0
	gradeD := 0
	gradeF := 0

	if summary.GradeDistribution != nil {
		gradeA = summary.GradeDistribution[models.SecurityGradeA]
		gradeB = summary.GradeDistribution[models.SecurityGradeB]
		gradeC = summary.GradeDistribution[models.SecurityGradeC]
		gradeD = summary.GradeDistribution[models.SecurityGradeD]
		gradeF = summary.GradeDistribution[models.SecurityGradeF]
	}

	return &SecurityOverviewData{
		TotalScanned:   summary.TotalContainers,
		AverageScore:   summary.AverageScore,
		GradeA:         gradeA,
		GradeB:         gradeB,
		GradeC:         gradeC,
		GradeD:         gradeD,
		GradeF:         gradeF,
		CriticalCount:  criticalCount,
		HighCount:      highCount,
		MediumCount:    mediumCount,
		LowCount:       lowCount,
		TrivyAvailable: a.IsTrivyAvailable(),
	}, nil
}

func (a *securityAdapter) ListScans(ctx context.Context) ([]SecurityScanView, error) {
	if a.svc == nil {
		return nil, nil
	}

	scans, _, err := a.svc.ListScans(ctx, securitysvc.ListScansOptions{Limit: 100})
	if err != nil {
		return nil, err
	}

	views := make([]SecurityScanView, 0, len(scans))
	for _, s := range scans {
		views = append(views, securityScanToView(s))
	}
	return views, nil
}

func (a *securityAdapter) ListContainersWithSecurity(ctx context.Context) ([]ContainerSecurityView, error) {
	if a.hostSvc == nil {
		return nil, nil
	}

	// Get Docker client
	dockerClient, err := a.hostSvc.GetClient(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, fmt.Errorf("failed to get docker client: %w", err)
	}

	// List all containers (including stopped)
	containers, err := dockerClient.ContainerList(ctx, docker.ContainerListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Build a map of latest scans by container ID
	scanMap := make(map[string]*models.SecurityScan)
	if a.svc != nil {
		scans, _, _ := a.svc.ListScans(ctx, securitysvc.ListScansOptions{Limit: 500})
		for _, scan := range scans {
			existing, ok := scanMap[scan.ContainerID]
			if !ok || scan.CreatedAt.After(existing.CreatedAt) {
				scanMap[scan.ContainerID] = scan
			}
		}
	}

	// Convert to views
	views := make([]ContainerSecurityView, 0, len(containers))
	for _, c := range containers {
		view := ContainerSecurityView{
			ID:    c.ID,
			Name:  c.Name,
			Image: c.Image,
			State: c.State,
		}

		// Check if there's a scan for this container
		if scan, ok := scanMap[c.ID]; ok {
			view.HasScan = true
			view.Score = scan.Score
			view.Grade = string(scan.Grade)
			view.IssueCount = scan.IssueCount
			view.LastScanned = scan.CompletedAt.Format("Jan 02 15:04")
		}

		views = append(views, view)
	}

	return views, nil
}

func (a *securityAdapter) GetScan(ctx context.Context, containerID string) (*SecurityScanView, error) {
	if a.svc == nil {
		return nil, nil
	}

	scan, err := a.svc.GetLatestScan(ctx, containerID)
	if err != nil {
		return nil, err
	}

	view := securityScanToView(scan)
	return &view, nil
}

func (a *securityAdapter) Scan(ctx context.Context, containerID string) (*SecurityScanView, error) {
	if a.svc == nil || a.hostSvc == nil {
		return nil, fmt.Errorf("security service not initialized")
	}

	// Get Docker client for this host
	dockerClient, err := a.hostSvc.GetClient(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, fmt.Errorf("failed to get docker client: %w", err)
	}

	// Get raw Docker inspect data
	inspectData, err := dockerClient.ContainerInspectRaw(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	// Run security scan
	scan, err := a.svc.ScanContainerJSON(ctx, inspectData, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Update container record with security score
	if a.containerSvc != nil && scan != nil {
		if updateErr := a.containerSvc.UpdateSecurityInfo(ctx, containerID, scan.Score, string(scan.Grade)); updateErr != nil {
			// Log but don't fail the scan
			_ = updateErr
		}
	}

	view := securityScanToView(scan)
	return &view, nil
}

func (a *securityAdapter) ScanAll(ctx context.Context) error {
	if a.svc == nil || a.hostSvc == nil {
		return fmt.Errorf("security service not initialized")
	}

	// Get Docker client
	dockerClient, err := a.hostSvc.GetClient(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return fmt.Errorf("failed to get docker client: %w", err)
	}

	// List all running containers
	containers, err := dockerClient.ContainerList(ctx, docker.ContainerListOptions{All: false})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	// Scan each container
	for _, c := range containers {
		inspectData, err := dockerClient.ContainerInspectRaw(ctx, c.ID)
		if err != nil {
			continue // skip containers we can't inspect
		}
		if _, err := a.svc.ScanContainerJSON(ctx, inspectData, resolveHostID(ctx, a.hostID)); err != nil {
			continue // skip failed scans
		}
	}

	return nil
}

func (a *securityAdapter) ListIssues(ctx context.Context) ([]IssueView, error) {
	if a.svc == nil {
		return nil, nil
	}

	issues, _, err := a.svc.GetHostIssues(ctx, resolveHostID(ctx, a.hostID), securitysvc.ListIssuesOptions{Limit: 100})
	if err != nil {
		return nil, err
	}

	views := make([]IssueView, 0, len(issues))
	for _, i := range issues {
		views = append(views, issueToView(i))
	}
	return views, nil
}

func parseIssueID(id string) (int64, error) {
	return strconv.ParseInt(id, 10, 64)
}

func (a *securityAdapter) IgnoreIssue(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	issueID, err := parseIssueID(id)
	if err != nil {
		return err
	}

	return a.svc.UpdateIssueStatus(ctx, issueID, models.IssueStatusIgnored, nil)
}

func (a *securityAdapter) ResolveIssue(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	issueID, err := parseIssueID(id)
	if err != nil {
		return err
	}

	return a.svc.UpdateIssueStatus(ctx, issueID, models.IssueStatusResolved, nil)
}

func (a *securityAdapter) GetTrends(ctx context.Context, days int) (*SecurityTrendsViewData, error) {
	if a.svc == nil {
		return nil, nil
	}
	if days <= 0 {
		days = 30
	}

	// Get score history (global average across all containers)
	points, err := a.svc.GetGlobalScoreHistory(ctx, days)
	if err != nil {
		return nil, err
	}

	history := make([]TrendPointView, 0, len(points))
	for _, p := range points {
		history = append(history, TrendPointView{
			Date:  p.Timestamp.Format("Jan 02"),
			Score: p.Value,
		})
	}

	// Get overview for summary
	overview, err := a.GetOverview(ctx)
	if err != nil {
		overview = &SecurityOverviewData{}
	}

	// Get per-container trends (latest scans)
	scans, _ := a.ListScans(ctx)
	containerTrends := make([]ContainerTrendViewData, 0, len(scans))
	for _, s := range scans {
		ct := ContainerTrendViewData{
			Name:         s.ContainerName,
			CurrentScore: s.Score,
			CurrentGrade: s.Grade,
		}
		// Get previous scan for this container to calculate change
		prevScans, _ := a.svc.GetContainerScans(ctx, s.ContainerID, 2)
		if len(prevScans) >= 2 {
			ct.PreviousScore = prevScans[1].Score
			ct.Change = ct.CurrentScore - ct.PreviousScore
		}
		containerTrends = append(containerTrends, ct)
	}

	return &SecurityTrendsViewData{
		Overview:        *overview,
		ScoreHistory:    history,
		ContainerTrends: containerTrends,
		Days:            days,
	}, nil
}

func (a *securityAdapter) GenerateReport(ctx context.Context, format string) ([]byte, string, error) {
	if a.svc == nil {
		return nil, "", fmt.Errorf("security service not available")
	}

	var reportFormat securitysvc.ReportFormat
	var contentType string

	switch format {
	case "html":
		reportFormat = securitysvc.ReportFormatHTML
		contentType = "text/html; charset=utf-8"
	case "json":
		reportFormat = securitysvc.ReportFormatJSON
		contentType = "application/json"
	case "markdown", "md":
		reportFormat = securitysvc.ReportFormatMarkdown
		contentType = "text/markdown; charset=utf-8"
	default:
		reportFormat = securitysvc.ReportFormatHTML
		contentType = "text/html; charset=utf-8"
	}

	opts := &securitysvc.ReportOptions{
		Format:          reportFormat,
		IncludeDetails:  true,
		GroupBySeverity: true,
		MinSeverity:     models.IssueSeverityLow,
	}

	data, err := a.svc.GenerateReport(ctx, resolveHostID(ctx, a.hostID), opts)
	if err != nil {
		return nil, "", err
	}

	return data, contentType, nil
}
