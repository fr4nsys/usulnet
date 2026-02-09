// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// SecurityService interface for security scanning operations (from Dept F)
type SecurityService interface {
	// ScanContainer scans a single container
	ScanContainer(ctx context.Context, containerInspect interface{}, hostID uuid.UUID) (*models.SecurityScan, error)

	// GetLatestScan retrieves the most recent scan for a container
	GetLatestScan(ctx context.Context, containerID string) (*models.SecurityScan, error)

	// GetSecuritySummary returns aggregated security stats
	GetSecuritySummary(ctx context.Context, hostID *uuid.UUID) (*SecuritySummary, error)
}

// SecuritySummary holds aggregated security statistics
type SecuritySummary struct {
	TotalContainers   int                          `json:"total_containers"`
	TotalIssues       int                          `json:"total_issues"`
	AverageScore      float64                      `json:"average_score"`
	GradeDistribution map[models.SecurityGrade]int `json:"grade_distribution"`
}

// DockerClientForScan interface for Docker operations needed by security worker
type DockerClientForScan interface {
	ContainerInspect(ctx context.Context, containerID string) (interface{}, error)
	ContainerList(ctx context.Context, all bool) ([]ContainerBasicInfo, error)
}

// ContainerBasicInfo holds basic container info for listing
type ContainerBasicInfo struct {
	ID     string
	Name   string
	Image  string
	State  string
	Status string
}

// SecurityScanWorker handles security scanning jobs
type SecurityScanWorker struct {
	BaseWorker
	securityService SecurityService
	dockerClient    DockerClientForScan
	logger          *logger.Logger
}

// NewSecurityScanWorker creates a new security scan worker
func NewSecurityScanWorker(
	securityService SecurityService,
	dockerClient DockerClientForScan,
	log *logger.Logger,
) *SecurityScanWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &SecurityScanWorker{
		BaseWorker:      NewBaseWorker(models.JobTypeSecurityScan),
		securityService: securityService,
		dockerClient:    dockerClient,
		logger:          log.Named("security-scan-worker"),
	}
}

// Execute performs the security scan job
func (w *SecurityScanWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	// Parse payload
	var payload models.SecurityScanPayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse payload")
	}

	// Get host ID
	hostID := job.HostID
	if hostID == nil {
		return nil, errors.New(errors.CodeValidation, "host_id is required for security scan")
	}

	log.Info("starting security scan",
		"host_id", hostID,
		"container_id", payload.ContainerID,
		"scan_all", payload.ScanAll,
		"include_cve", payload.IncludeCVE,
	)

	result := &SecurityScanResult{
		HostID:    *hostID,
		StartedAt: time.Now(),
		Scans:     make([]*ScanResultItem, 0),
	}

	if payload.ScanAll {
		// Scan all containers on host
		if err := w.scanAllContainers(ctx, job, *hostID, payload.IncludeCVE, result); err != nil {
			return result, err
		}
	} else if payload.ContainerID != "" {
		// Scan specific container
		if err := w.scanContainer(ctx, job, *hostID, payload.ContainerID, payload.IncludeCVE, result); err != nil {
			return result, err
		}
	} else {
		return nil, errors.New(errors.CodeValidation, "either container_id or scan_all must be specified")
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	// Calculate summary
	w.calculateSummary(result)

	log.Info("security scan completed",
		"scanned", result.TotalScanned,
		"passed", result.Passed,
		"failed", result.Failed,
		"avg_score", result.AverageScore,
		"duration", result.Duration,
	)

	return result, nil
}

func (w *SecurityScanWorker) scanAllContainers(
	ctx context.Context,
	job *models.Job,
	hostID uuid.UUID,
	includeCVE bool,
	result *SecurityScanResult,
) error {
	// List all containers
	containers, err := w.dockerClient.ContainerList(ctx, true)
	if err != nil {
		return errors.Wrap(err, errors.CodeDocker, "failed to list containers")
	}

	if len(containers) == 0 {
		w.logger.Info("no containers found to scan")
		return nil
	}

	result.TotalContainers = len(containers)

	// Report progress
	reportProgress := func(current int, containerName string) {
		progress := (current * 100) / len(containers)
		if job.ProgressMessage != nil {
			// Progress callback is handled by pool
		}
		job.Progress = progress
		msg := fmt.Sprintf("Scanning %s (%d/%d)", containerName, current, len(containers))
		job.ProgressMessage = &msg
	}

	// Scan each container
	for i, container := range containers {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		reportProgress(i+1, container.Name)

		scanItem := &ScanResultItem{
			ContainerID:   container.ID,
			ContainerName: container.Name,
			Image:         container.Image,
		}

		// Inspect container
		inspect, err := w.dockerClient.ContainerInspect(ctx, container.ID)
		if err != nil {
			scanItem.Error = fmt.Sprintf("failed to inspect: %v", err)
			scanItem.Success = false
			result.Scans = append(result.Scans, scanItem)
			result.Failed++
			continue
		}

		// Perform scan
		scan, err := w.securityService.ScanContainer(ctx, inspect, hostID)
		if err != nil {
			scanItem.Error = fmt.Sprintf("scan failed: %v", err)
			scanItem.Success = false
			result.Scans = append(result.Scans, scanItem)
			result.Failed++
			continue
		}

		scanItem.Success = true
		scanItem.ScanID = scan.ID
		scanItem.Score = scan.Score
		scanItem.Grade = scan.Grade
		scanItem.IssueCount = scan.CriticalCount + scan.HighCount + scan.MediumCount + scan.LowCount
		scanItem.CriticalCount = scan.CriticalCount
		scanItem.HighCount = scan.HighCount
		scanItem.MediumCount = scan.MediumCount
		scanItem.LowCount = scan.LowCount

		result.Scans = append(result.Scans, scanItem)
		result.Passed++
	}

	return nil
}

func (w *SecurityScanWorker) scanContainer(
	ctx context.Context,
	job *models.Job,
	hostID uuid.UUID,
	containerID string,
	includeCVE bool,
	result *SecurityScanResult,
) error {
	result.TotalContainers = 1

	scanItem := &ScanResultItem{
		ContainerID: containerID,
	}

	// Inspect container
	inspect, err := w.dockerClient.ContainerInspect(ctx, containerID)
	if err != nil {
		scanItem.Error = fmt.Sprintf("failed to inspect: %v", err)
		scanItem.Success = false
		result.Scans = append(result.Scans, scanItem)
		result.Failed++
		return errors.Wrap(err, errors.CodeDocker, "failed to inspect container")
	}

	// Update progress
	job.Progress = 50
	msg := fmt.Sprintf("Scanning container %s", containerID[:12])
	job.ProgressMessage = &msg

	// Perform scan
	scan, err := w.securityService.ScanContainer(ctx, inspect, hostID)
	if err != nil {
		scanItem.Error = fmt.Sprintf("scan failed: %v", err)
		scanItem.Success = false
		result.Scans = append(result.Scans, scanItem)
		result.Failed++
		return errors.Wrap(err, errors.CodeInternal, "security scan failed")
	}

	scanItem.Success = true
	scanItem.ScanID = scan.ID
	scanItem.ContainerName = scan.ContainerName
	scanItem.Image = scan.Image
	scanItem.Score = scan.Score
	scanItem.Grade = scan.Grade
	scanItem.IssueCount = scan.CriticalCount + scan.HighCount + scan.MediumCount + scan.LowCount
	scanItem.CriticalCount = scan.CriticalCount
	scanItem.HighCount = scan.HighCount
	scanItem.MediumCount = scan.MediumCount
	scanItem.LowCount = scan.LowCount

	result.Scans = append(result.Scans, scanItem)
	result.Passed++

	return nil
}

func (w *SecurityScanWorker) calculateSummary(result *SecurityScanResult) {
	result.TotalScanned = len(result.Scans)

	if result.TotalScanned == 0 {
		return
	}

	totalScore := 0
	result.GradeDistribution = make(map[models.SecurityGrade]int)

	for _, scan := range result.Scans {
		if scan.Success {
			totalScore += scan.Score
			result.GradeDistribution[scan.Grade]++
			result.TotalIssues += scan.IssueCount
			result.CriticalIssues += scan.CriticalCount
			result.HighIssues += scan.HighCount
			result.MediumIssues += scan.MediumCount
			result.LowIssues += scan.LowCount
		}
	}

	if result.Passed > 0 {
		result.AverageScore = float64(totalScore) / float64(result.Passed)
	}
}

// SecurityScanResult holds the result of a security scan job
type SecurityScanResult struct {
	HostID          uuid.UUID                    `json:"host_id"`
	StartedAt       time.Time                    `json:"started_at"`
	CompletedAt     time.Time                    `json:"completed_at"`
	Duration        time.Duration                `json:"duration"`
	TotalContainers int                          `json:"total_containers"`
	TotalScanned    int                          `json:"total_scanned"`
	Passed          int                          `json:"passed"`
	Failed          int                          `json:"failed"`
	AverageScore    float64                      `json:"average_score"`
	TotalIssues     int                          `json:"total_issues"`
	CriticalIssues  int                          `json:"critical_issues"`
	HighIssues      int                          `json:"high_issues"`
	MediumIssues    int                          `json:"medium_issues"`
	LowIssues       int                          `json:"low_issues"`
	GradeDistribution map[models.SecurityGrade]int `json:"grade_distribution"`
	Scans           []*ScanResultItem            `json:"scans"`
}

// ScanResultItem holds the result of scanning a single container
type ScanResultItem struct {
	ContainerID   string               `json:"container_id"`
	ContainerName string               `json:"container_name"`
	Image         string               `json:"image"`
	Success       bool                 `json:"success"`
	Error         string               `json:"error,omitempty"`
	ScanID        uuid.UUID            `json:"scan_id,omitempty"`
	Score         int                  `json:"score"`
	Grade         models.SecurityGrade `json:"grade"`
	IssueCount    int                  `json:"issue_count"`
	CriticalCount int                  `json:"critical_count"`
	HighCount     int                  `json:"high_count"`
	MediumCount   int                  `json:"medium_count"`
	LowCount      int                  `json:"low_count"`
}
