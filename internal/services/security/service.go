// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// DockerClient interface for Docker operations needed by security service
type DockerClient interface {
	ContainerInspect(ctx context.Context, containerID string) (interface{}, error)
	ContainerList(ctx context.Context, all bool) ([]interface{}, error)
}

// ScanRepository interface for persisting scan results
type ScanRepository interface {
	Create(ctx context.Context, scan *models.SecurityScan) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.SecurityScan, error)
	GetByContainerID(ctx context.Context, containerID string, limit int) ([]*models.SecurityScan, error)
	GetByHostID(ctx context.Context, hostID uuid.UUID, limit int) ([]*models.SecurityScan, error)
	GetLatestByContainer(ctx context.Context, containerID string) (*models.SecurityScan, error)
	List(ctx context.Context, opts ListScansOptions) ([]*models.SecurityScan, int, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteOlderThan(ctx context.Context, before time.Time) (int64, error)
	GetScoreHistory(ctx context.Context, containerID string, days int) ([]models.TrendPoint, error)
	GetGlobalScoreHistory(ctx context.Context, days int) ([]models.TrendPoint, error)
	GetAverageScore(ctx context.Context, hostID *uuid.UUID) (float64, error)
}

// IssueRepository interface for persisting security issues
type IssueRepository interface {
	CreateBatch(ctx context.Context, issues []models.SecurityIssue) error
	GetByID(ctx context.Context, id int64) (*models.SecurityIssue, error)
	GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*models.SecurityIssue, error)
	GetByContainerID(ctx context.Context, containerID string, status *models.IssueStatus) ([]*models.SecurityIssue, error)
	GetByHostID(ctx context.Context, hostID uuid.UUID, opts ListIssuesOptions) ([]*models.SecurityIssue, int, error)
	UpdateStatus(ctx context.Context, id int64, status models.IssueStatus, userID *uuid.UUID) error
	GetOpenIssueCount(ctx context.Context, containerID string) (int, error)
	DeleteByScanID(ctx context.Context, scanID uuid.UUID) error
}

// ListScansOptions holds options for listing scans
type ListScansOptions struct {
	HostID      *uuid.UUID
	ContainerID *string
	MinScore    *int
	MaxScore    *int
	Grade       *models.SecurityGrade
	Since       *time.Time
	Limit       int
	Offset      int
}

// ListIssuesOptions holds options for listing issues
type ListIssuesOptions struct {
	ContainerID *string
	ScanID      *uuid.UUID
	Severity    *models.IssueSeverity
	Category    *models.IssueCategory
	Status      *models.IssueStatus
	CheckID     *string
	Limit       int
	Offset      int
}

// ServiceConfig holds configuration for the security service
type ServiceConfig struct {
	// Scanner configuration
	ScannerConfig *ScannerConfig

	// Auto-scan interval (0 to disable)
	AutoScanInterval time.Duration

	// Retention period for scan history
	ScanRetentionDays int

	// Maximum scans to keep per container
	MaxScansPerContainer int
}

// DefaultServiceConfig returns the default service configuration
func DefaultServiceConfig() *ServiceConfig {
	return &ServiceConfig{
		ScannerConfig:        DefaultScannerConfig(),
		AutoScanInterval:     6 * time.Hour,
		ScanRetentionDays:    30,
		MaxScansPerContainer: 10,
	}
}

// Service provides security scanning functionality
type Service struct {
	config     *ServiceConfig
	scanner    *Scanner
	scanRepo   ScanRepository
	issueRepo  IssueRepository
	logger     *logger.Logger

	// For auto-scan background job
	stopChan chan struct{}
	wg       sync.WaitGroup
	mu       sync.RWMutex
	running  bool
}

// NewService creates a new security service
func NewService(
	config *ServiceConfig,
	scanRepo ScanRepository,
	issueRepo IssueRepository,
	log *logger.Logger,
) *Service {
	if config == nil {
		config = DefaultServiceConfig()
	}

	scanner := NewScanner(config.ScannerConfig)

	return &Service{
		config:    config,
		scanner:   scanner,
		scanRepo:  scanRepo,
		issueRepo: issueRepo,
		logger:    log.Named("security"),
		stopChan:  make(chan struct{}),
	}
}

// SetAnalyzers sets the analyzers to use
func (s *Service) SetAnalyzers(analyzers []Analyzer) {
	s.scanner.SetAnalyzers(analyzers)
}

// SetTrivyClient sets the Trivy client for CVE scanning
func (s *Service) SetTrivyClient(client TrivyClient) {
	s.scanner.SetTrivyClient(client)
}

// IsTrivyAvailable returns true if Trivy is configured and available
func (s *Service) IsTrivyAvailable() bool {
	return s.scanner.IsTrivyAvailable()
}

// ScanContainer performs a security scan on a container and persists results.
// It accepts either a types.ContainerJSON directly or a *types.ContainerJSON pointer
// and delegates to ScanContainerJSON for the actual scan.
func (s *Service) ScanContainer(ctx context.Context, containerInspect interface{}, hostID uuid.UUID) (*models.SecurityScan, error) {
	log := logger.FromContext(ctx)

	// Try direct type assertion to types.ContainerJSON
	switch v := containerInspect.(type) {
	case types.ContainerJSON:
		log.Info("Scanning container",
			"container_id", v.ID,
			"container_name", v.Name,
			"host_id", hostID)
		return s.ScanContainerJSON(ctx, v, hostID)

	case *types.ContainerJSON:
		if v == nil {
			return nil, errors.New(errors.CodeInvalidInput, "container inspect data is nil")
		}
		log.Info("Scanning container",
			"container_id", v.ID,
			"container_name", v.Name,
			"host_id", hostID)
		return s.ScanContainerJSON(ctx, *v, hostID)

	default:
		return nil, errors.New(errors.CodeInvalidInput,
			fmt.Sprintf("unsupported container inspect type %T: expected types.ContainerJSON or *types.ContainerJSON", containerInspect))
	}
}

// ScanContainerJSON performs a scan using Docker types.ContainerJSON and persists results
func (s *Service) ScanContainerJSON(ctx context.Context, containerJSON types.ContainerJSON, hostID uuid.UUID) (*models.SecurityScan, error) {
	log := logger.FromContext(ctx)

	result, err := s.scanner.ScanContainer(ctx, containerJSON, hostID)
	if err != nil {
		return nil, fmt.Errorf("scan failed for %s: %w", containerJSON.Name, err)
	}

	// Persist scan + issues
	if err := s.SaveScanResult(ctx, result); err != nil {
		log.Error("Failed to save scan result", "container", containerJSON.Name, "error", err)
		return nil, err
	}

	// Return the scan with issues loaded
	scan := result.ToSecurityScan()
	issues := result.ToSecurityIssues()
	scan.Issues = issues

	return scan, nil
}

// GetScan retrieves a scan by ID
func (s *Service) GetScan(ctx context.Context, id uuid.UUID) (*models.SecurityScan, error) {
	scan, err := s.scanRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Load issues
	issues, err := s.issueRepo.GetByScanID(ctx, id)
	if err != nil {
		s.logger.Warn("Failed to load issues for scan", "scan_id", id, "error", err)
	} else {
		scan.Issues = make([]models.SecurityIssue, len(issues))
		for i, issue := range issues {
			scan.Issues[i] = *issue
		}
	}

	return scan, nil
}

// GetLatestScan retrieves the most recent scan for a container
func (s *Service) GetLatestScan(ctx context.Context, containerID string) (*models.SecurityScan, error) {
	scan, err := s.scanRepo.GetLatestByContainer(ctx, containerID)
	if err != nil {
		return nil, err
	}

	if scan != nil {
		// Load issues
		issues, err := s.issueRepo.GetByScanID(ctx, scan.ID)
		if err == nil {
			scan.Issues = make([]models.SecurityIssue, len(issues))
			for i, issue := range issues {
				scan.Issues[i] = *issue
			}
		}
	}

	return scan, nil
}

// ListScans lists security scans with filtering
func (s *Service) ListScans(ctx context.Context, opts ListScansOptions) ([]*models.SecurityScan, int, error) {
	return s.scanRepo.List(ctx, opts)
}

// GetContainerScans retrieves scans for a specific container
func (s *Service) GetContainerScans(ctx context.Context, containerID string, limit int) ([]*models.SecurityScan, error) {
	if limit <= 0 {
		limit = 10
	}
	return s.scanRepo.GetByContainerID(ctx, containerID, limit)
}

// GetHostScans retrieves scans for all containers on a host
func (s *Service) GetHostScans(ctx context.Context, hostID uuid.UUID, limit int) ([]*models.SecurityScan, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.scanRepo.GetByHostID(ctx, hostID, limit)
}

// GetScoreHistory retrieves the score history for a container over N days.
// If containerID is empty, returns average scores across all containers.
func (s *Service) GetScoreHistory(ctx context.Context, containerID string, days int) ([]models.TrendPoint, error) {
	if days <= 0 {
		days = 30
	}
	return s.scanRepo.GetScoreHistory(ctx, containerID, days)
}

// GetGlobalScoreHistory returns average score across all containers over N days.
func (s *Service) GetGlobalScoreHistory(ctx context.Context, days int) ([]models.TrendPoint, error) {
	if days <= 0 {
		days = 30
	}
	return s.scanRepo.GetGlobalScoreHistory(ctx, days)
}

// GetAverageScore returns the current average security score
func (s *Service) GetAverageScore(ctx context.Context, hostID *uuid.UUID) (float64, error) {
	return s.scanRepo.GetAverageScore(ctx, hostID)
}

// GenerateReport generates a security report in the specified format
func (s *Service) GenerateReport(ctx context.Context, hostID uuid.UUID, opts *ReportOptions) ([]byte, error) {
	if opts == nil {
		opts = DefaultReportOptions()
	}

	// Get latest scans for all containers
	scans, err := s.scanRepo.GetByHostID(ctx, hostID, 200)
	if err != nil {
		return nil, err
	}

	// Build report data
	reportData := &ReportData{
		ID:                uuid.New(),
		GeneratedAt:       time.Now(),
		Title:             "Security Report",
		TotalContainers:   len(scans),
		ScannedContainers: len(scans),
		GradeDistribution: make(map[models.SecurityGrade]int),
		SeverityCounts:    make(map[models.IssueSeverity]int),
		Containers:        make([]ContainerReportData, 0, len(scans)),
	}

	var totalScore int
	lowest := 100
	highest := 0

	for _, scan := range scans {
		issues, _ := s.issueRepo.GetByScanID(ctx, scan.ID)

		crd := ContainerReportData{
			ContainerID:   scan.ContainerID,
			ContainerName: scan.ContainerName,
			Image:         scan.Image,
			Score:         scan.Score,
			Grade:         scan.Grade,
			IssueCount:    scan.IssueCount,
			CriticalCount: scan.CriticalCount,
			HighCount:     scan.HighCount,
			MediumCount:   scan.MediumCount,
			LowCount:      scan.LowCount,
			ScannedAt:     scan.CompletedAt,
			Issues:        make([]IssueReportData, 0, len(issues)),
		}

		for _, issue := range issues {
			ird := IssueReportData{
				ID:             fmt.Sprintf("%d", issue.ID),
				ContainerName:  scan.ContainerName,
				Severity:       issue.Severity,
				Category:       issue.Category,
				Title:          issue.Title,
				Description:    issue.Description,
				Recommendation: issue.Recommendation,
			}
			if issue.FixCommand != nil {
				ird.FixCommand = *issue.FixCommand
			}
			if issue.DocumentationURL != nil {
				ird.DocURL = *issue.DocumentationURL
			}
			if issue.CVEID != nil {
				ird.CVEID = *issue.CVEID
			}
			if issue.CVSSScore != nil {
				ird.CVSSScore = *issue.CVSSScore
			}
			crd.Issues = append(crd.Issues, ird)

			reportData.SeverityCounts[issue.Severity]++
			reportData.TotalIssues++
		}

		reportData.Containers = append(reportData.Containers, crd)
		reportData.GradeDistribution[scan.Grade]++
		totalScore += scan.Score
		if scan.Score < lowest {
			lowest = scan.Score
		}
		if scan.Score > highest {
			highest = scan.Score
		}
	}

	if len(scans) > 0 {
		reportData.AverageScore = float64(totalScore) / float64(len(scans))
		reportData.LowestScore = lowest
		reportData.HighestScore = highest
	}

	generator := NewReportGenerator()
	return generator.Generate(ctx, reportData, opts)
}

// UpdateIssueStatus updates the status of a security issue
func (s *Service) UpdateIssueStatus(ctx context.Context, issueID int64, status models.IssueStatus, userID *uuid.UUID) error {
	log := logger.FromContext(ctx)

	// Validate status
	validStatuses := map[models.IssueStatus]bool{
		models.IssueStatusAcknowledged:  true,
		models.IssueStatusResolved:      true,
		models.IssueStatusIgnored:       true,
		models.IssueStatusFalsePositive: true,
	}

	if !validStatuses[status] {
		return errors.New(errors.CodeInvalidInput, "invalid status")
	}

	err := s.issueRepo.UpdateStatus(ctx, issueID, status, userID)
	if err != nil {
		return err
	}

	log.Info("Issue status updated",
		"issue_id", issueID,
		"status", status,
		"user_id", userID)

	return nil
}

// GetIssue retrieves a security issue by ID
func (s *Service) GetIssue(ctx context.Context, id int64) (*models.SecurityIssue, error) {
	return s.issueRepo.GetByID(ctx, id)
}

// GetContainerIssues retrieves open issues for a container
func (s *Service) GetContainerIssues(ctx context.Context, containerID string, status *models.IssueStatus) ([]*models.SecurityIssue, error) {
	return s.issueRepo.GetByContainerID(ctx, containerID, status)
}

// GetHostIssues retrieves issues for a host
func (s *Service) GetHostIssues(ctx context.Context, hostID uuid.UUID, opts ListIssuesOptions) ([]*models.SecurityIssue, int, error) {
	return s.issueRepo.GetByHostID(ctx, hostID, opts)
}

// DeleteScan deletes a scan and its associated issues
func (s *Service) DeleteScan(ctx context.Context, id uuid.UUID) error {
	log := logger.FromContext(ctx)

	// Delete issues first
	if err := s.issueRepo.DeleteByScanID(ctx, id); err != nil {
		log.Warn("Failed to delete issues for scan", "scan_id", id, "error", err)
	}

	// Delete scan
	if err := s.scanRepo.Delete(ctx, id); err != nil {
		return err
	}

	log.Info("Scan deleted", "scan_id", id)
	return nil
}

// CleanupOldScans removes scans older than the retention period
func (s *Service) CleanupOldScans(ctx context.Context) (int64, error) {
	if s.config.ScanRetentionDays <= 0 {
		return 0, nil
	}

	cutoff := time.Now().AddDate(0, 0, -s.config.ScanRetentionDays)

	deleted, err := s.scanRepo.DeleteOlderThan(ctx, cutoff)
	if err != nil {
		return 0, err
	}

	if deleted > 0 {
		s.logger.Info("Cleaned up old scans",
			"deleted", deleted,
			"older_than", cutoff)
	}

	return deleted, nil
}

// GetSecuritySummary returns a summary of security status
func (s *Service) GetSecuritySummary(ctx context.Context, hostID *uuid.UUID) (*SecuritySummary, error) {
	summary := &SecuritySummary{
		GeneratedAt:       time.Now(),
		GradeDistribution: make(map[models.SecurityGrade]int),
		SeverityCounts:    make(map[models.IssueSeverity]int),
	}

	// Get recent scans
	opts := ListScansOptions{
		HostID: hostID,
		Limit:  1000,
	}

	scans, _, err := s.scanRepo.List(ctx, opts)
	if err != nil {
		return nil, err
	}

	if len(scans) == 0 {
		return summary, nil
	}

	// Calculate statistics
	totalScore := 0
	latestScans := make(map[string]*models.SecurityScan)

	for _, scan := range scans {
		// Keep only latest scan per container
		existing, exists := latestScans[scan.ContainerID]
		if !exists || scan.CreatedAt.After(existing.CreatedAt) {
			latestScans[scan.ContainerID] = scan
		}
	}

	for _, scan := range latestScans {
		totalScore += scan.Score
		summary.GradeDistribution[scan.Grade]++
		summary.TotalContainers++

		summary.SeverityCounts[models.IssueSeverityCritical] += scan.CriticalCount
		summary.SeverityCounts[models.IssueSeverityHigh] += scan.HighCount
		summary.SeverityCounts[models.IssueSeverityMedium] += scan.MediumCount
		summary.SeverityCounts[models.IssueSeverityLow] += scan.LowCount
	}

	if summary.TotalContainers > 0 {
		summary.AverageScore = float64(totalScore) / float64(summary.TotalContainers)
	}

	summary.TotalIssues = summary.SeverityCounts[models.IssueSeverityCritical] +
		summary.SeverityCounts[models.IssueSeverityHigh] +
		summary.SeverityCounts[models.IssueSeverityMedium] +
		summary.SeverityCounts[models.IssueSeverityLow]

	return summary, nil
}

// SecuritySummary holds aggregated security statistics
type SecuritySummary struct {
	GeneratedAt       time.Time                     `json:"generated_at"`
	TotalContainers   int                           `json:"total_containers"`
	TotalIssues       int                           `json:"total_issues"`
	AverageScore      float64                       `json:"average_score"`
	GradeDistribution map[models.SecurityGrade]int  `json:"grade_distribution"`
	SeverityCounts    map[models.IssueSeverity]int  `json:"severity_counts"`
}

// SaveScanResult persists a scan result to the database
func (s *Service) SaveScanResult(ctx context.Context, result *ScanResult) error {
	if err := ValidateScanResult(result); err != nil {
		return err
	}

	// Save scan
	scan := result.ToSecurityScan()
	if err := s.scanRepo.Create(ctx, scan); err != nil {
		return fmt.Errorf("failed to save scan: %w", err)
	}

	// Save issues
	if len(result.Issues) > 0 {
		issues := result.ToSecurityIssues()
		if err := s.issueRepo.CreateBatch(ctx, issues); err != nil {
			s.logger.Error("Failed to save issues",
				"scan_id", result.ID,
				"error", err)
			// Don't return error - scan is saved
		}
	}

	return nil
}

// GetScanner returns the underlying scanner for direct access
func (s *Service) GetScanner() *Scanner {
	return s.scanner
}
