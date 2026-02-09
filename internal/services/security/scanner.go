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

// ScannerConfig holds configuration for the security scanner
type ScannerConfig struct {
	// Analyzers to use (nil for all defaults)
	Analyzers []Analyzer

	// Scoring configuration
	ScoreConfig *ScoreConfig

	// Timeout for scanning a single container
	ScanTimeout time.Duration

	// Whether to include CVE scanning (requires Trivy)
	IncludeCVE bool

	// Maximum concurrent scans
	MaxConcurrent int
}

// DefaultScannerConfig returns the default scanner configuration
func DefaultScannerConfig() *ScannerConfig {
	return &ScannerConfig{
		Analyzers:     nil, // Will use all defaults
		ScoreConfig:   DefaultScoreConfig(),
		ScanTimeout:   5 * time.Minute,
		IncludeCVE:    true,
		MaxConcurrent: 5,
	}
}

// Scanner performs security analysis on Docker containers
type Scanner struct {
	config      *ScannerConfig
	analyzers   []Analyzer
	calculator  *Calculator
	trivyClient TrivyClient // Optional CVE scanner
	mu          sync.RWMutex
}

// TrivyClient interface for CVE scanning (implemented separately)
type TrivyClient interface {
	ScanImage(ctx context.Context, image string) ([]Issue, error)
	IsAvailable() bool
}

// NewScanner creates a new security scanner
func NewScanner(config *ScannerConfig) *Scanner {
	if config == nil {
		config = DefaultScannerConfig()
	}

	s := &Scanner{
		config:     config,
		calculator: NewCalculator(config.ScoreConfig),
	}

	// Set up analyzers
	if config.Analyzers != nil {
		s.analyzers = config.Analyzers
	} else {
		// Use default analyzers - this will be populated from analyzer package
		s.analyzers = nil // Will be set when analyzer package is available
	}

	return s
}

// SetAnalyzers sets the analyzers to use
func (s *Scanner) SetAnalyzers(analyzers []Analyzer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.analyzers = analyzers
}

// SetTrivyClient sets the optional Trivy client for CVE scanning
func (s *Scanner) SetTrivyClient(client TrivyClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trivyClient = client
}

// IsTrivyAvailable returns true if Trivy is configured and available
func (s *Scanner) IsTrivyAvailable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.trivyClient != nil && s.trivyClient.IsAvailable()
}

// ScanResult holds the result of a security scan
type ScanResult struct {
	// Scan metadata
	ID            uuid.UUID     `json:"id"`
	ContainerID   string        `json:"container_id"`
	ContainerName string        `json:"container_name"`
	Image         string        `json:"image"`
	HostID        uuid.UUID     `json:"host_id"`

	// Score and grade
	Score int                  `json:"score"`
	Grade models.SecurityGrade `json:"grade"`

	// Issues found
	Issues       []Issue `json:"issues"`
	IssueCount   int     `json:"issue_count"`
	CriticalCount int    `json:"critical_count"`
	HighCount    int     `json:"high_count"`
	MediumCount  int     `json:"medium_count"`
	LowCount     int     `json:"low_count"`

	// CVE information (if scanned)
	CVECount   int  `json:"cve_count"`
	IncludeCVE bool `json:"include_cve"`

	// Timing
	ScanDuration time.Duration `json:"scan_duration"`
	ScannedAt    time.Time     `json:"scanned_at"`

	// Errors during scan (non-fatal)
	Warnings []string `json:"warnings,omitempty"`
}

// ScanContainer performs a security scan on a single container
func (s *Scanner) ScanContainer(ctx context.Context, inspect types.ContainerJSON, hostID uuid.UUID) (*ScanResult, error) {
	log := logger.FromContext(ctx)
	start := time.Now()

	// Create scan ID
	scanID := uuid.New()

	// Convert Docker inspect to our ContainerData
	data := ContainerDataFromInspect(inspect)

	log.Debug("Starting security scan",
		"scan_id", scanID,
		"container_id", data.ID,
		"container_name", data.Name,
		"image", data.Image)

	result := &ScanResult{
		ID:            scanID,
		ContainerID:   data.ID,
		ContainerName: data.Name,
		Image:         data.Image,
		HostID:        hostID,
		IncludeCVE:    s.config.IncludeCVE,
		ScannedAt:     time.Now(),
	}

	// Collect issues from all analyzers
	var allIssues []Issue
	var warnings []string

	s.mu.RLock()
	analyzers := s.analyzers
	trivyClient := s.trivyClient
	s.mu.RUnlock()

	// Run analyzers
	for _, analyzer := range analyzers {
		if !analyzer.IsEnabled() {
			continue
		}

		// Create timeout context for this analyzer
		analyzerCtx, cancel := context.WithTimeout(ctx, 30*time.Second)

		issues, err := analyzer.Analyze(analyzerCtx, data)
		cancel()

		if err != nil {
			warning := fmt.Sprintf("Analyzer %s failed: %v", analyzer.Name(), err)
			warnings = append(warnings, warning)
			log.Warn("Analyzer failed",
				"analyzer", analyzer.Name(),
				"container", data.Name,
				"error", err)
			continue
		}

		allIssues = append(allIssues, issues...)
	}

	// Run CVE scan if enabled and Trivy is available
	if s.config.IncludeCVE && trivyClient != nil && trivyClient.IsAvailable() {
		cveCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		cveIssues, err := trivyClient.ScanImage(cveCtx, data.Image)
		cancel()

		if err != nil {
			warning := fmt.Sprintf("CVE scan failed: %v", err)
			warnings = append(warnings, warning)
			log.Warn("CVE scan failed",
				"container", data.Name,
				"image", data.Image,
				"error", err)
		} else {
			allIssues = append(allIssues, cveIssues...)
			result.CVECount = len(cveIssues)
		}
	}

	// Calculate score
	scoreResult := s.calculator.Calculate(allIssues)

	// Populate result
	result.Score = scoreResult.Score
	result.Grade = scoreResult.Grade
	result.Issues = allIssues
	result.IssueCount = len(allIssues)
	result.CriticalCount = scoreResult.SeverityCounts[models.IssueSeverityCritical]
	result.HighCount = scoreResult.SeverityCounts[models.IssueSeverityHigh]
	result.MediumCount = scoreResult.SeverityCounts[models.IssueSeverityMedium]
	result.LowCount = scoreResult.SeverityCounts[models.IssueSeverityLow]
	result.ScanDuration = time.Since(start)
	result.Warnings = warnings

	log.Info("Security scan completed",
		"scan_id", scanID,
		"container", data.Name,
		"score", result.Score,
		"grade", result.Grade,
		"issues", result.IssueCount,
		"duration", result.ScanDuration)

	return result, nil
}

// ScanContainers performs security scans on multiple containers concurrently
func (s *Scanner) ScanContainers(ctx context.Context, containers []types.ContainerJSON, hostID uuid.UUID) ([]*ScanResult, error) {
	log := logger.FromContext(ctx)
	log.Info("Starting batch security scan", "container_count", len(containers))

	if len(containers) == 0 {
		return nil, nil
	}

	results := make([]*ScanResult, len(containers))
	errs := make([]error, len(containers))

	// Semaphore for limiting concurrency
	sem := make(chan struct{}, s.config.MaxConcurrent)
	var wg sync.WaitGroup

	for i, container := range containers {
		wg.Add(1)
		go func(idx int, c types.ContainerJSON) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check if context cancelled
			select {
			case <-ctx.Done():
				errs[idx] = ctx.Err()
				return
			default:
			}

			result, err := s.ScanContainer(ctx, c, hostID)
			if err != nil {
				errs[idx] = err
			} else {
				results[idx] = result
			}
		}(i, container)
	}

	wg.Wait()

	// Filter out nil results and collect errors
	var validResults []*ScanResult
	var scanErrors []string
	for i, result := range results {
		if result != nil {
			validResults = append(validResults, result)
		}
		if errs[i] != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("%s: %v", containers[i].Name, errs[i]))
		}
	}

	if len(scanErrors) > 0 {
		log.Warn("Some scans failed",
			"total", len(containers),
			"success", len(validResults),
			"failed", len(scanErrors))
	}

	log.Info("Batch security scan completed",
		"total", len(containers),
		"scanned", len(validResults))

	return validResults, nil
}

// ToSecurityScan converts a ScanResult to a models.SecurityScan
func (r *ScanResult) ToSecurityScan() *models.SecurityScan {
	return &models.SecurityScan{
		ID:            r.ID,
		HostID:        r.HostID,
		ContainerID:   r.ContainerID,
		ContainerName: r.ContainerName,
		Image:         r.Image,
		Score:         r.Score,
		Grade:         r.Grade,
		IssueCount:    r.IssueCount,
		CriticalCount: r.CriticalCount,
		HighCount:     r.HighCount,
		MediumCount:   r.MediumCount,
		LowCount:      r.LowCount,
		CVECount:      r.CVECount,
		IncludeCVE:    r.IncludeCVE,
		ScanDuration:  r.ScanDuration,
		CompletedAt:   r.ScannedAt,
		CreatedAt:     r.ScannedAt,
	}
}

// ToSecurityIssues converts issues to models.SecurityIssue
func (r *ScanResult) ToSecurityIssues() []models.SecurityIssue {
	issues := make([]models.SecurityIssue, len(r.Issues))

	for i, issue := range r.Issues {
		mi := models.SecurityIssue{
			ScanID:         r.ID,
			ContainerID:    r.ContainerID,
			HostID:         r.HostID,
			Severity:       issue.Severity,
			Category:       issue.Category,
			CheckID:        issue.CheckID,
			Title:          issue.Title,
			Description:    issue.Description,
			Recommendation: issue.Recommendation,
			Status:         models.IssueStatusOpen,
			DetectedAt:     r.ScannedAt,
		}

		if issue.FixCommand != "" {
			mi.FixCommand = &issue.FixCommand
		}
		if issue.DocURL != "" {
			mi.DocumentationURL = &issue.DocURL
		}

		// Extract CVE-specific fields from Details map
		if issue.Details != nil {
			if cveID, ok := issue.Details["cve_id"].(string); ok && cveID != "" {
				mi.CVEID = &cveID
			}
			if cvss, ok := issue.Details["cvss_score"].(float64); ok && cvss > 0 {
				mi.CVSSScore = &cvss
			}
		}

		issues[i] = mi
	}

	return issues
}

// QuickScan performs a quick scan returning only the score (no issues stored)
func (s *Scanner) QuickScan(ctx context.Context, inspect types.ContainerJSON) (int, models.SecurityGrade, error) {
	data := ContainerDataFromInspect(inspect)

	var allIssues []Issue

	s.mu.RLock()
	analyzers := s.analyzers
	s.mu.RUnlock()

	for _, analyzer := range analyzers {
		if !analyzer.IsEnabled() {
			continue
		}

		issues, err := analyzer.Analyze(ctx, data)
		if err != nil {
			continue // Skip failed analyzers in quick scan
		}

		allIssues = append(allIssues, issues...)
	}

	score, grade := CalculateSimple(allIssues)
	return score, grade, nil
}

// ValidateScanResult validates a scan result
func ValidateScanResult(result *ScanResult) error {
	if result == nil {
		return errors.New(errors.CodeValidationFailed, "scan result is nil")
	}
	if result.ContainerID == "" {
		return errors.New(errors.CodeValidationFailed, "container ID is required")
	}
	if result.Score < 0 || result.Score > 100 {
		return errors.New(errors.CodeValidationFailed, "score must be between 0 and 100")
	}
	return nil
}
