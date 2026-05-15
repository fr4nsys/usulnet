// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package security

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

type mockScanRepo struct {
	scans       []*models.SecurityScan
	createErr   error
	deleteErr   error
	cleanupErr  error
	listErr     error
	getByIDErr  error
	avgScore    float64
	avgScoreErr error
}

func (r *mockScanRepo) Create(_ context.Context, scan *models.SecurityScan) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.scans = append(r.scans, scan)
	return nil
}

func (r *mockScanRepo) GetByID(_ context.Context, id uuid.UUID) (*models.SecurityScan, error) {
	if r.getByIDErr != nil {
		return nil, r.getByIDErr
	}
	for _, s := range r.scans {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, errors.New("scan not found")
}

func (r *mockScanRepo) GetByContainerID(_ context.Context, containerID string, limit int) ([]*models.SecurityScan, error) {
	var result []*models.SecurityScan
	for _, s := range r.scans {
		if s.ContainerID == containerID {
			result = append(result, s)
			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func (r *mockScanRepo) GetByHostID(_ context.Context, hostID uuid.UUID, limit int) ([]*models.SecurityScan, error) {
	var result []*models.SecurityScan
	for _, s := range r.scans {
		if s.HostID == hostID {
			result = append(result, s)
			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func (r *mockScanRepo) GetLatestByContainer(_ context.Context, containerID string) (*models.SecurityScan, error) {
	var latest *models.SecurityScan
	for _, s := range r.scans {
		if s.ContainerID == containerID {
			if latest == nil || s.CreatedAt.After(latest.CreatedAt) {
				latest = s
			}
		}
	}
	return latest, nil
}

func (r *mockScanRepo) List(_ context.Context, opts ListScansOptions) ([]*models.SecurityScan, int, error) {
	if r.listErr != nil {
		return nil, 0, r.listErr
	}
	var result []*models.SecurityScan
	for _, s := range r.scans {
		if opts.HostID != nil && s.HostID != *opts.HostID {
			continue
		}
		if opts.ContainerID != nil && s.ContainerID != *opts.ContainerID {
			continue
		}
		result = append(result, s)
	}
	return result, len(result), nil
}

func (r *mockScanRepo) Delete(_ context.Context, id uuid.UUID) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	for i, s := range r.scans {
		if s.ID == id {
			r.scans = append(r.scans[:i], r.scans[i+1:]...)
			return nil
		}
	}
	return errors.New("scan not found")
}

func (r *mockScanRepo) DeleteOlderThan(_ context.Context, before time.Time) (int64, error) {
	if r.cleanupErr != nil {
		return 0, r.cleanupErr
	}
	var kept []*models.SecurityScan
	var deleted int64
	for _, s := range r.scans {
		if s.CreatedAt.Before(before) {
			deleted++
		} else {
			kept = append(kept, s)
		}
	}
	r.scans = kept
	return deleted, nil
}

func (r *mockScanRepo) GetScoreHistory(_ context.Context, _ string, _ int) ([]models.TrendPoint, error) {
	return []models.TrendPoint{{Timestamp: time.Now(), Value: 85.0}}, nil
}

func (r *mockScanRepo) GetGlobalScoreHistory(_ context.Context, _ int) ([]models.TrendPoint, error) {
	return []models.TrendPoint{{Timestamp: time.Now(), Value: 80.0}}, nil
}

func (r *mockScanRepo) GetAverageScore(_ context.Context, _ *uuid.UUID) (float64, error) {
	return r.avgScore, r.avgScoreErr
}

// ---------------------------------------------------------------------------

type mockIssueRepo struct {
	issues      []*models.SecurityIssue
	createErr   error
	updateErr   error
	deleteErr   error
	getByIDErr  error
	nextIssueID int64
}

func (r *mockIssueRepo) CreateBatch(_ context.Context, issues []models.SecurityIssue) error {
	if r.createErr != nil {
		return r.createErr
	}
	for i := range issues {
		r.nextIssueID++
		issues[i].ID = r.nextIssueID
		r.issues = append(r.issues, &issues[i])
	}
	return nil
}

func (r *mockIssueRepo) GetByID(_ context.Context, id int64) (*models.SecurityIssue, error) {
	if r.getByIDErr != nil {
		return nil, r.getByIDErr
	}
	for _, issue := range r.issues {
		if issue.ID == id {
			return issue, nil
		}
	}
	return nil, errors.New("issue not found")
}

func (r *mockIssueRepo) GetByScanID(_ context.Context, scanID uuid.UUID) ([]*models.SecurityIssue, error) {
	var result []*models.SecurityIssue
	for _, issue := range r.issues {
		if issue.ScanID == scanID {
			result = append(result, issue)
		}
	}
	return result, nil
}

func (r *mockIssueRepo) GetByContainerID(_ context.Context, containerID string, status *models.IssueStatus) ([]*models.SecurityIssue, error) {
	var result []*models.SecurityIssue
	for _, issue := range r.issues {
		if issue.ContainerID == containerID {
			if status != nil && issue.Status != *status {
				continue
			}
			result = append(result, issue)
		}
	}
	return result, nil
}

func (r *mockIssueRepo) GetByHostID(_ context.Context, hostID uuid.UUID, _ ListIssuesOptions) ([]*models.SecurityIssue, int, error) {
	var result []*models.SecurityIssue
	for _, issue := range r.issues {
		if issue.HostID == hostID {
			result = append(result, issue)
		}
	}
	return result, len(result), nil
}

func (r *mockIssueRepo) UpdateStatus(_ context.Context, id int64, status models.IssueStatus, userID *uuid.UUID) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	for _, issue := range r.issues {
		if issue.ID == id {
			issue.Status = status
			if userID != nil {
				issue.AcknowledgedBy = userID
			}
			return nil
		}
	}
	return errors.New("issue not found")
}

func (r *mockIssueRepo) GetOpenIssueCount(_ context.Context, containerID string) (int, error) {
	count := 0
	for _, issue := range r.issues {
		if issue.ContainerID == containerID && issue.Status == models.IssueStatusOpen {
			count++
		}
	}
	return count, nil
}

func (r *mockIssueRepo) DeleteByScanID(_ context.Context, scanID uuid.UUID) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	var kept []*models.SecurityIssue
	for _, issue := range r.issues {
		if issue.ScanID != scanID {
			kept = append(kept, issue)
		}
	}
	r.issues = kept
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestService(scanRepo *mockScanRepo, issueRepo *mockIssueRepo) *Service {
	return NewService(nil, scanRepo, issueRepo, logger.Nop())
}

func testScan(containerID string, score int, grade models.SecurityGrade) *models.SecurityScan {
	return &models.SecurityScan{
		ID:            uuid.New(),
		HostID:        uuid.New(),
		ContainerID:   containerID,
		ContainerName: "test-" + containerID,
		Image:         "alpine:latest",
		Score:         score,
		Grade:         grade,
		IssueCount:    2,
		CriticalCount: 1,
		HighCount:     1,
		CreatedAt:     time.Now(),
		CompletedAt:   time.Now(),
	}
}

func testIssue(scanID uuid.UUID, containerID string, hostID uuid.UUID, severity models.IssueSeverity) *models.SecurityIssue {
	return &models.SecurityIssue{
		ScanID:      scanID,
		ContainerID: containerID,
		HostID:      hostID,
		Severity:    severity,
		Category:    models.IssueCategorySecurity,
		CheckID:     "TEST-001",
		Title:       "Test issue",
		Description: "A test issue",
		Status:      models.IssueStatusOpen,
		DetectedAt:  time.Now(),
	}
}

// ---------------------------------------------------------------------------
// Tests: GetScan
// ---------------------------------------------------------------------------

func TestGetScan_LoadsIssues(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	scan := testScan("ctr1", 85, models.SecurityGradeB)
	scanRepo.scans = append(scanRepo.scans, scan)

	issue := testIssue(scan.ID, "ctr1", scan.HostID, models.IssueSeverityHigh)
	issue.ID = 1
	issueRepo.issues = append(issueRepo.issues, issue)

	result, err := svc.GetScan(context.Background(), scan.ID)
	if err != nil {
		t.Fatalf("GetScan() error: %v", err)
	}
	if result.ID != scan.ID {
		t.Errorf("scan ID = %v, want %v", result.ID, scan.ID)
	}
	if len(result.Issues) != 1 {
		t.Errorf("issues loaded = %d, want 1", len(result.Issues))
	}
}

func TestGetScan_NotFound(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	_, err := svc.GetScan(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("GetScan() expected error for missing scan")
	}
}

// ---------------------------------------------------------------------------
// Tests: GetLatestScan
// ---------------------------------------------------------------------------

func TestGetLatestScan_ReturnsLatest(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	old := testScan("ctr1", 70, models.SecurityGradeC)
	old.CreatedAt = time.Now().Add(-1 * time.Hour)
	recent := testScan("ctr1", 90, models.SecurityGradeA)
	recent.CreatedAt = time.Now()

	scanRepo.scans = append(scanRepo.scans, old, recent)

	result, err := svc.GetLatestScan(context.Background(), "ctr1")
	if err != nil {
		t.Fatalf("GetLatestScan() error: %v", err)
	}
	if result.ID != recent.ID {
		t.Errorf("got scan %v, want latest %v", result.ID, recent.ID)
	}
}

func TestGetLatestScan_NoScans(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	result, err := svc.GetLatestScan(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("GetLatestScan() error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil for missing container, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// Tests: GetContainerScans / GetHostScans default limits
// ---------------------------------------------------------------------------

func TestGetContainerScans_DefaultLimit(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	for i := 0; i < 15; i++ {
		scanRepo.scans = append(scanRepo.scans, testScan("ctr1", 80, models.SecurityGradeB))
	}

	// limit <= 0 should default to 10
	result, err := svc.GetContainerScans(context.Background(), "ctr1", 0)
	if err != nil {
		t.Fatalf("GetContainerScans() error: %v", err)
	}
	if len(result) != 10 {
		t.Errorf("got %d scans, want 10 (default limit)", len(result))
	}
}

func TestGetHostScans_DefaultLimit(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	hostID := uuid.New()
	for i := 0; i < 5; i++ {
		s := testScan("ctr1", 80, models.SecurityGradeB)
		s.HostID = hostID
		scanRepo.scans = append(scanRepo.scans, s)
	}

	// Positive limit respected
	result, err := svc.GetHostScans(context.Background(), hostID, 3)
	if err != nil {
		t.Fatalf("GetHostScans() error: %v", err)
	}
	if len(result) != 3 {
		t.Errorf("got %d scans, want 3", len(result))
	}

	// limit <= 0 defaults to 100
	result, err = svc.GetHostScans(context.Background(), hostID, -1)
	if err != nil {
		t.Fatalf("GetHostScans() error: %v", err)
	}
	if len(result) != 5 {
		t.Errorf("got %d scans, want 5 (all, under default 100)", len(result))
	}
}

// ---------------------------------------------------------------------------
// Tests: ListScans
// ---------------------------------------------------------------------------

func TestListScans_FilterByHost(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	hostA := uuid.New()
	hostB := uuid.New()
	s1 := testScan("ctr1", 80, models.SecurityGradeB)
	s1.HostID = hostA
	s2 := testScan("ctr2", 90, models.SecurityGradeA)
	s2.HostID = hostB
	scanRepo.scans = append(scanRepo.scans, s1, s2)

	result, count, err := svc.ListScans(context.Background(), ListScansOptions{HostID: &hostA})
	if err != nil {
		t.Fatalf("ListScans() error: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if len(result) != 1 || result[0].HostID != hostA {
		t.Errorf("expected scan for host A")
	}
}

// ---------------------------------------------------------------------------
// Tests: Score history
// ---------------------------------------------------------------------------

func TestGetScoreHistory_DefaultDays(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	// days <= 0 should default to 30, but we just verify it doesn't error
	result, err := svc.GetScoreHistory(context.Background(), "ctr1", 0)
	if err != nil {
		t.Fatalf("GetScoreHistory() error: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected at least one trend point from mock")
	}
}

func TestGetGlobalScoreHistory_DefaultDays(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	result, err := svc.GetGlobalScoreHistory(context.Background(), -5)
	if err != nil {
		t.Fatalf("GetGlobalScoreHistory() error: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected at least one trend point from mock")
	}
}

// ---------------------------------------------------------------------------
// Tests: GetAverageScore
// ---------------------------------------------------------------------------

func TestGetAverageScore(t *testing.T) {
	scanRepo := &mockScanRepo{avgScore: 82.5}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	score, err := svc.GetAverageScore(context.Background(), nil)
	if err != nil {
		t.Fatalf("GetAverageScore() error: %v", err)
	}
	if score != 82.5 {
		t.Errorf("score = %f, want 82.5", score)
	}
}

// ---------------------------------------------------------------------------
// Tests: UpdateIssueStatus
// ---------------------------------------------------------------------------

func TestUpdateIssueStatus_ValidStatuses(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	scanID := uuid.New()
	issue := testIssue(scanID, "ctr1", uuid.New(), models.IssueSeverityHigh)
	issue.ID = 1
	issueRepo.issues = append(issueRepo.issues, issue)

	validStatuses := []models.IssueStatus{
		models.IssueStatusAcknowledged,
		models.IssueStatusResolved,
		models.IssueStatusIgnored,
		models.IssueStatusFalsePositive,
	}

	for _, status := range validStatuses {
		err := svc.UpdateIssueStatus(context.Background(), 1, status, nil)
		if err != nil {
			t.Errorf("UpdateIssueStatus(%q) error: %v", status, err)
		}
	}
}

func TestUpdateIssueStatus_InvalidStatus(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	err := svc.UpdateIssueStatus(context.Background(), 1, "bogus_status", nil)
	if err == nil {
		t.Fatal("expected error for invalid status")
	}
}

func TestUpdateIssueStatus_OpenIsInvalid(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	// "open" is not in the valid transition set
	err := svc.UpdateIssueStatus(context.Background(), 1, models.IssueStatusOpen, nil)
	if err == nil {
		t.Fatal("expected error for 'open' status (not a valid transition)")
	}
}

// ---------------------------------------------------------------------------
// Tests: GetIssue / GetContainerIssues / GetHostIssues
// ---------------------------------------------------------------------------

func TestGetIssue(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	issue := testIssue(uuid.New(), "ctr1", uuid.New(), models.IssueSeverityCritical)
	issue.ID = 42
	issueRepo.issues = append(issueRepo.issues, issue)

	result, err := svc.GetIssue(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetIssue() error: %v", err)
	}
	if result.ID != 42 {
		t.Errorf("issue ID = %d, want 42", result.ID)
	}
}

func TestGetContainerIssues_FilterByStatus(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	open := testIssue(uuid.New(), "ctr1", uuid.New(), models.IssueSeverityHigh)
	open.ID = 1
	open.Status = models.IssueStatusOpen

	acked := testIssue(uuid.New(), "ctr1", uuid.New(), models.IssueSeverityMedium)
	acked.ID = 2
	acked.Status = models.IssueStatusAcknowledged

	issueRepo.issues = append(issueRepo.issues, open, acked)

	status := models.IssueStatusOpen
	result, err := svc.GetContainerIssues(context.Background(), "ctr1", &status)
	if err != nil {
		t.Fatalf("GetContainerIssues() error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("got %d issues, want 1 open", len(result))
	}
}

func TestGetHostIssues(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	hostID := uuid.New()
	issue := testIssue(uuid.New(), "ctr1", hostID, models.IssueSeverityLow)
	issue.ID = 1
	issueRepo.issues = append(issueRepo.issues, issue)

	result, count, err := svc.GetHostIssues(context.Background(), hostID, ListIssuesOptions{})
	if err != nil {
		t.Fatalf("GetHostIssues() error: %v", err)
	}
	if count != 1 || len(result) != 1 {
		t.Errorf("count=%d, len=%d, want 1", count, len(result))
	}
}

// ---------------------------------------------------------------------------
// Tests: DeleteScan
// ---------------------------------------------------------------------------

func TestDeleteScan_DeletesIssuesFirst(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	scan := testScan("ctr1", 85, models.SecurityGradeB)
	scanRepo.scans = append(scanRepo.scans, scan)

	issue := testIssue(scan.ID, "ctr1", scan.HostID, models.IssueSeverityHigh)
	issue.ID = 1
	issueRepo.issues = append(issueRepo.issues, issue)

	err := svc.DeleteScan(context.Background(), scan.ID)
	if err != nil {
		t.Fatalf("DeleteScan() error: %v", err)
	}
	if len(scanRepo.scans) != 0 {
		t.Errorf("scan not deleted, %d remaining", len(scanRepo.scans))
	}
	if len(issueRepo.issues) != 0 {
		t.Errorf("issues not deleted, %d remaining", len(issueRepo.issues))
	}
}

func TestDeleteScan_IssueDeleteError_StillDeletesScan(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{deleteErr: errors.New("issue delete failed")}
	svc := newTestService(scanRepo, issueRepo)

	scan := testScan("ctr1", 85, models.SecurityGradeB)
	scanRepo.scans = append(scanRepo.scans, scan)

	// Issue delete fails, but scan delete should still proceed
	err := svc.DeleteScan(context.Background(), scan.ID)
	if err != nil {
		t.Fatalf("DeleteScan() error: %v", err)
	}
	if len(scanRepo.scans) != 0 {
		t.Errorf("scan should still be deleted even when issue delete fails")
	}
}

func TestDeleteScan_ScanDeleteError(t *testing.T) {
	scanRepo := &mockScanRepo{deleteErr: errors.New("db error")}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	err := svc.DeleteScan(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error when scan delete fails")
	}
}

// ---------------------------------------------------------------------------
// Tests: CleanupOldScans
// ---------------------------------------------------------------------------

func TestCleanupOldScans_DeletesExpired(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	cfg := DefaultServiceConfig()
	cfg.ScanRetentionDays = 7
	svc := NewService(cfg, scanRepo, issueRepo, logger.Nop())

	old := testScan("ctr1", 60, models.SecurityGradeD)
	old.CreatedAt = time.Now().Add(-14 * 24 * time.Hour)
	recent := testScan("ctr2", 90, models.SecurityGradeA)
	recent.CreatedAt = time.Now()
	scanRepo.scans = append(scanRepo.scans, old, recent)

	deleted, err := svc.CleanupOldScans(context.Background())
	if err != nil {
		t.Fatalf("CleanupOldScans() error: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}
	if len(scanRepo.scans) != 1 {
		t.Errorf("remaining scans = %d, want 1", len(scanRepo.scans))
	}
}

func TestCleanupOldScans_DisabledWhenZeroRetention(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	cfg := DefaultServiceConfig()
	cfg.ScanRetentionDays = 0
	svc := NewService(cfg, scanRepo, issueRepo, logger.Nop())

	deleted, err := svc.CleanupOldScans(context.Background())
	if err != nil {
		t.Fatalf("CleanupOldScans() error: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0 (disabled)", deleted)
	}
}

func TestCleanupOldScans_RepoError(t *testing.T) {
	scanRepo := &mockScanRepo{cleanupErr: errors.New("db error")}
	issueRepo := &mockIssueRepo{}
	cfg := DefaultServiceConfig()
	cfg.ScanRetentionDays = 30
	svc := NewService(cfg, scanRepo, issueRepo, logger.Nop())

	_, err := svc.CleanupOldScans(context.Background())
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// ---------------------------------------------------------------------------
// Tests: GetSecuritySummary
// ---------------------------------------------------------------------------

func TestGetSecuritySummary_Empty(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	summary, err := svc.GetSecuritySummary(context.Background(), nil)
	if err != nil {
		t.Fatalf("GetSecuritySummary() error: %v", err)
	}
	if summary.TotalContainers != 0 {
		t.Errorf("TotalContainers = %d, want 0", summary.TotalContainers)
	}
	if summary.TotalIssues != 0 {
		t.Errorf("TotalIssues = %d, want 0", summary.TotalIssues)
	}
}

func TestGetSecuritySummary_AggregatesStats(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	hostID := uuid.New()

	s1 := testScan("ctr1", 90, models.SecurityGradeA)
	s1.HostID = hostID
	s1.CriticalCount = 0
	s1.HighCount = 1
	s1.MediumCount = 2
	s1.LowCount = 1
	s1.CreatedAt = time.Now()

	s2 := testScan("ctr2", 70, models.SecurityGradeC)
	s2.HostID = hostID
	s2.CriticalCount = 2
	s2.HighCount = 3
	s2.MediumCount = 0
	s2.LowCount = 0
	s2.CreatedAt = time.Now()

	scanRepo.scans = append(scanRepo.scans, s1, s2)

	summary, err := svc.GetSecuritySummary(context.Background(), &hostID)
	if err != nil {
		t.Fatalf("GetSecuritySummary() error: %v", err)
	}
	if summary.TotalContainers != 2 {
		t.Errorf("TotalContainers = %d, want 2", summary.TotalContainers)
	}
	// Average = (90+70)/2 = 80
	if summary.AverageScore != 80.0 {
		t.Errorf("AverageScore = %f, want 80.0", summary.AverageScore)
	}
	if summary.GradeDistribution[models.SecurityGradeA] != 1 {
		t.Errorf("Grade A count = %d, want 1", summary.GradeDistribution[models.SecurityGradeA])
	}
	if summary.GradeDistribution[models.SecurityGradeC] != 1 {
		t.Errorf("Grade C count = %d, want 1", summary.GradeDistribution[models.SecurityGradeC])
	}
	expectedCritical := 2
	if summary.SeverityCounts[models.IssueSeverityCritical] != expectedCritical {
		t.Errorf("Critical = %d, want %d", summary.SeverityCounts[models.IssueSeverityCritical], expectedCritical)
	}
}

func TestGetSecuritySummary_KeepsLatestPerContainer(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	hostID := uuid.New()

	// Two scans for same container — only latest should count
	old := testScan("ctr1", 50, models.SecurityGradeF)
	old.HostID = hostID
	old.CreatedAt = time.Now().Add(-1 * time.Hour)

	latest := testScan("ctr1", 95, models.SecurityGradeA)
	latest.HostID = hostID
	latest.CreatedAt = time.Now()

	scanRepo.scans = append(scanRepo.scans, old, latest)

	summary, err := svc.GetSecuritySummary(context.Background(), &hostID)
	if err != nil {
		t.Fatalf("GetSecuritySummary() error: %v", err)
	}
	if summary.TotalContainers != 1 {
		t.Errorf("TotalContainers = %d, want 1 (deduped)", summary.TotalContainers)
	}
	if summary.AverageScore != 95.0 {
		t.Errorf("AverageScore = %f, want 95.0 (latest scan)", summary.AverageScore)
	}
}

func TestGetSecuritySummary_ListError(t *testing.T) {
	scanRepo := &mockScanRepo{listErr: errors.New("db error")}
	issueRepo := &mockIssueRepo{}
	svc := newTestService(scanRepo, issueRepo)

	_, err := svc.GetSecuritySummary(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error from list failure")
	}
}

// ---------------------------------------------------------------------------
// Tests: DefaultServiceConfig
// ---------------------------------------------------------------------------

func TestDefaultServiceConfig(t *testing.T) {
	cfg := DefaultServiceConfig()
	if cfg.ScanRetentionDays != 30 {
		t.Errorf("ScanRetentionDays = %d, want 30", cfg.ScanRetentionDays)
	}
	if cfg.MaxScansPerContainer != 10 {
		t.Errorf("MaxScansPerContainer = %d, want 10", cfg.MaxScansPerContainer)
	}
	if cfg.AutoScanInterval != 6*time.Hour {
		t.Errorf("AutoScanInterval = %v, want 6h", cfg.AutoScanInterval)
	}
}

// ---------------------------------------------------------------------------
// Tests: Constructor
// ---------------------------------------------------------------------------

func TestNewService_NilConfig_UsesDefault(t *testing.T) {
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := NewService(nil, scanRepo, issueRepo, logger.Nop())

	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.config.ScanRetentionDays != 30 {
		t.Errorf("default config not applied: ScanRetentionDays = %d", svc.config.ScanRetentionDays)
	}
}

func TestNewService_CustomConfig(t *testing.T) {
	cfg := &ServiceConfig{
		ScanRetentionDays:    90,
		MaxScansPerContainer: 20,
		AutoScanInterval:     12 * time.Hour,
	}
	scanRepo := &mockScanRepo{}
	issueRepo := &mockIssueRepo{}
	svc := NewService(cfg, scanRepo, issueRepo, logger.Nop())

	if svc.config.ScanRetentionDays != 90 {
		t.Errorf("ScanRetentionDays = %d, want 90", svc.config.ScanRetentionDays)
	}
}

// ---------------------------------------------------------------------------
// Tests: Trivy availability
// ---------------------------------------------------------------------------

func TestIsTrivyAvailable_NoClient(t *testing.T) {
	svc := newTestService(&mockScanRepo{}, &mockIssueRepo{})
	if svc.IsTrivyAvailable() {
		t.Error("IsTrivyAvailable() = true, want false (no client)")
	}
}

// ---------------------------------------------------------------------------
// Interface compliance
// ---------------------------------------------------------------------------

var (
	_ ScanRepository  = (*mockScanRepo)(nil)
	_ IssueRepository = (*mockIssueRepo)(nil)
)
