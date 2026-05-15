// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package backupverify

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
)

// ============================================================================
// Mocks
// ============================================================================

type mockVerifyRepo struct {
	mu        sync.Mutex
	rows      map[uuid.UUID]*models.BackupVerification
	createErr error
	updateErr error
}

func newMockVerifyRepo() *mockVerifyRepo {
	return &mockVerifyRepo{rows: map[uuid.UUID]*models.BackupVerification{}}
}

func (m *mockVerifyRepo) Create(_ context.Context, v *models.BackupVerification) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now()
	}
	cp := *v
	m.rows[v.ID] = &cp
	return nil
}

func (m *mockVerifyRepo) GetByID(_ context.Context, id uuid.UUID) (*models.BackupVerification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.rows[id]; ok {
		cp := *v
		return &cp, nil
	}
	return nil, stderrors.New("not found")
}

func (m *mockVerifyRepo) Update(_ context.Context, v *models.BackupVerification) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *v
	m.rows[v.ID] = &cp
	return nil
}

func (m *mockVerifyRepo) ListByBackup(_ context.Context, backupID uuid.UUID) ([]models.BackupVerification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []models.BackupVerification{}
	for _, v := range m.rows {
		if v.BackupID == backupID {
			out = append(out, *v)
		}
	}
	return out, nil
}

func (m *mockVerifyRepo) ListByHost(_ context.Context, hostID uuid.UUID, _, _ int) ([]models.BackupVerification, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []models.BackupVerification{}
	for _, v := range m.rows {
		if v.HostID == hostID {
			out = append(out, *v)
		}
	}
	return out, len(out), nil
}

func (m *mockVerifyRepo) GetLatestByBackup(_ context.Context, backupID uuid.UUID) (*models.BackupVerification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var latest *models.BackupVerification
	for _, v := range m.rows {
		if v.BackupID == backupID {
			if latest == nil || v.CreatedAt.After(latest.CreatedAt) {
				cp := *v
				latest = &cp
			}
		}
	}
	return latest, nil
}

func (m *mockVerifyRepo) GetStats(_ context.Context, hostID uuid.UUID) (*models.BackupVerificationStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stats := &models.BackupVerificationStats{}
	for _, v := range m.rows {
		if v.HostID != hostID {
			continue
		}
		stats.TotalVerified++
		if v.Status == models.VerificationStatusPassed {
			stats.Passed++
		}
		if v.Status == models.VerificationStatusFailed {
			stats.Failed++
		}
	}
	if stats.TotalVerified > 0 {
		stats.PassRate = float64(stats.Passed) / float64(stats.TotalVerified) * 100
	}
	return stats, nil
}

func (m *mockVerifyRepo) DeleteOlderThan(_ context.Context, older time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-older)
	var deleted int64
	for id, v := range m.rows {
		if v.CreatedAt.Before(cutoff) {
			delete(m.rows, id)
			deleted++
		}
	}
	return deleted, nil
}

type mockScheduleRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*models.BackupVerificationSchedule
}

func newMockScheduleRepo() *mockScheduleRepo {
	return &mockScheduleRepo{rows: map[uuid.UUID]*models.BackupVerificationSchedule{}}
}

func (m *mockScheduleRepo) Create(_ context.Context, s *models.BackupVerificationSchedule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now()
	}
	s.UpdatedAt = time.Now()
	cp := *s
	m.rows[s.ID] = &cp
	return nil
}

func (m *mockScheduleRepo) GetByID(_ context.Context, id uuid.UUID) (*models.BackupVerificationSchedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.rows[id]; ok {
		cp := *v
		return &cp, nil
	}
	return nil, stderrors.New("schedule not found")
}

func (m *mockScheduleRepo) List(_ context.Context, hostID uuid.UUID) ([]models.BackupVerificationSchedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []models.BackupVerificationSchedule{}
	for _, s := range m.rows {
		if s.HostID == hostID {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (m *mockScheduleRepo) ListDue(_ context.Context) ([]models.BackupVerificationSchedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	out := []models.BackupVerificationSchedule{}
	for _, s := range m.rows {
		if !s.Enabled {
			continue
		}
		if s.NextRunAt == nil || !s.NextRunAt.After(now) {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (m *mockScheduleRepo) Update(_ context.Context, s *models.BackupVerificationSchedule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[s.ID]; !ok {
		return stderrors.New("schedule not found")
	}
	s.UpdatedAt = time.Now()
	cp := *s
	m.rows[s.ID] = &cp
	return nil
}

func (m *mockScheduleRepo) Delete(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[id]; !ok {
		return stderrors.New("schedule not found")
	}
	delete(m.rows, id)
	return nil
}

type mockBackupGetter struct {
	backups       map[uuid.UUID]*models.Backup
	verifyResult  *models.BackupVerificationResult
	verifyErr     error
	verifyInvoked int
}

func (m *mockBackupGetter) Get(_ context.Context, id uuid.UUID) (*models.Backup, error) {
	if b, ok := m.backups[id]; ok {
		return b, nil
	}
	return nil, stderrors.New("backup not found")
}

func (m *mockBackupGetter) List(_ context.Context, opts models.BackupListOptions) ([]*models.Backup, int64, error) {
	out := []*models.Backup{}
	for _, b := range m.backups {
		if opts.HostID != nil && b.HostID != *opts.HostID {
			continue
		}
		if opts.Status != nil && b.Status != *opts.Status {
			continue
		}
		out = append(out, b)
		if opts.Limit > 0 && len(out) >= opts.Limit {
			break
		}
	}
	return out, int64(len(out)), nil
}

func (m *mockBackupGetter) Verify(_ context.Context, id uuid.UUID, _ backupsvc.VerifyOptions) (*models.BackupVerificationResult, error) {
	m.verifyInvoked++
	if m.verifyErr != nil {
		return nil, m.verifyErr
	}
	if m.verifyResult != nil {
		return m.verifyResult, nil
	}
	return &models.BackupVerificationResult{
		BackupID:      id,
		IsValid:       true,
		ChecksumValid: true,
		Readable:      true,
		FileCount:     7,
		VerifiedAt:    time.Now(),
	}, nil
}

type mockSandbox struct {
	containerErr error
	databaseErr  error
	containerN   int
	databaseN    int
}

func (m *mockSandbox) RunContainerVerify(_ context.Context, _ *models.Backup) error {
	m.containerN++
	return m.containerErr
}

func (m *mockSandbox) RunDatabaseVerify(_ context.Context, _ *models.Backup) error {
	m.databaseN++
	return m.databaseErr
}

// ============================================================================
// Tests
// ============================================================================

func newTestService(t *testing.T) (*Service, *mockVerifyRepo, *mockScheduleRepo, *mockBackupGetter, *mockSandbox) {
	t.Helper()
	verifyRepo := newMockVerifyRepo()
	schedRepo := newMockScheduleRepo()
	sandbox := &mockSandbox{}
	backupID := uuid.New()
	hostID := uuid.New()
	getter := &mockBackupGetter{
		backups: map[uuid.UUID]*models.Backup{
			backupID: {
				ID:        backupID,
				HostID:    hostID,
				Status:    models.BackupStatusCompleted,
				SizeBytes: 4096,
				Path:      "test/backup.tar.gz",
			},
		},
	}
	svc := NewService(verifyRepo, schedRepo, getter, nil, Options{Sandbox: sandbox})
	return svc, verifyRepo, schedRepo, getter, sandbox
}

func TestService_RunVerification_Extract_Pass(t *testing.T) {
	svc, verifyRepo, _, getter, _ := newTestService(t)
	var backupID uuid.UUID
	for id := range getter.backups {
		backupID = id
	}

	v, err := svc.RunVerification(context.Background(), backupID, models.VerificationMethodExtract, nil)
	if err != nil {
		t.Fatalf("RunVerification error: %v", err)
	}
	if v.Status != models.VerificationStatusPassed {
		t.Fatalf("status = %q, want passed", v.Status)
	}
	if v.ChecksumValid == nil || !*v.ChecksumValid {
		t.Fatalf("ChecksumValid not set true")
	}
	if v.FilesReadable == nil || !*v.FilesReadable {
		t.Fatalf("FilesReadable not set true")
	}
	if v.FileCount != 7 {
		t.Fatalf("FileCount = %d, want 7 (from mock verify result)", v.FileCount)
	}
	if v.CompletedAt == nil {
		t.Fatalf("CompletedAt nil after run")
	}
	if v.DurationMs < 0 {
		t.Fatalf("DurationMs negative")
	}
	if getter.verifyInvoked != 1 {
		t.Fatalf("backupGetter.Verify call count = %d, want 1", getter.verifyInvoked)
	}
	// Row must be persisted.
	if _, err := verifyRepo.GetByID(context.Background(), v.ID); err != nil {
		t.Fatalf("verification row not persisted: %v", err)
	}
}

func TestService_RunVerification_Extract_Fail(t *testing.T) {
	svc, _, _, getter, _ := newTestService(t)
	getter.verifyResult = &models.BackupVerificationResult{
		BackupID:      uuid.Nil,
		IsValid:       false,
		ChecksumValid: false,
		Readable:      false,
	}
	var backupID uuid.UUID
	for id := range getter.backups {
		backupID = id
	}

	v, err := svc.RunVerification(context.Background(), backupID, models.VerificationMethodExtract, nil)
	if err != nil {
		t.Fatalf("RunVerification returned error rather than failed-status: %v", err)
	}
	if v.Status != models.VerificationStatusFailed {
		t.Fatalf("status = %q, want failed", v.Status)
	}
	if v.ErrorMessage == "" {
		t.Fatalf("ErrorMessage empty on failed verification")
	}
}

func TestService_RunVerification_Container_Success(t *testing.T) {
	svc, _, _, getter, sandbox := newTestService(t)
	var backupID uuid.UUID
	for id := range getter.backups {
		backupID = id
	}

	v, err := svc.RunVerification(context.Background(), backupID, models.VerificationMethodContainer, nil)
	if err != nil {
		t.Fatalf("RunVerification error: %v", err)
	}
	if v.Status != models.VerificationStatusPassed {
		t.Fatalf("status = %q, want passed", v.Status)
	}
	if v.ContainerTest == nil || !*v.ContainerTest {
		t.Fatalf("ContainerTest not set true")
	}
	if sandbox.containerN != 1 {
		t.Fatalf("sandbox.RunContainerVerify called %d times, want 1", sandbox.containerN)
	}
}

func TestService_RunVerification_Container_NoSandbox(t *testing.T) {
	verifyRepo := newMockVerifyRepo()
	schedRepo := newMockScheduleRepo()
	backupID := uuid.New()
	hostID := uuid.New()
	getter := &mockBackupGetter{
		backups: map[uuid.UUID]*models.Backup{
			backupID: {ID: backupID, HostID: hostID, Status: models.BackupStatusCompleted, SizeBytes: 4096},
		},
	}
	svc := NewService(verifyRepo, schedRepo, getter, nil) // no sandbox

	v, err := svc.RunVerification(context.Background(), backupID, models.VerificationMethodContainer, nil)
	if err != nil {
		t.Fatalf("RunVerification error: %v", err)
	}
	if v.Status != models.VerificationStatusFailed {
		t.Fatalf("status = %q, want failed", v.Status)
	}
	if v.ContainerTest == nil || *v.ContainerTest {
		t.Fatalf("ContainerTest = %v, want pointer to false", v.ContainerTest)
	}
}

func TestService_RunVerification_Database_Success(t *testing.T) {
	svc, _, _, getter, sandbox := newTestService(t)
	var backupID uuid.UUID
	for id := range getter.backups {
		backupID = id
	}

	v, err := svc.RunVerification(context.Background(), backupID, models.VerificationMethodDatabase, nil)
	if err != nil {
		t.Fatalf("RunVerification error: %v", err)
	}
	if v.Status != models.VerificationStatusPassed {
		t.Fatalf("status = %q, want passed", v.Status)
	}
	if v.DataValid == nil || !*v.DataValid {
		t.Fatalf("DataValid not set true")
	}
	if sandbox.databaseN != 1 {
		t.Fatalf("sandbox.RunDatabaseVerify called %d times, want 1", sandbox.databaseN)
	}
}

func TestService_RunVerification_InvalidMethod(t *testing.T) {
	svc, _, _, getter, _ := newTestService(t)
	var backupID uuid.UUID
	for id := range getter.backups {
		backupID = id
	}

	_, err := svc.RunVerification(context.Background(), backupID, models.VerificationMethod("nonsense"), nil)
	if err == nil {
		t.Fatalf("expected ErrInvalidMethod, got nil")
	}
	if !stderrors.Is(err, ErrInvalidMethod) {
		t.Fatalf("error not wrapping ErrInvalidMethod: %v", err)
	}
}

func TestService_RunVerification_BackupGetterMissing(t *testing.T) {
	verifyRepo := newMockVerifyRepo()
	schedRepo := newMockScheduleRepo()
	svc := NewService(verifyRepo, schedRepo, nil, nil)

	_, err := svc.RunVerification(context.Background(), uuid.New(), models.VerificationMethodExtract, nil)
	if !stderrors.Is(err, ErrBackupGetterMissing) {
		t.Fatalf("expected ErrBackupGetterMissing, got %v", err)
	}
}

func TestService_CreateSchedule_ValidatesCron(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)

	hostID := uuid.New()
	if _, err := svc.CreateSchedule(context.Background(), hostID, "not-cron", "extract", 5); !stderrors.Is(err, ErrInvalidSchedule) {
		t.Fatalf("invalid cron must return ErrInvalidSchedule, got %v", err)
	}
	if _, err := svc.CreateSchedule(context.Background(), hostID, "0 3 * * 0", "nonsense", 5); !stderrors.Is(err, ErrInvalidMethod) {
		t.Fatalf("invalid method must return ErrInvalidMethod, got %v", err)
	}
	sched, err := svc.CreateSchedule(context.Background(), hostID, "0 3 * * 0", "extract", 5)
	if err != nil {
		t.Fatalf("CreateSchedule error: %v", err)
	}
	if sched.HostID != hostID {
		t.Fatalf("HostID mismatch")
	}
	if !sched.Enabled {
		t.Fatalf("new schedule should be enabled by default")
	}
	if sched.NextRunAt == nil {
		t.Fatalf("NextRunAt should be set on create")
	}
}

func TestService_CreateSchedule_RejectsZeroHost(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	if _, err := svc.CreateSchedule(context.Background(), uuid.Nil, "0 3 * * 0", "extract", 5); !stderrors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for nil host, got %v", err)
	}
}

func TestService_UpdateSchedule(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)

	sched, err := svc.CreateSchedule(context.Background(), uuid.New(), "0 3 * * 0", "extract", 5)
	if err != nil {
		t.Fatalf("CreateSchedule: %v", err)
	}

	newSched := "*/30 * * * *"
	enabled := false
	maxB := 10
	method := "container"
	updated, err := svc.UpdateSchedule(context.Background(), sched.ID, &newSched, &method, &maxB, &enabled)
	if err != nil {
		t.Fatalf("UpdateSchedule error: %v", err)
	}
	if updated.Schedule != newSched || updated.Method != "container" || updated.MaxBackups != 10 || updated.Enabled {
		t.Fatalf("UpdateSchedule did not apply changes: %+v", updated)
	}

	bad := "garbage"
	if _, err := svc.UpdateSchedule(context.Background(), sched.ID, &bad, nil, nil, nil); !stderrors.Is(err, ErrInvalidSchedule) {
		t.Fatalf("bad schedule string should return ErrInvalidSchedule, got %v", err)
	}
}

func TestService_DeleteSchedule(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)

	sched, err := svc.CreateSchedule(context.Background(), uuid.New(), "0 3 * * 0", "extract", 5)
	if err != nil {
		t.Fatalf("CreateSchedule: %v", err)
	}
	if err := svc.DeleteSchedule(context.Background(), sched.ID); err != nil {
		t.Fatalf("DeleteSchedule: %v", err)
	}
	if _, err := svc.GetSchedule(context.Background(), sched.ID); err == nil {
		t.Fatalf("schedule still present after delete")
	}
}

func TestService_MarkScheduleRan_AdvancesNextRun(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	sched, err := svc.CreateSchedule(context.Background(), uuid.New(), "0 3 * * *", "extract", 5)
	if err != nil {
		t.Fatalf("CreateSchedule: %v", err)
	}
	originalNext := *sched.NextRunAt

	ranAt := originalNext.Add(time.Minute) // simulate that the worker ran at the scheduled time
	if err := svc.MarkScheduleRan(context.Background(), sched.ID, ranAt, "passed"); err != nil {
		t.Fatalf("MarkScheduleRan: %v", err)
	}
	got, err := svc.GetSchedule(context.Background(), sched.ID)
	if err != nil {
		t.Fatalf("GetSchedule: %v", err)
	}
	if got.LastRunStatus != "passed" {
		t.Fatalf("LastRunStatus = %q, want passed", got.LastRunStatus)
	}
	if got.LastRunAt == nil || !got.LastRunAt.Equal(ranAt) {
		t.Fatalf("LastRunAt mismatch")
	}
	if got.NextRunAt == nil || !got.NextRunAt.After(originalNext) {
		t.Fatalf("NextRunAt did not advance: original=%v new=%v", originalNext, got.NextRunAt)
	}
}

func TestService_PickBackupsForSchedule(t *testing.T) {
	svc, _, _, getter, _ := newTestService(t)
	// Add a second backup for the same host so we can confirm filtering.
	for _, b := range getter.backups {
		newID := uuid.New()
		getter.backups[newID] = &models.Backup{
			ID:     newID,
			HostID: b.HostID,
			Status: models.BackupStatusCompleted,
		}
		break
	}
	var hostID uuid.UUID
	for _, b := range getter.backups {
		hostID = b.HostID
		break
	}

	out, err := svc.PickBackupsForSchedule(context.Background(), hostID, 5)
	if err != nil {
		t.Fatalf("PickBackupsForSchedule: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("expected at least one backup, got 0")
	}
	for _, b := range out {
		if b.HostID != hostID {
			t.Fatalf("backup returned for wrong host: %+v", b)
		}
		if b.Status != models.BackupStatusCompleted {
			t.Fatalf("backup returned with non-completed status: %+v", b)
		}
	}
}

func TestService_PruneOld(t *testing.T) {
	verifyRepo := newMockVerifyRepo()
	schedRepo := newMockScheduleRepo()
	getter := &mockBackupGetter{backups: map[uuid.UUID]*models.Backup{}}
	svc := NewService(verifyRepo, schedRepo, getter, nil, Options{Retention: time.Hour})

	// Insert two rows — one old, one recent.
	old := &models.BackupVerification{
		ID:        uuid.New(),
		BackupID:  uuid.New(),
		HostID:    uuid.New(),
		Status:    models.VerificationStatusPassed,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	recent := &models.BackupVerification{
		ID:        uuid.New(),
		BackupID:  uuid.New(),
		HostID:    uuid.New(),
		Status:    models.VerificationStatusPassed,
		CreatedAt: time.Now(),
	}
	if err := verifyRepo.Create(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := verifyRepo.Create(context.Background(), recent); err != nil {
		t.Fatal(err)
	}

	n, err := svc.PruneOld(context.Background())
	if err != nil {
		t.Fatalf("PruneOld: %v", err)
	}
	if n != 1 {
		t.Fatalf("PruneOld deleted %d rows, want 1", n)
	}
	if _, err := verifyRepo.GetByID(context.Background(), recent.ID); err != nil {
		t.Fatalf("recent row deleted unexpectedly: %v", err)
	}
}

func TestVerificationMethod_IsValid(t *testing.T) {
	cases := map[models.VerificationMethod]bool{
		models.VerificationMethodExtract:   true,
		models.VerificationMethodContainer: true,
		models.VerificationMethodDatabase:  true,
		"":                                 false,
		"nonsense":                         false,
	}
	for m, want := range cases {
		if got := m.IsValid(); got != want {
			t.Errorf("%q.IsValid() = %t, want %t", m, got, want)
		}
	}
}

func TestService_SetSandbox(t *testing.T) {
	svc, _, _, getter, _ := newTestService(t)
	newSandbox := &mockSandbox{containerErr: stderrors.New("simulated failure")}
	svc.SetSandbox(newSandbox)

	var backupID uuid.UUID
	for id := range getter.backups {
		backupID = id
	}
	v, err := svc.RunVerification(context.Background(), backupID, models.VerificationMethodContainer, nil)
	if err != nil {
		t.Fatalf("RunVerification error: %v", err)
	}
	if v.Status != models.VerificationStatusFailed {
		t.Fatalf("status = %q, want failed", v.Status)
	}
}
