// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package backupverify provides automated backup verification.
//
// Ported from v26.2.7 into v26.5.1 as a free AGPL feature — no biz
// gating, no edition checks, no call-home, no closed-source extension.
//
// A verification run takes an existing backup row, runs a restore test
// against it, and records the outcome in `backup_verifications`. Three
// methods are supported:
//
//   - extract:   decompress + checksum + file-readability via the
//     existing backup.Service.Verify with FullExtract=true.
//   - container: extract + spin up a sandbox container that mounts the
//     extracted artifact read-only (delegated to the worker).
//   - database:  extract + restore a dump into an isolated database
//     container (delegated to the worker).
//
// The service itself performs the extract verification synchronously by
// delegating to the existing backup service. Container/database
// verification is delegated to the scheduler worker so the long-running
// sandbox launch does not block the API.
package backupverify

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
)

// Sentinel errors so callers can distinguish failure modes without
// substring matching.
var (
	// ErrInvalidMethod is returned when the supplied VerificationMethod
	// is not one of the known constants.
	ErrInvalidMethod = stderrors.New("backupverify: invalid verification method")

	// ErrInvalidSchedule is returned when the supplied cron expression
	// fails standard 5-field parsing.
	ErrInvalidSchedule = stderrors.New("backupverify: invalid cron schedule")

	// ErrInvalidInput is returned when a required field is missing or
	// malformed.
	ErrInvalidInput = stderrors.New("backupverify: invalid input")

	// ErrBackupGetterMissing is returned when the BackupGetter dependency
	// is nil and a method needing it is invoked.
	ErrBackupGetterMissing = stderrors.New("backupverify: backup service not wired")
)

// VerificationRepository defines persistence operations for verifications.
type VerificationRepository interface {
	Create(ctx context.Context, v *models.BackupVerification) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.BackupVerification, error)
	Update(ctx context.Context, v *models.BackupVerification) error
	ListByBackup(ctx context.Context, backupID uuid.UUID) ([]models.BackupVerification, error)
	ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.BackupVerification, int, error)
	GetLatestByBackup(ctx context.Context, backupID uuid.UUID) (*models.BackupVerification, error)
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.BackupVerificationStats, error)
	DeleteOlderThan(ctx context.Context, olderThan time.Duration) (int64, error)
}

// ScheduleRepository defines persistence operations for schedules.
type ScheduleRepository interface {
	Create(ctx context.Context, s *models.BackupVerificationSchedule) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.BackupVerificationSchedule, error)
	List(ctx context.Context, hostID uuid.UUID) ([]models.BackupVerificationSchedule, error)
	ListDue(ctx context.Context) ([]models.BackupVerificationSchedule, error)
	Update(ctx context.Context, s *models.BackupVerificationSchedule) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// BackupGetter is the narrow read-side interface this package needs from
// the existing backup service. v26.2.7 declared this as just `Get`; v26.5.1
// also needs `Verify` so the service can run the extract check against the
// real backup pipeline rather than the v26.2.7 heuristic that claimed
// "1 file per 10 KiB". List is needed so the scheduler can pick the top-N
// most-recent backups for a host.
type BackupGetter interface {
	// Get returns a backup row by ID.
	Get(ctx context.Context, id uuid.UUID) (*models.Backup, error)

	// List returns backups matching the filter, newest first. Used by
	// the scheduler to pick the top-N to verify (Limit + HostID).
	List(ctx context.Context, opts models.BackupListOptions) ([]*models.Backup, int64, error)

	// Verify runs the existing backup-service verify pipeline
	// (checksum + file readability + optional full extraction). The
	// backup-service performs the I/O against the storage backend so
	// the verify path is shared with manual /backups verify clicks.
	Verify(ctx context.Context, backupID uuid.UUID, opts backupsvc.VerifyOptions) (*models.BackupVerificationResult, error)
}

// SandboxRunner is the narrow interface the service uses to run container
// and database verifications inside an isolated, read-only-rootfs sandbox.
// It is satisfied by *internal/scheduler/workers.BackupVerifySandbox and
// is provided by the worker so the service does not pull the docker SDK
// into its dependency graph.
//
// The interface is intentionally minimal: callers hand off the backup ID
// + method, get back a structured result that goes straight into the
// verification row. The sandbox launcher inside the worker enforces the
// read-only rootfs + dropped-caps baseline (see
// internal/services/recon/sandbox/launcher.go).
type SandboxRunner interface {
	// RunContainerVerify spins up a sandbox container, mounts the
	// extracted backup artifact read-only, and runs a no-op probe.
	// Returns nil on success.
	RunContainerVerify(ctx context.Context, backup *models.Backup) error

	// RunDatabaseVerify spins up an isolated database container,
	// restores the dump into it, and runs a `SELECT 1` probe. Returns
	// nil on success.
	RunDatabaseVerify(ctx context.Context, backup *models.Backup) error
}

// Service implements backup verification business logic.
type Service struct {
	verifications VerificationRepository
	schedules     ScheduleRepository
	backups       BackupGetter
	sandbox       SandboxRunner
	logger        *logger.Logger

	parser cron.Parser

	mu        sync.RWMutex
	retention time.Duration
}

// Options configures the Service. Zero-valued fields fall back to defaults.
type Options struct {
	// Sandbox is the runner used for container/database verifications.
	// May be nil — those methods then degrade to extract-only with a
	// recorded warning.
	Sandbox SandboxRunner

	// Retention is how long verification rows are kept by PruneOld.
	// Zero → 90 days.
	Retention time.Duration
}

// DefaultRetention is the verification-row retention window used when
// Options.Retention is unset.
const DefaultRetention = 90 * 24 * time.Hour

// NewService constructs a Service. log may be nil — a no-op logger is
// substituted. backups must be non-nil; verifications/schedules likewise.
func NewService(
	verifications VerificationRepository,
	schedules ScheduleRepository,
	backups BackupGetter,
	log *logger.Logger,
	opts ...Options,
) *Service {
	if log == nil {
		log = logger.Nop()
	}
	opt := Options{}
	if len(opts) > 0 {
		opt = opts[0]
	}
	if opt.Retention <= 0 {
		opt.Retention = DefaultRetention
	}
	return &Service{
		verifications: verifications,
		schedules:     schedules,
		backups:       backups,
		sandbox:       opt.Sandbox,
		logger:        log.Named("backupverify"),
		parser: cron.NewParser(
			cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
		),
		retention: opt.Retention,
	}
}

// SetSandbox swaps the sandbox runner. Lets the worker wire its concrete
// runner after the service has been constructed (avoids a circular import
// between service and worker packages).
func (s *Service) SetSandbox(runner SandboxRunner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sandbox = runner
}

// ============================================================================
// Verification
// ============================================================================

// RunVerification runs a verification against a single backup and persists
// the result row. The backup is loaded, transitioned through pending →
// running → passed/failed, and updated on every state change so concurrent
// readers can observe progress.
func (s *Service) RunVerification(ctx context.Context, backupID uuid.UUID, method models.VerificationMethod, userID *uuid.UUID) (*models.BackupVerification, error) {
	if s.backups == nil {
		return nil, ErrBackupGetterMissing
	}
	if !method.IsValid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidMethod, method)
	}

	backup, err := s.backups.Get(ctx, backupID)
	if err != nil {
		return nil, fmt.Errorf("get backup: %w", err)
	}

	now := time.Now()
	v := &models.BackupVerification{
		ID:         uuid.New(),
		BackupID:   backupID,
		HostID:     backup.HostID,
		Status:     models.VerificationStatusPending,
		Method:     method,
		Details:    json.RawMessage("{}"),
		VerifiedBy: userID,
		SizeBytes:  backup.SizeBytes,
	}

	if err := s.verifications.Create(ctx, v); err != nil {
		return nil, fmt.Errorf("create verification: %w", err)
	}

	v.Status = models.VerificationStatusRunning
	v.StartedAt = &now
	if err := s.verifications.Update(ctx, v); err != nil {
		return nil, fmt.Errorf("update verification to running: %w", err)
	}

	s.logger.Info("running backup verification",
		"verification_id", v.ID,
		"backup_id", backupID,
		"host_id", backup.HostID,
		"method", method,
	)

	verifyErr := s.performVerification(ctx, v, backup)

	completed := time.Now()
	v.CompletedAt = &completed
	v.DurationMs = int(completed.Sub(now).Milliseconds())

	if verifyErr != nil {
		v.Status = models.VerificationStatusFailed
		v.ErrorMessage = verifyErr.Error()
		s.logger.Warn("backup verification failed",
			"verification_id", v.ID,
			"backup_id", backupID,
			"error", verifyErr,
		)
	} else {
		v.Status = models.VerificationStatusPassed
		s.logger.Info("backup verification passed",
			"verification_id", v.ID,
			"backup_id", backupID,
			"duration_ms", v.DurationMs,
		)
	}

	if err := s.verifications.Update(ctx, v); err != nil {
		return nil, fmt.Errorf("update verification result: %w", err)
	}
	return v, nil
}

// performVerification dispatches to the method-specific verification. The
// extract path always runs first; container and database methods build on
// top of it so a failed extract short-circuits the heavier checks.
func (s *Service) performVerification(ctx context.Context, v *models.BackupVerification, backup *models.Backup) error {
	// Always run the extract pipeline first via the existing backup
	// service so the checksum + file-count come from real data.
	result, err := s.backups.Verify(ctx, backup.ID, backupsvc.VerifyOptions{
		CheckChecksum: true,
		CheckContents: true,
		FullExtract:   true,
	})
	if err != nil {
		return fmt.Errorf("extract verify: %w", err)
	}

	checksumValid := result.ChecksumValid
	filesReadable := result.Readable
	v.ChecksumValid = &checksumValid
	v.FilesReadable = &filesReadable
	v.FileCount = result.FileCount
	if result.ErrorMessage != nil && *result.ErrorMessage != "" {
		v.ErrorMessage = *result.ErrorMessage
	}
	if !result.IsValid {
		return fmt.Errorf("extract verification failed (checksum=%t readable=%t)", checksumValid, filesReadable)
	}

	switch v.Method {
	case models.VerificationMethodExtract:
		return nil

	case models.VerificationMethodContainer:
		s.mu.RLock()
		runner := s.sandbox
		s.mu.RUnlock()
		if runner == nil {
			containerTest := false
			v.ContainerTest = &containerTest
			return fmt.Errorf("container verification requested but sandbox runner not wired")
		}
		if err := runner.RunContainerVerify(ctx, backup); err != nil {
			containerTest := false
			v.ContainerTest = &containerTest
			return fmt.Errorf("container verify: %w", err)
		}
		containerTest := true
		v.ContainerTest = &containerTest
		return nil

	case models.VerificationMethodDatabase:
		s.mu.RLock()
		runner := s.sandbox
		s.mu.RUnlock()
		if runner == nil {
			dataValid := false
			v.DataValid = &dataValid
			return fmt.Errorf("database verification requested but sandbox runner not wired")
		}
		if err := runner.RunDatabaseVerify(ctx, backup); err != nil {
			dataValid := false
			v.DataValid = &dataValid
			return fmt.Errorf("database verify: %w", err)
		}
		dataValid := true
		v.DataValid = &dataValid
		return nil
	}
	return fmt.Errorf("%w: %q", ErrInvalidMethod, v.Method)
}

// ============================================================================
// Queries
// ============================================================================

// ListVerifications returns paginated verifications for a host.
func (s *Service) ListVerifications(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.BackupVerification, int, error) {
	return s.verifications.ListByHost(ctx, hostID, limit, offset)
}

// ListByBackup returns every verification for a single backup.
func (s *Service) ListByBackup(ctx context.Context, backupID uuid.UUID) ([]models.BackupVerification, error) {
	return s.verifications.ListByBackup(ctx, backupID)
}

// GetVerification returns a single verification by ID.
func (s *Service) GetVerification(ctx context.Context, id uuid.UUID) (*models.BackupVerification, error) {
	return s.verifications.GetByID(ctx, id)
}

// GetLatest returns the most recent verification for a backup, or nil if
// none has run.
func (s *Service) GetLatest(ctx context.Context, backupID uuid.UUID) (*models.BackupVerification, error) {
	return s.verifications.GetLatestByBackup(ctx, backupID)
}

// GetStats returns aggregate verification statistics for a host.
func (s *Service) GetStats(ctx context.Context, hostID uuid.UUID) (*models.BackupVerificationStats, error) {
	return s.verifications.GetStats(ctx, hostID)
}

// PruneOld deletes verification rows older than the configured retention
// window. Returns the count removed. The scheduler calls this periodically
// — typically wired to the existing retention worker — so the table stays
// bounded.
func (s *Service) PruneOld(ctx context.Context) (int64, error) {
	s.mu.RLock()
	retention := s.retention
	s.mu.RUnlock()
	return s.verifications.DeleteOlderThan(ctx, retention)
}

// ============================================================================
// Schedules
// ============================================================================

// ListSchedules returns every schedule for a host.
func (s *Service) ListSchedules(ctx context.Context, hostID uuid.UUID) ([]models.BackupVerificationSchedule, error) {
	return s.schedules.List(ctx, hostID)
}

// ListDueSchedules returns enabled schedules whose next_run_at has elapsed.
// The scheduler worker reads this to decide what to run on each tick.
func (s *Service) ListDueSchedules(ctx context.Context) ([]models.BackupVerificationSchedule, error) {
	return s.schedules.ListDue(ctx)
}

// GetSchedule returns a single schedule by ID.
func (s *Service) GetSchedule(ctx context.Context, id uuid.UUID) (*models.BackupVerificationSchedule, error) {
	return s.schedules.GetByID(ctx, id)
}

// CreateSchedule validates inputs and inserts a new schedule. The cron
// expression must parse against the standard 5-field grammar; the method
// must be a known VerificationMethod.
func (s *Service) CreateSchedule(ctx context.Context, hostID uuid.UUID, schedule, method string, maxBackups int) (*models.BackupVerificationSchedule, error) {
	if hostID == uuid.Nil {
		return nil, fmt.Errorf("%w: host_id is required", ErrInvalidInput)
	}
	if maxBackups <= 0 {
		maxBackups = 5
	}
	if maxBackups > 50 {
		maxBackups = 50
	}
	if !models.VerificationMethod(method).IsValid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidMethod, method)
	}
	parsed, err := s.parser.Parse(schedule)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrInvalidSchedule, schedule, err)
	}
	next := parsed.Next(time.Now())

	sched := &models.BackupVerificationSchedule{
		ID:         uuid.New(),
		HostID:     hostID,
		Schedule:   schedule,
		Method:     method,
		MaxBackups: maxBackups,
		Enabled:    true,
		NextRunAt:  &next,
	}

	if err := s.schedules.Create(ctx, sched); err != nil {
		return nil, fmt.Errorf("create verification schedule: %w", err)
	}
	s.logger.Info("created verification schedule",
		"schedule_id", sched.ID,
		"host_id", hostID,
		"schedule", schedule,
		"method", method,
		"next_run_at", next,
	)
	return sched, nil
}

// UpdateSchedule updates an existing schedule. Only the fields the caller
// provided are mutated.
func (s *Service) UpdateSchedule(ctx context.Context, id uuid.UUID, schedule, method *string, maxBackups *int, enabled *bool) (*models.BackupVerificationSchedule, error) {
	sched, err := s.schedules.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if schedule != nil {
		parsed, err := s.parser.Parse(*schedule)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidSchedule, *schedule, err)
		}
		sched.Schedule = *schedule
		next := parsed.Next(time.Now())
		sched.NextRunAt = &next
	}
	if method != nil {
		if !models.VerificationMethod(*method).IsValid() {
			return nil, fmt.Errorf("%w: %q", ErrInvalidMethod, *method)
		}
		sched.Method = *method
	}
	if maxBackups != nil {
		v := *maxBackups
		if v <= 0 {
			v = 5
		}
		if v > 50 {
			v = 50
		}
		sched.MaxBackups = v
	}
	if enabled != nil {
		sched.Enabled = *enabled
	}
	if err := s.schedules.Update(ctx, sched); err != nil {
		return nil, err
	}
	return sched, nil
}

// DeleteSchedule removes a verification schedule.
func (s *Service) DeleteSchedule(ctx context.Context, id uuid.UUID) error {
	return s.schedules.Delete(ctx, id)
}

// MarkScheduleRan updates a schedule after a tick: stores the run timestamp,
// the outcome string, and the computed next_run_at. The worker calls this
// after running the verifications produced by the schedule.
func (s *Service) MarkScheduleRan(ctx context.Context, id uuid.UUID, ranAt time.Time, status string) error {
	sched, err := s.schedules.GetByID(ctx, id)
	if err != nil {
		return err
	}
	sched.LastRunAt = &ranAt
	sched.LastRunStatus = status
	if parsed, err := s.parser.Parse(sched.Schedule); err == nil {
		next := parsed.Next(ranAt)
		sched.NextRunAt = &next
	}
	return s.schedules.Update(ctx, sched)
}

// PickBackupsForSchedule returns the N most recent completed backups for
// a host, suitable for verification by a schedule with MaxBackups=N. The
// worker iterates this list, one verification row per backup.
func (s *Service) PickBackupsForSchedule(ctx context.Context, hostID uuid.UUID, limit int) ([]*models.Backup, error) {
	if s.backups == nil {
		return nil, ErrBackupGetterMissing
	}
	if limit <= 0 {
		limit = 5
	}
	completed := models.BackupStatusCompleted
	backups, _, err := s.backups.List(ctx, models.BackupListOptions{
		HostID: &hostID,
		Status: &completed,
		Limit:  limit,
	})
	return backups, err
}
