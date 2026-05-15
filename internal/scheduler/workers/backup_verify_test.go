// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// ============================================================================
// Mocks
// ============================================================================

type stubLauncher struct {
	out     []byte
	code    int
	err     error
	lastCmd []string
	lastEnv map[string]string
	calls   int
}

func (s *stubLauncher) RunOnce(_ context.Context, spec recon.ContainerSpec) ([]byte, int, error) {
	s.calls++
	s.lastCmd = spec.Command
	s.lastEnv = spec.Env
	return s.out, s.code, s.err
}

type stubVerifySvc struct {
	due         []models.BackupVerificationSchedule
	backups     map[uuid.UUID][]*models.Backup
	runCalls    int
	runResult   *models.BackupVerification
	runErr      error
	markCalls   int
	pruneCalls  int
	pruneReturn int64
}

func (s *stubVerifySvc) ListDueSchedules(_ context.Context) ([]models.BackupVerificationSchedule, error) {
	return s.due, nil
}

func (s *stubVerifySvc) PickBackupsForSchedule(_ context.Context, hostID uuid.UUID, _ int) ([]*models.Backup, error) {
	return s.backups[hostID], nil
}

func (s *stubVerifySvc) RunVerification(_ context.Context, backupID uuid.UUID, method models.VerificationMethod, _ *uuid.UUID) (*models.BackupVerification, error) {
	s.runCalls++
	if s.runErr != nil {
		return nil, s.runErr
	}
	if s.runResult != nil {
		cp := *s.runResult
		cp.BackupID = backupID
		cp.Method = method
		return &cp, nil
	}
	return &models.BackupVerification{
		ID:       uuid.New(),
		BackupID: backupID,
		Status:   models.VerificationStatusPassed,
		Method:   method,
	}, nil
}

func (s *stubVerifySvc) MarkScheduleRan(_ context.Context, _ uuid.UUID, _ time.Time, _ string) error {
	s.markCalls++
	return nil
}

func (s *stubVerifySvc) PruneOld(_ context.Context) (int64, error) {
	s.pruneCalls++
	return s.pruneReturn, nil
}

// ============================================================================
// BackupVerifyWorker tests
// ============================================================================

func TestBackupVerifyWorker_OnDemand(t *testing.T) {
	svc := &stubVerifySvc{}
	w := NewBackupVerifyWorker(svc, nil)

	backupID := uuid.New()
	payload, _ := json.Marshal(models.BackupVerifyPayload{
		BackupID: backupID,
		Method:   string(models.VerificationMethodExtract),
	})
	job := &models.Job{
		ID:      uuid.New(),
		Type:    models.JobTypeBackupVerify,
		Payload: payload,
	}

	res, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if svc.runCalls != 1 {
		t.Fatalf("RunVerification calls = %d, want 1", svc.runCalls)
	}
	if svc.markCalls != 0 {
		t.Fatalf("MarkScheduleRan should not run on on-demand, got %d calls", svc.markCalls)
	}
	out, ok := res.(map[string]string)
	if !ok {
		t.Fatalf("result type %T, want map[string]string", res)
	}
	if out["status"] != string(models.VerificationStatusPassed) {
		t.Fatalf("status = %q, want passed", out["status"])
	}
}

func TestBackupVerifyWorker_Scheduled_NoDue(t *testing.T) {
	svc := &stubVerifySvc{}
	w := NewBackupVerifyWorker(svc, nil)

	payload, _ := json.Marshal(models.BackupVerifyPayload{})
	job := &models.Job{ID: uuid.New(), Type: models.JobTypeBackupVerify, Payload: payload}

	res, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if svc.markCalls != 0 {
		t.Fatalf("MarkScheduleRan should not run when no schedules due, got %d", svc.markCalls)
	}
	out, ok := res.(map[string]int)
	if !ok || out["schedules_processed"] != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestBackupVerifyWorker_Scheduled_RunsAllBackups(t *testing.T) {
	hostID := uuid.New()
	schedID := uuid.New()
	svc := &stubVerifySvc{
		due: []models.BackupVerificationSchedule{
			{ID: schedID, HostID: hostID, Method: "extract", MaxBackups: 3, Enabled: true},
		},
		backups: map[uuid.UUID][]*models.Backup{
			hostID: {
				{ID: uuid.New(), HostID: hostID, Status: models.BackupStatusCompleted},
				{ID: uuid.New(), HostID: hostID, Status: models.BackupStatusCompleted},
			},
		},
	}
	w := NewBackupVerifyWorker(svc, nil)

	payload, _ := json.Marshal(models.BackupVerifyPayload{})
	job := &models.Job{ID: uuid.New(), Type: models.JobTypeBackupVerify, Payload: payload}

	if _, err := w.Execute(context.Background(), job); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if svc.runCalls != 2 {
		t.Fatalf("RunVerification calls = %d, want 2", svc.runCalls)
	}
	if svc.markCalls != 1 {
		t.Fatalf("MarkScheduleRan calls = %d, want 1", svc.markCalls)
	}
	if svc.pruneCalls != 1 {
		t.Fatalf("PruneOld calls = %d, want 1 (best-effort)", svc.pruneCalls)
	}
}

func TestBackupVerifyWorker_Scheduled_InvalidMethodFallsBackToExtract(t *testing.T) {
	hostID := uuid.New()
	svc := &stubVerifySvc{
		due: []models.BackupVerificationSchedule{
			{ID: uuid.New(), HostID: hostID, Method: "garbage", MaxBackups: 1, Enabled: true},
		},
		backups: map[uuid.UUID][]*models.Backup{
			hostID: {{ID: uuid.New(), HostID: hostID, Status: models.BackupStatusCompleted}},
		},
	}
	w := NewBackupVerifyWorker(svc, nil)

	payload, _ := json.Marshal(models.BackupVerifyPayload{})
	job := &models.Job{ID: uuid.New(), Type: models.JobTypeBackupVerify, Payload: payload}

	if _, err := w.Execute(context.Background(), job); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if svc.runCalls != 1 {
		t.Fatalf("RunVerification calls = %d, want 1", svc.runCalls)
	}
}

func TestBackupVerifyWorker_NilService(t *testing.T) {
	w := NewBackupVerifyWorker(nil, nil)

	payload, _ := json.Marshal(models.BackupVerifyPayload{BackupID: uuid.New()})
	job := &models.Job{ID: uuid.New(), Type: models.JobTypeBackupVerify, Payload: payload}

	_, err := w.Execute(context.Background(), job)
	if err == nil {
		t.Fatalf("expected error when service is nil")
	}
}

// ============================================================================
// BackupVerifySandbox tests — the launcher is stubbed so we exercise the
// container-spec construction without standing up a real Docker daemon.
// ============================================================================

func TestSandbox_RunContainerVerify_NoLauncher(t *testing.T) {
	sb := &BackupVerifySandbox{cfg: VerifierConfig{VerifyImage: "alpine:3.21"}}
	if err := sb.RunContainerVerify(context.Background(), &models.Backup{ID: uuid.New(), Path: "/tmp/x"}); err == nil {
		t.Fatalf("expected error with nil launcher")
	}
}

func TestSandbox_RunContainerVerify_NoPath(t *testing.T) {
	sb := &BackupVerifySandbox{
		launcher: &stubLauncher{},
		cfg:      VerifierConfig{VerifyImage: "alpine:3.21"},
	}
	if err := sb.RunContainerVerify(context.Background(), &models.Backup{ID: uuid.New()}); err == nil {
		t.Fatalf("expected error when backup.Path is empty")
	}
}

func TestSandbox_RunContainerVerify_Success(t *testing.T) {
	stub := &stubLauncher{out: []byte("OK"), code: 0}
	cfg := VerifierConfig{}
	cfg.withDefaults()
	sb := NewBackupVerifySandbox(nil, cfg, nil)
	sb.launcher = stub

	err := sb.RunContainerVerify(context.Background(), &models.Backup{
		ID:   uuid.New(),
		Path: "/tmp/backup.tar.gz",
	})
	if err != nil {
		t.Fatalf("RunContainerVerify: %v", err)
	}
	if stub.calls != 1 {
		t.Fatalf("launcher called %d times, want 1", stub.calls)
	}
	if len(stub.lastEnv) != 0 {
		t.Fatalf("container verify must not pass env vars; got %+v", stub.lastEnv)
	}
}

func TestSandbox_RunContainerVerify_NonZeroExit(t *testing.T) {
	stub := &stubLauncher{out: []byte("BAD\n"), code: 42}
	cfg := VerifierConfig{}
	cfg.withDefaults()
	sb := NewBackupVerifySandbox(nil, cfg, nil)
	sb.launcher = stub

	err := sb.RunContainerVerify(context.Background(), &models.Backup{ID: uuid.New(), Path: "/tmp/x"})
	if err == nil {
		t.Fatalf("expected error for non-zero exit code")
	}
}

func TestSandbox_RunContainerVerify_LauncherError(t *testing.T) {
	stub := &stubLauncher{err: stderrors.New("docker offline")}
	cfg := VerifierConfig{}
	cfg.withDefaults()
	sb := NewBackupVerifySandbox(nil, cfg, nil)
	sb.launcher = stub

	if err := sb.RunContainerVerify(context.Background(), &models.Backup{ID: uuid.New(), Path: "/tmp/x"}); err == nil {
		t.Fatalf("expected error when launcher fails")
	}
}

func TestSandbox_RunDatabaseVerify_KeyNeverInEnv(t *testing.T) {
	stub := &stubLauncher{out: []byte("OK"), code: 0}
	cfg := VerifierConfig{}
	cfg.withDefaults()
	sb := NewBackupVerifySandbox(nil, cfg, nil)
	sb.launcher = stub
	sb.SetEncryptionKey([]byte("super-secret-key-32-bytes-long!!"))

	err := sb.RunDatabaseVerify(context.Background(), &models.Backup{ID: uuid.New(), Path: "/tmp/db.dump"})
	if err != nil {
		t.Fatalf("RunDatabaseVerify: %v", err)
	}
	// Critical: the encryption key must never appear in env vars.
	for k, v := range stub.lastEnv {
		if v == "super-secret-key-32-bytes-long!!" {
			t.Fatalf("encryption key leaked into env var %q", k)
		}
	}
}

func TestSandbox_SetEncryptionKey_ZeroesOnEmpty(t *testing.T) {
	sb := &BackupVerifySandbox{}
	sb.SetEncryptionKey([]byte("abc"))
	if len(sb.encryptionKey) == 0 {
		t.Fatalf("SetEncryptionKey did not store key")
	}
	sb.SetEncryptionKey(nil)
	if len(sb.encryptionKey) != 0 {
		t.Fatalf("SetEncryptionKey(nil) should clear key")
	}
}

func TestVerifierConfig_Defaults(t *testing.T) {
	cfg := VerifierConfig{}
	cfg.withDefaults()
	if cfg.VerifyImage == "" || cfg.DBVerifyImage == "" {
		t.Fatalf("images not defaulted: %+v", cfg)
	}
	if cfg.Timeout <= 0 {
		t.Fatalf("timeout not defaulted: %v", cfg.Timeout)
	}
	if cfg.KeyMountPath == "" {
		t.Fatalf("KeyMountPath not defaulted")
	}
}

func TestTruncateOutput(t *testing.T) {
	if s := truncateOutput([]byte("short"), 10); s != "short" {
		t.Fatalf("short string mutated: %q", s)
	}
	long := make([]byte, 50)
	for i := range long {
		long[i] = 'a'
	}
	s := truncateOutput(long, 10)
	if len(s) <= 10 {
		t.Fatalf("truncated string missing marker: %q", s)
	}
}
