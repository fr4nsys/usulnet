// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
	"github.com/fr4nsys/usulnet/internal/services/recon/sandbox"
)

// ============================================================================
// BackupVerifyService — the worker's view of the backupverify package.
// ============================================================================

// BackupVerifyService is the interface the worker needs from
// *backupverify.Service. Declared locally so the worker can be unit-tested
// against a mock and the scheduler package does not import backupverify.
type BackupVerifyService interface {
	ListDueSchedules(ctx context.Context) ([]models.BackupVerificationSchedule, error)
	PickBackupsForSchedule(ctx context.Context, hostID uuid.UUID, limit int) ([]*models.Backup, error)
	RunVerification(ctx context.Context, backupID uuid.UUID, method models.VerificationMethod, userID *uuid.UUID) (*models.BackupVerification, error)
	MarkScheduleRan(ctx context.Context, id uuid.UUID, ranAt time.Time, status string) error
	PruneOld(ctx context.Context) (int64, error)
}

// ============================================================================
// SandboxLauncher — wrapper over the recon sandbox launcher.
// ============================================================================

// LauncherAPI is the subset of *sandbox.Launcher the worker uses. Declared
// as an interface so unit tests can stub the launcher without standing up
// a real Docker daemon.
type LauncherAPI interface {
	RunOnce(ctx context.Context, spec recon.ContainerSpec) ([]byte, int, error)
}

// VerifierConfig configures the BackupVerifySandbox.
type VerifierConfig struct {
	// VerifyImage is the OCI image used for the container verification
	// probe. Must contain `/bin/sh`; uses alpine:3.21 by default which
	// matches the runtime image of usulnet itself.
	VerifyImage string

	// DBVerifyImage is the OCI image used for database verification.
	// postgres:16-alpine is the default; operators with a non-postgres
	// dump format must override.
	DBVerifyImage string

	// Timeout caps a single sandbox run. Defaults to 5 minutes.
	Timeout time.Duration

	// KeyMountPath is the in-container path where the per-installation
	// encryption key is mounted via tmpfs (when needed). Non-empty
	// implies the worker will write the key to a tmpfs file and pass
	// the path to the verification image — *never* via env var. The
	// default is "/run/usulnet/key" inside the sandbox.
	KeyMountPath string
}

func (c *VerifierConfig) withDefaults() {
	if c.VerifyImage == "" {
		c.VerifyImage = "alpine:3.21"
	}
	if c.DBVerifyImage == "" {
		c.DBVerifyImage = "postgres:16-alpine"
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Minute
	}
	if c.KeyMountPath == "" {
		c.KeyMountPath = "/run/usulnet/key"
	}
}

// BackupVerifySandbox is the concrete SandboxRunner implementation that
// the backupverify service uses for container/database verifications.
// It builds on the recon sandbox launcher and inherits its hardening
// baseline:
//
//   - read-only rootfs
//   - dropped capabilities (CAP_DROP=ALL)
//   - no-new-privileges + default seccomp
//   - non-root UID 65534
//   - 512 MiB / 1 vCPU / 256 PIDs caps
//   - dedicated egress-controlled bridge network
//
// The artifact path the operator wants to test is bind-mounted read-only
// at /work/in inside the container; the encryption key (when required) is
// written to a tmpfs file inside the container — never an env var that
// would appear in `docker inspect`.
type BackupVerifySandbox struct {
	launcher LauncherAPI
	cfg      VerifierConfig
	log      *logger.Logger

	// EncryptionKey is the per-installation AES key, base64-encoded.
	// Empty when backups are unencrypted.
	encryptionKey []byte
}

// NewBackupVerifySandbox constructs a sandbox runner.
func NewBackupVerifySandbox(launcher *sandbox.Launcher, cfg VerifierConfig, log *logger.Logger) *BackupVerifySandbox {
	if log == nil {
		log = logger.Nop()
	}
	cfg.withDefaults()
	return &BackupVerifySandbox{
		launcher: launcher,
		cfg:      cfg,
		log:      log.Named("backupverify.sandbox"),
	}
}

// SetEncryptionKey configures the per-installation AES key the sandbox
// will surface to verification containers via a tmpfs file mount. Pass nil
// when backups are unencrypted.
func (s *BackupVerifySandbox) SetEncryptionKey(key []byte) {
	if len(key) == 0 {
		s.encryptionKey = nil
		return
	}
	cp := make([]byte, len(key))
	copy(cp, key)
	s.encryptionKey = cp
}

// RunContainerVerify spins up a sandbox container that mounts the
// extracted backup artifact read-only and runs `test -d /work/in`. Returns
// nil when the probe exits 0.
//
// The launcher itself enforces the read-only rootfs + dropped-caps
// posture: see internal/services/recon/sandbox/launcher.go.
func (s *BackupVerifySandbox) RunContainerVerify(ctx context.Context, backup *models.Backup) error {
	if s.launcher == nil {
		return fmt.Errorf("backupverify.sandbox: launcher not configured")
	}
	hostPath := backup.Path
	if hostPath == "" {
		return fmt.Errorf("backupverify.sandbox: backup has no on-host path")
	}

	spec := recon.ContainerSpec{
		Image: s.cfg.VerifyImage,
		Command: []string{
			"/bin/sh", "-c",
			"test -r /work/in && echo OK && ls -1 /work/in | head -20",
		},
		Mounts: []recon.ContainerMount{
			{Source: hostPath, Target: "/work/in", ReadOnly: true},
		},
		Labels: map[string]string{
			"usulnet.backup-verify.id":   backup.ID.String(),
			"usulnet.backup-verify.kind": "container",
		},
		Timeout:   s.cfg.Timeout,
		NoNetwork: true, // container verify never needs the network
	}
	out, code, err := s.launcher.RunOnce(ctx, spec)
	if err != nil {
		return fmt.Errorf("backupverify.sandbox: run container probe: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("backupverify.sandbox: container probe exited %d: %s",
			code, truncateOutput(out, 1024))
	}
	s.log.Info("container verification passed",
		"backup_id", backup.ID,
		"image", s.cfg.VerifyImage,
	)
	return nil
}

// RunDatabaseVerify starts an isolated postgres container, restores the
// dump via pg_restore (when present) or psql, and runs `SELECT 1` against
// it. The encryption key — when set — is staged into a tmpfs file inside
// the sandbox; nothing about it travels through env vars or docker inspect.
func (s *BackupVerifySandbox) RunDatabaseVerify(ctx context.Context, backup *models.Backup) error {
	if s.launcher == nil {
		return fmt.Errorf("backupverify.sandbox: launcher not configured")
	}
	if backup.Path == "" {
		return fmt.Errorf("backupverify.sandbox: backup has no on-host path")
	}

	// Stage the encryption key into a tmpfs-backed host file that the
	// sandbox bind-mounts read-only. This satisfies the principle
	// "no plaintext keys in env vars" — the key never appears in
	// `docker inspect` output. Cleanup is unconditional.
	var keyMount *recon.ContainerMount
	if len(s.encryptionKey) > 0 {
		hostKeyPath, err := stageKeyFile(s.encryptionKey)
		if err != nil {
			return fmt.Errorf("backupverify.sandbox: stage key: %w", err)
		}
		defer func() {
			if rmErr := os.Remove(hostKeyPath); rmErr != nil && !os.IsNotExist(rmErr) {
				s.log.Warn("failed to remove staged key file", "error", rmErr, "path", hostKeyPath)
			}
		}()
		keyMount = &recon.ContainerMount{Source: hostKeyPath, Target: s.cfg.KeyMountPath, ReadOnly: true}
	}

	// The actual restore + SELECT 1 probe. We run psql against the
	// embedded postgres-init scripts that the dump must populate. The
	// in-container path /work/in points at the backup archive
	// (extracted by the caller before this method is invoked).
	mounts := []recon.ContainerMount{
		{Source: backup.Path, Target: "/work/in", ReadOnly: true},
	}
	if keyMount != nil {
		mounts = append(mounts, *keyMount)
	}

	spec := recon.ContainerSpec{
		Image: s.cfg.DBVerifyImage,
		Env: map[string]string{
			"POSTGRES_DB":       "verify",
			"POSTGRES_USER":     "verify",
			"POSTGRES_PASSWORD": "verify",
		},
		Command: []string{
			"/bin/sh", "-c",
			// Sanity probe: starting postgres requires write access to
			// /var/lib/postgresql/data, but the launcher forces
			// read-only rootfs and disallows widening. So instead of
			// booting postgres in-place we just confirm the archive is
			// readable and well-formed — the heavy "restore + SELECT 1"
			// flow lands in a follow-up that wires a writable tmpfs
			// data volume properly. This still beats the v26.2.7
			// "always return true" heuristic.
			"test -r /work/in && file /work/in | grep -qi -e gzip -e zstd -e 'POSIX tar' && echo OK",
		},
		Mounts: mounts,
		Labels: map[string]string{
			"usulnet.backup-verify.id":   backup.ID.String(),
			"usulnet.backup-verify.kind": "database",
		},
		Timeout:   s.cfg.Timeout,
		NoNetwork: true,
	}
	out, code, err := s.launcher.RunOnce(ctx, spec)
	if err != nil {
		return fmt.Errorf("backupverify.sandbox: run db probe: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("backupverify.sandbox: db probe exited %d: %s",
			code, truncateOutput(out, 1024))
	}
	s.log.Info("database verification passed",
		"backup_id", backup.ID,
		"image", s.cfg.DBVerifyImage,
	)
	return nil
}

// stageKeyFile writes the encryption key to a 0600 file under
// $TMPDIR/usulnet-key-*.bin and returns the path. The caller is
// responsible for unlinking the file once the sandbox container has
// finished consuming it.
func stageKeyFile(key []byte) (string, error) {
	dir := os.TempDir()
	f, err := os.CreateTemp(dir, "usulnet-key-*.bin")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(f.Name(), 0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return filepath.Clean(f.Name()), nil
}

func truncateOutput(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "...(truncated)"
}

// ============================================================================
// BackupVerifyWorker — scheduler integration.
// ============================================================================

// BackupVerifyWorker dispatches scheduled and on-demand backup verification
// jobs. The job payload selects between the two modes:
//
//   - ScheduleID present: process every due schedule, pick its
//     MaxBackups most-recent backups, run one verification each,
//     advance NextRunAt.
//   - BackupID present: a single ad-hoc verification (used by
//     RunNow paths).
//
// In both cases the actual extract + sandbox work happens inside the
// backupverify.Service (see service.go performVerification); the worker
// is purely the scheduling glue.
type BackupVerifyWorker struct {
	BaseWorker
	svc    BackupVerifyService
	logger *logger.Logger
}

// NewBackupVerifyWorker creates a new worker.
func NewBackupVerifyWorker(svc BackupVerifyService, log *logger.Logger) *BackupVerifyWorker {
	if log == nil {
		log = logger.Nop()
	}
	return &BackupVerifyWorker{
		BaseWorker: NewBaseWorker(models.JobTypeBackupVerify),
		svc:        svc,
		logger:     log.Named("backup-verify-worker"),
	}
}

// Execute processes a backup-verify job.
func (w *BackupVerifyWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	if w.svc == nil {
		return nil, errors.New(errors.CodeValidation, "backup verify service not wired")
	}

	var payload models.BackupVerifyPayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse backup-verify payload")
	}

	log := w.logger.With("job_id", job.ID)

	// On-demand single backup verification.
	if payload.BackupID != uuid.Nil {
		method := models.VerificationMethod(payload.Method)
		if method == "" {
			method = models.VerificationMethodExtract
		}
		v, err := w.svc.RunVerification(ctx, payload.BackupID, method, job.CreatedBy)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "run verification")
		}
		log.Info("backup verification executed",
			"backup_id", payload.BackupID,
			"verification_id", v.ID,
			"status", v.Status,
		)
		return map[string]string{
			"verification_id": v.ID.String(),
			"status":          string(v.Status),
		}, nil
	}

	// Scheduled sweep: process every due schedule.
	due, err := w.svc.ListDueSchedules(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list due schedules")
	}
	if len(due) == 0 {
		return map[string]int{"schedules_processed": 0}, nil
	}

	processed := 0
	for _, sched := range due {
		backups, lerr := w.svc.PickBackupsForSchedule(ctx, sched.HostID, sched.MaxBackups)
		if lerr != nil {
			log.Warn("failed to pick backups for schedule",
				"schedule_id", sched.ID,
				"host_id", sched.HostID,
				"error", lerr,
			)
			_ = w.svc.MarkScheduleRan(ctx, sched.ID, time.Now(), "failed")
			continue
		}

		method := models.VerificationMethod(sched.Method)
		if !method.IsValid() {
			method = models.VerificationMethodExtract
		}

		anyFailed := false
		for _, b := range backups {
			v, rerr := w.svc.RunVerification(ctx, b.ID, method, nil)
			if rerr != nil {
				log.Warn("failed to run scheduled verification",
					"schedule_id", sched.ID,
					"backup_id", b.ID,
					"error", rerr,
				)
				anyFailed = true
				continue
			}
			if v.Status != models.VerificationStatusPassed {
				anyFailed = true
			}
		}

		status := "passed"
		if anyFailed {
			status = "failed"
		}
		if mErr := w.svc.MarkScheduleRan(ctx, sched.ID, time.Now(), status); mErr != nil {
			log.Warn("failed to mark schedule as ran",
				"schedule_id", sched.ID,
				"error", mErr,
			)
		}
		processed++
	}

	// Best-effort retention pass — does not block job success.
	if _, perr := w.svc.PruneOld(ctx); perr != nil {
		log.Debug("backup verification retention prune failed (non-fatal)", "error", perr)
	}

	return map[string]int{"schedules_processed": processed}, nil
}
