// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package metadata

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/observability"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Config holds runtime knobs for the metadata Service. Values come from
// the `recon:` section of config.yaml (the metadata module shares
// retention and data-dir settings with the recon module).
type Config struct {
	// DataDir is the absolute parent directory under which the local
	// ArtifactStore writes its files. The store creates
	// "<DataDir>/recon/artifacts" on first use.
	DataDir string

	// MaxFileBytes caps the per-file size accepted by CreateJob. A
	// non-positive value defaults to 100 MiB.
	MaxFileBytes int64

	// RetentionDays controls how long stripped/extracted artifacts
	// survive before the retention worker (Session 12) sweeps them.
	// A non-positive value defaults to 90.
	RetentionDays int
}

func (c Config) withDefaults() Config {
	if c.MaxFileBytes <= 0 {
		c.MaxFileBytes = 100 << 20
	}
	if c.RetentionDays <= 0 {
		c.RetentionDays = 90
	}
	return c
}

// Implementation is the metadata Service. It satisfies the Service
// interface declared in metadata.go and adds RunJob, the worker-side
// method that drives the Extractor / Stripper through the artifact set.
//
// The struct is named Implementation rather than Service because the
// Service identifier in this package is the public interface contract.
type Implementation struct {
	repo      Repository
	store     ArtifactStore
	extractor Extractor
	stripper  Stripper
	cfg       Config
	log       *logger.Logger
}

// NewService constructs an *Implementation. All dependencies must be
// non-nil. The constructor returns an error rather than panicking so
// app wiring can fail-fast on misconfiguration.
func NewService(
	repo Repository,
	store ArtifactStore,
	extractor Extractor,
	stripper Stripper,
	cfg Config,
	log *logger.Logger,
) (*Implementation, error) {
	if repo == nil {
		return nil, errors.New("metadata service: nil repository")
	}
	if store == nil {
		return nil, errors.New("metadata service: nil artifact store")
	}
	if extractor == nil {
		return nil, errors.New("metadata service: nil extractor")
	}
	if stripper == nil {
		return nil, errors.New("metadata service: nil stripper")
	}
	if log == nil {
		log = logger.Nop()
	}
	return &Implementation{
		repo:      repo,
		store:     store,
		extractor: extractor,
		stripper:  stripper,
		cfg:       cfg.withDefaults(),
		log:       log.Named("metadata.service"),
	}, nil
}

// Compile-time assertion that *Implementation satisfies Service.
var _ Service = (*Implementation)(nil)

// ============================================================================
// CreateJob
// ============================================================================

// CreateJob validates the incoming files, writes their bytes to the
// artifact store, and persists the job and its artifacts in a single
// transaction. The returned Job is in the queued state; a worker (or
// the Service's own RunJob method) drives it to completion.
func (s *Implementation) CreateJob(ctx context.Context, in CreateJobInput) (*Job, error) {
	ctx, span := observability.StartSpan(ctx, "metadata.service.CreateJob")
	defer span.End()

	if err := validateMode(in.Mode); err != nil {
		return nil, fmt.Errorf("metadata service: create job: %w", err)
	}
	if in.Source == SourceUpload && len(in.Files) == 0 {
		return nil, fmt.Errorf("metadata service: create job: %w", ErrNoFiles)
	}

	for i, f := range in.Files {
		if err := validateUploadFilename(f.Filename); err != nil {
			return nil, fmt.Errorf("metadata service: create job: file %d: %w", i, err)
		}
		if f.Size < 0 || f.Size > s.cfg.MaxFileBytes {
			return nil, fmt.Errorf("metadata service: create job: file %d: %w", i, ErrArtifactTooLarge)
		}
	}

	job := &Job{
		ID:        uuid.New(),
		Source:    in.Source,
		SourceRef: in.SourceRef,
		Mode:      in.Mode,
		Status:    JobQueued,
		CreatedBy: in.CreatedBy,
	}

	// Stream files to disk first. Each Put returns the storage_ref and
	// the SHA-256 we need to populate the Artifact row.
	var artifacts []*Artifact
	for _, f := range in.Files {
		artifactID := uuid.New()
		ref := buildStorageRef(job.ID, artifactID)
		storedRef, sum, err := s.store.Put(ctx, ref, io.LimitReader(f.Content, s.cfg.MaxFileBytes+1), s.cfg.MaxFileBytes)
		if err != nil {
			s.cleanupArtifacts(ctx, artifacts)
			return nil, fmt.Errorf("metadata service: create job: store: %w", err)
		}
		artifacts = append(artifacts, &Artifact{
			ID:         artifactID,
			Filename:   f.Filename,
			MIME:       f.MIME,
			SizeBytes:  f.Size,
			SHA256:     sum,
			StorageRef: storedRef,
		})
	}

	job.ArtifactCount = len(artifacts)
	if err := s.repo.InsertJobWithArtifacts(ctx, job, artifacts); err != nil {
		s.cleanupArtifacts(ctx, artifacts)
		return nil, fmt.Errorf("metadata service: create job: persist: %w", err)
	}

	s.log.Info("metadata job created",
		"job_id", job.ID,
		"mode", string(job.Mode),
		"source", string(job.Source),
		"artifact_count", job.ArtifactCount,
	)

	return job, nil
}

// cleanupArtifacts removes on-disk state for artifacts created during a
// failed CreateJob attempt. It is best-effort: failures are logged at
// warn level but do not propagate (the caller already has a primary
// error to return).
func (s *Implementation) cleanupArtifacts(ctx context.Context, artifacts []*Artifact) {
	for _, a := range artifacts {
		if a.StorageRef == "" {
			continue
		}
		if err := s.store.Delete(ctx, a.StorageRef); err != nil {
			s.log.Warn("metadata cleanup failed",
				"storage_ref", a.StorageRef,
				"error", err,
			)
		}
	}
}

// ============================================================================
// GetJob / ListJobs / ListArtifacts
// ============================================================================

// GetJob returns a job by id, mapping pgx.ErrNoRows to ErrJobNotFound.
func (s *Implementation) GetJob(ctx context.Context, id uuid.UUID) (*Job, error) {
	ctx, span := observability.StartSpan(ctx, "metadata.service.GetJob")
	defer span.End()

	j, err := s.repo.GetJobByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("metadata service: get job: %w", ErrJobNotFound)
		}
		return nil, fmt.Errorf("metadata service: get job: %w", err)
	}
	return j, nil
}

// ListJobs returns jobs matching filter.
func (s *Implementation) ListJobs(ctx context.Context, filter ListJobsFilter) ([]Job, error) {
	ctx, span := observability.StartSpan(ctx, "metadata.service.ListJobs")
	defer span.End()

	out, err := s.repo.ListJobs(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("metadata service: list jobs: %w", err)
	}
	return out, nil
}

// ListArtifacts returns all artifacts for the given job.
func (s *Implementation) ListArtifacts(ctx context.Context, jobID uuid.UUID) ([]Artifact, error) {
	ctx, span := observability.StartSpan(ctx, "metadata.service.ListArtifacts")
	defer span.End()

	out, err := s.repo.ListArtifactsByJob(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("metadata service: list artifacts: %w", err)
	}
	return out, nil
}

// ============================================================================
// OpenStripped
// ============================================================================

// OpenStripped returns a ReadCloser over the stripped copy of an
// artifact. If the strip step has not completed (no stripped_sha256
// on the row) it returns ErrStripNotReady.
func (s *Implementation) OpenStripped(ctx context.Context, artifactID uuid.UUID) (io.ReadCloser, error) {
	ctx, span := observability.StartSpan(ctx, "metadata.service.OpenStripped")
	defer span.End()

	a, err := s.repo.GetArtifactByID(ctx, artifactID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("metadata service: open stripped: %w", ErrArtifactNotFound)
		}
		return nil, fmt.Errorf("metadata service: open stripped: %w", err)
	}
	if len(a.StrippedSHA256) == 0 {
		return nil, fmt.Errorf("metadata service: open stripped: %w", ErrStripNotReady)
	}

	resolver, ok := s.store.(pathResolver)
	if !ok {
		return nil, fmt.Errorf("metadata service: open stripped: store does not expose Resolve")
	}
	dir, err := resolver.Resolve(a.StorageRef)
	if err != nil {
		return nil, fmt.Errorf("metadata service: open stripped: %w", err)
	}
	path := filepath.Join(dir, strippedFilename)

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// The DB says the strip completed, but the file is gone.
			// This is an operator-visible inconsistency; surface it as
			// the typed not-ready error and warn.
			s.log.Warn("metadata stripped file missing on disk",
				"artifact_id", artifactID,
				"storage_ref", a.StorageRef,
			)
			return nil, fmt.Errorf("metadata service: open stripped: %w", ErrStripNotReady)
		}
		return nil, fmt.Errorf("metadata service: open stripped: %w", err)
	}
	return f, nil
}

// pathResolver is an optional capability the artifact store exposes so
// the Service can locate sibling files (the stripped copy) without
// duplicating the path-escape check. The local store satisfies it.
type pathResolver interface {
	Resolve(storageRef string) (string, error)
}

// strippedFilename mirrors the constant used by stripper.Stub and the
// (future) real mat2-backed stripper. Keeping it in one place avoids a
// circular dependency between metadata and stripper.
const strippedFilename = "stripped"

// ============================================================================
// RunJob — invoked by workers (Session 08)
// ============================================================================

// RunJob drives a queued job through its lifecycle: load the artifacts,
// invoke the configured Extractor and/or Stripper according to
// Job.Mode, persist the per-artifact results, and transition the job
// to completed (or failed). It is idempotent only insofar as the
// underlying Extractor and Stripper are.
func (s *Implementation) RunJob(ctx context.Context, jobID uuid.UUID) error {
	ctx, span := observability.StartSpan(ctx, "metadata.service.RunJob")
	defer span.End()

	job, err := s.repo.GetJobByID(ctx, jobID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("metadata service: run job: %w", ErrJobNotFound)
		}
		return fmt.Errorf("metadata service: run job: %w", err)
	}
	if job.Status != JobQueued {
		return fmt.Errorf("metadata service: run job: %w", ErrInvalidJobState)
	}

	now := time.Now().UTC()
	job.Status = JobRunning
	job.StartedAt = &now
	if err := s.repo.UpdateJob(ctx, job); err != nil {
		return fmt.Errorf("metadata service: run job: %w", err)
	}

	artifacts, err := s.repo.ListArtifactsByJob(ctx, jobID)
	if err != nil {
		s.markJobFailed(ctx, job, "list artifacts: "+err.Error())
		return fmt.Errorf("metadata service: run job: %w", err)
	}

	resolver, ok := s.store.(pathResolver)
	if !ok {
		s.markJobFailed(ctx, job, "store does not expose Resolve")
		return fmt.Errorf("metadata service: run job: store does not expose Resolve")
	}

	for i := range artifacts {
		a := &artifacts[i]
		if err := s.processArtifact(ctx, job, a, resolver); err != nil {
			s.markJobFailed(ctx, job, fmt.Sprintf("artifact %s: %v", a.ID, err))
			return fmt.Errorf("metadata service: run job: %w", err)
		}
	}

	finished := time.Now().UTC()
	job.Status = JobCompleted
	job.FinishedAt = &finished
	if err := s.repo.UpdateJob(ctx, job); err != nil {
		return fmt.Errorf("metadata service: run job: %w", err)
	}

	s.log.Info("metadata job completed",
		"job_id", job.ID,
		"artifact_count", job.ArtifactCount,
		"mode", string(job.Mode),
	)
	return nil
}

// processArtifact applies the job's Mode to a single artifact and
// persists the per-artifact result via UpdateArtifact.
func (s *Implementation) processArtifact(ctx context.Context, job *Job, a *Artifact, resolver pathResolver) error {
	dir, err := resolver.Resolve(a.StorageRef)
	if err != nil {
		return err
	}
	originalPath := filepath.Join(dir, "original")

	if job.Mode == ModeExtract || job.Mode == ModeBoth {
		extracted, err := s.extractor.Extract(ctx, ExtractInput{
			Path:     originalPath,
			Filename: a.Filename,
			MIME:     a.MIME,
		})
		if err != nil {
			return fmt.Errorf("extract: %w", err)
		}
		a.Extracted = extracted
		s.log.Debug("metadata extracted",
			"artifact_id", a.ID,
			"keys", topLevelKeys(extracted),
		)
	}

	if job.Mode == ModeStrip || job.Mode == ModeBoth {
		result, err := s.stripper.Strip(ctx, StripInput{
			Path:     originalPath,
			Filename: a.Filename,
			MIME:     a.MIME,
		})
		if err != nil {
			return fmt.Errorf("strip: %w", err)
		}
		a.StrippedSHA256 = result.SHA256
	}

	if err := s.repo.UpdateArtifact(ctx, a); err != nil {
		return fmt.Errorf("persist: %w", err)
	}
	return nil
}

// markJobFailed transitions a job to failed with the given message.
// Errors from the UpdateJob call are logged but not returned: the
// caller already has a primary error to surface.
func (s *Implementation) markJobFailed(ctx context.Context, job *Job, message string) {
	now := time.Now().UTC()
	job.Status = JobFailed
	job.Error = message
	job.FinishedAt = &now
	if err := s.repo.UpdateJob(ctx, job); err != nil {
		s.log.Warn("metadata mark-failed update failed",
			"job_id", job.ID,
			"error", err,
		)
	}
}

// ============================================================================
// Validators / helpers
// ============================================================================

func validateMode(m JobMode) error {
	switch m {
	case ModeExtract, ModeStrip, ModeBoth:
		return nil
	default:
		return ErrUnsupportedMode
	}
}

// validateUploadFilename rejects filenames that could result in path
// traversal even though the local artifact store has its own
// independent safety check. The rule is intentionally strict: the
// filename must equal filepath.Clean(filename), must not contain a
// path separator on either platform, and must not equal "." or "..".
func validateUploadFilename(name string) error {
	if name == "" || name == "." || name == ".." {
		return ErrInvalidFilename
	}
	if filepath.Clean(name) != name {
		return ErrInvalidFilename
	}
	if strings.ContainsAny(name, `/\`) {
		return ErrInvalidFilename
	}
	return nil
}

// buildStorageRef constructs the per-artifact path fragment the local
// store and UpdateArtifact share. Keeping the construction in one
// place lets future relocations (e.g., S3 prefixes) touch one line.
func buildStorageRef(jobID, artifactID uuid.UUID) string {
	return jobID.String() + "/" + artifactID.String()
}

// topLevelKeys returns the sorted set of top-level keys from an
// extracted-metadata map. It exists so the Service can log a
// fingerprint of the extraction without printing PII (filenames,
// EXIF GPS coordinates, etc.).
func topLevelKeys(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
