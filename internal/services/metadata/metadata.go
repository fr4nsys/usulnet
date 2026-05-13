// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package metadata defines the contracts for the metadata hygiene module
// introduced in usulnet v26.5.0. It exposes a Service for extracting and
// stripping EXIF/XMP/IPTC/PDF/Office metadata from files supplied by the
// user, via the recon-toolkit container sandbox.
//
// This file contains only the public domain types and interfaces. The
// implementation lands in a subsequent PR per the RFC's rollout plan
// (see docs/recon.md).
package metadata

import (
	"context"
	"io"
	"time"

	"github.com/google/uuid"
)

// JobSource enumerates where the file being processed came from.
type JobSource string

const (
	SourceUpload   JobSource = "upload"
	SourceHostPath JobSource = "host_path"
	SourceVolume   JobSource = "volume"
	SourceRegistry JobSource = "registry"
)

// JobMode is what the user wants done with the file.
type JobMode string

const (
	ModeExtract JobMode = "extract"
	ModeStrip   JobMode = "strip"
	ModeBoth    JobMode = "both"
)

// JobStatus is the lifecycle of a metadata job.
type JobStatus string

const (
	JobQueued    JobStatus = "queued"
	JobRunning   JobStatus = "running"
	JobCompleted JobStatus = "completed"
	JobFailed    JobStatus = "failed"
	JobCancelled JobStatus = "cancelled"
)

// Job is a single metadata operation (one or more files).
type Job struct {
	ID            uuid.UUID
	Source        JobSource
	SourceRef     string
	Mode          JobMode
	Status        JobStatus
	ArtifactCount int
	Error         string
	StartedAt     *time.Time
	FinishedAt    *time.Time
	CreatedBy     *uuid.UUID
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Artifact is one file processed by a Job.
type Artifact struct {
	ID             uuid.UUID
	JobID          uuid.UUID
	Filename       string
	MIME           string
	SizeBytes      int64
	SHA256         []byte
	StrippedSHA256 []byte
	Extracted      map[string]any
	StorageRef     string
	CreatedAt      time.Time
}

// Service is the entry point for metadata operations. Consumed by web,
// API, CLI, and scheduler workers.
type Service interface {
	// CreateJob registers a new metadata job and returns it in the queued state.
	CreateJob(ctx context.Context, in CreateJobInput) (*Job, error)

	// GetJob returns a job by ID.
	GetJob(ctx context.Context, id uuid.UUID) (*Job, error)

	// ListJobs returns recent jobs.
	ListJobs(ctx context.Context, filter ListJobsFilter) ([]Job, error)

	// ListArtifacts returns the per-file results for a job.
	ListArtifacts(ctx context.Context, jobID uuid.UUID) ([]Artifact, error)

	// OpenStripped returns a reader for the cleaned bytes of an artifact.
	// Callers are responsible for closing the reader.
	OpenStripped(ctx context.Context, artifactID uuid.UUID) (io.ReadCloser, error)
}

// CreateJobInput is the request to create a metadata job.
type CreateJobInput struct {
	Source    JobSource
	SourceRef string
	Mode      JobMode
	CreatedBy *uuid.UUID

	// Files is set when Source == SourceUpload; the Service is
	// responsible for persisting these bytes to the local artifact
	// store before dispatching the job.
	Files []UploadedFile
}

// UploadedFile carries the raw bytes for an upload-mode job.
type UploadedFile struct {
	Filename string
	MIME     string
	Content  io.Reader
	Size     int64
}

// ListJobsFilter is the filter struct for ListJobs.
type ListJobsFilter struct {
	Status    *JobStatus
	CreatedBy *uuid.UUID
	Since     *time.Time
	Limit     int
	Offset    int
}

// Repository abstracts persistence for the metadata module. Implemented in
// internal/repository/postgres/recon_metadata_repo.go.
type Repository interface {
	InsertJob(ctx context.Context, j *Job) error
	UpdateJob(ctx context.Context, j *Job) error
	GetJobByID(ctx context.Context, id uuid.UUID) (*Job, error)
	ListJobs(ctx context.Context, filter ListJobsFilter) ([]Job, error)

	InsertArtifact(ctx context.Context, a *Artifact) error
	UpdateArtifact(ctx context.Context, a *Artifact) error
	ListArtifactsByJob(ctx context.Context, jobID uuid.UUID) ([]Artifact, error)
	GetArtifactByID(ctx context.Context, id uuid.UUID) (*Artifact, error)

	// InsertJobWithArtifacts persists a job and a set of artifacts in a
	// single database transaction. Pre-set IDs are honored when non-zero
	// so callers (the Service) can locate the on-disk storage_ref
	// before persisting.
	InsertJobWithArtifacts(ctx context.Context, j *Job, artifacts []*Artifact) error
}

// Extractor reads metadata from a file. Implementations call the
// recon-toolkit container (exiftool, pdfid, oletools).
type Extractor interface {
	Extract(ctx context.Context, input ExtractInput) (map[string]any, error)
}

// ExtractInput is the request to read metadata from a single file.
type ExtractInput struct {
	Path     string // path inside the toolkit container, after mount
	Filename string
	MIME     string
}

// Stripper writes a cleaned copy of a file. Implementations call mat2
// inside the recon-toolkit container with `--inplace --no-backup` on a
// dedicated copy and return the cleaned path + sha256.
type Stripper interface {
	Strip(ctx context.Context, input StripInput) (StripResult, error)
}

// StripInput is the request to strip metadata from a single file.
type StripInput struct {
	Path     string
	Filename string
	MIME     string
}

// StripResult is the outcome of a strip operation.
type StripResult struct {
	CleanedPath string
	SHA256      []byte
	SizeBytes   int64
}

// ArtifactStore persists user-uploaded files for the lifetime of a job.
// Files are removed when the job is deleted or its retention TTL expires.
// Implemented over the local filesystem in v26.5.0; S3 backend deferred.
type ArtifactStore interface {
	Put(ctx context.Context, filename string, r io.Reader, size int64) (storageRef string, sha256 []byte, err error)
	Open(ctx context.Context, storageRef string) (io.ReadCloser, error)
	Delete(ctx context.Context, storageRef string) error
}
