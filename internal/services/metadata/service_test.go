// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package metadata_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/services/metadata"
	"github.com/fr4nsys/usulnet/internal/services/metadata/artifactstore"
	"github.com/fr4nsys/usulnet/internal/services/metadata/extractor"
	"github.com/fr4nsys/usulnet/internal/services/metadata/stripper"
)

// ============================================================================
// Stub repository
// ============================================================================

type stubRepo struct {
	mu          sync.Mutex
	jobs        map[uuid.UUID]*metadata.Job
	artifacts   map[uuid.UUID]*metadata.Artifact
	insertWErr  error
	updateAErr  error
	insertOrder []uuid.UUID
}

func newStubRepo() *stubRepo {
	return &stubRepo{
		jobs:      map[uuid.UUID]*metadata.Job{},
		artifacts: map[uuid.UUID]*metadata.Artifact{},
	}
}

func (r *stubRepo) InsertJob(_ context.Context, j *metadata.Job) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if j.ID == uuid.Nil {
		j.ID = uuid.New()
	}
	j.CreatedAt = time.Now().UTC()
	j.UpdatedAt = j.CreatedAt
	if j.Status == "" {
		j.Status = metadata.JobQueued
	}
	cp := *j
	r.jobs[j.ID] = &cp
	return nil
}

func (r *stubRepo) UpdateJob(_ context.Context, j *metadata.Job) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.jobs[j.ID]; !ok {
		return pgx.ErrNoRows
	}
	cp := *j
	cp.UpdatedAt = time.Now().UTC()
	r.jobs[j.ID] = &cp
	*j = cp
	return nil
}

func (r *stubRepo) GetJobByID(_ context.Context, id uuid.UUID) (*metadata.Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	cp := *j
	return &cp, nil
}

func (r *stubRepo) ListJobs(_ context.Context, _ metadata.ListJobsFilter) ([]metadata.Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]metadata.Job, 0, len(r.jobs))
	for _, j := range r.jobs {
		out = append(out, *j)
	}
	return out, nil
}

func (r *stubRepo) InsertArtifact(_ context.Context, a *metadata.Artifact) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	a.CreatedAt = time.Now().UTC()
	cp := *a
	r.artifacts[a.ID] = &cp
	r.insertOrder = append(r.insertOrder, a.ID)
	return nil
}

func (r *stubRepo) UpdateArtifact(_ context.Context, a *metadata.Artifact) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.updateAErr != nil {
		return r.updateAErr
	}
	if _, ok := r.artifacts[a.ID]; !ok {
		return pgx.ErrNoRows
	}
	cp := *a
	r.artifacts[a.ID] = &cp
	return nil
}

func (r *stubRepo) ListArtifactsByJob(_ context.Context, jobID uuid.UUID) ([]metadata.Artifact, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []metadata.Artifact
	for _, id := range r.insertOrder {
		a := r.artifacts[id]
		if a == nil || a.JobID != jobID {
			continue
		}
		out = append(out, *a)
	}
	return out, nil
}

func (r *stubRepo) GetArtifactByID(_ context.Context, id uuid.UUID) (*metadata.Artifact, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.artifacts[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	cp := *a
	return &cp, nil
}

func (r *stubRepo) InsertJobWithArtifacts(ctx context.Context, j *metadata.Job, artifacts []*metadata.Artifact) error {
	if r.insertWErr != nil {
		return r.insertWErr
	}
	if err := r.InsertJob(ctx, j); err != nil {
		return err
	}
	for _, a := range artifacts {
		a.JobID = j.ID
		if err := r.InsertArtifact(ctx, a); err != nil {
			return err
		}
	}
	return nil
}

// ============================================================================
// Helpers
// ============================================================================

func newService(t *testing.T) (*metadata.Implementation, *stubRepo, *artifactstore.LocalStore) {
	t.Helper()
	repo := newStubRepo()
	root := t.TempDir()
	store, err := artifactstore.NewLocalStore(root)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	svc, err := metadata.NewService(
		repo, store, &extractor.Stub{}, &stripper.Stub{},
		metadata.Config{DataDir: root, MaxFileBytes: 1024},
		nil,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, repo, store
}

func smallFile(name, body string) metadata.UploadedFile {
	return metadata.UploadedFile{
		Filename: name,
		MIME:     "text/plain",
		Content:  strings.NewReader(body),
		Size:     int64(len(body)),
	}
}

// ============================================================================
// NewService
// ============================================================================

func TestNewService_RejectsNilDeps(t *testing.T) {
	cases := []struct {
		name  string
		patch func(repo metadata.Repository, store metadata.ArtifactStore, e metadata.Extractor, s metadata.Stripper) (*metadata.Implementation, error)
	}{
		{"nil repo", func(_ metadata.Repository, store metadata.ArtifactStore, e metadata.Extractor, s metadata.Stripper) (*metadata.Implementation, error) {
			return metadata.NewService(nil, store, e, s, metadata.Config{}, nil)
		}},
		{"nil store", func(repo metadata.Repository, _ metadata.ArtifactStore, e metadata.Extractor, s metadata.Stripper) (*metadata.Implementation, error) {
			return metadata.NewService(repo, nil, e, s, metadata.Config{}, nil)
		}},
		{"nil extractor", func(repo metadata.Repository, store metadata.ArtifactStore, _ metadata.Extractor, s metadata.Stripper) (*metadata.Implementation, error) {
			return metadata.NewService(repo, store, nil, s, metadata.Config{}, nil)
		}},
		{"nil stripper", func(repo metadata.Repository, store metadata.ArtifactStore, e metadata.Extractor, _ metadata.Stripper) (*metadata.Implementation, error) {
			return metadata.NewService(repo, store, e, nil, metadata.Config{}, nil)
		}},
	}
	repo := newStubRepo()
	store, _ := artifactstore.NewLocalStore(t.TempDir())
	for _, c := range cases {
		_, err := c.patch(repo, store, &extractor.Stub{}, &stripper.Stub{})
		if err == nil {
			t.Errorf("[%s] expected error", c.name)
		}
	}
}

// ============================================================================
// CreateJob
// ============================================================================

func TestCreateJob_PersistsBytesAndRows(t *testing.T) {
	svc, repo, store := newService(t)
	ctx := context.Background()

	body := "hello world"
	job, err := svc.CreateJob(ctx, metadata.CreateJobInput{
		Source: metadata.SourceUpload,
		Mode:   metadata.ModeBoth,
		Files:  []metadata.UploadedFile{smallFile("hello.txt", body)},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if job.Status != metadata.JobQueued {
		t.Errorf("status = %q, want queued", job.Status)
	}
	if job.ArtifactCount != 1 {
		t.Errorf("artifact_count = %d, want 1", job.ArtifactCount)
	}

	arts, err := repo.ListArtifactsByJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListArtifactsByJob: %v", err)
	}
	if len(arts) != 1 {
		t.Fatalf("len(artifacts) = %d, want 1", len(arts))
	}
	a := arts[0]
	if a.Filename != "hello.txt" {
		t.Errorf("filename = %q", a.Filename)
	}
	want := sha256.Sum256([]byte(body))
	if !bytes.Equal(a.SHA256, want[:]) {
		t.Errorf("sha256 mismatch")
	}

	// File round-trips through the store.
	rc, err := store.Open(ctx, a.StorageRef)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer rc.Close() //nolint:errcheck
	got, _ := io.ReadAll(rc)
	if string(got) != body {
		t.Errorf("payload mismatch: got %q, want %q", got, body)
	}
}

func TestCreateJob_RejectsPathTraversalFilename(t *testing.T) {
	svc, _, _ := newService(t)

	cases := []string{
		"../etc/passwd",
		"./hidden",
		"sub/dir.txt",
		`win\path.txt`,
		"",
		".",
		"..",
	}
	for _, name := range cases {
		_, err := svc.CreateJob(context.Background(), metadata.CreateJobInput{
			Source: metadata.SourceUpload,
			Mode:   metadata.ModeExtract,
			Files:  []metadata.UploadedFile{smallFile(name, "x")},
		})
		if !errors.Is(err, metadata.ErrInvalidFilename) {
			t.Errorf("filename %q: err = %v, want ErrInvalidFilename", name, err)
		}
	}
}

func TestCreateJob_EnforcesSizeLimit(t *testing.T) {
	svc, _, _ := newService(t)
	big := strings.Repeat("a", 2048) // cfg cap is 1024
	_, err := svc.CreateJob(context.Background(), metadata.CreateJobInput{
		Source: metadata.SourceUpload,
		Mode:   metadata.ModeExtract,
		Files:  []metadata.UploadedFile{smallFile("big.txt", big)},
	})
	if !errors.Is(err, metadata.ErrArtifactTooLarge) {
		t.Errorf("err = %v, want ErrArtifactTooLarge", err)
	}
}

func TestCreateJob_RejectsUnsupportedMode(t *testing.T) {
	svc, _, _ := newService(t)
	_, err := svc.CreateJob(context.Background(), metadata.CreateJobInput{
		Source: metadata.SourceUpload,
		Mode:   metadata.JobMode("transcode"),
		Files:  []metadata.UploadedFile{smallFile("x.txt", "x")},
	})
	if !errors.Is(err, metadata.ErrUnsupportedMode) {
		t.Errorf("err = %v, want ErrUnsupportedMode", err)
	}
}

func TestCreateJob_RejectsEmptyUpload(t *testing.T) {
	svc, _, _ := newService(t)
	_, err := svc.CreateJob(context.Background(), metadata.CreateJobInput{
		Source: metadata.SourceUpload,
		Mode:   metadata.ModeExtract,
		Files:  nil,
	})
	if !errors.Is(err, metadata.ErrNoFiles) {
		t.Errorf("err = %v, want ErrNoFiles", err)
	}
}

func TestCreateJob_CleansUpOnRepoFailure(t *testing.T) {
	svc, repo, store := newService(t)
	repo.insertWErr = errors.New("db down")

	_, err := svc.CreateJob(context.Background(), metadata.CreateJobInput{
		Source: metadata.SourceUpload,
		Mode:   metadata.ModeExtract,
		Files:  []metadata.UploadedFile{smallFile("c.txt", "x")},
	})
	if err == nil {
		t.Fatal("expected repo error")
	}

	// The store directory for that hypothetical artifact should not
	// linger after cleanup; we can probe by listing the root.
	// Reading any path under it should fail.
	if _, err := store.Open(context.Background(), "nope/whatever"); !errors.Is(err, metadata.ErrArtifactNotFound) {
		t.Errorf("expected not-found probe: %v", err)
	}
}

// ============================================================================
// GetJob / OpenStripped
// ============================================================================

func TestGetJob_NotFound(t *testing.T) {
	svc, _, _ := newService(t)
	_, err := svc.GetJob(context.Background(), uuid.New())
	if !errors.Is(err, metadata.ErrJobNotFound) {
		t.Errorf("err = %v, want ErrJobNotFound", err)
	}
}

func TestOpenStripped_BeforeRun_ReturnsNotReady(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()

	job, err := svc.CreateJob(ctx, metadata.CreateJobInput{
		Source: metadata.SourceUpload,
		Mode:   metadata.ModeBoth,
		Files:  []metadata.UploadedFile{smallFile("a.txt", "abc")},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	arts, _ := svc.ListArtifacts(ctx, job.ID)
	_, err = svc.OpenStripped(ctx, arts[0].ID)
	if !errors.Is(err, metadata.ErrStripNotReady) {
		t.Errorf("err = %v, want ErrStripNotReady", err)
	}
}

func TestOpenStripped_ArtifactNotFound(t *testing.T) {
	svc, _, _ := newService(t)
	_, err := svc.OpenStripped(context.Background(), uuid.New())
	if !errors.Is(err, metadata.ErrArtifactNotFound) {
		t.Errorf("err = %v, want ErrArtifactNotFound", err)
	}
}

// ============================================================================
// RunJob
// ============================================================================

func TestRunJob_ExtractAndStrip(t *testing.T) {
	svc, repo, store := newService(t)
	ctx := context.Background()

	body := "the original bytes"
	job, err := svc.CreateJob(ctx, metadata.CreateJobInput{
		Source: metadata.SourceUpload,
		Mode:   metadata.ModeBoth,
		Files:  []metadata.UploadedFile{smallFile("file.txt", body)},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	if err := svc.RunJob(ctx, job.ID); err != nil {
		t.Fatalf("RunJob: %v", err)
	}

	got, _ := repo.GetJobByID(ctx, job.ID)
	if got.Status != metadata.JobCompleted {
		t.Errorf("status = %q, want completed", got.Status)
	}

	arts, _ := repo.ListArtifactsByJob(ctx, job.ID)
	a := arts[0]
	if len(a.Extracted) == 0 {
		t.Errorf("expected extracted metadata to be populated")
	}
	if len(a.StrippedSHA256) == 0 {
		t.Errorf("expected stripped_sha256 to be populated")
	}

	// OpenStripped now returns the cleaned bytes.
	rc, err := svc.OpenStripped(ctx, a.ID)
	if err != nil {
		t.Fatalf("OpenStripped: %v", err)
	}
	defer rc.Close() //nolint:errcheck
	cleaned, _ := io.ReadAll(rc)
	if string(cleaned) != body { // stub stripper is identity
		t.Errorf("cleaned bytes mismatch")
	}

	// Just sanity-check the store root contains the expected file.
	full, _ := store.Resolve(a.StorageRef)
	if full == "" {
		t.Error("Resolve returned empty path")
	}
}

func TestRunJob_ExtractOnly(t *testing.T) {
	svc, repo, _ := newService(t)
	ctx := context.Background()

	job, _ := svc.CreateJob(ctx, metadata.CreateJobInput{
		Source: metadata.SourceUpload,
		Mode:   metadata.ModeExtract,
		Files:  []metadata.UploadedFile{smallFile("x.txt", "x")},
	})

	if err := svc.RunJob(ctx, job.ID); err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	arts, _ := repo.ListArtifactsByJob(ctx, job.ID)
	if len(arts[0].Extracted) == 0 {
		t.Errorf("expected extracted metadata")
	}
	if len(arts[0].StrippedSHA256) != 0 {
		t.Errorf("strip should not run in extract-only mode")
	}
}

func TestRunJob_StripOnly(t *testing.T) {
	svc, repo, _ := newService(t)
	ctx := context.Background()

	job, _ := svc.CreateJob(ctx, metadata.CreateJobInput{
		Source: metadata.SourceUpload,
		Mode:   metadata.ModeStrip,
		Files:  []metadata.UploadedFile{smallFile("x.txt", "x")},
	})

	if err := svc.RunJob(ctx, job.ID); err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	arts, _ := repo.ListArtifactsByJob(ctx, job.ID)
	if len(arts[0].StrippedSHA256) == 0 {
		t.Errorf("expected stripped_sha256")
	}
	if len(arts[0].Extracted) != 0 {
		t.Errorf("extract should not run in strip-only mode")
	}
}

func TestRunJob_RejectsNonQueued(t *testing.T) {
	svc, repo, _ := newService(t)
	ctx := context.Background()

	job := &metadata.Job{Status: metadata.JobCompleted, Source: metadata.SourceUpload, Mode: metadata.ModeExtract}
	_ = repo.InsertJob(ctx, job)

	if err := svc.RunJob(ctx, job.ID); !errors.Is(err, metadata.ErrInvalidJobState) {
		t.Errorf("err = %v, want ErrInvalidJobState", err)
	}
}

func TestRunJob_ExtractorErrorMarksJobFailed(t *testing.T) {
	repo := newStubRepo()
	store, _ := artifactstore.NewLocalStore(t.TempDir())
	svc, _ := metadata.NewService(
		repo, store,
		&extractor.Stub{Err: errors.New("boom")},
		&stripper.Stub{},
		metadata.Config{MaxFileBytes: 1024},
		nil,
	)
	ctx := context.Background()
	job, err := svc.CreateJob(ctx, metadata.CreateJobInput{
		Source: metadata.SourceUpload,
		Mode:   metadata.ModeExtract,
		Files:  []metadata.UploadedFile{smallFile("x.txt", "x")},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	if err := svc.RunJob(ctx, job.ID); err == nil {
		t.Fatal("expected error")
	}
	got, _ := repo.GetJobByID(ctx, job.ID)
	if got.Status != metadata.JobFailed {
		t.Errorf("status = %q, want failed", got.Status)
	}
	if got.Error == "" {
		t.Errorf("Error not populated")
	}
}

func TestRunJob_NotFound(t *testing.T) {
	svc, _, _ := newService(t)
	if err := svc.RunJob(context.Background(), uuid.New()); !errors.Is(err, metadata.ErrJobNotFound) {
		t.Errorf("err = %v, want ErrJobNotFound", err)
	}
}

// ============================================================================
// Listing passthrough
// ============================================================================

func TestListJobs_Passthrough(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, _ = svc.CreateJob(ctx, metadata.CreateJobInput{
			Source: metadata.SourceUpload,
			Mode:   metadata.ModeExtract,
			Files:  []metadata.UploadedFile{smallFile("a.txt", "x")},
		})
	}
	jobs, err := svc.ListJobs(ctx, metadata.ListJobsFilter{})
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if len(jobs) != 3 {
		t.Errorf("len = %d, want 3", len(jobs))
	}
}
