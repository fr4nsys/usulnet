// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/services/metadata"
)

var metadataTables = []string{
	"recon_metadata_artifacts",
	"recon_metadata_jobs",
}

// Compile-time interface check.
var _ metadata.Repository = (*postgres.ReconMetadataRepository)(nil)

func newMetadataRepo() *postgres.ReconMetadataRepository {
	return postgres.NewReconMetadataRepository(testDB)
}

// ============================================================================
// Jobs
// ============================================================================

func TestMetadataRepo_JobRoundTrip(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, metadataTables...) })

	repo := newMetadataRepo()
	ctx := context.Background()

	job := &metadata.Job{
		Source:    metadata.SourceUpload,
		SourceRef: "upload-abc",
		Mode:      metadata.ModeBoth,
	}
	if err := repo.InsertJob(ctx, job); err != nil {
		t.Fatalf("InsertJob: %v", err)
	}
	if job.ID == uuid.Nil {
		t.Fatal("expected ID to be set")
	}
	if job.Status != metadata.JobQueued {
		t.Errorf("status = %q, want queued (default)", job.Status)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	job.Status = metadata.JobCompleted
	job.ArtifactCount = 3
	job.StartedAt = &now
	job.FinishedAt = &now
	if err := repo.UpdateJob(ctx, job); err != nil {
		t.Fatalf("UpdateJob: %v", err)
	}

	got, err := repo.GetJobByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetJobByID: %v", err)
	}
	if got.Status != metadata.JobCompleted {
		t.Errorf("status = %q, want completed", got.Status)
	}
	if got.ArtifactCount != 3 {
		t.Errorf("artifact_count = %d, want 3", got.ArtifactCount)
	}
	if got.Source != metadata.SourceUpload {
		t.Errorf("source = %q, want upload", got.Source)
	}
	if got.Mode != metadata.ModeBoth {
		t.Errorf("mode = %q, want both", got.Mode)
	}
}

func TestMetadataRepo_ListJobs_FilterByStatus(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, metadataTables...) })

	repo := newMetadataRepo()
	ctx := context.Background()

	// Two queued + one completed.
	for i := 0; i < 2; i++ {
		j := &metadata.Job{Source: metadata.SourceUpload, Mode: metadata.ModeExtract}
		if err := repo.InsertJob(ctx, j); err != nil {
			t.Fatalf("insert queued: %v", err)
		}
	}
	done := &metadata.Job{
		Source: metadata.SourceUpload,
		Mode:   metadata.ModeStrip,
		Status: metadata.JobCompleted,
	}
	if err := repo.InsertJob(ctx, done); err != nil {
		t.Fatalf("insert completed: %v", err)
	}

	queued := metadata.JobQueued
	list, err := repo.ListJobs(ctx, metadata.ListJobsFilter{Status: &queued, Limit: 10})
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("len = %d, want 2", len(list))
	}
	for _, j := range list {
		if j.Status != metadata.JobQueued {
			t.Errorf("unexpected status %q in filtered result", j.Status)
		}
	}
}

// ============================================================================
// Artifacts
// ============================================================================

func TestMetadataRepo_ArtifactRoundTrip(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, metadataTables...) })

	repo := newMetadataRepo()
	ctx := context.Background()

	job := &metadata.Job{Source: metadata.SourceUpload, Mode: metadata.ModeBoth}
	if err := repo.InsertJob(ctx, job); err != nil {
		t.Fatalf("InsertJob: %v", err)
	}

	original := sha256.Sum256([]byte("original-file-bytes"))
	stripped := sha256.Sum256([]byte("stripped-file-bytes"))

	art := &metadata.Artifact{
		JobID:          job.ID,
		Filename:       "photo.jpg",
		MIME:           "image/jpeg",
		SizeBytes:      2048,
		SHA256:         original[:],
		StrippedSHA256: stripped[:],
		Extracted: map[string]any{
			"Make":  "Canon",
			"Model": "EOS R6",
			"GPS":   map[string]any{"Lat": 40.0, "Lon": -3.0},
		},
		StorageRef: "/var/recon/" + job.ID.String() + "/photo.jpg",
	}
	if err := repo.InsertArtifact(ctx, art); err != nil {
		t.Fatalf("InsertArtifact: %v", err)
	}
	if art.ID == uuid.Nil {
		t.Fatal("expected ID to be set")
	}

	got, err := repo.GetArtifactByID(ctx, art.ID)
	if err != nil {
		t.Fatalf("GetArtifactByID: %v", err)
	}
	if got.Filename != "photo.jpg" {
		t.Errorf("filename = %q", got.Filename)
	}
	if got.MIME != "image/jpeg" {
		t.Errorf("mime = %q", got.MIME)
	}
	if !bytes.Equal(got.SHA256, original[:]) {
		t.Errorf("sha256 mismatch")
	}
	if !bytes.Equal(got.StrippedSHA256, stripped[:]) {
		t.Errorf("stripped_sha256 mismatch")
	}
	if got.Extracted["Make"] != "Canon" {
		t.Errorf("extracted not persisted: %#v", got.Extracted)
	}

	list, err := repo.ListArtifactsByJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListArtifactsByJob: %v", err)
	}
	if len(list) != 1 || list[0].ID != art.ID {
		t.Errorf("list mismatch: %+v", list)
	}
}

func TestMetadataRepo_InsertJobWithArtifacts(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, metadataTables...) })

	repo := newMetadataRepo()
	ctx := context.Background()

	// Pre-allocate IDs so the caller can compute storage_ref before
	// the rows exist.
	jobID := uuid.New()
	a1ID := uuid.New()
	a2ID := uuid.New()
	sum1 := sha256.Sum256([]byte("one"))
	sum2 := sha256.Sum256([]byte("two"))

	job := &metadata.Job{
		ID:     jobID,
		Source: metadata.SourceUpload,
		Mode:   metadata.ModeBoth,
	}
	artifacts := []*metadata.Artifact{
		{ID: a1ID, Filename: "a.txt", MIME: "text/plain", SizeBytes: 3, SHA256: sum1[:], StorageRef: jobID.String() + "/" + a1ID.String()},
		{ID: a2ID, Filename: "b.txt", MIME: "text/plain", SizeBytes: 3, SHA256: sum2[:], StorageRef: jobID.String() + "/" + a2ID.String()},
	}

	if err := repo.InsertJobWithArtifacts(ctx, job, artifacts); err != nil {
		t.Fatalf("InsertJobWithArtifacts: %v", err)
	}
	if job.ID != jobID {
		t.Errorf("job id changed: %s vs %s (pre-set should be honored)", job.ID, jobID)
	}
	for i, a := range artifacts {
		if a.JobID != jobID {
			t.Errorf("artifact[%d] job_id = %s, want %s", i, a.JobID, jobID)
		}
	}

	got, err := repo.GetJobByID(ctx, jobID)
	if err != nil {
		t.Fatalf("GetJobByID: %v", err)
	}
	if got.Mode != metadata.ModeBoth {
		t.Errorf("mode = %q", got.Mode)
	}
	list, _ := repo.ListArtifactsByJob(ctx, jobID)
	if len(list) != 2 {
		t.Errorf("artifact count = %d, want 2", len(list))
	}
}

func TestMetadataRepo_UpdateArtifact(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, metadataTables...) })

	repo := newMetadataRepo()
	ctx := context.Background()

	job := &metadata.Job{Source: metadata.SourceUpload, Mode: metadata.ModeBoth}
	if err := repo.InsertJob(ctx, job); err != nil {
		t.Fatalf("InsertJob: %v", err)
	}
	sum := sha256.Sum256([]byte("orig"))
	art := &metadata.Artifact{
		JobID: job.ID, Filename: "f", MIME: "text/plain", SizeBytes: 4, SHA256: sum[:],
	}
	if err := repo.InsertArtifact(ctx, art); err != nil {
		t.Fatalf("InsertArtifact: %v", err)
	}

	stripped := sha256.Sum256([]byte("stripped"))
	art.StrippedSHA256 = stripped[:]
	art.Extracted = map[string]any{"Make": "Acme"}
	art.StorageRef = job.ID.String() + "/" + art.ID.String()

	if err := repo.UpdateArtifact(ctx, art); err != nil {
		t.Fatalf("UpdateArtifact: %v", err)
	}

	got, err := repo.GetArtifactByID(ctx, art.ID)
	if err != nil {
		t.Fatalf("GetArtifactByID: %v", err)
	}
	if !bytes.Equal(got.StrippedSHA256, stripped[:]) {
		t.Errorf("stripped_sha256 not updated")
	}
	if got.Extracted["Make"] != "Acme" {
		t.Errorf("extracted not updated: %v", got.Extracted)
	}
	if got.StorageRef != art.StorageRef {
		t.Errorf("storage_ref not updated: %s", got.StorageRef)
	}
}

func TestMetadataRepo_ArtifactCascade(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	t.Cleanup(func() { truncateTables(t, metadataTables...) })

	repo := newMetadataRepo()
	ctx := context.Background()

	job := &metadata.Job{Source: metadata.SourceUpload, Mode: metadata.ModeBoth}
	if err := repo.InsertJob(ctx, job); err != nil {
		t.Fatalf("InsertJob: %v", err)
	}

	sum := sha256.Sum256([]byte("file"))
	art := &metadata.Artifact{
		JobID:    job.ID,
		Filename: "doc.pdf",
		MIME:     "application/pdf",
		SHA256:   sum[:],
	}
	if err := repo.InsertArtifact(ctx, art); err != nil {
		t.Fatalf("InsertArtifact: %v", err)
	}

	if _, err := testDB.Exec(ctx, `DELETE FROM recon_metadata_jobs WHERE id = $1`, job.ID); err != nil {
		t.Fatalf("delete job: %v", err)
	}

	list, err := repo.ListArtifactsByJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListArtifactsByJob: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected cascade to remove artifacts, got %d remaining", len(list))
	}
}
