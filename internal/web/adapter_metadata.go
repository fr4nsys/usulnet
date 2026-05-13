// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/services/metadata"
)

// MetadataService is the web-layer abstraction over the metadata
// hygiene backend. Handlers depend on this interface so they remain
// decoupled from internal/services/metadata for testability.
type MetadataService interface {
	IsEnabled() bool

	CreateJob(ctx context.Context, in MetadataCreateJobInput) (*MetadataJobView, error)
	GetJob(ctx context.Context, id uuid.UUID) (*MetadataJobDetailView, error)
	ListJobs(ctx context.Context, limit int) ([]MetadataJobView, error)
	OpenStripped(ctx context.Context, artifactID uuid.UUID) (io.ReadCloser, string, error)
}

// MetadataJobView is one row in the jobs list / upload-result partial.
type MetadataJobView struct {
	ID            string
	Source        string
	SourceRef     string
	Mode          string
	Status        string
	ArtifactCount int
	Error         string
	StartedAt     string
	FinishedAt    string
	Duration      string
	CreatedAt     string
	CreatedBy     string
}

// MetadataJobDetailView wraps a job with its per-file artifact results.
type MetadataJobDetailView struct {
	Job       MetadataJobView
	Artifacts []MetadataArtifactView
}

// MetadataArtifactView is one processed file.
type MetadataArtifactView struct {
	ID                string
	JobID             string
	Filename          string
	MIME              string
	SizeBytes         int64
	SizeHuman         string
	SHA256Hex         string
	StrippedSHA256Hex string
	StrippedAvailable bool
	DownloadURL       string
	Extracted         []MetadataField
	ExtractedJSON     string
	CreatedAt         string
}

// MetadataField is one key/value pair extracted from a file.
type MetadataField struct {
	Key   string
	Value string
}

// MetadataCreateJobInput is the web-layer input passed by the upload
// handler. Files are streamed by the caller to keep this struct lean.
type MetadataCreateJobInput struct {
	Source    string
	SourceRef string
	Mode      string
	CreatedBy *uuid.UUID
	Files     []MetadataUploadedFile
}

// MetadataUploadedFile is one element of an upload-mode job.
type MetadataUploadedFile struct {
	Filename string
	MIME     string
	Content  io.Reader
	Size     int64
}

// metadataAdapter is the concrete MetadataService used by the web layer.
type metadataAdapter struct {
	svc     metadata.Service
	enabled bool
}

func (a *metadataAdapter) IsEnabled() bool {
	return a != nil && a.enabled
}

func (a *metadataAdapter) CreateJob(ctx context.Context, in MetadataCreateJobInput) (*MetadataJobView, error) {
	if a == nil || a.svc == nil {
		return nil, ErrServiceNotConfigured
	}
	files := make([]metadata.UploadedFile, 0, len(in.Files))
	for _, f := range in.Files {
		files = append(files, metadata.UploadedFile{
			Filename: f.Filename,
			MIME:     f.MIME,
			Content:  f.Content,
			Size:     f.Size,
		})
	}
	source := metadata.JobSource(in.Source)
	if source == "" {
		source = metadata.SourceUpload
	}
	mode := metadata.JobMode(in.Mode)
	if mode == "" {
		mode = metadata.ModeBoth
	}
	job, err := a.svc.CreateJob(ctx, metadata.CreateJobInput{
		Source:    source,
		SourceRef: in.SourceRef,
		Mode:      mode,
		CreatedBy: in.CreatedBy,
		Files:     files,
	})
	if err != nil {
		return nil, fmt.Errorf("create metadata job: %w", err)
	}
	v := metadataJobToView(job)
	return &v, nil
}

func (a *metadataAdapter) GetJob(ctx context.Context, id uuid.UUID) (*MetadataJobDetailView, error) {
	if a == nil || a.svc == nil {
		return nil, ErrServiceNotConfigured
	}
	job, err := a.svc.GetJob(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get metadata job: %w", err)
	}
	if job == nil {
		return nil, errors.New("job not found")
	}
	detail := &MetadataJobDetailView{Job: metadataJobToView(job)}

	arts, err := a.svc.ListArtifacts(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("list metadata artifacts: %w", err)
	}
	for i := range arts {
		detail.Artifacts = append(detail.Artifacts, metadataArtifactToView(&arts[i]))
	}
	return detail, nil
}

func (a *metadataAdapter) ListJobs(ctx context.Context, limit int) ([]MetadataJobView, error) {
	if a == nil || a.svc == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	jobs, err := a.svc.ListJobs(ctx, metadata.ListJobsFilter{Limit: limit})
	if err != nil {
		return nil, fmt.Errorf("list metadata jobs: %w", err)
	}
	out := make([]MetadataJobView, 0, len(jobs))
	for i := range jobs {
		out = append(out, metadataJobToView(&jobs[i]))
	}
	return out, nil
}

func (a *metadataAdapter) OpenStripped(ctx context.Context, artifactID uuid.UUID) (io.ReadCloser, string, error) {
	if a == nil || a.svc == nil {
		return nil, "", ErrServiceNotConfigured
	}
	rc, err := a.svc.OpenStripped(ctx, artifactID)
	if err != nil {
		return nil, "", fmt.Errorf("open stripped artifact: %w", err)
	}
	return rc, "application/octet-stream", nil
}

// ----------------------------------------------------------------------------
// Conversion helpers
// ----------------------------------------------------------------------------

func metadataJobToView(j *metadata.Job) MetadataJobView {
	v := MetadataJobView{
		ID:            j.ID.String(),
		Source:        string(j.Source),
		SourceRef:     j.SourceRef,
		Mode:          string(j.Mode),
		Status:        string(j.Status),
		ArtifactCount: j.ArtifactCount,
		Error:         j.Error,
		CreatedAt:     j.CreatedAt.Format("2006-01-02 15:04"),
	}
	if j.StartedAt != nil {
		v.StartedAt = j.StartedAt.Format("2006-01-02 15:04:05")
	}
	if j.FinishedAt != nil {
		v.FinishedAt = j.FinishedAt.Format("2006-01-02 15:04:05")
		if j.StartedAt != nil {
			v.Duration = humanDuration(j.FinishedAt.Sub(*j.StartedAt))
		}
	} else if j.StartedAt != nil {
		v.Duration = humanDuration(time.Since(*j.StartedAt))
	}
	if j.CreatedBy != nil {
		v.CreatedBy = j.CreatedBy.String()
	}
	return v
}

func metadataArtifactToView(a *metadata.Artifact) MetadataArtifactView {
	v := MetadataArtifactView{
		ID:                a.ID.String(),
		JobID:             a.JobID.String(),
		Filename:          a.Filename,
		MIME:              a.MIME,
		SizeBytes:         a.SizeBytes,
		SizeHuman:         humanBytes(a.SizeBytes),
		StrippedAvailable: len(a.StrippedSHA256) > 0,
		CreatedAt:         a.CreatedAt.Format("2006-01-02 15:04"),
	}
	if len(a.SHA256) > 0 {
		v.SHA256Hex = hex.EncodeToString(a.SHA256)
	}
	if len(a.StrippedSHA256) > 0 {
		v.StrippedSHA256Hex = hex.EncodeToString(a.StrippedSHA256)
	}
	if v.StrippedAvailable {
		v.DownloadURL = fmt.Sprintf("/api/v1/recon/metadata/artifacts/%s/stripped", a.ID.String())
	}
	v.Extracted = flattenExtracted(a.Extracted)
	if a.Extracted != nil {
		if b, err := json.MarshalIndent(a.Extracted, "", "  "); err == nil {
			v.ExtractedJSON = string(b)
		}
	}
	return v
}

func flattenExtracted(in map[string]any) []MetadataField {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]MetadataField, 0, len(keys))
	for _, k := range keys {
		out = append(out, MetadataField{Key: k, Value: formatMetadataValue(in[k])})
	}
	return out
}

func formatMetadataValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

func humanBytes(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	const k = 1024
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	f := float64(n)
	for f >= k && i < len(units)-1 {
		f /= k
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}
