// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/metadata"
)

// MetadataUploadLimits caps per-file and per-request body sizes for the
// multipart upload endpoint. Values mirror the defaults documented in
// docs/recon.md §13 and can be overridden by the app wiring.
type MetadataUploadLimits struct {
	// MaxFileBytes is the cap per individual uploaded file.
	// Default: 100 MiB.
	MaxFileBytes int64
	// MaxTotalBytes is the cap for the whole multipart body.
	// Default: 200 MiB.
	MaxTotalBytes int64
}

// DefaultMetadataUploadLimits returns the documented defaults.
func DefaultMetadataUploadLimits() MetadataUploadLimits {
	return MetadataUploadLimits{
		MaxFileBytes:  100 << 20,
		MaxTotalBytes: 200 << 20,
	}
}

// MetadataHandler handles /api/v1/metadata/* requests. The handler
// tolerates a nil service so the routes still register before the
// follow-up PR lands the metadata.Service implementation.
type MetadataHandler struct {
	BaseHandler
	svc    metadata.Service
	limits MetadataUploadLimits
}

// NewMetadataHandler creates a new metadata handler.
func NewMetadataHandler(svc metadata.Service, limits MetadataUploadLimits, log *logger.Logger) *MetadataHandler {
	if limits.MaxFileBytes <= 0 || limits.MaxTotalBytes <= 0 {
		limits = DefaultMetadataUploadLimits()
	}
	return &MetadataHandler{
		BaseHandler: NewBaseHandler(log),
		svc:         svc,
		limits:      limits,
	}
}

// Routes returns the chi router for /api/v1/metadata. The caller is
// responsible for placing this subtree behind the feature-flag and
// acknowledgement middleware (see internal/api/router.go).
func (h *MetadataHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Route("/jobs", func(r chi.Router) {
		r.With(middleware.RequireViewer).Get("/", h.ListJobs)
		r.With(middleware.RequireOperator).Post("/", h.CreateJob)

		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.RequireViewer).Get("/", h.GetJob)
			r.With(middleware.RequireViewer).Get("/artifacts/{aid}/stripped", h.DownloadStripped)
		})
	})

	return r
}

// ============================================================================
// DTOs
// ============================================================================

// MetadataJobResponse is the API view of a metadata.Job.
type MetadataJobResponse struct {
	ID            string  `json:"id"`
	Source        string  `json:"source"`
	SourceRef     string  `json:"source_ref,omitempty"`
	Mode          string  `json:"mode"`
	Status        string  `json:"status"`
	ArtifactCount int     `json:"artifact_count"`
	Error         string  `json:"error,omitempty"`
	StartedAt     *string `json:"started_at,omitempty"`
	FinishedAt    *string `json:"finished_at,omitempty"`
	CreatedBy     *string `json:"created_by,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// ============================================================================
// CreateJob
// ============================================================================

// CreateJob handles POST /api/v1/metadata/jobs. The endpoint accepts a
// multipart/form-data body. Form fields:
//   - mode: extract | strip | both (default: extract)
//   - files[]: one or more files
func (h *MetadataHandler) CreateJob(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	// Total body cap before parsing — protects against very large
	// multipart envelopes even when no single file exceeds the per-file
	// cap.
	r.Body = http.MaxBytesReader(w, r.Body, h.limits.MaxTotalBytes)

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		if errors.As(err, new(*http.MaxBytesError)) {
			apierrors.WriteError(w, apierrors.ArtifactTooLarge(h.limits.MaxTotalBytes))
			return
		}
		h.BadRequest(w, "invalid multipart body: "+err.Error())
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	mode := strings.ToLower(r.FormValue("mode"))
	if mode == "" {
		mode = string(metadata.ModeExtract)
	}
	switch metadata.JobMode(mode) {
	case metadata.ModeExtract, metadata.ModeStrip, metadata.ModeBoth:
	default:
		h.BadRequest(w, "invalid mode (must be extract, strip, or both)")
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		// Tolerate "files[]" too, mirroring HTML-form conventions.
		files = r.MultipartForm.File["files[]"]
	}
	if len(files) == 0 {
		h.BadRequest(w, "no files supplied")
		return
	}

	uploads := make([]metadata.UploadedFile, 0, len(files))
	var openedFiles []io.Closer
	defer func() {
		for _, c := range openedFiles {
			_ = c.Close()
		}
	}()

	for _, fh := range files {
		if fh.Size > h.limits.MaxFileBytes {
			apierrors.WriteError(w, apierrors.ArtifactTooLarge(h.limits.MaxFileBytes))
			return
		}
		f, err := fh.Open()
		if err != nil {
			h.InternalError(w, err)
			return
		}
		openedFiles = append(openedFiles, f)
		uploads = append(uploads, metadata.UploadedFile{
			Filename: fh.Filename,
			MIME:     fh.Header.Get("Content-Type"),
			Content:  f,
			Size:     fh.Size,
		})
	}

	actor, _ := h.GetUserID(r)
	in := metadata.CreateJobInput{
		Source:    metadata.SourceUpload,
		Mode:      metadata.JobMode(mode),
		CreatedBy: nilableUUID(actor),
		Files:     uploads,
	}

	job, err := h.svc.CreateJob(r.Context(), in)
	if err != nil {
		h.HandleError(w, mapMetadataError(err, h.limits.MaxFileBytes))
		return
	}
	h.Created(w, toMetadataJobResponse(job))
}

// ============================================================================
// ListJobs
// ============================================================================

// ListJobs handles GET /api/v1/metadata/jobs.
func (h *MetadataHandler) ListJobs(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	pagination := h.GetPagination(r)
	filter := metadata.ListJobsFilter{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}
	if s := h.QueryParam(r, "status"); s != "" {
		st := metadata.JobStatus(s)
		filter.Status = &st
	}
	if c := h.QueryParamUUID(r, "created_by"); c != nil {
		filter.CreatedBy = c
	}

	jobs, err := h.svc.ListJobs(r.Context(), filter)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]MetadataJobResponse, len(jobs))
	for i := range jobs {
		resp[i] = toMetadataJobResponse(&jobs[i])
	}
	h.OK(w, resp)
}

// ============================================================================
// GetJob
// ============================================================================

// GetJob handles GET /api/v1/metadata/jobs/{id}.
func (h *MetadataHandler) GetJob(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	job, err := h.svc.GetJob(r.Context(), id)
	if err != nil {
		h.HandleError(w, mapMetadataError(err, h.limits.MaxFileBytes))
		return
	}

	artifacts, err := h.svc.ListArtifacts(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := toMetadataJobResponse(job)
	out := map[string]any{
		"job":       resp,
		"artifacts": toMetadataArtifactResponses(artifacts),
	}
	h.OK(w, out)
}

// ============================================================================
// DownloadStripped
// ============================================================================

// DownloadStripped handles GET /api/v1/metadata/jobs/{id}/artifacts/{aid}/stripped.
func (h *MetadataHandler) DownloadStripped(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		h.engineUnavailable(w)
		return
	}

	jobID, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}
	artifactID, err := h.URLParamUUID(r, "aid")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	// Verify the artifact belongs to the job — defends against id
	// guessing and gives a clean 404 instead of leaking another job's
	// artifact.
	artifacts, err := h.svc.ListArtifacts(r.Context(), jobID)
	if err != nil {
		h.HandleError(w, mapMetadataError(err, h.limits.MaxFileBytes))
		return
	}
	var found *metadata.Artifact
	for i := range artifacts {
		if artifacts[i].ID == artifactID {
			a := artifacts[i]
			found = &a
			break
		}
	}
	if found == nil {
		apierrors.WriteError(w, apierrors.NotFound("artifact"))
		return
	}

	rc, err := h.svc.OpenStripped(r.Context(), artifactID)
	if err != nil {
		h.HandleError(w, mapMetadataError(err, h.limits.MaxFileBytes))
		return
	}
	defer rc.Close()

	filename := strings.TrimSpace(found.Filename)
	if filename == "" {
		filename = "stripped-" + artifactID.String()
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+url.PathEscape(filename)+`"`)
	if found.SizeBytes > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(found.SizeBytes, 10))
	}
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, rc); err != nil {
		h.Logger().Warn("metadata stripped stream interrupted",
			"job_id", jobID,
			"artifact_id", artifactID,
			"error", err,
		)
	}
}

// ============================================================================
// Helpers
// ============================================================================

func (h *MetadataHandler) engineUnavailable(w http.ResponseWriter) {
	apierrors.WriteError(w, apierrors.NewError(
		http.StatusServiceUnavailable,
		apierrors.ErrCodeEngineUnavailable,
		"Metadata engine is not available",
	))
}

// mapMetadataError converts package-level metadata errors to APIErrors.
func mapMetadataError(err error, fileLimit int64) error {
	switch {
	case errors.Is(err, metadata.ErrJobNotFound):
		return apierrors.NotFound("metadata job")
	case errors.Is(err, metadata.ErrArtifactNotFound):
		return apierrors.NotFound("metadata artifact")
	case errors.Is(err, metadata.ErrArtifactTooLarge):
		return apierrors.ArtifactTooLarge(fileLimit)
	case errors.Is(err, metadata.ErrInvalidFilename):
		return apierrors.InvalidInput("invalid filename")
	case errors.Is(err, metadata.ErrUnsupportedMode):
		return apierrors.InvalidInput("unsupported job mode")
	case errors.Is(err, metadata.ErrStripNotReady):
		return apierrors.Conflict("stripped copy not ready")
	case errors.Is(err, metadata.ErrNoFiles):
		return apierrors.InvalidInput("no files supplied")
	}
	return err
}

func toMetadataJobResponse(j *metadata.Job) MetadataJobResponse {
	resp := MetadataJobResponse{
		ID:            j.ID.String(),
		Source:        string(j.Source),
		SourceRef:     j.SourceRef,
		Mode:          string(j.Mode),
		Status:        string(j.Status),
		ArtifactCount: j.ArtifactCount,
		Error:         j.Error,
		CreatedAt:     j.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     j.UpdatedAt.Format(time.RFC3339),
	}
	if j.StartedAt != nil {
		v := j.StartedAt.Format(time.RFC3339)
		resp.StartedAt = &v
	}
	if j.FinishedAt != nil {
		v := j.FinishedAt.Format(time.RFC3339)
		resp.FinishedAt = &v
	}
	if j.CreatedBy != nil {
		v := j.CreatedBy.String()
		resp.CreatedBy = &v
	}
	return resp
}

// MetadataArtifactResponse is the API view of a metadata.Artifact.
type MetadataArtifactResponse struct {
	ID             string         `json:"id"`
	JobID          string         `json:"job_id"`
	Filename       string         `json:"filename"`
	MIME           string         `json:"mime,omitempty"`
	SizeBytes      int64          `json:"size_bytes"`
	SHA256         string         `json:"sha256,omitempty"`
	StrippedSHA256 string         `json:"stripped_sha256,omitempty"`
	Extracted      map[string]any `json:"extracted,omitempty"`
	CreatedAt      string         `json:"created_at"`
}

func toMetadataArtifactResponses(in []metadata.Artifact) []MetadataArtifactResponse {
	out := make([]MetadataArtifactResponse, len(in))
	for i := range in {
		out[i] = toMetadataArtifactResponse(&in[i])
	}
	return out
}

func toMetadataArtifactResponse(a *metadata.Artifact) MetadataArtifactResponse {
	resp := MetadataArtifactResponse{
		ID:        a.ID.String(),
		JobID:     a.JobID.String(),
		Filename:  a.Filename,
		MIME:      a.MIME,
		SizeBytes: a.SizeBytes,
		Extracted: a.Extracted,
		CreatedAt: a.CreatedAt.Format(time.RFC3339),
	}
	if len(a.SHA256) > 0 {
		resp.SHA256 = hex.EncodeToString(a.SHA256)
	}
	if len(a.StrippedSHA256) > 0 {
		resp.StrippedSHA256 = hex.EncodeToString(a.StrippedSHA256)
	}
	return resp
}

// Compile-time guarantee that *uuid.UUID still resolves via the shared
// helper so the build fails fast if someone moves nilableUUID.
var _ *uuid.UUID = nilableUUID(uuid.Nil)
