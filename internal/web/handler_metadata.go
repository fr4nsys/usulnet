// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	metadatatmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/metadata"
	metadatapart "github.com/fr4nsys/usulnet/internal/web/templates/partials/metadata"
)

// metadataUploadMaxBytes caps the multipart payload at 256 MiB. The
// scheduler worker enforces a per-artifact MIME allow-list further down;
// the web layer only guards request body size to keep memory bounded.
const metadataUploadMaxBytes = 256 << 20

// MetadataUploadTempl renders /recon/metadata — drag-drop upload page.
func (h *Handler) MetadataUploadTempl(w http.ResponseWriter, r *http.Request) {
	mds := h.metadataService()
	if mds == nil || !mds.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	pageData := h.prepareTemplPageData(r, "Metadata Hygiene", "recon-metadata")
	data := metadatatmpl.UploadData{PageData: pageData}
	if jobs, err := mds.ListJobs(r.Context(), 20); err == nil {
		for _, j := range jobs {
			data.RecentJobs = append(data.RecentJobs, metadataJobViewToTmpl(j))
		}
	}
	h.renderTempl(w, r, metadatatmpl.Upload(data))
}

// MetadataJobDetailTempl renders /recon/metadata/jobs/{id}.
func (h *Handler) MetadataJobDetailTempl(w http.ResponseWriter, r *http.Request) {
	mds := h.metadataService()
	if mds == nil || !mds.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid job id", http.StatusBadRequest)
		return
	}
	detail, err := mds.GetJob(r.Context(), id)
	if err != nil || detail == nil {
		http.NotFound(w, r)
		return
	}
	pageData := h.prepareTemplPageData(r, "Metadata Job", "recon-metadata")
	data := metadatatmpl.JobDetailData{
		PageData: pageData,
		Job:      metadataJobViewToTmpl(detail.Job),
	}
	for _, a := range detail.Artifacts {
		data.Artifacts = append(data.Artifacts, metadataArtifactViewToTmpl(a))
	}
	h.renderTempl(w, r, metadatatmpl.JobDetail(data))
}

// MetadataUploadSubmit handles POST /recon/metadata/jobs (multipart).
// Returns the upload_result partial when called via HTMX, or a JSON shape
// for regular form consumers. The canonical JSON-API equivalent lives at
// POST /api/v1/metadata/jobs and is owned by internal/api/handlers/metadata.go.
func (h *Handler) MetadataUploadSubmit(w http.ResponseWriter, r *http.Request) {
	mds := h.metadataService()
	if mds == nil || !mds.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseMultipartForm(metadataUploadMaxBytes); err != nil {
		h.logger.Error("metadata upload parse failed", "error", err)
		http.Error(w, "upload too large or malformed", http.StatusBadRequest)
		return
	}

	mode := r.FormValue("mode")
	if mode == "" {
		mode = "both"
	}

	var actor *uuid.UUID
	if u := GetUserFromContext(r.Context()); u != nil {
		if id, err := uuid.Parse(u.ID); err == nil {
			actor = &id
		}
	}

	form := r.MultipartForm
	if form == nil || len(form.File["files"]) == 0 {
		http.Error(w, "no files provided", http.StatusBadRequest)
		return
	}

	in := MetadataCreateJobInput{
		Source:    "upload",
		Mode:      mode,
		CreatedBy: actor,
	}
	openedFiles := make([]io.Closer, 0, len(form.File["files"]))
	defer func() {
		for _, c := range openedFiles {
			_ = c.Close()
		}
	}()
	for _, fh := range form.File["files"] {
		f, err := fh.Open()
		if err != nil {
			h.logger.Error("metadata upload open failed", "filename", fh.Filename, "error", err)
			http.Error(w, "failed to read upload: "+err.Error(), http.StatusBadRequest)
			return
		}
		openedFiles = append(openedFiles, f)
		mime := fh.Header.Get("Content-Type")
		in.Files = append(in.Files, MetadataUploadedFile{
			Filename: fh.Filename,
			MIME:     mime,
			Content:  f,
			Size:     fh.Size,
		})
	}

	job, err := mds.CreateJob(r.Context(), in)
	if err != nil {
		h.logger.Error("metadata create job failed", "error", err)
		http.Error(w, "failed to create job: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Look up the freshly created job so the template can render
	// per-artifact results inline.
	id, err := uuid.Parse(job.ID)
	if err != nil {
		http.Error(w, "invalid job id", http.StatusInternalServerError)
		return
	}
	detail, err := mds.GetJob(r.Context(), id)
	if err != nil || detail == nil {
		http.Error(w, "job missing after creation", http.StatusInternalServerError)
		return
	}

	partialData := metadatapart.UploadResultData{
		Job: metadataJobViewToTmpl(detail.Job),
	}
	for _, a := range detail.Artifacts {
		partialData.Artifacts = append(partialData.Artifacts, metadataArtifactViewToTmpl(a))
	}
	h.renderTempl(w, r, metadatapart.UploadResult(partialData))
}

// MetadataDownloadStripped streams the stripped bytes for an artifact.
func (h *Handler) MetadataDownloadStripped(w http.ResponseWriter, r *http.Request) {
	mds := h.metadataService()
	if mds == nil || !mds.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid artifact id", http.StatusBadRequest)
		return
	}
	rc, contentType, err := mds.OpenStripped(r.Context(), id)
	if err != nil {
		h.logger.Error("metadata download failed", "id", id, "error", err)
		http.Error(w, "artifact not available", http.StatusNotFound)
		return
	}
	defer rc.Close()
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="stripped"`)
	_, _ = io.Copy(w, rc)
}

// ----------------------------------------------------------------------------
// Type bridges
// ----------------------------------------------------------------------------

func metadataJobViewToTmpl(j MetadataJobView) metadatatmpl.JobView {
	return metadatatmpl.JobView{
		ID:            j.ID,
		Source:        j.Source,
		SourceRef:     j.SourceRef,
		Mode:          j.Mode,
		Status:        j.Status,
		ArtifactCount: j.ArtifactCount,
		Error:         j.Error,
		StartedAt:     j.StartedAt,
		FinishedAt:    j.FinishedAt,
		Duration:      j.Duration,
		CreatedAt:     j.CreatedAt,
	}
}

func metadataArtifactViewToTmpl(a MetadataArtifactView) metadatatmpl.ArtifactView {
	fields := make([]metadatatmpl.MetadataField, 0, len(a.Extracted))
	for _, kv := range a.Extracted {
		fields = append(fields, metadatatmpl.MetadataField{Key: kv.Key, Value: kv.Value})
	}
	return metadatatmpl.ArtifactView{
		ID:                a.ID,
		Filename:          a.Filename,
		MIME:              a.MIME,
		SizeHuman:         a.SizeHuman,
		SHA256Hex:         a.SHA256Hex,
		StrippedSHA256Hex: a.StrippedSHA256Hex,
		StrippedAvailable: a.StrippedAvailable,
		DownloadURL:       a.DownloadURL,
		Fields:            fields,
		ExtractedJSON:     a.ExtractedJSON,
	}
}
