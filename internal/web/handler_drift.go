// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	drifttmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/drift"
)

// DriftTempl renders the drift detection dashboard page.
func (h *Handler) DriftTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Drift Detection", "drift")

	data := drifttmpl.DriftData{
		PageData: pageData,
	}

	if h.driftSvc == nil {
		h.renderTempl(w, r, drifttmpl.Drift(data))
		return
	}

	// Parse query filters
	opts := models.DriftListOptions{
		Limit:  50,
		Offset: 0,
	}
	if q := r.URL.Query().Get("status"); q != "" {
		opts.Status = q
		data.FilterStatus = q
	}
	if q := r.URL.Query().Get("severity"); q != "" {
		opts.Severity = q
		data.FilterSeverity = q
	}
	if q := r.URL.Query().Get("resource_type"); q != "" {
		opts.ResourceType = q
		data.FilterResource = q
	}
	if q := r.URL.Query().Get("page"); q != "" {
		if p, err := strconv.Atoi(q); err == nil && p > 1 {
			opts.Offset = (p - 1) * opts.Limit
			data.CurrentPage = p
		}
	}
	if data.CurrentPage == 0 {
		data.CurrentPage = 1
	}

	// Fetch drift detections
	drifts, total, err := h.driftSvc.ListDrifts(ctx, opts)
	if err != nil {
		h.logger.Error("failed to list drift detections", "error", err)
	}
	data.TotalDetections = total
	data.TotalPages = (total + opts.Limit - 1) / opts.Limit

	// Convert to template views
	for _, d := range drifts {
		data.Detections = append(data.Detections, driftToView(d))
	}

	// Fetch stats
	stats, err := h.driftSvc.GetStats(ctx)
	if err != nil {
		h.logger.Error("failed to get drift stats", "error", err)
	}
	if stats != nil {
		data.Stats = drifttmpl.DriftStatsView{
			TotalOpen:         stats.TotalOpen,
			Critical:          stats.Critical,
			Warning:           stats.Warning,
			Info:              stats.Info,
			ResourcesAffected: stats.ResourcesAffected,
		}
	}

	h.renderTempl(w, r, drifttmpl.Drift(data))
}

// DriftDetailAPI returns a single drift detection with full diffs as JSON.
func (h *Handler) DriftDetailAPI(w http.ResponseWriter, r *http.Request) {
	if h.driftSvc == nil {
		h.jsonError(w, "drift detection not available", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid drift detection ID", http.StatusBadRequest)
		return
	}
	detection, err := h.driftSvc.GetDriftByID(r.Context(), id)
	if err != nil {
		h.jsonError(w, "drift detection not found", http.StatusNotFound)
		return
	}
	h.jsonOK(w, detection)
}

// DriftAcceptAPI accepts a drift detection (POST).
func (h *Handler) DriftAcceptAPI(w http.ResponseWriter, r *http.Request) {
	if h.driftSvc == nil {
		h.jsonError(w, "drift detection not available", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid drift detection ID", http.StatusBadRequest)
		return
	}

	var userID *uuid.UUID
	if user := GetUserFromContext(r.Context()); user != nil {
		if parsed, err := uuid.Parse(user.ID); err == nil {
			userID = &parsed
		}
	}

	if err := h.driftSvc.AcceptDrift(r.Context(), id, userID, ""); err != nil {
		h.logger.Error("failed to accept drift", "id", id, "error", err)
		h.setFlash(w, r, "error", "Failed to accept drift detection.")
		h.redirect(w, r, "/drift")
		return
	}

	h.setFlash(w, r, "success", "Drift detection accepted.")
	h.redirect(w, r, "/drift")
}

// DriftRemediateAPI remediates a drift detection (POST).
func (h *Handler) DriftRemediateAPI(w http.ResponseWriter, r *http.Request) {
	if h.driftSvc == nil {
		h.jsonError(w, "drift detection not available", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid drift detection ID", http.StatusBadRequest)
		return
	}

	var userID *uuid.UUID
	if user := GetUserFromContext(r.Context()); user != nil {
		if parsed, err := uuid.Parse(user.ID); err == nil {
			userID = &parsed
		}
	}

	if err := h.driftSvc.RemediateDrift(r.Context(), id, userID, ""); err != nil {
		h.logger.Error("failed to remediate drift", "id", id, "error", err)
		h.setFlash(w, r, "error", "Failed to remediate drift detection.")
		h.redirect(w, r, "/drift")
		return
	}

	h.setFlash(w, r, "success", "Drift detection remediated.")
	h.redirect(w, r, "/drift")
}

// DriftStatsAPI returns drift statistics as JSON.
func (h *Handler) DriftStatsAPI(w http.ResponseWriter, r *http.Request) {
	if h.driftSvc == nil {
		h.jsonError(w, "drift detection not available", http.StatusServiceUnavailable)
		return
	}

	stats, err := h.driftSvc.GetStats(r.Context())
	if err != nil {
		h.jsonError(w, "failed to get drift stats", http.StatusInternalServerError)
		return
	}
	h.jsonOK(w, stats)
}

// driftToView converts a DriftDetection model to a template view.
func driftToView(d *models.DriftDetection) drifttmpl.DriftView {
	v := drifttmpl.DriftView{
		ID:             d.ID.String(),
		ResourceType:   d.ResourceType,
		ResourceID:     d.ResourceID,
		ResourceName:   d.ResourceName,
		Status:         d.Status,
		Severity:       d.Severity,
		DiffCount:      d.DiffCount,
		DetectedAt:     d.DetectedAt.Format("Jan 02, 15:04"),
		DetectedAtFull: d.DetectedAt.Format(time.RFC3339),
	}

	// Marshal diffs to JSON string for Alpine.js consumption
	if d.Diffs != nil {
		v.DiffsJSON = string(*d.Diffs)
	} else {
		v.DiffsJSON = "[]"
	}

	return v
}
