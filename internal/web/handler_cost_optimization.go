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
	costopttmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/costopt"
)

// CostOptTempl renders the resource optimization dashboard page.
func (h *Handler) CostOptTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Resource Optimization", "resource-optimization")

	data := costopttmpl.CostOptData{
		PageData: pageData,
	}

	if h.costOptSvc == nil {
		h.renderTempl(w, r, costopttmpl.CostOpt(data))
		return
	}

	// Parse query filters
	opts := models.RecommendationListOptions{
		Limit:  50,
		Offset: 0,
	}
	if q := r.URL.Query().Get("type"); q != "" {
		opts.Type = q
		data.FilterType = q
	}
	if q := r.URL.Query().Get("status"); q != "" {
		opts.Status = q
		data.FilterStatus = q
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

	// Fetch recommendations
	recs, total, err := h.costOptSvc.ListRecommendations(ctx, opts)
	if err != nil {
		h.logger.Error("failed to list recommendations", "error", err)
	}
	data.TotalRecommendations = total
	data.TotalPages = (total + opts.Limit - 1) / opts.Limit

	// Convert to template views
	for _, rec := range recs {
		data.Recommendations = append(data.Recommendations, recommendationToView(rec))
	}

	// Fetch stats
	stats, err := h.costOptSvc.GetStats(ctx)
	if err != nil {
		h.logger.Error("failed to get cost opt stats", "error", err)
	}
	if stats != nil {
		data.Stats = costopttmpl.CostOptStatsView{
			TotalRecommendations: stats.TotalRecommendations,
			OpenRecommendations:  stats.OpenRecommendations,
			ByType:               stats.ByType,
			ByStatus:             stats.ByStatus,
		}
	}

	h.renderTempl(w, r, costopttmpl.CostOpt(data))
}

// CostOptApplyAPI applies a resource optimization recommendation (POST).
func (h *Handler) CostOptApplyAPI(w http.ResponseWriter, r *http.Request) {
	if h.costOptSvc == nil {
		h.jsonError(w, "resource optimization not available", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid recommendation ID", http.StatusBadRequest)
		return
	}

	var userID *uuid.UUID
	if user := GetUserFromContext(r.Context()); user != nil {
		if parsed, err := uuid.Parse(user.ID); err == nil {
			userID = &parsed
		}
	}

	if err := h.costOptSvc.ApplyRecommendation(r.Context(), id, userID); err != nil {
		h.logger.Error("failed to apply recommendation", "id", id, "error", err)
		h.setFlash(w, r, "error", "Failed to apply recommendation.")
		h.redirect(w, r, "/resource-optimization")
		return
	}

	h.setFlash(w, r, "success", "Recommendation applied.")
	h.redirect(w, r, "/resource-optimization")
}

// CostOptDismissAPI dismisses a resource optimization recommendation (POST).
func (h *Handler) CostOptDismissAPI(w http.ResponseWriter, r *http.Request) {
	if h.costOptSvc == nil {
		h.jsonError(w, "resource optimization not available", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid recommendation ID", http.StatusBadRequest)
		return
	}

	var userID *uuid.UUID
	if user := GetUserFromContext(r.Context()); user != nil {
		if parsed, err := uuid.Parse(user.ID); err == nil {
			userID = &parsed
		}
	}

	if err := h.costOptSvc.DismissRecommendation(r.Context(), id, userID); err != nil {
		h.logger.Error("failed to dismiss recommendation", "id", id, "error", err)
		h.setFlash(w, r, "error", "Failed to dismiss recommendation.")
		h.redirect(w, r, "/resource-optimization")
		return
	}

	h.setFlash(w, r, "success", "Recommendation dismissed.")
	h.redirect(w, r, "/resource-optimization")
}

// CostOptStatsAPI returns resource optimization statistics as JSON.
func (h *Handler) CostOptStatsAPI(w http.ResponseWriter, r *http.Request) {
	if h.costOptSvc == nil {
		h.jsonError(w, "resource optimization not available", http.StatusServiceUnavailable)
		return
	}

	stats, err := h.costOptSvc.GetStats(r.Context())
	if err != nil {
		h.jsonError(w, "failed to get resource optimization stats", http.StatusInternalServerError)
		return
	}
	h.jsonOK(w, stats)
}

// recommendationToView converts a ResourceRecommendation model to a template view.
func recommendationToView(r *models.ResourceRecommendation) costopttmpl.RecommendationView {
	return costopttmpl.RecommendationView{
		ID:               r.ID.String(),
		ContainerID:      r.ContainerID,
		ContainerName:    r.ContainerName,
		Type:             r.Type,
		Severity:         r.Severity,
		Status:           r.Status,
		CurrentValue:     r.CurrentValue,
		RecommendedValue: r.RecommendedValue,
		EstimatedSavings: r.EstimatedSavings,
		Reason:           r.Reason,
		CreatedAt:        r.CreatedAt.Format("Jan 02, 15:04"),
		CreatedAtFull:    r.CreatedAt.Format(time.RFC3339),
	}
}
