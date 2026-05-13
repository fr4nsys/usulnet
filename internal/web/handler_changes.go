// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	changestmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/changes"
)

// ChangesTempl renders the Change Management Audit Trail page.
func (h *Handler) ChangesTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Change Management", "changes")

	data := changestmpl.ChangesData{
		PageData: pageData,
	}

	if h.changesSvc == nil {
		h.renderTempl(w, r, changestmpl.Changes(data))
		return
	}

	// Parse query filters
	opts := models.ChangeEventListOptions{
		Limit:  50,
		Offset: 0,
	}
	if q := r.URL.Query().Get("resource_type"); q != "" {
		opts.ResourceType = q
		data.FilterResourceType = q
	}
	if q := r.URL.Query().Get("action"); q != "" {
		opts.Action = q
		data.FilterAction = q
	}
	if q := r.URL.Query().Get("search"); q != "" {
		opts.Search = q
		data.FilterSearch = q
	}
	if q := r.URL.Query().Get("user_id"); q != "" {
		if uid, err := uuid.Parse(q); err == nil {
			opts.UserID = &uid
			data.FilterUserID = q
		}
	}
	if q := r.URL.Query().Get("since"); q != "" {
		if t, err := time.Parse("2006-01-02", q); err == nil {
			opts.Since = &t
			data.FilterSince = q
		}
	}
	if q := r.URL.Query().Get("until"); q != "" {
		if t, err := time.Parse("2006-01-02", q); err == nil {
			opts.Until = &t
			data.FilterUntil = q
		}
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

	// Fetch events
	events, total, err := h.changesSvc.List(ctx, opts)
	if err != nil {
		h.logger.Error("failed to list change events", "error", err)
	}
	data.TotalEvents = total
	data.TotalPages = (total + opts.Limit - 1) / opts.Limit

	// Convert to template views
	for _, e := range events {
		data.Events = append(data.Events, changeEventToView(e))
	}

	// Fetch stats (last 30 days)
	since := time.Now().AddDate(0, 0, -30)
	stats, err := h.changesSvc.GetStats(ctx, since)
	if err != nil {
		h.logger.Error("failed to get change stats", "error", err)
	}
	if stats != nil {
		data.Stats = changestmpl.ChangeStats{
			TotalEvents: stats.TotalEvents,
			TodayEvents: stats.TodayEvents,
			ByAction:    stats.ByAction,
			ByResource:  stats.ByResource,
		}
		for _, u := range stats.TopUsers {
			data.Stats.TopUsers = append(data.Stats.TopUsers, changestmpl.ChangeUserStat{
				UserName: u.UserName,
				Count:    u.Count,
			})
		}
	}

	h.renderTempl(w, r, changestmpl.Changes(data))
}

// ChangeDetailAPI returns a single change event with full state as JSON.
func (h *Handler) ChangeDetailAPI(w http.ResponseWriter, r *http.Request) {
	if h.changesSvc == nil {
		h.jsonError(w, "change tracking not available", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "invalid change event ID", http.StatusBadRequest)
		return
	}
	event, err := h.changesSvc.GetByID(r.Context(), id)
	if err != nil {
		h.jsonError(w, "change event not found", http.StatusNotFound)
		return
	}
	h.jsonOK(w, event)
}

// ChangeResourceAPI returns change events for a specific resource.
func (h *Handler) ChangeResourceAPI(w http.ResponseWriter, r *http.Request) {
	if h.changesSvc == nil {
		h.jsonError(w, "change tracking not available", http.StatusServiceUnavailable)
		return
	}
	resourceType := chi.URLParam(r, "resourceType")
	resourceID := chi.URLParam(r, "resourceID")

	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if l, err := strconv.Atoi(q); err == nil && l > 0 && l <= 200 {
			limit = l
		}
	}

	events, err := h.changesSvc.GetByResource(r.Context(), resourceType, resourceID, limit)
	if err != nil {
		h.jsonError(w, "failed to fetch resource changes", http.StatusInternalServerError)
		return
	}
	h.jsonOK(w, events)
}

// ChangeStatsAPI returns change event statistics as JSON.
func (h *Handler) ChangeStatsAPI(w http.ResponseWriter, r *http.Request) {
	if h.changesSvc == nil {
		h.jsonError(w, "change tracking not available", http.StatusServiceUnavailable)
		return
	}

	days := 30
	if q := r.URL.Query().Get("days"); q != "" {
		if d, err := strconv.Atoi(q); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}
	since := time.Now().AddDate(0, 0, -days)

	stats, err := h.changesSvc.GetStats(r.Context(), since)
	if err != nil {
		h.jsonError(w, "failed to get change stats", http.StatusInternalServerError)
		return
	}
	h.jsonOK(w, stats)
}

// ChangeExportCSV exports change events as a CSV file.
func (h *Handler) ChangeExportCSV(w http.ResponseWriter, r *http.Request) {
	if h.changesSvc == nil {
		h.jsonError(w, "change tracking not available", http.StatusServiceUnavailable)
		return
	}

	opts := models.ChangeEventListOptions{Limit: 10000}
	if q := r.URL.Query().Get("resource_type"); q != "" {
		opts.ResourceType = q
	}
	if q := r.URL.Query().Get("action"); q != "" {
		opts.Action = q
	}
	if q := r.URL.Query().Get("since"); q != "" {
		if t, err := time.Parse("2006-01-02", q); err == nil {
			opts.Since = &t
		}
	}
	if q := r.URL.Query().Get("until"); q != "" {
		if t, err := time.Parse("2006-01-02", q); err == nil {
			opts.Until = &t
		}
	}

	rows, err := h.changesSvc.ExportCSV(r.Context(), opts)
	if err != nil {
		h.jsonError(w, "failed to export change events", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=change-events-%s.csv", time.Now().Format("20060102")))

	writer := csv.NewWriter(w)
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return
		}
	}
	writer.Flush()
}

// ChangeListAPI returns change events as JSON with pagination.
func (h *Handler) ChangeListAPI(w http.ResponseWriter, r *http.Request) {
	if h.changesSvc == nil {
		h.jsonError(w, "change tracking not available", http.StatusServiceUnavailable)
		return
	}

	opts := models.ChangeEventListOptions{Limit: 50}
	if q := r.URL.Query().Get("resource_type"); q != "" {
		opts.ResourceType = q
	}
	if q := r.URL.Query().Get("action"); q != "" {
		opts.Action = q
	}
	if q := r.URL.Query().Get("search"); q != "" {
		opts.Search = q
	}
	if q := r.URL.Query().Get("limit"); q != "" {
		if l, err := strconv.Atoi(q); err == nil && l > 0 && l <= 200 {
			opts.Limit = l
		}
	}
	if q := r.URL.Query().Get("offset"); q != "" {
		if o, err := strconv.Atoi(q); err == nil && o >= 0 {
			opts.Offset = o
		}
	}

	events, total, err := h.changesSvc.List(r.Context(), opts)
	if err != nil {
		h.jsonError(w, "failed to list change events", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"events": events,
		"total":  total,
	})
}

// changeEventToView converts a ChangeEvent model to a template view.
func changeEventToView(e *models.ChangeEvent) changestmpl.ChangeEventView {
	v := changestmpl.ChangeEventView{
		ID:            e.ID.String(),
		Timestamp:     e.Timestamp.Format("Jan 02, 15:04"),
		TimestampFull: e.Timestamp.Format(time.RFC3339),
		UserName:      e.UserName,
		ClientIP:      e.ClientIP,
		ResourceType:  e.ResourceType,
		ResourceID:    e.ResourceID,
		ResourceName:  e.ResourceName,
		Action:        e.Action,
		DiffSummary:   e.DiffSummary,
		RelatedTicket: e.RelatedTicket,
		HasDiff:       e.OldState != nil && e.NewState != nil,
	}
	if e.UserID != nil {
		v.UserID = e.UserID.String()
	}
	return v
}
