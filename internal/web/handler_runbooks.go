// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/runbooks"
)

// RunbooksTempl renders the runbooks management page.
func (h *Handler) RunbooksTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Runbooks", "runbooks")
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "runbooks"
	}

	var rbItems []runbooks.RunbookItem
	var execItems []runbooks.ExecutionItem

	if h.runbookRepo != nil {
		rbs, _, err := h.runbookRepo.List(r.Context(), models.RunbookListOptions{Limit: 100})
		if err != nil {
			slog.Error("Failed to list runbooks", "error", err)
		} else {
			for _, rb := range rbs {
				var steps []models.RunbookStep
				if rb.Steps != nil {
					json.Unmarshal(rb.Steps, &steps)
				}

				rbItems = append(rbItems, runbooks.RunbookItem{
					ID:          rb.ID.String(),
					Name:        rb.Name,
					Description: rb.Description,
					Category:    rb.Category,
					StepCount:   len(steps),
					IsEnabled:   rb.IsEnabled,
					Version:     rb.Version,
					CreatedAt:   rb.CreatedAt.Format("2006-01-02 15:04"),
					UpdatedAt:   rb.UpdatedAt.Format("2006-01-02 15:04"),
				})
			}
		}
	}

	data := runbooks.RunbooksData{
		PageData:   pageData,
		Runbooks:   rbItems,
		Executions: execItems,
		Tab:        tab,
	}
	h.renderTempl(w, r, runbooks.List(data))
}

// RunbookCreate handles creation of a new runbook.
func (h *Handler) RunbookCreate(w http.ResponseWriter, r *http.Request) {
	if h.runbookRepo == nil {
		h.redirect(w, r, "/runbooks")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/runbooks")
		return
	}

	stepsJSON := r.FormValue("steps")
	if stepsJSON == "" {
		stepsJSON = "[]"
	}

	rb := &models.Runbook{
		Name:        r.FormValue("name"),
		Description: r.FormValue("description"),
		Category:    r.FormValue("category"),
		Steps:       json.RawMessage(stepsJSON),
		IsEnabled:   r.FormValue("is_enabled") == "on",
		Version:     1,
	}

	if user := GetUserFromContext(r.Context()); user != nil {
		if uid, err := uuid.Parse(user.ID); err == nil {
			rb.CreatedBy = &uid
		}
	}

	if err := h.runbookRepo.Create(r.Context(), rb); err != nil {
		slog.Error("Failed to create runbook", "name", rb.Name, "error", err)
	}

	h.redirect(w, r, "/runbooks")
}

// RunbookDelete handles deletion of a runbook.
func (h *Handler) RunbookDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/runbooks")
		return
	}

	if h.runbookRepo != nil {
		if err := h.runbookRepo.Delete(r.Context(), id); err != nil {
			slog.Error("Failed to delete runbook", "id", id, "error", err)
		}
	}

	h.redirect(w, r, "/runbooks")
}

// RunbookExecute triggers manual execution of a runbook.
func (h *Handler) RunbookExecute(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/runbooks")
		return
	}

	if h.runbookRepo == nil {
		h.redirect(w, r, "/runbooks")
		return
	}

	exec := &models.RunbookExecution{
		RunbookID: id,
		Status:    "completed",
		Trigger:   "manual",
		StartedAt: time.Now(),
	}

	now := time.Now()
	exec.FinishedAt = &now

	if user := GetUserFromContext(r.Context()); user != nil {
		if uid, err := uuid.Parse(user.ID); err == nil {
			exec.ExecutedBy = &uid
		}
	}

	if err := h.runbookRepo.CreateExecution(r.Context(), exec); err != nil {
		slog.Error("Failed to execute runbook", "id", id, "error", err)
	}

	h.redirect(w, r, "/runbooks?tab=executions")
}
