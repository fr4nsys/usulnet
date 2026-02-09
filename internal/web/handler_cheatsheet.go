// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"

	"github.com/fr4nsys/usulnet/internal/models"
	toolspages "github.com/fr4nsys/usulnet/internal/web/templates/pages/tools"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ============================================================================
// Cheat Sheet Handlers
// ============================================================================

// CheatSheet renders the command cheat sheet page.
// GET /tools/cheatsheet
func (h *Handler) CheatSheet(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Command Cheat Sheet", "cheatsheet")

	// Load default command categories
	categories := toolspages.DefaultCategories()

	// Load user's custom commands from snippet repo
	ctx := r.Context()
	user := GetUserFromContext(ctx)
	var customCmds []toolspages.CustomCommand

	if user != nil && h.snippetRepo != nil {
		// Fetch custom cheatsheet commands (stored as snippets with path prefix)
		userID, err := uuid.Parse(user.ID)
		if err == nil {
			opts := &models.SnippetListOptions{
				Path:  "cheatsheet/",
				Limit: 100,
			}
			snippets, err := h.snippetRepo.List(ctx, userID, opts)
			if err == nil {
				for _, s := range snippets {
					category := ""
					if len(s.Path) > 11 { // len("cheatsheet/") = 11
						category = s.Path[11:]
					}
					customCmds = append(customCmds, toolspages.CustomCommand{
						ID:          s.ID.String(),
						Title:       s.Name,
						Command:     "", // Content not included in list items
						Category:    category,
						Description: ptrToString(s.Description),
						CreatedAt:   s.UpdatedAt.Format("Jan 2, 2006"),
					})
				}
			}
		}
	}

	data := toolspages.CheatSheetData{
		PageData:   pageData,
		Categories: categories,
		Custom:     customCmds,
	}

	h.renderTempl(w, r, toolspages.CheatSheet(data))
}

// CheatSheetCustomCreate creates a new custom command.
// POST /tools/cheatsheet/custom
func (h *Handler) CheatSheetCustomCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/tools/cheatsheet", http.StatusSeeOther)
		return
	}

	ctx := r.Context()
	user := GetUserFromContext(ctx)
	if user == nil {
		h.setFlash(w, r, "error", "You must be logged in to save custom commands")
		http.Redirect(w, r, "/tools/cheatsheet", http.StatusSeeOther)
		return
	}

	title := r.FormValue("title")
	command := r.FormValue("command")
	description := r.FormValue("description")
	category := r.FormValue("category")

	if title == "" || command == "" {
		h.setFlash(w, r, "error", "Title and command are required")
		http.Redirect(w, r, "/tools/cheatsheet", http.StatusSeeOther)
		return
	}

	if h.snippetRepo == nil {
		h.setFlash(w, r, "error", "Custom commands not available")
		http.Redirect(w, r, "/tools/cheatsheet", http.StatusSeeOther)
		return
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid user session")
		http.Redirect(w, r, "/tools/cheatsheet", http.StatusSeeOther)
		return
	}

	// Store as snippet with cheatsheet/ path prefix
	path := "cheatsheet/"
	if category != "" {
		path += category
	}

	input := &models.CreateSnippetInput{
		Name:        title,
		Path:        path,
		Language:    "shell",
		Content:     command,
		Description: description,
		Tags:        []string{"cheatsheet"},
	}

	_, err = h.snippetRepo.Create(ctx, userID, input)
	if err != nil {
		h.logger.Error("Failed to create custom command", "error", err)
		h.setFlash(w, r, "error", "Failed to save custom command")
		http.Redirect(w, r, "/tools/cheatsheet", http.StatusSeeOther)
		return
	}

	h.logger.Info("Custom command created",
		"user", user.Username,
		"title", title,
		"category", category,
	)

	h.setFlash(w, r, "success", "Custom command saved")
	http.Redirect(w, r, "/tools/cheatsheet", http.StatusSeeOther)
}

// CheatSheetCustomDelete deletes a custom command.
// DELETE /tools/cheatsheet/custom/{id}
func (h *Handler) CheatSheetCustomDelete(w http.ResponseWriter, r *http.Request) {
	cmdID := chi.URLParam(r, "id")
	if cmdID == "" {
		http.Error(w, "Missing command ID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	user := GetUserFromContext(ctx)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if h.snippetRepo == nil {
		http.Error(w, "Custom commands not available", http.StatusServiceUnavailable)
		return
	}

	snippetID, err := uuid.Parse(cmdID)
	if err != nil {
		http.Error(w, "Invalid command ID", http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		http.Error(w, "Invalid user session", http.StatusBadRequest)
		return
	}

	err = h.snippetRepo.Delete(ctx, userID, snippetID)
	if err != nil {
		h.logger.Error("Failed to delete custom command", "error", err)
		h.setFlash(w, r, "error", "Failed to delete command")
		http.Redirect(w, r, "/tools/cheatsheet", http.StatusSeeOther)
		return
	}

	h.logger.Info("Custom command deleted",
		"user", user.Username,
		"id", cmdID,
	)

	h.setFlash(w, r, "success", "Command deleted")
	http.Redirect(w, r, "/tools/cheatsheet", http.StatusSeeOther)
}
