// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// SnippetRepository defines the interface for snippet storage.
type SnippetRepository interface {
	Create(ctx context.Context, userID uuid.UUID, input *models.CreateSnippetInput) (*models.UserSnippet, error)
	Get(ctx context.Context, userID, snippetID uuid.UUID) (*models.UserSnippet, error)
	Update(ctx context.Context, userID, snippetID uuid.UUID, input *models.UpdateSnippetInput) (*models.UserSnippet, error)
	Delete(ctx context.Context, userID, snippetID uuid.UUID) error
	List(ctx context.Context, userID uuid.UUID, opts *models.SnippetListOptions) ([]*models.UserSnippetListItem, error)
	ListPaths(ctx context.Context, userID uuid.UUID) ([]string, error)
	Count(ctx context.Context, userID uuid.UUID) (int, error)
}

// SetSnippetRepo sets the snippet repository.
func (h *Handler) SetSnippetRepo(repo SnippetRepository) {
	h.snippetRepo = repo
}

// ============================================================================
// Snippet Handlers (Editor file storage)
// ============================================================================

// SnippetList returns user's snippets.
// GET /api/snippets
func (h *Handler) SnippetList(w http.ResponseWriter, r *http.Request) {
	if h.snippetRepo == nil {
		h.jsonError(w, "Snippet storage not configured", http.StatusServiceUnavailable)
		return
	}

	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	opts := &models.SnippetListOptions{
		Path:     r.URL.Query().Get("path"),
		Language: r.URL.Query().Get("language"),
		Search:   r.URL.Query().Get("search"),
	}

	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil {
			opts.Limit = l
		}
	}
	if offset := r.URL.Query().Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil {
			opts.Offset = o
		}
	}

	snippets, err := h.snippetRepo.List(r.Context(), userID, opts)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, map[string]interface{}{
		"snippets": snippets,
		"count":    len(snippets),
	})
}

// SnippetCreate creates a new snippet.
// POST /api/snippets
func (h *Handler) SnippetCreate(w http.ResponseWriter, r *http.Request) {
	if h.snippetRepo == nil {
		h.jsonError(w, "Snippet storage not configured", http.StatusServiceUnavailable)
		return
	}

	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var input models.CreateSnippetInput

	// Support both JSON and form data
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			h.jsonError(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
	} else {
		// Form data
		input.Name = r.FormValue("name")
		input.Path = r.FormValue("path")
		input.Language = r.FormValue("language")
		input.Content = r.FormValue("content")
		input.Description = r.FormValue("description")
		if tags := r.FormValue("tags"); tags != "" {
			input.Tags = strings.Split(tags, ",")
		}
	}

	if input.Name == "" {
		h.jsonError(w, "Name is required", http.StatusBadRequest)
		return
	}
	if input.Language == "" {
		input.Language = "plaintext"
	}

	snippet, err := h.snippetRepo.Create(r.Context(), userID, &input)
	isFormSubmit := !strings.Contains(contentType, "application/json")
	if err != nil {
		if isFormSubmit {
			http.Redirect(w, r, "/editor", http.StatusSeeOther)
			return
		}
		if strings.Contains(err.Error(), "already exists") {
			h.jsonError(w, err.Error(), http.StatusConflict)
			return
		}
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Form submission: redirect to editor with the new snippet
	if isFormSubmit {
		http.Redirect(w, r, "/editor/monaco?snippet="+snippet.ID.String(), http.StatusSeeOther)
		return
	}

	w.WriteHeader(http.StatusCreated)
	h.jsonResponse(w, snippet)
}

// SnippetGet returns a single snippet with content.
// GET /api/snippets/{id}
func (h *Handler) SnippetGet(w http.ResponseWriter, r *http.Request) {
	if h.snippetRepo == nil {
		h.jsonError(w, "Snippet storage not configured", http.StatusServiceUnavailable)
		return
	}

	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	snippetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "Invalid snippet ID", http.StatusBadRequest)
		return
	}

	snippet, err := h.snippetRepo.Get(r.Context(), userID, snippetID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.jsonError(w, "Snippet not found", http.StatusNotFound)
			return
		}
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, snippet)
}

// SnippetUpdate updates a snippet.
// PUT /api/snippets/{id}
func (h *Handler) SnippetUpdate(w http.ResponseWriter, r *http.Request) {
	if h.snippetRepo == nil {
		h.jsonError(w, "Snippet storage not configured", http.StatusServiceUnavailable)
		return
	}

	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	snippetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "Invalid snippet ID", http.StatusBadRequest)
		return
	}

	var input models.UpdateSnippetInput

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			h.jsonError(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
	} else {
		// Form data - only set non-empty values
		if name := r.FormValue("name"); name != "" {
			input.Name = &name
		}
		if path := r.FormValue("path"); path != "" {
			input.Path = &path
		}
		if lang := r.FormValue("language"); lang != "" {
			input.Language = &lang
		}
		if content := r.FormValue("content"); content != "" {
			input.Content = &content
		}
		if desc := r.FormValue("description"); desc != "" {
			input.Description = &desc
		}
		if tags := r.FormValue("tags"); tags != "" {
			input.Tags = strings.Split(tags, ",")
		}
	}

	snippet, err := h.snippetRepo.Update(r.Context(), userID, snippetID, &input)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.jsonError(w, "Snippet not found", http.StatusNotFound)
			return
		}
		if strings.Contains(err.Error(), "already exists") {
			h.jsonError(w, err.Error(), http.StatusConflict)
			return
		}
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, snippet)
}

// SnippetDelete deletes a snippet.
// DELETE /api/snippets/{id}
func (h *Handler) SnippetDelete(w http.ResponseWriter, r *http.Request) {
	if h.snippetRepo == nil {
		h.jsonError(w, "Snippet storage not configured", http.StatusServiceUnavailable)
		return
	}

	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	snippetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.jsonError(w, "Invalid snippet ID", http.StatusBadRequest)
		return
	}

	if err := h.snippetRepo.Delete(r.Context(), userID, snippetID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.jsonError(w, "Snippet not found", http.StatusNotFound)
			return
		}
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SnippetPaths returns unique folder paths for navigation.
// GET /api/snippets/paths
func (h *Handler) SnippetPaths(w http.ResponseWriter, r *http.Request) {
	if h.snippetRepo == nil {
		h.jsonError(w, "Snippet storage not configured", http.StatusServiceUnavailable)
		return
	}

	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	paths, err := h.snippetRepo.ListPaths(r.Context(), userID)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, map[string]interface{}{
		"paths": paths,
	})
}

// ============================================================================
// Helper methods (may be duplicated if not already defined elsewhere)
// ============================================================================

func (h *Handler) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (h *Handler) jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (h *Handler) jsonSuccess(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	data["success"] = true
	json.NewEncoder(w).Encode(data)
}
