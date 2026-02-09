// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ShortcutRepository defines the interface for shortcut persistence.
type ShortcutRepository interface {
	Create(ctx context.Context, shortcut *models.WebShortcut) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.WebShortcut, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.WebShortcut, error)
	ListForMenu(ctx context.Context, userID uuid.UUID) ([]*models.WebShortcut, error)
	ListByCategory(ctx context.Context, userID uuid.UUID, category string) ([]*models.WebShortcut, error)
	Update(ctx context.Context, shortcut *models.WebShortcut) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetCategories(ctx context.Context, userID uuid.UUID) ([]string, error)
	UpdateSortOrder(ctx context.Context, orders map[uuid.UUID]int) error
}

// ShortcutHandler handles shortcut-related API requests.
type ShortcutHandler struct {
	BaseHandler
	repo ShortcutRepository
}

// NewShortcutHandler creates a new shortcut handler.
func NewShortcutHandler(repo ShortcutRepository, log *logger.Logger) *ShortcutHandler {
	return &ShortcutHandler{
		BaseHandler: NewBaseHandler(log),
		repo:        repo,
	}
}

// Routes registers shortcut API routes.
func (h *ShortcutHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Get("/menu", h.ListForMenu)
	r.Get("/categories", h.GetCategories)
	r.Put("/sort", h.UpdateSortOrder)
	r.Get("/{id}", h.Get)
	r.Put("/{id}", h.Update)
	r.Delete("/{id}", h.Delete)

	return r
}

// List returns all shortcuts for the current user.
func (h *ShortcutHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	category := h.QueryParam(r, "category")

	var shortcuts []*models.WebShortcut
	if category != "" {
		shortcuts, err = h.repo.ListByCategory(r.Context(), userID, category)
	} else {
		shortcuts, err = h.repo.ListByUser(r.Context(), userID)
	}

	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, shortcuts)
}

// ListForMenu returns shortcuts marked for menu display.
func (h *ShortcutHandler) ListForMenu(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	shortcuts, err := h.repo.ListForMenu(r.Context(), userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, shortcuts)
}

// Create creates a new shortcut.
func (h *ShortcutHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var input models.CreateWebShortcutInput
	if err := h.ParseJSON(r, &input); err != nil {
		h.HandleError(w, err)
		return
	}

	// Set defaults
	if input.IconType == "" {
		input.IconType = "fa"
	}
	if input.Icon == "" {
		input.Icon = "fa-link"
	}

	shortcut := &models.WebShortcut{
		Name:        input.Name,
		Description: input.Description,
		URL:         input.URL,
		Type:        input.Type,
		Icon:        input.Icon,
		IconType:    input.IconType,
		Color:       input.Color,
		Category:    input.Category,
		SortOrder:   input.SortOrder,
		OpenInNew:   input.OpenInNew,
		ShowInMenu:  input.ShowInMenu,
		IsPublic:    input.IsPublic,
		CreatedBy:   userID,
	}

	if err := h.repo.Create(r.Context(), shortcut); err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, shortcut)
}

// Get returns a shortcut by ID.
func (h *ShortcutHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	shortcut, err := h.repo.GetByID(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, shortcut)
}

// Update updates a shortcut.
func (h *ShortcutHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	shortcut, err := h.repo.GetByID(r.Context(), id)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var input models.UpdateWebShortcutInput
	if err := h.ParseJSON(r, &input); err != nil {
		h.HandleError(w, err)
		return
	}

	// Apply updates
	if input.Name != nil {
		shortcut.Name = *input.Name
	}
	if input.Description != nil {
		shortcut.Description = *input.Description
	}
	if input.URL != nil {
		shortcut.URL = *input.URL
	}
	if input.Type != nil {
		shortcut.Type = *input.Type
	}
	if input.Icon != nil {
		shortcut.Icon = *input.Icon
	}
	if input.IconType != nil {
		shortcut.IconType = *input.IconType
	}
	if input.Color != nil {
		shortcut.Color = *input.Color
	}
	if input.Category != nil {
		shortcut.Category = *input.Category
	}
	if input.SortOrder != nil {
		shortcut.SortOrder = *input.SortOrder
	}
	if input.OpenInNew != nil {
		shortcut.OpenInNew = *input.OpenInNew
	}
	if input.ShowInMenu != nil {
		shortcut.ShowInMenu = *input.ShowInMenu
	}
	if input.IsPublic != nil {
		shortcut.IsPublic = *input.IsPublic
	}

	if err := h.repo.Update(r.Context(), shortcut); err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, shortcut)
}

// Delete deletes a shortcut.
func (h *ShortcutHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := h.URLParamUUID(r, "id")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.repo.Delete(r.Context(), id); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// GetCategories returns all unique categories for the current user.
func (h *ShortcutHandler) GetCategories(w http.ResponseWriter, r *http.Request) {
	userID, err := h.GetUserID(r)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	categories, err := h.repo.GetCategories(r.Context(), userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]any{
		"categories": categories,
	})
}

// UpdateSortOrder updates the sort order for multiple shortcuts.
func (h *ShortcutHandler) UpdateSortOrder(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Orders map[string]int `json:"orders"`
	}

	if err := h.ParseJSON(r, &input); err != nil {
		h.HandleError(w, err)
		return
	}

	orders := make(map[uuid.UUID]int)
	for idStr, order := range input.Orders {
		id, err := uuid.Parse(idStr)
		if err != nil {
			h.BadRequest(w, "invalid shortcut ID: "+idStr)
			return
		}
		orders[id] = order
	}

	if err := h.repo.UpdateSortOrder(r.Context(), orders); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}
