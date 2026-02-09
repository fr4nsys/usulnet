// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/registries"
)

// RegistriesTempl renders the registries management page.
func (h *Handler) RegistriesTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Registries", "registries")

	var items []registries.RegistryItem
	if h.registryRepo != nil {
		regs, err := h.registryRepo.List(r.Context())
		if err != nil {
			slog.Error("Failed to list registries", "error", err)
		} else {
			for _, reg := range regs {
				item := registries.RegistryItem{
					ID:        reg.ID.String(),
					Name:      reg.Name,
					URL:       reg.URL,
					IsDefault: reg.IsDefault,
					CreatedAt: reg.CreatedAt.Format("2006-01-02 15:04"),
				}
				if reg.Username != nil {
					item.Username = *reg.Username
				}
				items = append(items, item)
			}
		}
	}

	data := registries.RegistriesData{
		PageData:   pageData,
		Registries: items,
	}
	h.renderTempl(w, r, registries.List(data))
}

// RegistryCreate handles creation of a new registry.
func (h *Handler) RegistryCreate(w http.ResponseWriter, r *http.Request) {
	if h.registryRepo == nil {
		h.redirect(w, r, "/registries")
		return
	}

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", "error", err)
		h.redirect(w, r, "/registries")
		return
	}

	input := models.CreateRegistryInput{
		Name:      r.FormValue("name"),
		URL:       r.FormValue("url"),
		IsDefault: r.FormValue("is_default") == "on",
	}

	if username := r.FormValue("username"); username != "" {
		input.Username = &username
	}
	if password := r.FormValue("password"); password != "" {
		if h.encryptor != nil {
			encrypted, err := h.encryptor.Encrypt(password)
			if err == nil {
				input.Password = &encrypted
			}
		} else {
			input.Password = &password
		}
	}

	_, err := h.registryRepo.Create(r.Context(), input)
	if err != nil {
		slog.Error("Failed to create registry", "name", input.Name, "error", err)
	}

	h.redirect(w, r, "/registries")
}

// RegistryUpdate handles updating a registry.
func (h *Handler) RegistryUpdate(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/registries")
		return
	}

	if h.registryRepo == nil {
		h.redirect(w, r, "/registries")
		return
	}

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", "error", err)
		h.redirect(w, r, "/registries")
		return
	}

	input := models.CreateRegistryInput{
		Name:      r.FormValue("name"),
		URL:       r.FormValue("url"),
		IsDefault: r.FormValue("is_default") == "on",
	}

	if username := r.FormValue("username"); username != "" {
		input.Username = &username
	}
	if password := r.FormValue("password"); password != "" {
		if h.encryptor != nil {
			encrypted, err := h.encryptor.Encrypt(password)
			if err == nil {
				input.Password = &encrypted
			}
		} else {
			input.Password = &password
		}
	}

	_, err = h.registryRepo.Update(r.Context(), id, input)
	if err != nil {
		slog.Error("Failed to update registry", "id", id, "error", err)
	}

	h.redirect(w, r, "/registries")
}

// RegistryDelete handles deletion of a registry.
func (h *Handler) RegistryDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/registries")
		return
	}

	if h.registryRepo != nil {
		if err := h.registryRepo.Delete(r.Context(), id); err != nil {
			slog.Error("Failed to delete registry", "id", id, "error", err)
		}
	}

	h.redirect(w, r, "/registries")
}
