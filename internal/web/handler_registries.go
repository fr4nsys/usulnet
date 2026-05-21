// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"

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
// registryForm captures the registry create/update inputs.
// Username / Password are optional; an empty Password on Update
// preserves the existing credential (the handler only assigns
// when the form value is non-empty).
type registryForm struct {
	Name      string `form:"name" validate:"required"`
	URL       string `form:"url" validate:"required"`
	IsDefault bool   `form:"is_default"`
	Username  string `form:"username"`
	Password  string `form:"password"`
}

func (h *Handler) RegistryCreate(w http.ResponseWriter, r *http.Request) {
	if h.registryRepo == nil {
		h.setFlash(w, r, "error", "Registry service not configured")
		h.redirect(w, r, "/registries")
		return
	}

	var form registryForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		h.redirect(w, r, "/registries")
		return
	}

	input := models.CreateRegistryInput{
		Name:      form.Name,
		URL:       form.URL,
		IsDefault: form.IsDefault,
	}

	if form.Username != "" {
		u := form.Username
		input.Username = &u
	}
	if form.Password != "" {
		if h.encryptor != nil {
			encrypted, err := h.encryptor.Encrypt(form.Password)
			if err == nil {
				input.Password = &encrypted
			} else {
				slog.Error("Failed to encrypt registry password", "error", err)
				h.setFlash(w, r, "error", "Failed to encrypt password")
				h.redirect(w, r, "/registries")
				return
			}
		} else {
			p := form.Password
			input.Password = &p
		}
	}

	_, err := h.registryRepo.Create(r.Context(), input)
	if err != nil {
		slog.Error("Failed to create registry", "name", input.Name, "error", err)
		h.setFlash(w, r, "error", "Failed to create registry: "+err.Error())
		h.redirect(w, r, "/registries")
		return
	}

	h.setFlash(w, r, "success", "Registry created successfully")
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
		h.setFlash(w, r, "error", "Registry service not configured")
		h.redirect(w, r, "/registries")
		return
	}

	var form registryForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		h.redirect(w, r, "/registries")
		return
	}

	input := models.CreateRegistryInput{
		Name:      form.Name,
		URL:       form.URL,
		IsDefault: form.IsDefault,
	}

	if form.Username != "" {
		u := form.Username
		input.Username = &u
	}
	if form.Password != "" {
		if h.encryptor != nil {
			encrypted, encErr := h.encryptor.Encrypt(form.Password)
			if encErr == nil {
				input.Password = &encrypted
			} else {
				slog.Error("Failed to encrypt registry password", "error", encErr)
				h.setFlash(w, r, "error", "Failed to encrypt password")
				h.redirect(w, r, "/registries")
				return
			}
		} else {
			p := form.Password
			input.Password = &p
		}
	}

	_, err = h.registryRepo.Update(r.Context(), id, input)
	if err != nil {
		slog.Error("Failed to update registry", "id", id, "error", err)
		h.setFlash(w, r, "error", "Failed to update registry: "+err.Error())
		h.redirect(w, r, "/registries")
		return
	}

	h.setFlash(w, r, "success", "Registry updated successfully")
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
			h.setFlash(w, r, "error", "Failed to delete registry: "+err.Error())
			h.redirect(w, r, "/registries")
			return
		}
	}

	h.setFlash(w, r, "success", "Registry deleted")
	h.redirect(w, r, "/registries")
}

// RegistryBrowse renders the registry browsing page showing repositories.
func (h *Handler) RegistryBrowse(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/registries")
		return
	}

	if h.registryBrowseSvc == nil {
		h.setFlash(w, r, "error", "Registry browsing service not configured")
		h.redirect(w, r, "/registries")
		return
	}

	pageData := h.prepareTemplPageData(r, "Browse Registry", "registries")

	// Get registry metadata
	var regName, regURL string
	if h.registryRepo != nil {
		reg, err := h.registryRepo.GetByID(r.Context(), id)
		if err != nil {
			h.setFlash(w, r, "error", "Registry not found")
			h.redirect(w, r, "/registries")
			return
		}
		regName = reg.Name
		regURL = reg.URL
	}

	namespace := r.URL.Query().Get("namespace")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage := 50

	repos, err := h.registryBrowseSvc.ListRepositories(r.Context(), id, namespace, page, perPage)
	if err != nil {
		slog.Error("Failed to list repositories", "registry_id", id, "error", err)
	}

	var items []registries.RepoItem
	for _, repo := range repos {
		item := registries.RepoItem{
			Name:        repo.Name,
			Description: repo.Description,
			TagCount:    repo.TagCount,
			PullCount:   repo.PullCount,
			StarCount:   repo.StarCount,
			IsPrivate:   repo.IsPrivate,
		}
		if repo.LastUpdated != nil {
			item.LastUpdated = repo.LastUpdated.Format("2006-01-02 15:04")
		}
		items = append(items, item)
	}

	data := registries.BrowseData{
		PageData:   pageData,
		RegistryID: id.String(),
		RegName:    regName,
		RegURL:     regURL,
		Namespace:  namespace,
		Repos:      items,
		Page:       page,
		PerPage:    perPage,
		HasMore:    len(items) >= perPage,
	}
	h.renderTempl(w, r, registries.Browse(data))
}

// RegistryRepoTags renders the tag list for a specific repository.
func (h *Handler) RegistryRepoTags(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/registries")
		return
	}

	if h.registryBrowseSvc == nil {
		h.setFlash(w, r, "error", "Registry browsing service not configured")
		h.redirect(w, r, "/registries")
		return
	}

	// Repository name comes from the wildcard (can contain slashes like "library/nginx")
	repo := chi.URLParam(r, "*")
	repo = strings.TrimPrefix(repo, "/")
	if repo == "" {
		h.redirect(w, r, "/registries/"+idStr+"/browse")
		return
	}

	pageData := h.prepareTemplPageData(r, "Tags: "+repo, "registries")

	// Get registry metadata
	var regName string
	if h.registryRepo != nil {
		reg, err := h.registryRepo.GetByID(r.Context(), id)
		if err == nil {
			regName = reg.Name
		}
	}

	tags, err := h.registryBrowseSvc.ListTags(r.Context(), id, repo)
	if err != nil {
		slog.Error("Failed to list tags", "registry_id", id, "repo", repo, "error", err)
	}

	var items []registries.TagItem
	for _, tag := range tags {
		item := registries.TagItem{
			Name:   tag.Name,
			Digest: tag.Digest,
			Size:   tag.Size,
		}
		if tag.LastPushed != nil {
			item.LastPushed = tag.LastPushed.Format("2006-01-02 15:04")
		}
		items = append(items, item)
	}

	data := registries.TagsData{
		PageData:   pageData,
		RegistryID: id.String(),
		RegName:    regName,
		RepoName:   repo,
		Tags:       items,
	}
	h.renderTempl(w, r, registries.Tags(data))
}

// RegistryTagManifest renders manifest details for a specific tag.
func (h *Handler) RegistryTagManifest(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/registries")
		return
	}

	if h.registryBrowseSvc == nil {
		h.setFlash(w, r, "error", "Registry browsing service not configured")
		h.redirect(w, r, "/registries")
		return
	}

	repo := r.URL.Query().Get("repo")
	reference := r.URL.Query().Get("ref")
	if repo == "" || reference == "" {
		h.redirect(w, r, "/registries/"+idStr+"/browse")
		return
	}

	pageData := h.prepareTemplPageData(r, "Manifest: "+reference, "registries")

	// Get registry metadata
	var regName string
	if h.registryRepo != nil {
		reg, err := h.registryRepo.GetByID(r.Context(), id)
		if err == nil {
			regName = reg.Name
		}
	}

	manifest, err := h.registryBrowseSvc.GetManifest(r.Context(), id, repo, reference)
	if err != nil {
		slog.Error("Failed to get manifest", "registry_id", id, "repo", repo, "ref", reference, "error", err)
		h.setFlash(w, r, "error", "Failed to get manifest: "+err.Error())
		h.redirect(w, r, "/registries/"+idStr+"/browse/repos/"+repo)
		return
	}

	data := registries.ManifestData{
		PageData:   pageData,
		RegistryID: id.String(),
		RegName:    regName,
		RepoName:   repo,
		Reference:  reference,
		Digest:     manifest.Digest,
		MediaType:  manifest.MediaType,
		Size:       manifest.Size,
		Platform:   manifest.Platform,
		Layers:     manifest.Layers,
	}
	h.renderTempl(w, r, registries.Manifest(data))
}
