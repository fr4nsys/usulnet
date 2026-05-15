// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	stderrors "errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	imagebuildersvc "github.com/fr4nsys/usulnet/internal/services/imagebuilder"
	ibtpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/imagebuilder"
)

// requireImageBuilderSvc returns the image builder service or renders a
// "not configured" page. The service is wired unconditionally in
// init_services, but a deployment that disables migration 053 would
// observe a nil pointer here.
func (h *Handler) requireImageBuilderSvc(w http.ResponseWriter, r *http.Request) *imagebuildersvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.imageBuilderSvc != nil {
		return reg.imageBuilderSvc
	}
	h.RenderErrorTempl(w, r, http.StatusServiceUnavailable,
		"Image Builder Not Configured",
		"The image builder service is not enabled in this build.")
	return nil
}

// getIBHostID resolves the active host ID for image builder operations.
func (h *Handler) getIBHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

// imageBuilderUserUUID returns the request user's UUID, or nil if absent.
func (h *Handler) imageBuilderUserUUID(r *http.Request) *uuid.UUID {
	user := h.getUserData(r)
	if user == nil || user.ID == "" {
		return nil
	}
	id, err := uuid.Parse(user.ID)
	if err != nil {
		return nil
	}
	return &id
}

// ============================================================================
// Build List
// ============================================================================

// ImageBuilderListTempl renders the image builder list page.
func (h *Handler) ImageBuilderListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireImageBuilderSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getIBHostID(r)
	pageData := h.prepareTemplPageData(r, "Image Builder", "image-builder")

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	pageSize := 50
	offset := (page - 1) * pageSize

	builds, total, err := svc.ListBuilds(ctx, hostID, pageSize, offset)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load builds: "+err.Error())
		return
	}

	stats, _ := svc.GetStats(ctx, hostID)

	views := make([]ibtpl.BuildView, 0, len(builds))
	for i := range builds {
		views = append(views, buildJobToView(builds[i]))
	}

	statsView := ibtpl.StatsView{}
	if stats != nil {
		statsView.TotalBuilds = stats.TotalBuilds
		statsView.Successful = stats.Successful
		statsView.Failed = stats.Failed
		statsView.Building = stats.Building
		statsView.AvgDurationMs = stats.AvgDurationMs
	}

	data := ibtpl.ListData{
		PageData: pageData,
		Builds:   views,
		Stats:    statsView,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}

	h.renderTempl(w, r, ibtpl.List(data))
}

// ============================================================================
// Build Detail
// ============================================================================

// ImageBuilderDetailTempl renders a build detail page with a live log
// pane wired to the API's WebSocket endpoint.
func (h *Handler) ImageBuilderDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireImageBuilderSvc(w, r)
	if svc == nil {
		return
	}

	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The build ID is not valid.")
		return
	}

	b, err := svc.GetBuild(r.Context(), buildID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested build was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Build Detail", "image-builder")

	data := ibtpl.DetailData{
		PageData:      pageData,
		Build:         buildJobToView(*b),
		LogStreamPath: "/api/v1/builds/" + buildID.String() + "/log",
	}

	h.renderTempl(w, r, ibtpl.Detail(data))
}

// ============================================================================
// New Build
// ============================================================================

// ImageBuilderNewTempl renders the new build form. When ?template=<id>
// is present the Dockerfile field pre-fills from that template.
func (h *Handler) ImageBuilderNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireImageBuilderSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getIBHostID(r)
	pageData := h.prepareTemplPageData(r, "New Image Build", "image-builder")

	templates, _ := svc.ListTemplates(ctx, hostID)
	templateViews := make([]ibtpl.TemplateView, 0, len(templates))
	for _, t := range templates {
		templateViews = append(templateViews, ibtpl.TemplateView{
			ID:          t.ID.String(),
			Name:        t.Name,
			Description: t.Description,
			Category:    t.Category,
			IsBuiltin:   t.IsBuiltin,
			CreatedAt:   t.CreatedAt.Format("2006-01-02 15:04"),
		})
	}

	var prefill, prefillName string
	if tplID := r.URL.Query().Get("template"); tplID != "" {
		if id, err := uuid.Parse(tplID); err == nil {
			if t, err := svc.GetTemplate(ctx, id); err == nil {
				prefill = t.Dockerfile
				prefillName = t.Name
			}
		}
	}

	h.renderTempl(w, r, ibtpl.NewBuild(ibtpl.NewBuildData{
		PageData:    pageData,
		Templates:   templateViews,
		Prefill:     prefill,
		PrefillName: prefillName,
	}))
}

// ImageBuilderCreateTempl handles POST /image-builder — starts a new build.
func (h *Handler) ImageBuilderCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireImageBuilderSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	hostID := h.getIBHostID(r)

	name := r.FormValue("name")
	tag := r.FormValue("tag")
	dockerfile := r.FormValue("dockerfile")
	contextPath := r.FormValue("context_path")
	platform := r.FormValue("platform")
	target := r.FormValue("target")
	noCache := r.FormValue("no_cache") == "true"
	pull := r.FormValue("pull") == "true"

	if tag == "" || dockerfile == "" {
		pageData := h.prepareTemplPageData(r, "New Image Build", "image-builder")
		h.renderTempl(w, r, ibtpl.NewBuild(ibtpl.NewBuildData{
			PageData: pageData,
			Error:    "Tag and Dockerfile are required.",
		}))
		return
	}

	tags := []string{tag}
	userID := h.imageBuilderUserUUID(r)

	if _, err := svc.StartBuild(r.Context(), imagebuildersvc.StartBuildOptions{
		HostID:      hostID,
		Name:        name,
		Tags:        tags,
		Dockerfile:  dockerfile,
		ContextPath: contextPath,
		NoCache:     noCache,
		Pull:        pull,
		Platform:    platform,
		Target:      target,
		UserID:      userID,
	}); err != nil {
		pageData := h.prepareTemplPageData(r, "New Image Build", "image-builder")
		h.renderTempl(w, r, ibtpl.NewBuild(ibtpl.NewBuildData{
			PageData: pageData,
			Error:    "Failed to start build: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/image-builder", http.StatusSeeOther)
}

// ============================================================================
// Templates
// ============================================================================

// ImageBuilderTemplateListTempl renders the Dockerfile templates page.
func (h *Handler) ImageBuilderTemplateListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireImageBuilderSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getIBHostID(r)
	pageData := h.prepareTemplPageData(r, "Dockerfile Templates", "image-builder")

	templates, err := svc.ListTemplates(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load templates: "+err.Error())
		return
	}

	views := make([]ibtpl.TemplateView, 0, len(templates))
	for _, t := range templates {
		views = append(views, ibtpl.TemplateView{
			ID:          t.ID.String(),
			Name:        t.Name,
			Description: t.Description,
			Category:    t.Category,
			IsBuiltin:   t.IsBuiltin,
			CreatedAt:   t.CreatedAt.Format("2006-01-02 15:04"),
		})
	}

	data := ibtpl.TemplateListData{
		PageData:  pageData,
		Templates: views,
	}

	h.renderTempl(w, r, ibtpl.TemplateList(data))
}

// ImageBuilderTemplateNewTempl renders the new template form.
func (h *Handler) ImageBuilderTemplateNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireImageBuilderSvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New Dockerfile Template", "image-builder")
	h.renderTempl(w, r, ibtpl.TemplateNew(ibtpl.TemplateNewData{PageData: pageData}))
}

// ImageBuilderTemplateCreateTempl handles POST /image-builder/templates.
func (h *Handler) ImageBuilderTemplateCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireImageBuilderSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	hostID := h.getIBHostID(r)
	name := r.FormValue("name")
	description := r.FormValue("description")
	category := r.FormValue("category")
	dockerfile := r.FormValue("dockerfile")
	userID := h.imageBuilderUserUUID(r)

	if name == "" || dockerfile == "" {
		pageData := h.prepareTemplPageData(r, "New Dockerfile Template", "image-builder")
		h.renderTempl(w, r, ibtpl.TemplateNew(ibtpl.TemplateNewData{
			PageData: pageData,
			Error:    "Name and Dockerfile are required.",
		}))
		return
	}

	if _, err := svc.CreateTemplate(r.Context(), hostID, name, description, category, dockerfile, userID); err != nil {
		pageData := h.prepareTemplPageData(r, "New Dockerfile Template", "image-builder")
		h.renderTempl(w, r, ibtpl.TemplateNew(ibtpl.TemplateNewData{
			PageData: pageData,
			Error:    "Failed to create template: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/image-builder/templates", http.StatusSeeOther)
}

// ImageBuilderTemplateDeleteTempl handles POST /image-builder/templates/{id}/delete.
// Built-in templates surface a 403 instead of being removed.
func (h *Handler) ImageBuilderTemplateDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireImageBuilderSvc(w, r)
	if svc == nil {
		return
	}

	tplID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := svc.DeleteTemplate(r.Context(), tplID); err != nil {
		status := http.StatusInternalServerError
		if stderrors.Is(err, imagebuildersvc.ErrBuiltinDelete) {
			status = http.StatusForbidden
		}
		h.RenderErrorTempl(w, r, status, "Error", "Failed to delete template: "+err.Error())
		return
	}

	http.Redirect(w, r, "/image-builder/templates", http.StatusSeeOther)
}

// ============================================================================
// Helpers
// ============================================================================

func buildJobToView(b models.ImageBuildJob) ibtpl.BuildView {
	view := ibtpl.BuildView{
		ID:           b.ID.String(),
		Name:         b.Name,
		Tags:         b.Tags,
		Status:       string(b.Status),
		Platform:     b.Platform,
		ImageID:      b.ImageID,
		ImageSize:    formatBytes(b.ImageSize),
		DurationMs:   b.DurationMs,
		ErrorMessage: b.ErrorMessage,
		Output:       b.Output,
		Signed:       b.Signed,
		SignatureRef: b.SignatureRef,
		CreatedAt:    b.CreatedAt.Format("2006-01-02 15:04"),
	}
	if b.CompletedAt != nil {
		view.CompletedAt = b.CompletedAt.Format("2006-01-02 15:04")
	}
	return view
}
