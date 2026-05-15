// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	stderrors "errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	marketplacesvc "github.com/fr4nsys/usulnet/internal/services/marketplace"
	mktpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/marketplace"
)

// requireMarketplaceSvc returns the marketplace service or renders a
// "not configured" page.
func (h *Handler) requireMarketplaceSvc(w http.ResponseWriter, r *http.Request) *marketplacesvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.marketplaceSvc != nil {
		return reg.marketplaceSvc
	}
	h.RenderErrorTempl(w, r, http.StatusServiceUnavailable,
		"Marketplace Not Configured",
		"The marketplace service is not enabled in this build.")
	return nil
}

func (h *Handler) marketplaceHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

func (h *Handler) marketplaceUserUUID(r *http.Request) *uuid.UUID {
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

func (h *Handler) marketplaceUserName(r *http.Request) string {
	user := h.getUserData(r)
	if user == nil {
		return "Anonymous"
	}
	if user.Username != "" {
		return user.Username
	}
	return user.ID
}

// marketplaceCategories matches models.MarketplaceAppCategory.
var marketplaceCategories = []string{
	"networking", "storage", "development", "monitoring",
	"security", "communication", "productivity", "database", "other",
}

// ============================================================================
// Browse
// ============================================================================

// MarketplaceListTempl renders the marketplace browse page.
func (h *Handler) MarketplaceListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Marketplace", "marketplace")

	query := r.URL.Query().Get("q")
	category := r.URL.Query().Get("category")
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	pageSize := 24
	offset := (page - 1) * pageSize

	apps, total, err := svc.SearchApps(ctx, query, category, pageSize, offset)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load apps: "+err.Error())
		return
	}

	var featured []mktpl.AppView
	if query == "" && category == "" {
		featuredApps, _ := svc.ListFeatured(ctx, 3)
		for _, a := range featuredApps {
			featured = append(featured, marketplaceAppToView(a))
		}
	}

	views := make([]mktpl.AppView, 0, len(apps))
	for _, a := range apps {
		views = append(views, marketplaceAppToView(a))
	}

	data := mktpl.ListData{
		PageData:   pageData,
		Featured:   featured,
		Apps:       views,
		Categories: marketplaceCategories,
		Query:      query,
		Category:   category,
		Total:      total,
	}
	_ = mktpl.List(data).Render(ctx, w)
}

// ============================================================================
// App Detail
// ============================================================================

// MarketplaceDetailTempl renders the app detail page.
func (h *Handler) MarketplaceDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	slug := chi.URLParam(r, "slug")

	app, err := svc.GetAppBySlug(ctx, slug)
	if err != nil {
		if stderrors.Is(err, marketplacesvc.ErrAppNotFound) {
			h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "App not found.")
			return
		}
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", err.Error())
		return
	}

	pageData := h.prepareTemplPageData(r, app.Name, "marketplace")

	reviews, _ := svc.ListReviews(ctx, app.ID)
	reviewViews := make([]mktpl.ReviewView, 0, len(reviews))
	for _, rv := range reviews {
		reviewViews = append(reviewViews, marketplaceReviewToView(rv, h.marketplaceUserName(r)))
	}

	data := mktpl.DetailData{
		PageData: pageData,
		App: mktpl.AppDetailView{
			AppView:         marketplaceAppToView(app),
			LongDescription: app.LongDescription,
			ComposeTemplate: app.ComposeTemplate,
			Website:         app.Website,
			Source:          app.Source,
			License:         app.License,
			MinMemoryMB:     app.MinMemoryMB,
			MinCPUCores:     app.MinCPUCores,
			Tags:            app.Tags,
		},
		Reviews: reviewViews,
	}
	_ = mktpl.Detail(data).Render(ctx, w)
}

// ============================================================================
// Install
// ============================================================================

// MarketplaceInstallTempl renders the per-app install form.
func (h *Handler) MarketplaceInstallTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	slug := chi.URLParam(r, "slug")

	app, err := svc.GetAppBySlug(r.Context(), slug)
	if err != nil {
		if stderrors.Is(err, marketplacesvc.ErrAppNotFound) {
			h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "App not found.")
			return
		}
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", err.Error())
		return
	}

	pageData := h.prepareTemplPageData(r, "Install "+app.Name, "marketplace")

	fields := marketplaceFieldsToViews(app)

	data := mktpl.InstallData{
		PageData: pageData,
		App:      marketplaceAppToView(app),
		Fields:   fields,
	}
	_ = mktpl.Install(data).Render(r.Context(), w)
}

// MarketplaceInstallCreateTempl handles the install form submission.
func (h *Handler) MarketplaceInstallCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/marketplace", http.StatusSeeOther)
		return
	}

	slug := chi.URLParam(r, "slug")
	app, err := svc.GetAppBySlug(r.Context(), slug)
	if err != nil {
		http.Redirect(w, r, "/marketplace", http.StatusSeeOther)
		return
	}

	hostID := h.marketplaceHostID(r)
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = app.Slug
	}

	configValues := make(map[string]string)
	for key, values := range r.Form {
		if strings.HasPrefix(key, "field_") && len(values) > 0 {
			configValues[strings.TrimPrefix(key, "field_")] = values[0]
		}
	}

	opts := marketplacesvc.InstallOptions{
		Name:         name,
		ConfigValues: configValues,
		UserID:       h.marketplaceUserUUID(r),
	}
	if _, err := svc.InstallApp(r.Context(), app.ID, hostID, opts); err != nil {
		// Re-render the install form with the error so the user keeps
		// their input. The previous form values are not yet
		// re-populated; matching v26.2.7 behavior for now.
		fields := marketplaceFieldsToViews(app)
		pageData := h.prepareTemplPageData(r, "Install "+app.Name, "marketplace")
		_ = mktpl.Install(mktpl.InstallData{
			PageData: pageData,
			App:      marketplaceAppToView(app),
			Fields:   fields,
			Error:    err.Error(),
		}).Render(r.Context(), w)
		return
	}

	http.Redirect(w, r, "/marketplace/installed", http.StatusSeeOther)
}

// ============================================================================
// Installed
// ============================================================================

// MarketplaceInstalledTempl renders the installed apps page.
func (h *Handler) MarketplaceInstalledTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.marketplaceHostID(r)
	pageData := h.prepareTemplPageData(r, "Installed Apps", "marketplace")

	installations, total, err := svc.ListInstallations(ctx, hostID, 100, 0)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load installations: "+err.Error())
		return
	}

	views := make([]mktpl.InstallationView, 0, len(installations))
	for _, inst := range installations {
		v := mktpl.InstallationView{
			ID:          inst.ID.String(),
			Name:        inst.Name,
			Status:      string(inst.Status),
			Version:     inst.Version,
			InstalledAt: inst.InstalledAt.Format("2006-01-02 15:04"),
		}
		if inst.StackID != nil {
			v.StackID = inst.StackID.String()
		}
		if app, err := svc.GetApp(ctx, inst.AppID); err == nil {
			v.AppName = app.Name
			v.AppSlug = app.Slug
			v.AppIcon = app.Icon
			v.AppIconColor = app.IconColor
		}
		views = append(views, v)
	}

	data := mktpl.InstalledData{
		PageData:      pageData,
		Installations: views,
		Total:         total,
	}
	_ = mktpl.Installed(data).Render(ctx, w)
}

// MarketplaceUninstallTempl handles uninstalling an app.
func (h *Handler) MarketplaceUninstallTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Redirect(w, r, "/marketplace/installed", http.StatusSeeOther)
		return
	}
	_ = svc.UninstallApp(r.Context(), id)
	http.Redirect(w, r, "/marketplace/installed", http.StatusSeeOther)
}

// ============================================================================
// Submit App
// ============================================================================

// MarketplaceSubmitTempl renders the submit app form.
func (h *Handler) MarketplaceSubmitTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "Submit App", "marketplace")
	data := mktpl.SubmitData{
		PageData:   pageData,
		Categories: marketplaceCategories,
	}
	_ = mktpl.Submit(data).Render(r.Context(), w)
}

// MarketplaceSubmitCreateTempl handles the submit app form submission.
func (h *Handler) MarketplaceSubmitCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/marketplace", http.StatusSeeOther)
		return
	}

	var tags []string
	if t := r.FormValue("tags"); t != "" {
		for _, tag := range strings.Split(t, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				tags = append(tags, tag)
			}
		}
	}

	app := &models.MarketplaceApp{
		Name:            strings.TrimSpace(r.FormValue("name")),
		Description:     strings.TrimSpace(r.FormValue("description")),
		LongDescription: strings.TrimSpace(r.FormValue("long_description")),
		Category:        models.MarketplaceAppCategory(r.FormValue("category")),
		ComposeTemplate: r.FormValue("compose_template"),
		Version:         strings.TrimSpace(r.FormValue("version")),
		License:         strings.TrimSpace(r.FormValue("license")),
		Website:         strings.TrimSpace(r.FormValue("website")),
		Source:          strings.TrimSpace(r.FormValue("source")),
		Tags:            tags,
		CreatedBy:       h.marketplaceUserUUID(r),
	}

	if err := svc.CreateApp(r.Context(), app); err != nil {
		pageData := h.prepareTemplPageData(r, "Submit App", "marketplace")
		_ = mktpl.Submit(mktpl.SubmitData{
			PageData:   pageData,
			Categories: marketplaceCategories,
			Error:      err.Error(),
		}).Render(r.Context(), w)
		return
	}

	http.Redirect(w, r, "/marketplace/"+app.Slug, http.StatusSeeOther)
}

// ============================================================================
// Reviews
// ============================================================================

// MarketplaceReviewTempl renders the leave-a-review form.
func (h *Handler) MarketplaceReviewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	slug := chi.URLParam(r, "slug")
	app, err := svc.GetAppBySlug(r.Context(), slug)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "App not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Review "+app.Name, "marketplace")
	data := mktpl.ReviewFormData{
		PageData: pageData,
		App:      marketplaceAppToView(app),
	}
	_ = mktpl.Review(data).Render(r.Context(), w)
}

// MarketplaceReviewCreateTempl handles the review form submission.
func (h *Handler) MarketplaceReviewCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/marketplace", http.StatusSeeOther)
		return
	}
	slug := chi.URLParam(r, "slug")
	app, err := svc.GetAppBySlug(r.Context(), slug)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "App not found.")
		return
	}
	userID := h.marketplaceUserUUID(r)
	if userID == nil {
		h.RenderErrorTempl(w, r, http.StatusUnauthorized, "Sign-in required", "You must sign in to review apps.")
		return
	}
	rating, _ := strconv.Atoi(r.FormValue("rating"))
	review := &models.MarketplaceReview{
		AppID:   app.ID,
		UserID:  *userID,
		Rating:  rating,
		Title:   strings.TrimSpace(r.FormValue("title")),
		Comment: strings.TrimSpace(r.FormValue("comment")),
	}
	if err := svc.AddReview(r.Context(), review); err != nil {
		pageData := h.prepareTemplPageData(r, "Review "+app.Name, "marketplace")
		_ = mktpl.Review(mktpl.ReviewFormData{
			PageData: pageData,
			App:      marketplaceAppToView(app),
			Error:    err.Error(),
		}).Render(r.Context(), w)
		return
	}
	http.Redirect(w, r, "/marketplace/"+app.Slug, http.StatusSeeOther)
}

// ============================================================================
// View adapters
// ============================================================================

func marketplaceAppToView(a *models.MarketplaceApp) mktpl.AppView {
	return mktpl.AppView{
		ID:           a.ID.String(),
		Slug:         a.Slug,
		Name:         a.Name,
		Description:  a.Description,
		Icon:         a.Icon,
		IconColor:    a.IconColor,
		IconSVG:      a.IconSVG,
		Category:     string(a.Category),
		Version:      a.Version,
		Author:       a.Author,
		IsOfficial:   a.IsOfficial,
		IsVerified:   a.IsVerified,
		BuiltIn:      a.BuiltIn,
		InstallCount: a.InstallCount,
		AvgRating:    a.AvgRating,
		RatingCount:  a.RatingCount,
	}
}

func marketplaceReviewToView(rv *models.MarketplaceReview, fallbackName string) mktpl.ReviewView {
	return mktpl.ReviewView{
		ID:        rv.ID.String(),
		UserName:  fallbackName,
		Rating:    rv.Rating,
		Title:     rv.Title,
		Comment:   rv.Comment,
		CreatedAt: rv.CreatedAt.Format("2006-01-02"),
	}
}

func marketplaceFieldsToViews(app *models.MarketplaceApp) []mktpl.FieldView {
	if app.Fields == nil {
		return nil
	}
	var mFields []models.MarketplaceField
	if err := json.Unmarshal(app.Fields, &mFields); err != nil {
		return nil
	}
	out := make([]mktpl.FieldView, 0, len(mFields))
	for _, f := range mFields {
		out = append(out, mktpl.FieldView{
			Key:         f.Key,
			Label:       f.Label,
			Description: f.Description,
			Type:        f.Type,
			Default:     f.Default,
			Required:    f.Required,
			Options:     f.Options,
			Placeholder: f.Placeholder,
		})
	}
	return out
}
