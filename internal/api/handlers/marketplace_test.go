// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"context"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	marketplacesvc "github.com/fr4nsys/usulnet/internal/services/marketplace"
)

// fakeMarketplaceSvc is a minimal MarketplaceService stub. Only the
// methods exercised by the handler are filled in; everything else
// returns nil so callers can opt into the behavior they care about.
type fakeMarketplaceSvc struct {
	searchApps    []*models.MarketplaceApp
	searchTotal   int
	getAppBySlug  *models.MarketplaceApp
	getAppErr     error
	installInst   *models.MarketplaceInstallation
	installErr    error
	uninstallErr  error
	reviews       []*models.MarketplaceReview
	addReviewCall *models.MarketplaceReview
	listFeatured  []*models.MarketplaceApp
}

func (f *fakeMarketplaceSvc) SearchApps(_ context.Context, _, _ string, _, _ int) ([]*models.MarketplaceApp, int, error) {
	return f.searchApps, f.searchTotal, nil
}

func (f *fakeMarketplaceSvc) GetApp(_ context.Context, _ uuid.UUID) (*models.MarketplaceApp, error) {
	return f.getAppBySlug, f.getAppErr
}

func (f *fakeMarketplaceSvc) GetAppBySlug(_ context.Context, _ string) (*models.MarketplaceApp, error) {
	return f.getAppBySlug, f.getAppErr
}

func (f *fakeMarketplaceSvc) ListFeatured(_ context.Context, _ int) ([]*models.MarketplaceApp, error) {
	return f.listFeatured, nil
}

func (f *fakeMarketplaceSvc) InstallApp(_ context.Context, _, _ uuid.UUID, _ marketplacesvc.InstallOptions) (*models.MarketplaceInstallation, error) {
	if f.installErr != nil {
		return nil, f.installErr
	}
	return f.installInst, nil
}

func (f *fakeMarketplaceSvc) ListInstallations(_ context.Context, _ uuid.UUID, _, _ int) ([]*models.MarketplaceInstallation, int, error) {
	if f.installInst == nil {
		return nil, 0, nil
	}
	return []*models.MarketplaceInstallation{f.installInst}, 1, nil
}

func (f *fakeMarketplaceSvc) GetInstallation(_ context.Context, _ uuid.UUID) (*models.MarketplaceInstallation, error) {
	if f.installInst == nil {
		return nil, marketplacesvc.ErrAppNotFound
	}
	return f.installInst, nil
}

func (f *fakeMarketplaceSvc) UninstallApp(_ context.Context, _ uuid.UUID) error {
	return f.uninstallErr
}

func (f *fakeMarketplaceSvc) AddReview(_ context.Context, r *models.MarketplaceReview) error {
	f.addReviewCall = r
	return nil
}

func (f *fakeMarketplaceSvc) ListReviews(_ context.Context, _ uuid.UUID) ([]*models.MarketplaceReview, error) {
	return f.reviews, nil
}

func newTestMarketplaceHandler(svc MarketplaceService) *MarketplaceHandler {
	hostID := uuid.New()
	return NewMarketplaceHandler(svc, func(_ *http.Request) uuid.UUID { return hostID }, logger.Nop())
}

// requestWithSlug sets the chi URL param "slug" so handler methods can
// pull it via chi.URLParam without spinning up a full router (which
// would also apply RequireViewer etc.).
func requestWithSlug(method, target, slug, body string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, http.NoBody)
	}
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	if slug != "" {
		rctx.URLParams.Add("slug", slug)
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func requestWithID(method, target, id, body string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, http.NoBody)
	}
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	if id != "" {
		rctx.URLParams.Add("id", id)
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestMarketplaceHandler_ServiceUnavailableWhenSvcNil(t *testing.T) {
	h := NewMarketplaceHandler(nil, nil, logger.Nop())
	w := httptest.NewRecorder()
	h.ListApps(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil service: got %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestMarketplaceHandler_ListApps(t *testing.T) {
	id := uuid.New()
	svc := &fakeMarketplaceSvc{
		searchApps:  []*models.MarketplaceApp{{ID: id, Slug: "alpha", Name: "Alpha", Category: models.MarketplaceAppCategoryOther}},
		searchTotal: 1,
	}
	h := newTestMarketplaceHandler(svc)
	w := httptest.NewRecorder()
	h.ListApps(w, httptest.NewRequest(http.MethodGet, "/?q=al", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ListApps: status %d, body %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"slug":"alpha"`) {
		t.Errorf("response missing slug: %s", w.Body.String())
	}
}

func TestMarketplaceHandler_GetApp_NotFound(t *testing.T) {
	svc := &fakeMarketplaceSvc{getAppErr: marketplacesvc.ErrAppNotFound}
	h := newTestMarketplaceHandler(svc)
	w := httptest.NewRecorder()
	h.GetApp(w, requestWithSlug(http.MethodGet, "/missing", "missing", ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("GetApp missing: got %d, body %s", w.Code, w.Body.String())
	}
}

func TestMarketplaceHandler_GetApp_OK(t *testing.T) {
	id := uuid.New()
	svc := &fakeMarketplaceSvc{getAppBySlug: &models.MarketplaceApp{ID: id, Slug: "alpha", Name: "Alpha"}}
	h := newTestMarketplaceHandler(svc)
	w := httptest.NewRecorder()
	h.GetApp(w, requestWithSlug(http.MethodGet, "/alpha", "alpha", ""))
	if w.Code != http.StatusOK {
		t.Errorf("GetApp: got %d, body %s", w.Code, w.Body.String())
	}
}

func TestMarketplaceHandler_ListFeatured(t *testing.T) {
	svc := &fakeMarketplaceSvc{listFeatured: []*models.MarketplaceApp{{Slug: "alpha", Name: "Alpha", Featured: true}}}
	h := newTestMarketplaceHandler(svc)
	w := httptest.NewRecorder()
	h.ListFeatured(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("ListFeatured: got %d, body %s", w.Code, w.Body.String())
	}
}

func TestMarketplaceHandler_Install_StackRequired(t *testing.T) {
	id := uuid.New()
	svc := &fakeMarketplaceSvc{
		getAppBySlug: &models.MarketplaceApp{ID: id, Slug: "alpha", Name: "Alpha"},
		installErr:   marketplacesvc.ErrStackRequired,
	}
	h := newTestMarketplaceHandler(svc)
	w := httptest.NewRecorder()
	h.InstallApp(w, requestWithSlug(http.MethodPost, "/alpha/install", "alpha", `{}`))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Install: got %d, body %s", w.Code, w.Body.String())
	}
}

func TestMarketplaceHandler_Install_OK(t *testing.T) {
	appID := uuid.New()
	instID := uuid.New()
	stackID := uuid.New()
	svc := &fakeMarketplaceSvc{
		getAppBySlug: &models.MarketplaceApp{ID: appID, Slug: "alpha", Name: "Alpha"},
		installInst: &models.MarketplaceInstallation{
			ID: instID, AppID: appID, StackID: &stackID,
			Status: models.MarketplaceInstallationStatusInstalled,
		},
	}
	h := newTestMarketplaceHandler(svc)
	w := httptest.NewRecorder()
	h.InstallApp(w, requestWithSlug(http.MethodPost, "/alpha/install", "alpha", `{}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("Install: got %d, body %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), stackID.String()) {
		t.Errorf("response missing stack_id: %s", w.Body.String())
	}
}

func TestMarketplaceHandler_Uninstall(t *testing.T) {
	svc := &fakeMarketplaceSvc{}
	h := newTestMarketplaceHandler(svc)
	w := httptest.NewRecorder()
	h.Uninstall(w, requestWithID(http.MethodPost, "/installations/x/uninstall", uuid.New().String(), ""))
	if w.Code != http.StatusNoContent {
		t.Errorf("Uninstall: got %d, body %s", w.Code, w.Body.String())
	}
}

func TestMarketplaceHandler_ListReviews(t *testing.T) {
	appID := uuid.New()
	svc := &fakeMarketplaceSvc{
		getAppBySlug: &models.MarketplaceApp{ID: appID, Slug: "alpha"},
		reviews: []*models.MarketplaceReview{
			{ID: uuid.New(), AppID: appID, UserID: uuid.New(), Rating: 4, Title: "good"},
		},
	}
	h := newTestMarketplaceHandler(svc)
	w := httptest.NewRecorder()
	h.ListReviews(w, requestWithSlug(http.MethodGet, "/alpha/reviews", "alpha", ""))
	if w.Code != http.StatusOK {
		t.Errorf("ListReviews: got %d, body %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"rating":4`) {
		t.Errorf("response missing rating: %s", w.Body.String())
	}
}

func TestMarketplaceHandler_Install_AppNotFound(t *testing.T) {
	svc := &fakeMarketplaceSvc{getAppErr: marketplacesvc.ErrAppNotFound}
	h := newTestMarketplaceHandler(svc)
	w := httptest.NewRecorder()
	h.InstallApp(w, requestWithSlug(http.MethodPost, "/missing/install", "missing", `{}`))
	if w.Code != http.StatusNotFound {
		t.Errorf("Install missing: got %d, body %s", w.Code, w.Body.String())
	}
}

func TestMapMarketplaceError(t *testing.T) {
	cases := []struct {
		in   error
		want string
	}{
		{marketplacesvc.ErrAppNotFound, "not found"},
		{marketplacesvc.ErrInvalidInput, "invalid"},
		{marketplacesvc.ErrStackRequired, "stack service"},
	}
	for _, c := range cases {
		out := mapMarketplaceError(c.in)
		if out == nil {
			t.Errorf("mapMarketplaceError(%v): got nil", c.in)
			continue
		}
		if !strings.Contains(strings.ToLower(out.Error()), c.want) {
			t.Errorf("mapMarketplaceError(%v) = %q, want substring %q", c.in, out.Error(), c.want)
		}
	}
	if mapMarketplaceError(stderrors.New("other")) == nil {
		t.Error("mapMarketplaceError(other): want pass-through, got nil")
	}
}
