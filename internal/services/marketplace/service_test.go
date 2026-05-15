// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package marketplace

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ----------------------------------------------------------------------------
// In-memory repositories
// ----------------------------------------------------------------------------

type memAppRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*models.MarketplaceApp
	slug map[string]uuid.UUID
}

func newMemAppRepo() *memAppRepo {
	return &memAppRepo{
		rows: make(map[uuid.UUID]*models.MarketplaceApp),
		slug: make(map[string]uuid.UUID),
	}
}

func (m *memAppRepo) Create(ctx context.Context, app *models.MarketplaceApp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if app.ID == uuid.Nil {
		app.ID = uuid.New()
	}
	clone := *app
	m.rows[app.ID] = &clone
	m.slug[app.Slug] = app.ID
	return nil
}

func (m *memAppRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.MarketplaceApp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	app, ok := m.rows[id]
	if !ok {
		return nil, stderrors.New("marketplace_app not found")
	}
	clone := *app
	return &clone, nil
}

func (m *memAppRepo) GetBySlug(ctx context.Context, slug string) (*models.MarketplaceApp, error) {
	m.mu.Lock()
	id, ok := m.slug[slug]
	m.mu.Unlock()
	if !ok {
		return nil, stderrors.New("marketplace_app not found")
	}
	return m.GetByID(ctx, id)
}

func (m *memAppRepo) Search(ctx context.Context, query string, category string, limit, offset int) ([]*models.MarketplaceApp, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.MarketplaceApp
	for _, a := range m.rows {
		if query != "" && !strings.Contains(strings.ToLower(a.Name), strings.ToLower(query)) &&
			!strings.Contains(strings.ToLower(a.Description), strings.ToLower(query)) {
			continue
		}
		if category != "" && string(a.Category) != category {
			continue
		}
		clone := *a
		out = append(out, &clone)
	}
	total := len(out)
	if offset > len(out) {
		offset = len(out)
	}
	out = out[offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, total, nil
}

func (m *memAppRepo) ListFeatured(ctx context.Context, limit int) ([]*models.MarketplaceApp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.MarketplaceApp
	for _, a := range m.rows {
		if !a.Featured {
			continue
		}
		clone := *a
		out = append(out, &clone)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *memAppRepo) ListByCategory(ctx context.Context, category string, limit, offset int) ([]*models.MarketplaceApp, int, error) {
	return m.Search(ctx, "", category, limit, offset)
}

func (m *memAppRepo) Update(ctx context.Context, app *models.MarketplaceApp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[app.ID]; !ok {
		return stderrors.New("marketplace_app not found")
	}
	clone := *app
	m.rows[app.ID] = &clone
	m.slug[app.Slug] = app.ID
	return nil
}

func (m *memAppRepo) Delete(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	app, ok := m.rows[id]
	if !ok {
		return stderrors.New("marketplace_app not found")
	}
	delete(m.rows, id)
	delete(m.slug, app.Slug)
	return nil
}

func (m *memAppRepo) IncrementInstallCount(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	app, ok := m.rows[id]
	if !ok {
		return stderrors.New("marketplace_app not found")
	}
	app.InstallCount++
	return nil
}

func (m *memAppRepo) UpdateRating(ctx context.Context, id uuid.UUID) error {
	return nil
}

type memInstallRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*models.MarketplaceInstallation
}

func newMemInstallRepo() *memInstallRepo {
	return &memInstallRepo{rows: make(map[uuid.UUID]*models.MarketplaceInstallation)}
}

func (m *memInstallRepo) Create(ctx context.Context, inst *models.MarketplaceInstallation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if inst.ID == uuid.Nil {
		inst.ID = uuid.New()
	}
	clone := *inst
	m.rows[inst.ID] = &clone
	return nil
}

func (m *memInstallRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.MarketplaceInstallation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.rows[id]
	if !ok {
		return nil, stderrors.New("marketplace_installation not found")
	}
	clone := *inst
	return &clone, nil
}

func (m *memInstallRepo) ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.MarketplaceInstallation, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.MarketplaceInstallation
	for _, inst := range m.rows {
		if inst.HostID == hostID {
			clone := *inst
			out = append(out, &clone)
		}
	}
	total := len(out)
	if offset > len(out) {
		offset = len(out)
	}
	out = out[offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, total, nil
}

func (m *memInstallRepo) ListByApp(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceInstallation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.MarketplaceInstallation
	for _, inst := range m.rows {
		if inst.AppID == appID {
			clone := *inst
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (m *memInstallRepo) Update(ctx context.Context, inst *models.MarketplaceInstallation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[inst.ID]; !ok {
		return stderrors.New("marketplace_installation not found")
	}
	clone := *inst
	m.rows[inst.ID] = &clone
	return nil
}

func (m *memInstallRepo) Delete(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, id)
	return nil
}

type memReviewRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*models.MarketplaceReview
	pair map[string]uuid.UUID // user_id|app_id -> row id
}

func newMemReviewRepo() *memReviewRepo {
	return &memReviewRepo{
		rows: make(map[uuid.UUID]*models.MarketplaceReview),
		pair: make(map[string]uuid.UUID),
	}
}

func (m *memReviewRepo) Upsert(ctx context.Context, r *models.MarketplaceReview) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := r.UserID.String() + "|" + r.AppID.String()
	if existingID, ok := m.pair[key]; ok {
		existing := m.rows[existingID]
		existing.Rating = r.Rating
		existing.Title = r.Title
		existing.Comment = r.Comment
		return nil
	}
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	clone := *r
	m.rows[r.ID] = &clone
	m.pair[key] = r.ID
	return nil
}

func (m *memReviewRepo) ListByApp(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceReview, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.MarketplaceReview
	for _, r := range m.rows {
		if r.AppID == appID {
			clone := *r
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (m *memReviewRepo) GetByUserAndApp(ctx context.Context, userID, appID uuid.UUID) (*models.MarketplaceReview, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.pair[userID.String()+"|"+appID.String()]
	if !ok {
		return nil, stderrors.New("marketplace_review not found")
	}
	clone := *m.rows[id]
	return &clone, nil
}

func (m *memReviewRepo) Delete(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok {
		return nil
	}
	delete(m.rows, id)
	delete(m.pair, r.UserID.String()+"|"+r.AppID.String())
	return nil
}

// ----------------------------------------------------------------------------
// Mock stack installer
// ----------------------------------------------------------------------------

type fakeStackInstaller struct {
	mu      sync.Mutex
	calls   int
	last    *models.CreateStackInput
	lastHID uuid.UUID
	fail    error
}

func (f *fakeStackInstaller) Create(ctx context.Context, hostID uuid.UUID, input *models.CreateStackInput) (*models.Stack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.last = input
	f.lastHID = hostID
	if f.fail != nil {
		return nil, f.fail
	}
	return &models.Stack{ID: uuid.New(), HostID: hostID, Name: input.Name, ComposeFile: input.ComposeFile}, nil
}

// ----------------------------------------------------------------------------
// Static catalog used by hydration tests
// ----------------------------------------------------------------------------

type fakeCatalog struct {
	entries []CatalogEntry
	calls   int
	err     error
}

func (f *fakeCatalog) Load() ([]CatalogEntry, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.entries, nil
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

func TestService_HydrateCatalog_InsertsAllEntries(t *testing.T) {
	apps := newMemAppRepo()
	cat := &fakeCatalog{entries: []CatalogEntry{
		{Slug: "alpha", Name: "Alpha", Description: "d", Category: "other", License: "MIT", Compose: "services: {}", ManifestVersion: 1},
		{Slug: "beta", Name: "Beta", Description: "d", Category: "other", License: "MIT", Compose: "services: {}", ManifestVersion: 1},
	}}
	svc := NewService(apps, newMemInstallRepo(), newMemReviewRepo(), &fakeStackInstaller{}, cat, nil)

	if err := svc.HydrateCatalog(context.Background()); err != nil {
		t.Fatalf("HydrateCatalog: %v", err)
	}
	if got := len(apps.rows); got != 2 {
		t.Errorf("rows: got %d, want 2", got)
	}
	for _, row := range apps.rows {
		if !row.BuiltIn {
			t.Errorf("row %q: built_in must be true", row.Slug)
		}
	}
}

func TestService_HydrateCatalog_Idempotent(t *testing.T) {
	apps := newMemAppRepo()
	cat := &fakeCatalog{entries: []CatalogEntry{
		{Slug: "alpha", Name: "Alpha", Description: "d", Category: "other", License: "MIT", Compose: "x", ManifestVersion: 1},
	}}
	svc := NewService(apps, newMemInstallRepo(), newMemReviewRepo(), &fakeStackInstaller{}, cat, nil)

	for i := 0; i < 3; i++ {
		if err := svc.HydrateCatalog(context.Background()); err != nil {
			t.Fatalf("HydrateCatalog #%d: %v", i, err)
		}
	}
	if got := len(apps.rows); got != 1 {
		t.Errorf("rows: got %d, want 1 after 3 hydrations", got)
	}
}

func TestService_HydrateCatalog_UpdatesOnManifestBump(t *testing.T) {
	apps := newMemAppRepo()
	cat := &fakeCatalog{entries: []CatalogEntry{
		{Slug: "alpha", Name: "Alpha v1", Description: "d", Category: "other", License: "MIT", Compose: "v1", ManifestVersion: 1},
	}}
	svc := NewService(apps, newMemInstallRepo(), newMemReviewRepo(), &fakeStackInstaller{}, cat, nil)
	if err := svc.HydrateCatalog(context.Background()); err != nil {
		t.Fatalf("first hydrate: %v", err)
	}
	// Inflate the install count so we can verify the merge keeps it.
	for _, row := range apps.rows {
		row.InstallCount = 42
	}

	cat.entries[0].Name = "Alpha v2"
	cat.entries[0].Compose = "v2"
	cat.entries[0].ManifestVersion = 2
	if err := svc.HydrateCatalog(context.Background()); err != nil {
		t.Fatalf("second hydrate: %v", err)
	}
	if got := len(apps.rows); got != 1 {
		t.Errorf("rows: got %d, want 1", got)
	}
	for _, row := range apps.rows {
		if row.Name != "Alpha v2" || row.ComposeTemplate != "v2" {
			t.Errorf("manifest not refreshed: %+v", row)
		}
		if row.InstallCount != 42 {
			t.Errorf("install_count clobbered: got %d, want 42", row.InstallCount)
		}
	}
}

func TestService_HydrateCatalog_RespectsUserSubmitted(t *testing.T) {
	apps := newMemAppRepo()
	user := &models.MarketplaceApp{
		ID: uuid.New(), Slug: "alpha", Name: "User-submitted", Description: "ud", Category: "other",
		ComposeTemplate: "user", BuiltIn: false, ManifestVersion: 1,
	}
	_ = apps.Create(context.Background(), user)

	cat := &fakeCatalog{entries: []CatalogEntry{
		{Slug: "alpha", Name: "Built-in", Description: "d", Category: "other", License: "MIT", Compose: "builtin", ManifestVersion: 5},
	}}
	svc := NewService(apps, newMemInstallRepo(), newMemReviewRepo(), &fakeStackInstaller{}, cat, nil)
	if err := svc.HydrateCatalog(context.Background()); err != nil {
		t.Fatalf("HydrateCatalog: %v", err)
	}
	row, _ := apps.GetBySlug(context.Background(), "alpha")
	if row.Name != "User-submitted" || row.BuiltIn {
		t.Errorf("user-submitted app was overwritten: %+v", row)
	}
}

func TestService_HydrateCatalog_NoSource(t *testing.T) {
	apps := newMemAppRepo()
	svc := NewService(apps, newMemInstallRepo(), newMemReviewRepo(), &fakeStackInstaller{}, nil, nil)
	if err := svc.HydrateCatalog(context.Background()); err != nil {
		t.Fatalf("expected nil-source hydrate to succeed, got %v", err)
	}
	if got := len(apps.rows); got != 0 {
		t.Errorf("rows: got %d, want 0", got)
	}
}

func TestService_GetAppBySlug(t *testing.T) {
	apps := newMemAppRepo()
	svc := NewService(apps, newMemInstallRepo(), newMemReviewRepo(), &fakeStackInstaller{}, nil, nil)
	_ = apps.Create(context.Background(), &models.MarketplaceApp{ID: uuid.New(), Slug: "found", Name: "Found"})

	if _, err := svc.GetAppBySlug(context.Background(), ""); err == nil {
		t.Error("expected error for empty slug")
	}
	if _, err := svc.GetAppBySlug(context.Background(), "missing"); !stderrors.Is(err, ErrAppNotFound) {
		t.Errorf("missing: expected ErrAppNotFound, got %v", err)
	}
	if _, err := svc.GetAppBySlug(context.Background(), "found"); err != nil {
		t.Errorf("found: unexpected error %v", err)
	}
}

func TestService_CreateApp_Validation(t *testing.T) {
	apps := newMemAppRepo()
	svc := NewService(apps, newMemInstallRepo(), newMemReviewRepo(), &fakeStackInstaller{}, nil, nil)

	cases := []struct {
		name string
		app  *models.MarketplaceApp
		ok   bool
	}{
		{"nil", nil, false},
		{"missing name", &models.MarketplaceApp{ComposeTemplate: "x"}, false},
		{"missing compose", &models.MarketplaceApp{Name: "X"}, false},
		{"invalid slug", &models.MarketplaceApp{Name: "X", Slug: "BAD SLUG", ComposeTemplate: "x"}, false},
		{"ok", &models.MarketplaceApp{Name: "Hello World", ComposeTemplate: "services: {}"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := svc.CreateApp(context.Background(), c.app)
			if c.ok && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !c.ok && err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestService_CreateApp_GeneratesSlug(t *testing.T) {
	apps := newMemAppRepo()
	svc := NewService(apps, newMemInstallRepo(), newMemReviewRepo(), &fakeStackInstaller{}, nil, nil)
	app := &models.MarketplaceApp{Name: "  My_App  ", ComposeTemplate: "x"}
	if err := svc.CreateApp(context.Background(), app); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	if app.Slug != "my-app" {
		t.Errorf("slug: got %q, want %q", app.Slug, "my-app")
	}
	if app.BuiltIn {
		t.Error("user-submitted apps must not be built_in")
	}
}

func TestService_DeleteApp_RefusesBuiltIn(t *testing.T) {
	apps := newMemAppRepo()
	svc := NewService(apps, newMemInstallRepo(), newMemReviewRepo(), &fakeStackInstaller{}, nil, nil)
	id := uuid.New()
	_ = apps.Create(context.Background(), &models.MarketplaceApp{ID: id, Slug: "x", Name: "X", BuiltIn: true})

	if err := svc.DeleteApp(context.Background(), id); err == nil {
		t.Error("expected error deleting built-in app")
	}
	if _, ok := apps.rows[id]; !ok {
		t.Error("row was deleted despite the error")
	}
}

func TestService_InstallApp(t *testing.T) {
	apps := newMemAppRepo()
	stacks := &fakeStackInstaller{}
	svc := NewService(apps, newMemInstallRepo(), newMemReviewRepo(), stacks, nil, nil)
	appID := uuid.New()
	_ = apps.Create(context.Background(), &models.MarketplaceApp{
		ID:              appID,
		Slug:            "alpha",
		Name:            "Alpha",
		Version:         "1.0",
		ComposeTemplate: "image: alpine\nports:\n  - \"{{PORT}}:80\"\n",
		Fields:          json.RawMessage(`[{"key":"PORT","default":"8080"}]`),
	})
	hostID := uuid.New()

	inst, err := svc.InstallApp(context.Background(), appID, hostID, InstallOptions{Name: "demo", ConfigValues: map[string]string{"PORT": "9999"}})
	if err != nil {
		t.Fatalf("InstallApp: %v", err)
	}
	if inst.StackID == nil {
		t.Fatal("StackID is nil — stack not linked")
	}
	if stacks.calls != 1 {
		t.Errorf("stack create calls: got %d, want 1", stacks.calls)
	}
	if !strings.Contains(stacks.last.ComposeFile, "9999:80") {
		t.Errorf("compose not rendered with port: %s", stacks.last.ComposeFile)
	}
	if stacks.lastHID != hostID {
		t.Errorf("host id: got %v, want %v", stacks.lastHID, hostID)
	}
	got, _ := apps.GetByID(context.Background(), appID)
	if got.InstallCount != 1 {
		t.Errorf("install_count: got %d, want 1", got.InstallCount)
	}
}

func TestService_InstallApp_StackRequired(t *testing.T) {
	apps := newMemAppRepo()
	svc := NewService(apps, newMemInstallRepo(), newMemReviewRepo(), nil, nil, nil)
	id := uuid.New()
	_ = apps.Create(context.Background(), &models.MarketplaceApp{ID: id, Slug: "alpha", Name: "Alpha", ComposeTemplate: "x"})

	if _, err := svc.InstallApp(context.Background(), id, uuid.New(), InstallOptions{}); !stderrors.Is(err, ErrStackRequired) {
		t.Errorf("expected ErrStackRequired, got %v", err)
	}
}

func TestService_InstallApp_AppNotFound(t *testing.T) {
	svc := NewService(newMemAppRepo(), newMemInstallRepo(), newMemReviewRepo(), &fakeStackInstaller{}, nil, nil)
	if _, err := svc.InstallApp(context.Background(), uuid.New(), uuid.New(), InstallOptions{}); !stderrors.Is(err, ErrAppNotFound) {
		t.Errorf("expected ErrAppNotFound, got %v", err)
	}
}

func TestService_UninstallApp(t *testing.T) {
	insts := newMemInstallRepo()
	svc := NewService(newMemAppRepo(), insts, newMemReviewRepo(), &fakeStackInstaller{}, nil, nil)
	id := uuid.New()
	_ = insts.Create(context.Background(), &models.MarketplaceInstallation{ID: id, Status: models.MarketplaceInstallationStatusInstalled})

	if err := svc.UninstallApp(context.Background(), id); err != nil {
		t.Fatalf("UninstallApp: %v", err)
	}
	got, _ := insts.GetByID(context.Background(), id)
	if got.Status != models.MarketplaceInstallationStatusUninstalled {
		t.Errorf("status: got %q, want uninstalled", got.Status)
	}
}

func TestService_AddReview_Validation(t *testing.T) {
	svc := NewService(newMemAppRepo(), newMemInstallRepo(), newMemReviewRepo(), &fakeStackInstaller{}, nil, nil)
	if err := svc.AddReview(context.Background(), nil); err == nil {
		t.Error("expected error for nil review")
	}
	r := &models.MarketplaceReview{Rating: 6, AppID: uuid.New(), UserID: uuid.New()}
	if err := svc.AddReview(context.Background(), r); err == nil {
		t.Error("expected error for out-of-range rating")
	}
}

func TestService_AddReview_OnePerUser(t *testing.T) {
	apps := newMemAppRepo()
	reviews := newMemReviewRepo()
	svc := NewService(apps, newMemInstallRepo(), reviews, &fakeStackInstaller{}, nil, nil)

	appID := uuid.New()
	userID := uuid.New()
	_ = apps.Create(context.Background(), &models.MarketplaceApp{ID: appID, Slug: "x", Name: "X"})

	if err := svc.AddReview(context.Background(), &models.MarketplaceReview{AppID: appID, UserID: userID, Rating: 3}); err != nil {
		t.Fatalf("first review: %v", err)
	}
	if err := svc.AddReview(context.Background(), &models.MarketplaceReview{AppID: appID, UserID: userID, Rating: 5}); err != nil {
		t.Fatalf("second review (upsert): %v", err)
	}
	if got := len(reviews.rows); got != 1 {
		t.Errorf("reviews: got %d, want 1", got)
	}
}

func TestRenderCompose(t *testing.T) {
	out, err := renderCompose("port {{P}} host {{H}}", map[string]string{"P": "1", "H": "x"})
	if err != nil {
		t.Fatalf("renderCompose: %v", err)
	}
	if out != "port 1 host x" {
		t.Errorf("got %q", out)
	}
}

func TestRenderCompose_Empty(t *testing.T) {
	if _, err := renderCompose("", nil); err == nil {
		t.Error("expected error for empty template")
	}
}

func TestGenerateSlug(t *testing.T) {
	cases := map[string]string{
		"Hello World": "hello-world",
		"My_App":      "my-app",
		"---":         "app",
		"":            "app",
		"AAA bbb 123": "aaa-bbb-123",
		"!@#$%^":      "app",
	}
	for in, want := range cases {
		if got := generateSlug(in); got != want {
			t.Errorf("generateSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsValidSlug(t *testing.T) {
	good := []string{"a", "abc", "a-b", "abc123", "x-y-z"}
	for _, s := range good {
		if !isValidSlug(s) {
			t.Errorf("expected %q to be valid", s)
		}
	}
	bad := []string{"", "-x", "x-", "X", "x_y", "x y", strings.Repeat("a", 200)}
	for _, s := range bad {
		if isValidSlug(s) {
			t.Errorf("expected %q to be invalid", s)
		}
	}
}
