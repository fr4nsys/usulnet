// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package marketplace provides a curated container app marketplace for
// usulnet.
//
// The catalog is **offline-first**: the entries shipped under
// internal/templates/marketplace/ are baked into the binary via an
// embedded filesystem and hydrated into the marketplace_apps table the
// first time the service starts. There is no central JSON endpoint, no
// call-home, and no outbound HTTP request at runtime. Updates to the
// catalog ship with new usulnet binary releases.
//
// Installation is integrated with the stack service: installing an app
// renders its compose template with the user-supplied field values and
// creates a stack on the active host. The resulting stack_id is stored
// on the installation row.
//
// Reviews are local. They never leave the usulnet instance. One review
// per (user, app) is enforced by a unique constraint in the migration;
// the repository upserts so a user updating their review does not
// generate a duplicate-key error.
//
// The package is free AGPL: no edition checks, no biz gating, no
// runtime caps.
package marketplace

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Sentinel errors returned by the service.
var (
	// ErrInvalidInput is returned when an input payload fails validation.
	ErrInvalidInput = stderrors.New("marketplace: invalid input")

	// ErrAppNotFound is returned when GetApp / GetAppBySlug fails to
	// locate the requested row. The repository wraps a pkg/errors
	// NotFound; this sentinel is used by the handler layer to translate
	// to HTTP 404.
	ErrAppNotFound = stderrors.New("marketplace: app not found")

	// ErrStackRequired is returned by Install when the host has no
	// stack service wired (e.g. an early-boot installation). Hands the
	// caller a clear message instead of a nil pointer dereference.
	ErrStackRequired = stderrors.New("marketplace: stack service is required to install apps")
)

// AppRepository defines persistence for marketplace apps.
type AppRepository interface {
	Create(ctx context.Context, app *models.MarketplaceApp) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.MarketplaceApp, error)
	GetBySlug(ctx context.Context, slug string) (*models.MarketplaceApp, error)
	Search(ctx context.Context, query string, category string, limit, offset int) ([]*models.MarketplaceApp, int, error)
	ListFeatured(ctx context.Context, limit int) ([]*models.MarketplaceApp, error)
	ListByCategory(ctx context.Context, category string, limit, offset int) ([]*models.MarketplaceApp, int, error)
	Update(ctx context.Context, app *models.MarketplaceApp) error
	Delete(ctx context.Context, id uuid.UUID) error
	IncrementInstallCount(ctx context.Context, id uuid.UUID) error
	UpdateRating(ctx context.Context, id uuid.UUID) error
}

// InstallationRepository defines persistence for marketplace installations.
type InstallationRepository interface {
	Create(ctx context.Context, inst *models.MarketplaceInstallation) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.MarketplaceInstallation, error)
	ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.MarketplaceInstallation, int, error)
	ListByApp(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceInstallation, error)
	Update(ctx context.Context, inst *models.MarketplaceInstallation) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// ReviewRepository defines persistence for marketplace reviews. Upsert
// uses the (user_id, app_id) unique constraint so concurrent writes
// from the same user collapse to a single row instead of racing.
type ReviewRepository interface {
	Upsert(ctx context.Context, review *models.MarketplaceReview) error
	ListByApp(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceReview, error)
	GetByUserAndApp(ctx context.Context, userID, appID uuid.UUID) (*models.MarketplaceReview, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// StackInstaller is the narrow slice of the stack service this package
// depends on. Defined here so the marketplace service can be unit
// tested with a mock without importing the concrete stack package.
type StackInstaller interface {
	Create(ctx context.Context, hostID uuid.UUID, input *models.CreateStackInput) (*models.Stack, error)
}

// CatalogSource enumerates the offline catalog entries. The
// embedded marketplace package implements this; tests inject a
// deterministic implementation. The interface is intentionally minimal
// — the service only needs read access.
type CatalogSource interface {
	Load() ([]CatalogEntry, error)
}

// CatalogEntry is the subset of the embedded manifest the service
// cares about. The full Entry type lives in
// internal/templates/marketplace; this re-declaration keeps the service
// from importing the templates package transitively into every test.
type CatalogEntry struct {
	Slug            string
	Name            string
	Description     string
	LongDescription string
	Category        string
	Icon            string
	IconColor       string
	IconSVG         string
	Version         string
	ManifestVersion int
	Website         string
	Source          string
	Author          string
	License         string
	Tags            []string
	MinMemoryMB     int
	MinCPUCores     float64
	IsOfficial      bool
	IsVerified      bool
	Featured        bool
	Fields          []models.MarketplaceField
	Compose         string
}

// Service implements marketplace business logic.
type Service struct {
	apps          AppRepository
	installations InstallationRepository
	reviews       ReviewRepository
	stacks        StackInstaller
	catalog       CatalogSource
	logger        *logger.Logger
}

// NewService creates a new marketplace service. The catalog source
// may be nil — hydration is then a no-op (useful for tests). The stack
// installer may be nil at construction time; without it Install will
// return ErrStackRequired.
func NewService(
	apps AppRepository,
	installations InstallationRepository,
	reviews ReviewRepository,
	stacks StackInstaller,
	catalog CatalogSource,
	log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		apps:          apps,
		installations: installations,
		reviews:       reviews,
		stacks:        stacks,
		catalog:       catalog,
		logger:        log.Named("marketplace"),
	}
}

// ============================================================================
// Catalog hydration
// ============================================================================

// HydrateCatalog idempotently syncs the embedded catalog into the
// marketplace_apps table. On every boot:
//
//   - rows with built_in=true whose manifest_version is older than the
//     embedded one are replaced (keeping their UUID, install_count,
//     and rating);
//   - missing built-in apps are inserted;
//   - rows submitted by users (built_in=false) are left untouched.
//
// The method is safe to call repeatedly; the bookkeeping is per-slug.
// It is intentionally NOT called from NewService — wiring code calls
// it after the migrations run so the table exists.
func (s *Service) HydrateCatalog(ctx context.Context) error {
	if s.catalog == nil {
		s.logger.Debug("HydrateCatalog: no catalog source registered")
		return nil
	}
	entries, err := s.catalog.Load()
	if err != nil {
		return fmt.Errorf("load embedded catalog: %w", err)
	}

	var inserted, updated, skipped int
	for _, e := range entries {
		applied, action, err := s.upsertCatalogEntry(ctx, e)
		if err != nil {
			return fmt.Errorf("hydrate %s: %w", e.Slug, err)
		}
		if !applied {
			skipped++
			continue
		}
		switch action {
		case "insert":
			inserted++
		case "update":
			updated++
		}
	}
	s.logger.Info("Marketplace catalog hydrated",
		"entries", len(entries),
		"inserted", inserted,
		"updated", updated,
		"skipped", skipped,
	)
	return nil
}

func (s *Service) upsertCatalogEntry(ctx context.Context, e CatalogEntry) (bool, string, error) {
	existing, err := s.apps.GetBySlug(ctx, e.Slug)
	if err == nil {
		// Row exists. Only refresh built-in rows; user-submitted apps
		// are sacrosanct, even if they share a slug.
		if !existing.BuiltIn {
			s.logger.Warn("Marketplace catalog: slug used by a user-submitted app, skipping",
				"slug", e.Slug)
			return false, "", nil
		}
		if existing.ManifestVersion >= e.ManifestVersion {
			return false, "", nil
		}
		next := mergeEntryIntoApp(existing, e)
		if err := s.apps.Update(ctx, next); err != nil {
			return false, "", err
		}
		return true, "update", nil
	}
	if !isNotFound(err) {
		return false, "", err
	}

	// Row is missing — insert a fresh one.
	app := newAppFromEntry(e)
	if err := s.apps.Create(ctx, app); err != nil {
		return false, "", err
	}
	return true, "insert", nil
}

func newAppFromEntry(e CatalogEntry) *models.MarketplaceApp {
	fields := marshalFields(e.Fields)
	return &models.MarketplaceApp{
		Slug:            e.Slug,
		Name:            e.Name,
		Description:     e.Description,
		LongDescription: e.LongDescription,
		Icon:            e.Icon,
		IconColor:       e.IconColor,
		IconSVG:         e.IconSVG,
		Category:        models.MarketplaceAppCategory(e.Category),
		Version:         e.Version,
		ManifestVersion: e.ManifestVersion,
		Website:         e.Website,
		Source:          e.Source,
		Author:          e.Author,
		License:         e.License,
		ComposeTemplate: e.Compose,
		Fields:          fields,
		Tags:            e.Tags,
		MinMemoryMB:     e.MinMemoryMB,
		MinCPUCores:     e.MinCPUCores,
		IsOfficial:      e.IsOfficial,
		IsVerified:      e.IsVerified,
		Featured:        e.Featured,
		BuiltIn:         true,
	}
}

// mergeEntryIntoApp keeps the existing row's identity and counters but
// refreshes every field that the embedded manifest owns. The counters
// (install_count, avg_rating, rating_count, created_at) come from
// `existing`; everything else comes from the new entry.
func mergeEntryIntoApp(existing *models.MarketplaceApp, e CatalogEntry) *models.MarketplaceApp {
	next := newAppFromEntry(e)
	next.ID = existing.ID
	next.CreatedAt = existing.CreatedAt
	next.InstallCount = existing.InstallCount
	next.AvgRating = existing.AvgRating
	next.RatingCount = existing.RatingCount
	next.CreatedBy = existing.CreatedBy
	return next
}

func marshalFields(fields []models.MarketplaceField) json.RawMessage {
	if len(fields) == 0 {
		return json.RawMessage("[]")
	}
	buf, err := json.Marshal(fields)
	if err != nil {
		return json.RawMessage("[]")
	}
	return buf
}

// ============================================================================
// App browsing
// ============================================================================

// SearchApps searches marketplace apps by query and optional category.
func (s *Service) SearchApps(ctx context.Context, query, category string, limit, offset int) ([]*models.MarketplaceApp, int, error) {
	limit, offset = clampPagination(limit, offset)
	return s.apps.Search(ctx, query, category, limit, offset)
}

// GetApp returns a marketplace app by ID.
func (s *Service) GetApp(ctx context.Context, id uuid.UUID) (*models.MarketplaceApp, error) {
	app, err := s.apps.GetByID(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrAppNotFound
		}
		return nil, err
	}
	return app, nil
}

// GetAppBySlug returns a marketplace app by slug.
func (s *Service) GetAppBySlug(ctx context.Context, slug string) (*models.MarketplaceApp, error) {
	if slug == "" {
		return nil, fmt.Errorf("%w: slug is required", ErrInvalidInput)
	}
	app, err := s.apps.GetBySlug(ctx, slug)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrAppNotFound
		}
		return nil, err
	}
	return app, nil
}

// ListFeatured returns featured apps.
func (s *Service) ListFeatured(ctx context.Context, limit int) ([]*models.MarketplaceApp, error) {
	if limit <= 0 || limit > 50 {
		limit = 6
	}
	return s.apps.ListFeatured(ctx, limit)
}

// ListByCategory returns apps filtered by category.
func (s *Service) ListByCategory(ctx context.Context, category string, limit, offset int) ([]*models.MarketplaceApp, int, error) {
	limit, offset = clampPagination(limit, offset)
	return s.apps.ListByCategory(ctx, category, limit, offset)
}

// ============================================================================
// App management
// ============================================================================

// CreateApp creates a new marketplace app (user-submitted; built_in=false).
func (s *Service) CreateApp(ctx context.Context, app *models.MarketplaceApp) error {
	if app == nil {
		return fmt.Errorf("%w: app is required", ErrInvalidInput)
	}
	if app.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if app.ComposeTemplate == "" {
		return fmt.Errorf("%w: compose_template is required", ErrInvalidInput)
	}
	if app.Slug == "" {
		app.Slug = generateSlug(app.Name)
	}
	if !isValidSlug(app.Slug) {
		return fmt.Errorf("%w: slug must match [a-z0-9-]+ and be ≤ 128 chars", ErrInvalidInput)
	}
	if app.Icon == "" {
		app.Icon = "fa-cube"
	}
	if app.IconColor == "" {
		app.IconColor = "#6c757d"
	}
	if app.Category == "" {
		app.Category = models.MarketplaceAppCategoryOther
	}
	if app.ManifestVersion == 0 {
		app.ManifestVersion = 1
	}
	// User-submitted apps are never built-in.
	app.BuiltIn = false

	if err := s.apps.Create(ctx, app); err != nil {
		return fmt.Errorf("create app: %w", err)
	}
	s.logger.Info("Marketplace app created",
		"app_id", app.ID,
		"slug", app.Slug,
		"name", app.Name)
	return nil
}

// UpdateApp updates a marketplace app.
func (s *Service) UpdateApp(ctx context.Context, app *models.MarketplaceApp) error {
	if err := s.apps.Update(ctx, app); err != nil {
		return fmt.Errorf("update app: %w", err)
	}
	s.logger.Info("Marketplace app updated", "app_id", app.ID)
	return nil
}

// DeleteApp deletes a marketplace app. Built-in apps are refused —
// they will rehydrate on next boot anyway.
func (s *Service) DeleteApp(ctx context.Context, id uuid.UUID) error {
	app, err := s.apps.GetByID(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return ErrAppNotFound
		}
		return fmt.Errorf("get app: %w", err)
	}
	if app.BuiltIn {
		return fmt.Errorf("%w: built-in apps cannot be deleted", ErrInvalidInput)
	}
	if err := s.apps.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete app: %w", err)
	}
	s.logger.Info("Marketplace app deleted", "app_id", id)
	return nil
}

// ============================================================================
// Installation management
// ============================================================================

// InstallOptions carries the per-install configuration values.
type InstallOptions struct {
	// Name is the user-chosen instance name. Falls back to the app name.
	Name string

	// ConfigValues map field keys (defined in MarketplaceApp.Fields) to
	// the user-provided string values. Missing keys fall through to
	// the field's Default. Keys not declared by the manifest are left
	// in the compose template as-is — they are simply unused.
	ConfigValues map[string]string

	// UserID identifies the operator triggering the install, for audit
	// trail purposes. Optional.
	UserID *uuid.UUID
}

// InstallApp installs a marketplace app on a host. It renders the
// compose template with the supplied field values, creates a stack via
// the stack service, and persists the installation linked to that
// stack ID.
func (s *Service) InstallApp(ctx context.Context, appID, hostID uuid.UUID, opts InstallOptions) (*models.MarketplaceInstallation, error) {
	if appID == uuid.Nil {
		return nil, fmt.Errorf("%w: app_id is required", ErrInvalidInput)
	}
	if hostID == uuid.Nil {
		return nil, fmt.Errorf("%w: host_id is required", ErrInvalidInput)
	}
	if s.stacks == nil {
		return nil, ErrStackRequired
	}

	app, err := s.apps.GetByID(ctx, appID)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("get app: %w", err)
	}

	name := opts.Name
	if name == "" {
		name = app.Slug
	}

	resolved := resolveFieldValues(app, opts.ConfigValues)
	composeBody, err := renderCompose(app.ComposeTemplate, resolved)
	if err != nil {
		return nil, fmt.Errorf("render compose: %w", err)
	}

	stack, err := s.stacks.Create(ctx, hostID, &models.CreateStackInput{
		Name:        name,
		ComposeFile: composeBody,
	})
	if err != nil {
		return nil, fmt.Errorf("create stack: %w", err)
	}

	configJSON, _ := json.Marshal(resolved)
	stackID := stack.ID
	inst := &models.MarketplaceInstallation{
		AppID:        appID,
		HostID:       hostID,
		StackID:      &stackID,
		Name:         name,
		Status:       models.MarketplaceInstallationStatusInstalled,
		Version:      app.Version,
		ConfigValues: configJSON,
		InstalledBy:  opts.UserID,
	}
	if err := s.installations.Create(ctx, inst); err != nil {
		// Stack is already created; the installation row failing to
		// persist is a real bug — surface it. The operator can delete
		// the stack manually if needed.
		return nil, fmt.Errorf("create installation: %w", err)
	}

	if err := s.apps.IncrementInstallCount(ctx, appID); err != nil {
		s.logger.Warn("Marketplace: failed to increment install_count", "app_id", appID, "error", err)
	}

	s.logger.Info("Marketplace app installed",
		"installation_id", inst.ID,
		"app_id", appID,
		"host_id", hostID,
		"stack_id", stack.ID,
		"name", name)
	return inst, nil
}

// ListInstallations returns paginated installations for a host.
func (s *Service) ListInstallations(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.MarketplaceInstallation, int, error) {
	limit, offset = clampPagination(limit, offset)
	return s.installations.ListByHost(ctx, hostID, limit, offset)
}

// GetInstallation returns an installation by ID.
func (s *Service) GetInstallation(ctx context.Context, id uuid.UUID) (*models.MarketplaceInstallation, error) {
	inst, err := s.installations.GetByID(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrAppNotFound
		}
		return nil, err
	}
	return inst, nil
}

// UninstallApp marks an installation as uninstalled. The underlying
// stack lifecycle is the stack service's concern — this method does
// not delete the stack, so the operator can review what was deployed
// before tearing it down.
func (s *Service) UninstallApp(ctx context.Context, id uuid.UUID) error {
	inst, err := s.installations.GetByID(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return ErrAppNotFound
		}
		return fmt.Errorf("get installation: %w", err)
	}
	inst.Status = models.MarketplaceInstallationStatusUninstalled
	if err := s.installations.Update(ctx, inst); err != nil {
		return fmt.Errorf("update installation status: %w", err)
	}
	s.logger.Info("Marketplace app uninstalled",
		"installation_id", id,
		"app_id", inst.AppID)
	return nil
}

// ============================================================================
// Reviews
// ============================================================================

// AddReview persists or updates a user review for an app. The
// (user_id, app_id) unique constraint in migration 056 guarantees that
// concurrent writes from the same user collapse to a single row.
//
// Reviews are local-only: they never leave the usulnet instance.
func (s *Service) AddReview(ctx context.Context, review *models.MarketplaceReview) error {
	if review == nil {
		return fmt.Errorf("%w: review is required", ErrInvalidInput)
	}
	if review.AppID == uuid.Nil {
		return fmt.Errorf("%w: app_id is required", ErrInvalidInput)
	}
	if review.UserID == uuid.Nil {
		return fmt.Errorf("%w: user_id is required", ErrInvalidInput)
	}
	if review.Rating < 1 || review.Rating > 5 {
		return fmt.Errorf("%w: rating must be between 1 and 5", ErrInvalidInput)
	}
	if err := s.reviews.Upsert(ctx, review); err != nil {
		return fmt.Errorf("upsert review: %w", err)
	}
	if err := s.apps.UpdateRating(ctx, review.AppID); err != nil {
		s.logger.Warn("Marketplace: failed to refresh rating aggregate", "app_id", review.AppID, "error", err)
	}
	s.logger.Info("Marketplace review submitted (local-only)",
		"app_id", review.AppID,
		"user_id", review.UserID,
		"rating", review.Rating)
	return nil
}

// ListReviews returns all reviews for an app.
func (s *Service) ListReviews(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceReview, error) {
	return s.reviews.ListByApp(ctx, appID)
}

// DeleteReview deletes a review.
func (s *Service) DeleteReview(ctx context.Context, id uuid.UUID) error {
	if err := s.reviews.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete review: %w", err)
	}
	return nil
}

// ============================================================================
// Helpers
// ============================================================================

const (
	maxPageSize     = 100
	defaultPageSize = 24
)

func clampPagination(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = defaultPageSize
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// generateSlug creates a URL-safe slug from a name.
func generateSlug(name string) string {
	slug := strings.ToLower(name)
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "_", "-")
	var clean strings.Builder
	clean.Grow(len(slug))
	for _, r := range slug {
		switch {
		case r >= 'a' && r <= 'z':
			clean.WriteRune(r)
		case r >= '0' && r <= '9':
			clean.WriteRune(r)
		case r == '-':
			clean.WriteRune(r)
		}
	}
	out := clean.String()
	out = strings.Trim(out, "-")
	if out == "" {
		out = "app"
	}
	if len(out) > 128 {
		out = out[:128]
	}
	return out
}

func isValidSlug(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return !strings.HasPrefix(s, "-") && !strings.HasSuffix(s, "-")
}

// resolveFieldValues merges the manifest defaults with the user-supplied
// values. Required fields without a value fall back to the default; the
// renderer below will leave any unresolved {{KEY}} placeholders intact
// so the compose validator catches them before we ever ship to the
// stack service.
func resolveFieldValues(app *models.MarketplaceApp, supplied map[string]string) map[string]string {
	out := make(map[string]string)
	if app.Fields != nil {
		var fields []models.MarketplaceField
		if err := json.Unmarshal(app.Fields, &fields); err == nil {
			for _, f := range fields {
				if v, ok := supplied[f.Key]; ok && v != "" {
					out[f.Key] = v
					continue
				}
				out[f.Key] = f.Default
			}
		}
	}
	// Allow callers to override / add values that are not declared on
	// the manifest. The compose template won't use undeclared keys but
	// they will be stored on the installation row for auditing.
	for k, v := range supplied {
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}
	return out
}

// renderCompose substitutes `{{KEY}}` placeholders in the template
// with the values from `vars`. We don't use text/template here because
// the v26.2.7 templates use bare `{{KEY}}` (no leading dot), which
// text/template would reject as missing field references.
func renderCompose(tpl string, vars map[string]string) (string, error) {
	if tpl == "" {
		return "", fmt.Errorf("%w: compose template is empty", ErrInvalidInput)
	}
	out := tpl
	for k, v := range vars {
		out = strings.ReplaceAll(out, "{{"+k+"}}", v)
	}
	return out, nil
}

// isNotFound returns true if err is a "resource not found" condition
// from the repository layer. The repos wrap pkg/errors.NotFound which
// renders as "not found" in Error(); checking the substring is
// resilient to nested wrapping.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}
