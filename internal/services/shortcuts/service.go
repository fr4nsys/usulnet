// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package shortcuts

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// Service manages web shortcuts.
type Service struct {
	shortcutRepo *postgres.WebShortcutRepository
	categoryRepo *postgres.ShortcutCategoryRepository
	logger       *logger.Logger
	httpClient   *http.Client
}

// NewService creates a new shortcuts service.
func NewService(
	shortcutRepo *postgres.WebShortcutRepository,
	categoryRepo *postgres.ShortcutCategoryRepository,
	log *logger.Logger,
) *Service {
	return &Service{
		shortcutRepo: shortcutRepo,
		categoryRepo: categoryRepo,
		logger:       log.Named("shortcuts"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ============================================================================
// Shortcut CRUD
// ============================================================================

// Create creates a new web shortcut.
func (s *Service) Create(ctx context.Context, input models.CreateWebShortcutInput, userID uuid.UUID) (*models.WebShortcut, error) {
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

	// Set default icon type if icon is provided but type is not
	if shortcut.Icon != "" && shortcut.IconType == "" {
		if strings.HasPrefix(shortcut.Icon, "fa-") {
			shortcut.IconType = "fa"
		} else if strings.HasPrefix(shortcut.Icon, "http") {
			shortcut.IconType = "url"
		}
	}

	if err := s.shortcutRepo.Create(ctx, shortcut); err != nil {
		return nil, err
	}

	s.logger.Info("created web shortcut",
		"id", shortcut.ID,
		"name", shortcut.Name,
		"url", shortcut.URL,
		"user_id", userID,
	)

	return shortcut, nil
}

// Get retrieves a shortcut by ID.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.WebShortcut, error) {
	return s.shortcutRepo.GetByID(ctx, id)
}

// List retrieves all shortcuts for a user.
func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]*models.WebShortcut, error) {
	return s.shortcutRepo.ListByUser(ctx, userID)
}

// ListByCategory retrieves shortcuts for a specific category.
func (s *Service) ListByCategory(ctx context.Context, userID uuid.UUID, category string) ([]*models.WebShortcut, error) {
	return s.shortcutRepo.ListByCategory(ctx, userID, category)
}

// ListForMenu retrieves shortcuts marked for menu display.
func (s *Service) ListForMenu(ctx context.Context, userID uuid.UUID) ([]*models.WebShortcut, error) {
	return s.shortcutRepo.ListForMenu(ctx, userID)
}

// Update updates a web shortcut.
func (s *Service) Update(ctx context.Context, id uuid.UUID, input models.UpdateWebShortcutInput) (*models.WebShortcut, error) {
	shortcut, err := s.shortcutRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

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

	if err := s.shortcutRepo.Update(ctx, shortcut); err != nil {
		return nil, err
	}

	return shortcut, nil
}

// Delete removes a web shortcut.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	return s.shortcutRepo.Delete(ctx, id)
}

// GetCategories returns all unique categories for a user.
func (s *Service) GetCategories(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.shortcutRepo.GetCategories(ctx, userID)
}

// UpdateSortOrder updates the sort order for multiple shortcuts.
func (s *Service) UpdateSortOrder(ctx context.Context, orders map[uuid.UUID]int) error {
	return s.shortcutRepo.UpdateSortOrder(ctx, orders)
}

// ============================================================================
// Favicon Fetching
// ============================================================================

// FetchFavicon fetches the favicon for a URL.
func (s *Service) FetchFavicon(ctx context.Context, targetURL string) (string, []byte, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return "", nil, errors.Wrap(err, errors.CodeValidationFailed, "invalid URL")
	}

	// Common favicon locations to try
	faviconURLs := []string{
		parsed.Scheme + "://" + parsed.Host + "/favicon.ico",
		parsed.Scheme + "://" + parsed.Host + "/favicon.png",
		parsed.Scheme + "://" + parsed.Host + "/apple-touch-icon.png",
		parsed.Scheme + "://" + parsed.Host + "/apple-touch-icon-precomposed.png",
	}

	for _, faviconURL := range faviconURLs {
		iconData, err := s.downloadFavicon(ctx, faviconURL)
		if err == nil && len(iconData) > 0 {
			return faviconURL, iconData, nil
		}
	}

	// Try Google's favicon service as fallback
	googleFaviconURL := "https://www.google.com/s2/favicons?domain=" + parsed.Host + "&sz=64"
	iconData, err := s.downloadFavicon(ctx, googleFaviconURL)
	if err == nil && len(iconData) > 0 {
		return googleFaviconURL, iconData, nil
	}

	return "", nil, errors.NotFound("favicon")
}

func (s *Service) downloadFavicon(ctx context.Context, faviconURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, faviconURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; usulnet/1.0)")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(errors.CodeNotFound, "favicon not found")
	}

	// Limit read to 1MB
	iconData, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	// Check if it's a valid image (basic check)
	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "image/") && len(iconData) < 100 {
		return nil, errors.New(errors.CodeValidationFailed, "not a valid image")
	}

	return iconData, nil
}

// FetchAndSetFavicon fetches and sets the favicon for a shortcut.
func (s *Service) FetchAndSetFavicon(ctx context.Context, shortcutID uuid.UUID) error {
	shortcut, err := s.shortcutRepo.GetByID(ctx, shortcutID)
	if err != nil {
		return err
	}

	faviconURL, _, err := s.FetchFavicon(ctx, shortcut.URL)
	if err != nil {
		s.logger.Warn("failed to fetch favicon",
			"shortcut_id", shortcutID,
			"url", shortcut.URL,
			"error", err,
		)
		return err
	}

	shortcut.Icon = faviconURL
	shortcut.IconType = "url"

	return s.shortcutRepo.Update(ctx, shortcut)
}

// ============================================================================
// Category Management
// ============================================================================

// CreateCategory creates a new shortcut category.
func (s *Service) CreateCategory(ctx context.Context, input models.CreateCategoryInput, userID uuid.UUID) (*models.ShortcutCategory, error) {
	cat := &models.ShortcutCategory{
		Name:      input.Name,
		Icon:      input.Icon,
		Color:     input.Color,
		SortOrder: input.SortOrder,
		IsDefault: input.IsDefault,
		CreatedBy: userID,
	}

	if err := s.categoryRepo.Create(ctx, cat); err != nil {
		return nil, err
	}

	return cat, nil
}

// GetCategory retrieves a category by ID.
func (s *Service) GetCategory(ctx context.Context, id uuid.UUID) (*models.ShortcutCategory, error) {
	return s.categoryRepo.GetByID(ctx, id)
}

// ListCategories retrieves all categories for a user.
func (s *Service) ListCategories(ctx context.Context, userID uuid.UUID) ([]*models.ShortcutCategory, error) {
	return s.categoryRepo.ListByUser(ctx, userID)
}

// UpdateCategory updates a category.
func (s *Service) UpdateCategory(ctx context.Context, cat *models.ShortcutCategory) error {
	return s.categoryRepo.Update(ctx, cat)
}

// DeleteCategory removes a category.
func (s *Service) DeleteCategory(ctx context.Context, id uuid.UUID) error {
	return s.categoryRepo.Delete(ctx, id)
}
