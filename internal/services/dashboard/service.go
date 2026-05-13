// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package dashboard provides the custom dashboard layout service.
package dashboard

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Repository defines the persistence interface for dashboard data.
type Repository interface {
	CreateLayout(ctx context.Context, layout *models.DashboardLayout) error
	GetLayout(ctx context.Context, id uuid.UUID) (*models.DashboardLayout, error)
	UpdateLayout(ctx context.Context, layout *models.DashboardLayout) error
	DeleteLayout(ctx context.Context, id uuid.UUID) error
	ListLayouts(ctx context.Context, userID uuid.UUID) ([]*models.DashboardLayout, error)
	GetDefaultLayout(ctx context.Context, userID uuid.UUID) (*models.DashboardLayout, error)
	ClearDefault(ctx context.Context, userID uuid.UUID) error

	CreateWidget(ctx context.Context, widget *models.DashboardWidget) error
	GetWidget(ctx context.Context, id uuid.UUID) (*models.DashboardWidget, error)
	UpdateWidget(ctx context.Context, widget *models.DashboardWidget) error
	DeleteWidget(ctx context.Context, id uuid.UUID) error
	ListWidgets(ctx context.Context, layoutID uuid.UUID) ([]*models.DashboardWidget, error)
}

// Service provides dashboard layout and widget operations.
type Service struct {
	repo   Repository
	logger *logger.Logger
}

// NewService creates a new dashboard service.
func NewService(repo Repository, log *logger.Logger) *Service {
	return &Service{
		repo:   repo,
		logger: log.Named("dashboard"),
	}
}

// ============================================================================
// Layout operations
// ============================================================================

// CreateLayoutInput represents input for creating a layout.
type CreateLayoutInput struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	IsShared    bool            `json:"is_shared"`
	IsDefault   bool            `json:"is_default"`
	LayoutJSON  json.RawMessage `json:"layout_json"`
}

// CreateLayout creates a new dashboard layout for a user.
func (s *Service) CreateLayout(ctx context.Context, userID uuid.UUID, input *CreateLayoutInput) (*models.DashboardLayout, error) {
	if input.Name == "" {
		return nil, errors.New(errors.CodeValidation, "layout name is required")
	}

	layout := &models.DashboardLayout{
		Name:        input.Name,
		Description: input.Description,
		UserID:      &userID,
		IsShared:    input.IsShared,
		IsDefault:   input.IsDefault,
		LayoutJSON:  input.LayoutJSON,
	}

	// If setting as default, clear existing default first
	if input.IsDefault {
		if err := s.repo.ClearDefault(ctx, userID); err != nil {
			return nil, err
		}
	}

	if err := s.repo.CreateLayout(ctx, layout); err != nil {
		return nil, err
	}

	s.logger.Info("layout created",
		"layout_id", layout.ID,
		"user_id", userID,
		"name", layout.Name,
	)

	return layout, nil
}

// GetLayout retrieves a layout by ID, checking access.
func (s *Service) GetLayout(ctx context.Context, userID uuid.UUID, layoutID uuid.UUID) (*models.DashboardLayout, error) {
	layout, err := s.repo.GetLayout(ctx, layoutID)
	if err != nil {
		return nil, err
	}

	// Access check: must be owner or layout must be shared
	if !layout.IsShared && (layout.UserID == nil || *layout.UserID != userID) {
		return nil, errors.New(errors.CodeForbidden, "access denied to dashboard layout")
	}

	return layout, nil
}

// UpdateLayoutInput represents input for updating a layout.
type UpdateLayoutInput struct {
	Name        *string          `json:"name"`
	Description *string          `json:"description"`
	IsShared    *bool            `json:"is_shared"`
	IsDefault   *bool            `json:"is_default"`
	LayoutJSON  *json.RawMessage `json:"layout_json"`
}

// UpdateLayout updates a layout owned by the user.
func (s *Service) UpdateLayout(ctx context.Context, userID uuid.UUID, layoutID uuid.UUID, input *UpdateLayoutInput) (*models.DashboardLayout, error) {
	layout, err := s.repo.GetLayout(ctx, layoutID)
	if err != nil {
		return nil, err
	}

	// Must be owner
	if layout.UserID == nil || *layout.UserID != userID {
		return nil, errors.New(errors.CodeForbidden, "can only update own layouts")
	}

	if input.Name != nil {
		if *input.Name == "" {
			return nil, errors.New(errors.CodeValidation, "layout name cannot be empty")
		}
		layout.Name = *input.Name
	}
	if input.Description != nil {
		layout.Description = *input.Description
	}
	if input.IsShared != nil {
		layout.IsShared = *input.IsShared
	}
	if input.IsDefault != nil {
		if *input.IsDefault {
			if err := s.repo.ClearDefault(ctx, userID); err != nil {
				return nil, err
			}
		}
		layout.IsDefault = *input.IsDefault
	}
	if input.LayoutJSON != nil {
		layout.LayoutJSON = *input.LayoutJSON
	}

	if err := s.repo.UpdateLayout(ctx, layout); err != nil {
		return nil, err
	}

	return layout, nil
}

// DeleteLayout deletes a layout owned by the user.
func (s *Service) DeleteLayout(ctx context.Context, userID uuid.UUID, layoutID uuid.UUID) error {
	layout, err := s.repo.GetLayout(ctx, layoutID)
	if err != nil {
		return err
	}

	if layout.UserID == nil || *layout.UserID != userID {
		return errors.New(errors.CodeForbidden, "can only delete own layouts")
	}

	return s.repo.DeleteLayout(ctx, layoutID)
}

// ListLayouts returns all layouts visible to the user.
func (s *Service) ListLayouts(ctx context.Context, userID uuid.UUID) ([]*models.DashboardLayout, error) {
	return s.repo.ListLayouts(ctx, userID)
}

// ============================================================================
// Widget operations
// ============================================================================

// validWidgetTypes is the set of valid widget type identifiers.
var validWidgetTypes = map[string]bool{
	models.WidgetTypeCPUGauge:         true,
	models.WidgetTypeMemoryGauge:      true,
	models.WidgetTypeDiskGauge:        true,
	models.WidgetTypeCPUChart:         true,
	models.WidgetTypeMemoryChart:      true,
	models.WidgetTypeNetworkChart:     true,
	models.WidgetTypeContainerTable:   true,
	models.WidgetTypeContainerCount:   true,
	models.WidgetTypeAlertFeed:        true,
	models.WidgetTypeLogStream:        true,
	models.WidgetTypeSecurityScore:    true,
	models.WidgetTypeComplianceStatus: true,
	models.WidgetTypeTopContainers:    true,
	models.WidgetTypeHostInfo:         true,
	models.WidgetTypeCustomMetric:     true,
}

// AddWidgetInput represents input for adding a widget to a layout.
type AddWidgetInput struct {
	WidgetType string          `json:"widget_type"`
	Title      string          `json:"title"`
	Config     json.RawMessage `json:"config"`
	PositionX  int             `json:"position_x"`
	PositionY  int             `json:"position_y"`
	Width      int             `json:"width"`
	Height     int             `json:"height"`
}

// AddWidget adds a widget to a layout.
func (s *Service) AddWidget(ctx context.Context, userID uuid.UUID, layoutID uuid.UUID, input *AddWidgetInput) (*models.DashboardWidget, error) {
	// Verify layout ownership
	layout, err := s.repo.GetLayout(ctx, layoutID)
	if err != nil {
		return nil, err
	}
	if layout.UserID == nil || *layout.UserID != userID {
		return nil, errors.New(errors.CodeForbidden, "can only add widgets to own layouts")
	}

	// Validate widget type
	if !validWidgetTypes[input.WidgetType] {
		return nil, errors.New(errors.CodeValidation, "invalid widget type")
	}

	// Apply defaults
	width := input.Width
	if width <= 0 {
		width = 6
	}
	height := input.Height
	if height <= 0 {
		height = 4
	}

	widget := &models.DashboardWidget{
		LayoutID:   layoutID,
		WidgetType: input.WidgetType,
		Title:      input.Title,
		Config:     input.Config,
		PositionX:  input.PositionX,
		PositionY:  input.PositionY,
		Width:      width,
		Height:     height,
	}

	if err := s.repo.CreateWidget(ctx, widget); err != nil {
		return nil, err
	}

	return widget, nil
}

// UpdateWidgetInput represents input for updating a widget.
type UpdateWidgetInput struct {
	Title     *string          `json:"title"`
	Config    *json.RawMessage `json:"config"`
	PositionX *int             `json:"position_x"`
	PositionY *int             `json:"position_y"`
	Width     *int             `json:"width"`
	Height    *int             `json:"height"`
}

// UpdateWidget updates a widget, verifying layout ownership.
func (s *Service) UpdateWidget(ctx context.Context, userID uuid.UUID, widgetID uuid.UUID, input *UpdateWidgetInput) (*models.DashboardWidget, error) {
	widget, err := s.repo.GetWidget(ctx, widgetID)
	if err != nil {
		return nil, err
	}

	// Verify layout ownership
	layout, err := s.repo.GetLayout(ctx, widget.LayoutID)
	if err != nil {
		return nil, err
	}
	if layout.UserID == nil || *layout.UserID != userID {
		return nil, errors.New(errors.CodeForbidden, "can only update widgets on own layouts")
	}

	if input.Title != nil {
		widget.Title = *input.Title
	}
	if input.Config != nil {
		widget.Config = *input.Config
	}
	if input.PositionX != nil {
		widget.PositionX = *input.PositionX
	}
	if input.PositionY != nil {
		widget.PositionY = *input.PositionY
	}
	if input.Width != nil {
		widget.Width = *input.Width
	}
	if input.Height != nil {
		widget.Height = *input.Height
	}

	if err := s.repo.UpdateWidget(ctx, widget); err != nil {
		return nil, err
	}

	return widget, nil
}

// RemoveWidget removes a widget, verifying layout ownership.
func (s *Service) RemoveWidget(ctx context.Context, userID uuid.UUID, widgetID uuid.UUID) error {
	widget, err := s.repo.GetWidget(ctx, widgetID)
	if err != nil {
		return err
	}

	layout, err := s.repo.GetLayout(ctx, widget.LayoutID)
	if err != nil {
		return err
	}
	if layout.UserID == nil || *layout.UserID != userID {
		return errors.New(errors.CodeForbidden, "can only remove widgets from own layouts")
	}

	return s.repo.DeleteWidget(ctx, widgetID)
}

// GetLayoutWidgets retrieves all widgets for a layout with access check.
func (s *Service) GetLayoutWidgets(ctx context.Context, userID uuid.UUID, layoutID uuid.UUID) ([]*models.DashboardWidget, error) {
	// Verify access
	layout, err := s.repo.GetLayout(ctx, layoutID)
	if err != nil {
		return nil, err
	}
	if !layout.IsShared && (layout.UserID == nil || *layout.UserID != userID) {
		return nil, errors.New(errors.CodeForbidden, "access denied to dashboard layout")
	}

	return s.repo.ListWidgets(ctx, layoutID)
}
