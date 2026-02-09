// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/google/uuid"
)

// RegistryRepo defines the interface for registry persistence.
type RegistryRepo interface {
	Create(ctx context.Context, input models.CreateRegistryInput) (*models.Registry, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Registry, error)
	List(ctx context.Context) ([]*models.Registry, error)
	Update(ctx context.Context, id uuid.UUID, input models.CreateRegistryInput) (*models.Registry, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// WebhookRepo defines the interface for outgoing webhook persistence.
type WebhookRepo interface {
	Create(ctx context.Context, wh *models.OutgoingWebhook) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.OutgoingWebhook, error)
	List(ctx context.Context) ([]*models.OutgoingWebhook, error)
	Update(ctx context.Context, wh *models.OutgoingWebhook) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListDeliveries(ctx context.Context, opts models.WebhookDeliveryListOptions) ([]*models.WebhookDelivery, int64, error)
}

// RunbookRepo defines the interface for runbook persistence.
type RunbookRepo interface {
	Create(ctx context.Context, rb *models.Runbook) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Runbook, error)
	List(ctx context.Context, opts models.RunbookListOptions) ([]*models.Runbook, int64, error)
	Update(ctx context.Context, rb *models.Runbook) error
	Delete(ctx context.Context, id uuid.UUID) error
	CreateExecution(ctx context.Context, exec *models.RunbookExecution) error
	ListExecutions(ctx context.Context, runbookID uuid.UUID, limit int) ([]*models.RunbookExecution, error)
	GetCategories(ctx context.Context) ([]string, error)
}

// AutoDeployRepo defines the interface for auto-deploy rule persistence.
type AutoDeployRepo interface {
	Create(ctx context.Context, rule *models.AutoDeployRule) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.AutoDeployRule, error)
	List(ctx context.Context) ([]*models.AutoDeployRule, error)
	Delete(ctx context.Context, id uuid.UUID) error
	MatchRules(ctx context.Context, sourceType, sourceRepo string, branch *string) ([]*models.AutoDeployRule, error)
}

// SetRegistryRepo sets the registry repository.
func (h *Handler) SetRegistryRepo(repo RegistryRepo) { h.registryRepo = repo }

// SetWebhookRepo sets the outgoing webhook repository.
func (h *Handler) SetWebhookRepo(repo WebhookRepo) { h.webhookRepo = repo }

// SetRunbookRepo sets the runbook repository.
func (h *Handler) SetRunbookRepo(repo RunbookRepo) { h.runbookRepo = repo }

// SetAutoDeployRepo sets the auto-deploy rule repository.
func (h *Handler) SetAutoDeployRepo(repo AutoDeployRepo) { h.autoDeployRepo = repo }
