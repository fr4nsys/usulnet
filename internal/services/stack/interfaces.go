// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package stack

import (
	"context"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// StackRepository defines persistence operations for stacks.
type StackRepository interface {
	Create(ctx context.Context, stack *models.Stack) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Stack, error)
	GetByName(ctx context.Context, hostID uuid.UUID, name string) (*models.Stack, error)
	Update(ctx context.Context, stack *models.Stack) error
	Delete(ctx context.Context, id uuid.UUID) error
	ExistsByName(ctx context.Context, hostID uuid.UUID, name string) (bool, error)
	List(ctx context.Context, opts postgres.StackListOptions) ([]*models.Stack, int64, error)
	ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.Stack, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.StackStatus) error
	UpdateCounts(ctx context.Context, id uuid.UUID, serviceCount, runningCount int) error
}

// HostService defines the host operations needed by the stack service.
type HostService interface {
	Get(ctx context.Context, id uuid.UUID) (*models.Host, error)
	GetClient(ctx context.Context, hostID uuid.UUID) (docker.ClientAPI, error)
}

// ContainerService defines the container operations needed by the stack service.
type ContainerService interface {
	ListByLabel(ctx context.Context, hostID uuid.UUID, key, value string) ([]*models.Container, error)
}
