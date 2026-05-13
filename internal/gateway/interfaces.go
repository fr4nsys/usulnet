// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package gateway

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/models"
)

// HostRepository defines the interface for host data access.
// This allows the gateway to verify agent tokens and update host status.
type HostRepository interface {
	GetByAgentToken(ctx context.Context, token string) (*models.HostInfo, error)
	UpdateStatus(ctx context.Context, hostID uuid.UUID, status string, lastSeen time.Time) error
	UpdateAgentInfo(ctx context.Context, hostID uuid.UUID, info *protocol.AgentInfo) error
}
