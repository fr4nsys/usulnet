// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package agent provides the executor wrapper for the usulnet agent.
package agent

import (
	"context"

	"github.com/fr4nsys/usulnet/internal/agent/executor"
	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Executor wraps the command executor for the agent.
type Executor struct {
	exec *executor.Executor
}

// NewExecutor creates a new executor wrapper.
func NewExecutor(dockerClient *docker.Client, log *logger.Logger) *Executor {
	return &Executor{
		exec: executor.New(dockerClient, log),
	}
}

// Execute executes a command and returns the result.
func (e *Executor) Execute(ctx context.Context, cmd *protocol.Command) *protocol.CommandResult {
	return e.exec.Execute(ctx, cmd)
}
