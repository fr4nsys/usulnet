// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import "github.com/google/uuid"

// StackStatusResponse contains detailed status information for a stack.
// This is separate from StackStatus which is a string enum type.
type StackStatusResponse struct {
	StackID      uuid.UUID             `json:"stack_id"`
	Status       StackStatus           `json:"status"`
	Services     []*StackServiceStatus `json:"services"`
	ServiceCount int                   `json:"service_count"`
	RunningCount int                   `json:"running_count"`
}

// StackServiceStatus contains status information for a single service in a stack.
type StackServiceStatus struct {
	Name    string `json:"name"`
	Running int    `json:"running"`
	Desired int    `json:"desired"`
	Healthy int    `json:"healthy,omitempty"`
	Exited  int    `json:"exited,omitempty"`
	Status  string `json:"status"`
}

// IsFullyRunning returns true if all desired replicas are running.
func (s *StackServiceStatus) IsFullyRunning() bool {
	return s.Running >= s.Desired && s.Desired > 0
}

// IsHealthy returns true if all running replicas are healthy.
func (s *StackServiceStatus) IsHealthy() bool {
	return s.Healthy >= s.Running && s.Running > 0
}

// NewStackStatusResponse creates a new StackStatusResponse with initialized slices.
func NewStackStatusResponse(stackID uuid.UUID, status StackStatus) *StackStatusResponse {
	return &StackStatusResponse{
		StackID:  stackID,
		Status:   status,
		Services: make([]*StackServiceStatus, 0),
	}
}
