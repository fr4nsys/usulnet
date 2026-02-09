// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Runbook represents a stored operational runbook.
type Runbook struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	Name        string          `json:"name" db:"name"`
	Description string          `json:"description,omitempty" db:"description"`
	Category    string          `json:"category,omitempty" db:"category"`
	Steps       json.RawMessage `json:"steps" db:"steps"` // JSON array of steps
	IsEnabled   bool            `json:"is_enabled" db:"is_enabled"`
	Version     int             `json:"version" db:"version"`
	CreatedBy   *uuid.UUID      `json:"created_by,omitempty" db:"created_by"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at" db:"updated_at"`
}

// RunbookStep represents a single step in a runbook.
type RunbookStep struct {
	Order       int               `json:"order"`
	Name        string            `json:"name"`
	Type        string            `json:"type"` // command, api_call, docker_exec, notify, wait, condition
	Config      map[string]string `json:"config"`
	OnFailure   string            `json:"on_failure,omitempty"` // continue, stop, skip_to
	Timeout     int               `json:"timeout,omitempty"`    // seconds
}

// RunbookExecution represents a single execution of a runbook.
type RunbookExecution struct {
	ID         uuid.UUID       `json:"id" db:"id"`
	RunbookID  uuid.UUID       `json:"runbook_id" db:"runbook_id"`
	Status     string          `json:"status" db:"status"` // running, completed, failed, cancelled
	Trigger    string          `json:"trigger" db:"trigger"` // manual, alert, schedule, event
	TriggerRef *string         `json:"trigger_ref,omitempty" db:"trigger_ref"`
	StepResults json.RawMessage `json:"step_results,omitempty" db:"step_results"`
	StartedAt  time.Time       `json:"started_at" db:"started_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty" db:"finished_at"`
	ExecutedBy *uuid.UUID      `json:"executed_by,omitempty" db:"executed_by"`
	CreatedAt  time.Time       `json:"created_at" db:"created_at"`
}

// CreateRunbookInput represents input for creating a runbook.
type CreateRunbookInput struct {
	Name        string        `json:"name" validate:"required,min=1,max=255"`
	Description string        `json:"description,omitempty" validate:"max=2000"`
	Category    string        `json:"category,omitempty" validate:"max=100"`
	Steps       []RunbookStep `json:"steps" validate:"required,min=1"`
	IsEnabled   bool          `json:"is_enabled"`
}

// UpdateRunbookInput represents input for updating a runbook.
type UpdateRunbookInput struct {
	Name        *string       `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Description *string       `json:"description,omitempty"`
	Category    *string       `json:"category,omitempty"`
	Steps       []RunbookStep `json:"steps,omitempty"`
	IsEnabled   *bool         `json:"is_enabled,omitempty"`
}

// RunbookListOptions represents options for listing runbooks.
type RunbookListOptions struct {
	Category  *string `json:"category,omitempty"`
	IsEnabled *bool   `json:"is_enabled,omitempty"`
	Limit     int     `json:"limit,omitempty"`
	Offset    int     `json:"offset,omitempty"`
}
