// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// CrontabCommandType defines how a cron job command is executed.
type CrontabCommandType string

const (
	// CrontabCommandShell executes the command on the host shell.
	CrontabCommandShell CrontabCommandType = "shell"
	// CrontabCommandDocker executes the command inside a Docker container.
	CrontabCommandDocker CrontabCommandType = "docker"
	// CrontabCommandHTTP performs an HTTP webhook call.
	CrontabCommandHTTP CrontabCommandType = "http"
)

// CrontabEntry represents a managed cron job.
type CrontabEntry struct {
	ID          uuid.UUID          `json:"id" db:"id"`
	HostID      uuid.UUID          `json:"host_id" db:"host_id"`
	Name        string             `json:"name" db:"name"`
	Description string             `json:"description,omitempty" db:"description"`
	Schedule    string             `json:"schedule" db:"schedule"`
	CommandType CrontabCommandType `json:"command_type" db:"command_type"`
	Command     string             `json:"command" db:"command"`
	ContainerID *string            `json:"container_id,omitempty" db:"container_id"`
	WorkingDir  *string            `json:"working_dir,omitempty" db:"working_dir"`
	HTTPMethod  *string            `json:"http_method,omitempty" db:"http_method"`
	HTTPURL     *string            `json:"http_url,omitempty" db:"http_url"`

	Enabled       bool       `json:"enabled" db:"enabled"`
	RunCount      int64      `json:"run_count" db:"run_count"`
	FailCount     int64      `json:"fail_count" db:"fail_count"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty" db:"last_run_at"`
	LastRunStatus *string    `json:"last_run_status,omitempty" db:"last_run_status"`
	LastRunOutput *string    `json:"last_run_output,omitempty" db:"last_run_output"`
	NextRunAt     *time.Time `json:"next_run_at,omitempty" db:"next_run_at"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
}

// CrontabExecution records one execution of a cron job.
type CrontabExecution struct {
	ID         uuid.UUID `json:"id" db:"id"`
	EntryID    uuid.UUID `json:"entry_id" db:"entry_id"`
	HostID     uuid.UUID `json:"host_id" db:"host_id"`
	Status     string    `json:"status" db:"status"`
	Output     string    `json:"output,omitempty" db:"output"`
	Error      string    `json:"error,omitempty" db:"error"`
	ExitCode   *int      `json:"exit_code,omitempty" db:"exit_code"`
	DurationMs int64     `json:"duration_ms" db:"duration_ms"`
	StartedAt  time.Time `json:"started_at" db:"started_at"`
	FinishedAt time.Time `json:"finished_at" db:"finished_at"`
}

// CreateCrontabInput is the input for creating a new crontab entry.
type CreateCrontabInput struct {
	Name        string
	Description string
	Schedule    string
	CommandType CrontabCommandType
	Command     string
	ContainerID *string
	WorkingDir  *string
	HTTPMethod  *string
	HTTPURL     *string
	Enabled     bool
}

// UpdateCrontabInput is the input for updating a crontab entry.
type UpdateCrontabInput struct {
	Name        *string
	Description *string
	Schedule    *string
	CommandType *CrontabCommandType
	Command     *string
	ContainerID *string
	WorkingDir  *string
	HTTPMethod  *string
	HTTPURL     *string
	Enabled     *bool
}

// CrontabStats holds aggregate statistics for the crontab dashboard.
type CrontabStats struct {
	Total    int `json:"total"`
	Enabled  int `json:"enabled"`
	Disabled int `json:"disabled"`
	Running  int `json:"running"`
}
