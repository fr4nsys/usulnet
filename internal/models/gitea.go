// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// GiteaConnectionStatus represents the status of a Gitea connection
type GiteaConnectionStatus string

const (
	GiteaStatusPending   GiteaConnectionStatus = "pending"
	GiteaStatusConnected GiteaConnectionStatus = "connected"
	GiteaStatusError     GiteaConnectionStatus = "error"
	GiteaStatusDisabled  GiteaConnectionStatus = "disabled"
)

// GiteaConnection represents a connection to a Gitea instance
type GiteaConnection struct {
	ID                     uuid.UUID             `json:"id" db:"id"`
	HostID                 uuid.UUID             `json:"host_id" db:"host_id"`
	Name                   string                `json:"name" db:"name"`
	URL                    string                `json:"url" db:"url"`
	APITokenEncrypted      string                `json:"-" db:"api_token_encrypted"`
	WebhookSecretEncrypted *string               `json:"-" db:"webhook_secret_encrypted"`
	Status                 GiteaConnectionStatus `json:"status" db:"status"`
	StatusMessage          *string               `json:"status_message,omitempty" db:"status_message"`
	LastSyncAt             *time.Time            `json:"last_sync_at,omitempty" db:"last_sync_at"`
	ReposCount             int                   `json:"repos_count" db:"repos_count"`
	AutoSync               bool                  `json:"auto_sync" db:"auto_sync"`
	SyncIntervalMinutes    int                   `json:"sync_interval_minutes" db:"sync_interval_minutes"`
	GiteaVersion           *string               `json:"gitea_version,omitempty" db:"gitea_version"`
	CreatedAt              time.Time             `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time             `json:"updated_at" db:"updated_at"`
	CreatedBy              *uuid.UUID            `json:"created_by,omitempty" db:"created_by"`
}

// GiteaRepository represents a synced repository from Gitea
type GiteaRepository struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	ConnectionID  uuid.UUID  `json:"connection_id" db:"connection_id"`
	GiteaID       int64      `json:"gitea_id" db:"gitea_id"`
	FullName      string     `json:"full_name" db:"full_name"`
	Description   *string    `json:"description,omitempty" db:"description"`
	CloneURL      string     `json:"clone_url" db:"clone_url"`
	HTMLURL       string     `json:"html_url" db:"html_url"`
	DefaultBranch string     `json:"default_branch" db:"default_branch"`
	IsPrivate     bool       `json:"is_private" db:"is_private"`
	IsFork        bool       `json:"is_fork" db:"is_fork"`
	IsArchived    bool       `json:"is_archived" db:"is_archived"`
	StarsCount    int        `json:"stars_count" db:"stars_count"`
	ForksCount    int        `json:"forks_count" db:"forks_count"`
	OpenIssues    int        `json:"open_issues" db:"open_issues"`
	SizeKB        int64      `json:"size_kb" db:"size_kb"`
	LastCommitSHA *string    `json:"last_commit_sha,omitempty" db:"last_commit_sha"`
	LastCommitAt  *time.Time `json:"last_commit_at,omitempty" db:"last_commit_at"`
	LastSyncAt    *time.Time `json:"last_sync_at,omitempty" db:"last_sync_at"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
}

// GiteaWebhookEvent represents a received webhook event
type GiteaWebhookEvent struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	ConnectionID   uuid.UUID  `json:"connection_id" db:"connection_id"`
	RepositoryID   *uuid.UUID `json:"repository_id,omitempty" db:"repository_id"`
	EventType      string     `json:"event_type" db:"event_type"`
	DeliveryID     *string    `json:"delivery_id,omitempty" db:"delivery_id"`
	Payload        []byte     `json:"payload" db:"payload"` // JSONB
	Processed      bool       `json:"processed" db:"processed"`
	ProcessedAt    *time.Time `json:"processed_at,omitempty" db:"processed_at"`
	ProcessResult  *string    `json:"process_result,omitempty" db:"process_result"`
	ProcessError   *string    `json:"process_error,omitempty" db:"process_error"`
	ReceivedAt     time.Time  `json:"received_at" db:"received_at"`
}

// GiteaWebhookEventType constants
const (
	GiteaEventPush         = "push"
	GiteaEventPullRequest  = "pull_request"
	GiteaEventRelease      = "release"
	GiteaEventCreate       = "create"
	GiteaEventDelete       = "delete"
	GiteaEventIssues       = "issues"
	GiteaEventIssueComment = "issue_comment"
)
