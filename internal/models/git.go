// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Provider Types
// ============================================================================

// GitProviderType identifies the Git hosting provider
type GitProviderType string

const (
	GitProviderGitea  GitProviderType = "gitea"
	GitProviderGitHub GitProviderType = "github"
	GitProviderGitLab GitProviderType = "gitlab"
)

// String returns the display name for the provider
func (p GitProviderType) String() string {
	switch p {
	case GitProviderGitea:
		return "Gitea"
	case GitProviderGitHub:
		return "GitHub"
	case GitProviderGitLab:
		return "GitLab"
	default:
		return string(p)
	}
}

// Icon returns the Font Awesome icon class for the provider
func (p GitProviderType) Icon() string {
	switch p {
	case GitProviderGitea:
		return "fa-leaf" // Gitea's logo is a tea leaf
	case GitProviderGitHub:
		return "fa-github"
	case GitProviderGitLab:
		return "fa-gitlab"
	default:
		return "fa-code-branch"
	}
}

// Color returns the brand color class for the provider
func (p GitProviderType) Color() string {
	switch p {
	case GitProviderGitea:
		return "text-green-400"
	case GitProviderGitHub:
		return "text-gray-100"
	case GitProviderGitLab:
		return "text-orange-400"
	default:
		return "text-blue-400"
	}
}

// DefaultURL returns the default API URL for the provider
func (p GitProviderType) DefaultURL() string {
	switch p {
	case GitProviderGitHub:
		return "https://api.github.com"
	case GitProviderGitLab:
		return "https://gitlab.com"
	default:
		return ""
	}
}

// ============================================================================
// Connection Status
// ============================================================================

// GitConnectionStatus represents the status of a Git connection
type GitConnectionStatus string

const (
	GitStatusPending   GitConnectionStatus = "pending"
	GitStatusConnected GitConnectionStatus = "connected"
	GitStatusError     GitConnectionStatus = "error"
	GitStatusDisabled  GitConnectionStatus = "disabled"
)

// ============================================================================
// Unified Git Connection Model
// ============================================================================

// GitConnection represents a connection to any Git provider (Gitea, GitHub, GitLab)
// This is the unified model that works across all providers.
// NOTE: For backwards compatibility, this maps to the existing gitea_connections table
// with an additional provider_type column.
type GitConnection struct {
	ID                     uuid.UUID           `json:"id" db:"id"`
	HostID                 uuid.UUID           `json:"host_id" db:"host_id"`
	ProviderType           GitProviderType     `json:"provider_type" db:"provider_type"`
	Name                   string              `json:"name" db:"name"`
	URL                    string              `json:"url" db:"url"`
	APITokenEncrypted      string              `json:"-" db:"api_token_encrypted"`
	WebhookSecretEncrypted *string             `json:"-" db:"webhook_secret_encrypted"`
	Status                 GitConnectionStatus `json:"status" db:"status"`
	StatusMessage          *string             `json:"status_message,omitempty" db:"status_message"`
	LastSyncAt             *time.Time          `json:"last_sync_at,omitempty" db:"last_sync_at"`
	ReposCount             int                 `json:"repos_count" db:"repos_count"`
	AutoSync               bool                `json:"auto_sync" db:"auto_sync"`
	SyncIntervalMinutes    int                 `json:"sync_interval_minutes" db:"sync_interval_minutes"`
	ProviderVersion        *string             `json:"provider_version,omitempty" db:"gitea_version"` // Reuses gitea_version column
	CreatedAt              time.Time           `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time           `json:"updated_at" db:"updated_at"`
	CreatedBy              *uuid.UUID          `json:"created_by,omitempty" db:"created_by"`
}

// ============================================================================
// Unified Git Repository Model
// ============================================================================

// GitRepository represents a synced repository from any Git provider.
// NOTE: For backwards compatibility, this maps to the existing gitea_repositories table
// with an additional provider_type column.
type GitRepository struct {
	ID            uuid.UUID       `json:"id" db:"id"`
	ConnectionID  uuid.UUID       `json:"connection_id" db:"connection_id"`
	ProviderType  GitProviderType `json:"provider_type" db:"provider_type"`
	ProviderID    int64           `json:"provider_id" db:"gitea_id"` // Reuses gitea_id column (provider-specific ID)
	FullName      string          `json:"full_name" db:"full_name"`
	Description   *string         `json:"description,omitempty" db:"description"`
	CloneURL      string          `json:"clone_url" db:"clone_url"`
	HTMLURL       string          `json:"html_url" db:"html_url"`
	DefaultBranch string          `json:"default_branch" db:"default_branch"`
	IsPrivate     bool            `json:"is_private" db:"is_private"`
	IsFork        bool            `json:"is_fork" db:"is_fork"`
	IsArchived    bool            `json:"is_archived" db:"is_archived"`
	StarsCount    int             `json:"stars_count" db:"stars_count"`
	ForksCount    int             `json:"forks_count" db:"forks_count"`
	OpenIssues    int             `json:"open_issues" db:"open_issues"`
	SizeKB        int64           `json:"size_kb" db:"size_kb"`
	LastCommitSHA *string         `json:"last_commit_sha,omitempty" db:"last_commit_sha"`
	LastCommitAt  *time.Time      `json:"last_commit_at,omitempty" db:"last_commit_at"`
	LastSyncAt    *time.Time      `json:"last_sync_at,omitempty" db:"last_sync_at"`
	CreatedAt     time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at" db:"updated_at"`
}

// ============================================================================
// Provider Interface Types (for service layer)
// ============================================================================

// GitBranch represents a branch in a repository
type GitBranch struct {
	Name      string `json:"name"`
	CommitSHA string `json:"commit_sha"`
	Protected bool   `json:"protected"`
}

// GitCommit represents a commit
type GitCommit struct {
	SHA       string     `json:"sha"`
	Message   string     `json:"message"`
	Author    string     `json:"author"`
	Email     string     `json:"email"`
	Date      time.Time  `json:"date"`
	HTMLURL   string     `json:"html_url"`
	Additions int        `json:"additions"`
	Deletions int        `json:"deletions"`
}

// GitTag represents a tag
type GitTag struct {
	Name      string     `json:"name"`
	CommitSHA string     `json:"commit_sha"`
	Message   string     `json:"message"`
	Tagger    string     `json:"tagger"`
	Date      *time.Time `json:"date,omitempty"`
}

// GitPullRequest represents a pull/merge request
type GitPullRequest struct {
	ID          int64      `json:"id"`
	Number      int64      `json:"number"`
	Title       string     `json:"title"`
	Body        string     `json:"body"`
	State       string     `json:"state"` // open, closed, merged
	HeadBranch  string     `json:"head_branch"`
	HeadSHA     string     `json:"head_sha"`
	BaseBranch  string     `json:"base_branch"`
	AuthorName  string     `json:"author_name"`
	AuthorLogin string     `json:"author_login"`
	AvatarURL   string     `json:"avatar_url"`
	Mergeable   bool       `json:"mergeable"`
	Merged      bool       `json:"merged"`
	Comments    int        `json:"comments"`
	HTMLURL     string     `json:"html_url"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// GitIssue represents an issue
type GitIssue struct {
	ID          int64      `json:"id"`
	Number      int64      `json:"number"`
	Title       string     `json:"title"`
	Body        string     `json:"body"`
	State       string     `json:"state"` // open, closed
	AuthorName  string     `json:"author_name"`
	AuthorLogin string     `json:"author_login"`
	AvatarURL   string     `json:"avatar_url"`
	Labels      []string   `json:"labels"`
	Comments    int        `json:"comments"`
	HTMLURL     string     `json:"html_url"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// GitFileContent represents file content from a repository
type GitFileContent struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	SHA      string `json:"sha"`
	Size     int64  `json:"size"`
	Type     string `json:"type"` // file, dir, symlink
	Content  []byte `json:"content,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	HTMLURL  string `json:"html_url"`
}

// GitTreeEntry represents an entry in a directory listing
type GitTreeEntry struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Type string `json:"type"` // file, dir, symlink
	Size int64  `json:"size"`
	SHA  string `json:"sha"`
}

// GitRelease represents a release
type GitRelease struct {
	ID           int64      `json:"id"`
	TagName      string     `json:"tag_name"`
	Name         string     `json:"name"`
	Body         string     `json:"body"`
	IsDraft      bool       `json:"is_draft"`
	IsPrerelease bool       `json:"is_prerelease"`
	AuthorLogin  string     `json:"author_login"`
	HTMLURL      string     `json:"html_url"`
	CreatedAt    time.Time  `json:"created_at"`
	PublishedAt  *time.Time `json:"published_at,omitempty"`
}

// GitWebhook represents a webhook configuration
type GitWebhook struct {
	ID        int64     `json:"id"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// GitDeployKey represents a deploy key
type GitDeployKey struct {
	ID          int64     `json:"id"`
	Title       string    `json:"title"`
	Key         string    `json:"key"`
	Fingerprint string    `json:"fingerprint"`
	ReadOnly    bool      `json:"read_only"`
	CreatedAt   time.Time `json:"created_at"`
}

// ============================================================================
// Conversion helpers (for backwards compatibility with existing Gitea code)
// ============================================================================

// ToGiteaConnection converts a GitConnection to the legacy GiteaConnection type
func (c *GitConnection) ToGiteaConnection() *GiteaConnection {
	return &GiteaConnection{
		ID:                     c.ID,
		HostID:                 c.HostID,
		Name:                   c.Name,
		URL:                    c.URL,
		APITokenEncrypted:      c.APITokenEncrypted,
		WebhookSecretEncrypted: c.WebhookSecretEncrypted,
		Status:                 GiteaConnectionStatus(c.Status),
		StatusMessage:          c.StatusMessage,
		LastSyncAt:             c.LastSyncAt,
		ReposCount:             c.ReposCount,
		AutoSync:               c.AutoSync,
		SyncIntervalMinutes:    c.SyncIntervalMinutes,
		GiteaVersion:           c.ProviderVersion,
		CreatedAt:              c.CreatedAt,
		UpdatedAt:              c.UpdatedAt,
		CreatedBy:              c.CreatedBy,
	}
}

// FromGiteaConnection creates a GitConnection from a legacy GiteaConnection
func FromGiteaConnection(gc *GiteaConnection) *GitConnection {
	return &GitConnection{
		ID:                     gc.ID,
		HostID:                 gc.HostID,
		ProviderType:           GitProviderGitea,
		Name:                   gc.Name,
		URL:                    gc.URL,
		APITokenEncrypted:      gc.APITokenEncrypted,
		WebhookSecretEncrypted: gc.WebhookSecretEncrypted,
		Status:                 GitConnectionStatus(gc.Status),
		StatusMessage:          gc.StatusMessage,
		LastSyncAt:             gc.LastSyncAt,
		ReposCount:             gc.ReposCount,
		AutoSync:               gc.AutoSync,
		SyncIntervalMinutes:    gc.SyncIntervalMinutes,
		ProviderVersion:        gc.GiteaVersion,
		CreatedAt:              gc.CreatedAt,
		UpdatedAt:              gc.UpdatedAt,
		CreatedBy:              gc.CreatedBy,
	}
}

// ToGiteaRepository converts a GitRepository to the legacy GiteaRepository type
func (r *GitRepository) ToGiteaRepository() *GiteaRepository {
	return &GiteaRepository{
		ID:            r.ID,
		ConnectionID:  r.ConnectionID,
		GiteaID:       r.ProviderID,
		FullName:      r.FullName,
		Description:   r.Description,
		CloneURL:      r.CloneURL,
		HTMLURL:       r.HTMLURL,
		DefaultBranch: r.DefaultBranch,
		IsPrivate:     r.IsPrivate,
		IsFork:        r.IsFork,
		IsArchived:    r.IsArchived,
		StarsCount:    r.StarsCount,
		ForksCount:    r.ForksCount,
		OpenIssues:    r.OpenIssues,
		SizeKB:        r.SizeKB,
		LastCommitSHA: r.LastCommitSHA,
		LastCommitAt:  r.LastCommitAt,
		LastSyncAt:    r.LastSyncAt,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
}

// FromGiteaRepository creates a GitRepository from a legacy GiteaRepository
func FromGiteaRepository(gr *GiteaRepository) *GitRepository {
	return &GitRepository{
		ID:            gr.ID,
		ConnectionID:  gr.ConnectionID,
		ProviderType:  GitProviderGitea,
		ProviderID:    gr.GiteaID,
		FullName:      gr.FullName,
		Description:   gr.Description,
		CloneURL:      gr.CloneURL,
		HTMLURL:       gr.HTMLURL,
		DefaultBranch: gr.DefaultBranch,
		IsPrivate:     gr.IsPrivate,
		IsFork:        gr.IsFork,
		IsArchived:    gr.IsArchived,
		StarsCount:    gr.StarsCount,
		ForksCount:    gr.ForksCount,
		OpenIssues:    gr.OpenIssues,
		SizeKB:        gr.SizeKB,
		LastCommitSHA: gr.LastCommitSHA,
		LastCommitAt:  gr.LastCommitAt,
		LastSyncAt:    gr.LastSyncAt,
		CreatedAt:     gr.CreatedAt,
		UpdatedAt:     gr.UpdatedAt,
	}
}
