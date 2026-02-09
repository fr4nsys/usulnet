// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package git

import (
	"context"
	"fmt"

	"github.com/fr4nsys/usulnet/internal/models"
)

// Provider defines the interface for Git hosting providers (Gitea, GitHub, GitLab)
type Provider interface {
	// Connection
	TestConnection(ctx context.Context) error
	GetVersion(ctx context.Context) (string, error)

	// Repositories
	ListRepositories(ctx context.Context) ([]models.GitRepository, error)
	GetRepository(ctx context.Context, repoID string) (*models.GitRepository, error)
	CreateRepository(ctx context.Context, opts CreateRepoOptions) (*models.GitRepository, error)
	UpdateRepository(ctx context.Context, repoID string, opts UpdateRepoOptions) (*models.GitRepository, error)
	DeleteRepository(ctx context.Context, repoID string) error

	// Branches
	ListBranches(ctx context.Context, repoID string) ([]models.GitBranch, error)
	GetBranch(ctx context.Context, repoID, branch string) (*models.GitBranch, error)
	CreateBranch(ctx context.Context, repoID string, opts CreateBranchOptions) (*models.GitBranch, error)
	DeleteBranch(ctx context.Context, repoID, branch string) error

	// Tags
	ListTags(ctx context.Context, repoID string) ([]models.GitTag, error)
	CreateTag(ctx context.Context, repoID string, opts CreateTagOptions) (*models.GitTag, error)
	DeleteTag(ctx context.Context, repoID, tag string) error

	// Commits
	ListCommits(ctx context.Context, repoID string, opts ListCommitsOptions) ([]models.GitCommit, error)
	GetCommit(ctx context.Context, repoID, sha string) (*models.GitCommit, error)

	// Files
	GetFileContent(ctx context.Context, repoID, path, ref string) (*models.GitFileContent, error)
	ListTree(ctx context.Context, repoID, path, ref string) ([]models.GitTreeEntry, error)
	CreateOrUpdateFile(ctx context.Context, repoID, path string, opts UpdateFileOptions) error

	// Pull Requests / Merge Requests
	ListPullRequests(ctx context.Context, repoID string, opts ListPROptions) ([]models.GitPullRequest, error)
	GetPullRequest(ctx context.Context, repoID string, number int64) (*models.GitPullRequest, error)
	CreatePullRequest(ctx context.Context, repoID string, opts CreatePROptions) (*models.GitPullRequest, error)
	MergePullRequest(ctx context.Context, repoID string, number int64, opts MergePROptions) error

	// Issues
	ListIssues(ctx context.Context, repoID string, opts ListIssueOptions) ([]models.GitIssue, error)
	GetIssue(ctx context.Context, repoID string, number int64) (*models.GitIssue, error)
	CreateIssue(ctx context.Context, repoID string, opts CreateIssueOptions) (*models.GitIssue, error)

	// Releases
	ListReleases(ctx context.Context, repoID string) ([]models.GitRelease, error)
	GetLatestRelease(ctx context.Context, repoID string) (*models.GitRelease, error)
	CreateRelease(ctx context.Context, repoID string, opts CreateReleaseOptions) (*models.GitRelease, error)

	// Webhooks
	ListWebhooks(ctx context.Context, repoID string) ([]models.GitWebhook, error)
	CreateWebhook(ctx context.Context, repoID string, opts CreateWebhookOptions) (*models.GitWebhook, error)
	DeleteWebhook(ctx context.Context, repoID string, hookID int64) error

	// Deploy Keys
	ListDeployKeys(ctx context.Context, repoID string) ([]models.GitDeployKey, error)
	CreateDeployKey(ctx context.Context, repoID string, opts CreateDeployKeyOptions) (*models.GitDeployKey, error)
	DeleteDeployKey(ctx context.Context, repoID string, keyID int64) error

	// Templates (for repo creation)
	ListGitignoreTemplates(ctx context.Context) ([]string, error)
	ListLicenseTemplates(ctx context.Context) ([]LicenseTemplate, error)
}

// ============================================================================
// Option Types
// ============================================================================

// CreateRepoOptions for creating a repository
type CreateRepoOptions struct {
	Name        string
	Description string
	Private     bool
	AutoInit    bool
	Gitignore   string
	License     string
}

// UpdateRepoOptions for updating a repository
type UpdateRepoOptions struct {
	Name          *string
	Description   *string
	Private       *bool
	Archived      *bool
	DefaultBranch *string
}

// CreateBranchOptions for creating a branch
type CreateBranchOptions struct {
	Name   string
	Source string // branch name or commit SHA
}

// CreateTagOptions for creating a tag
type CreateTagOptions struct {
	Name    string
	Target  string // branch name or commit SHA
	Message string
}

// ListCommitsOptions for listing commits
type ListCommitsOptions struct {
	SHA     string // branch name or commit SHA
	Path    string // file path filter
	Page    int
	PerPage int
}

// UpdateFileOptions for creating/updating a file
type UpdateFileOptions struct {
	Branch  string
	Message string
	Content []byte
	SHA     string // required for updates
}

// ListPROptions for listing pull requests
type ListPROptions struct {
	State   string // open, closed, all
	Page    int
	PerPage int
}

// CreatePROptions for creating a pull request
type CreatePROptions struct {
	Title      string
	Body       string
	HeadBranch string
	BaseBranch string
	Draft      bool
}

// MergePROptions for merging a pull request
type MergePROptions struct {
	MergeMethod   string // merge, squash, rebase
	CommitTitle   string
	CommitMessage string
	Squash        bool
}

// ListIssueOptions for listing issues
type ListIssueOptions struct {
	State   string // open, closed, all
	Page    int
	PerPage int
}

// CreateIssueOptions for creating an issue
type CreateIssueOptions struct {
	Title     string
	Body      string
	Labels    []string
	Assignees []string
}

// CreateReleaseOptions for creating a release
type CreateReleaseOptions struct {
	TagName    string
	Name       string
	Body       string
	Draft      bool
	Prerelease bool
	Target     string // branch or commit
}

// CreateWebhookOptions for creating a webhook
type CreateWebhookOptions struct {
	URL         string
	Secret      string
	Events      []string
	Active      bool
	ContentType string
}

// CreateDeployKeyOptions for creating a deploy key
type CreateDeployKeyOptions struct {
	Title    string
	Key      string
	ReadOnly bool
}

// LicenseTemplate represents a license template
type LicenseTemplate struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// ============================================================================
// Factory
// ============================================================================

// NewProvider creates a new Git provider based on type
func NewProvider(providerType models.GitProviderType, baseURL, token string) (Provider, error) {
	switch providerType {
	case models.GitProviderGitea:
		return NewGiteaProvider(baseURL, token)
	case models.GitProviderGitHub:
		return NewGitHubProvider(baseURL, token)
	case models.GitProviderGitLab:
		return NewGitLabProvider(baseURL, token)
	default:
		return nil, fmt.Errorf("unknown provider type: %s", providerType)
	}
}
