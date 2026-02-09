// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package git

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/integrations/gitea"
	"github.com/fr4nsys/usulnet/internal/models"
)

// GiteaProvider implements Provider interface for Gitea
type GiteaProvider struct {
	client *gitea.Client
}

// NewGiteaProvider creates a new Gitea provider
func NewGiteaProvider(baseURL, token string) (*GiteaProvider, error) {
	client := gitea.NewClient(baseURL, token)
	return &GiteaProvider{client: client}, nil
}

// TestConnection tests the connection
func (p *GiteaProvider) TestConnection(ctx context.Context) error {
	_, err := p.client.GetVersion(ctx)
	return err
}

// GetVersion gets the Gitea version
func (p *GiteaProvider) GetVersion(ctx context.Context) (string, error) {
	ver, err := p.client.GetVersion(ctx)
	if err != nil {
		return "", err
	}
	return ver.Version, nil
}

// ListRepositories lists all accessible repositories
func (p *GiteaProvider) ListRepositories(ctx context.Context) ([]models.GitRepository, error) {
	repos, err := p.client.ListAllRepos(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]models.GitRepository, len(repos))
	for i, r := range repos {
		result[i] = giteaRepoToModel(r)
	}
	return result, nil
}

// GetRepository gets a repository by ID
func (p *GiteaProvider) GetRepository(ctx context.Context, repoID string) (*models.GitRepository, error) {
	// Parse owner/name from repoID
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	repo, err := p.client.GetRepository(ctx, owner, name)
	if err != nil {
		return nil, err
	}

	result := giteaRepoToModel(*repo)
	return &result, nil
}

// CreateRepository creates a new repository
func (p *GiteaProvider) CreateRepository(ctx context.Context, opts CreateRepoOptions) (*models.GitRepository, error) {
	apiOpts := gitea.CreateRepoOptions{
		Name:        opts.Name,
		Description: opts.Description,
		Private:     opts.Private,
		AutoInit:    opts.AutoInit,
		Gitignores:  opts.Gitignore,
		License:     opts.License,
	}

	repo, err := p.client.CreateUserRepository(ctx, apiOpts)
	if err != nil {
		return nil, err
	}

	result := giteaRepoToModel(*repo)
	return &result, nil
}

// UpdateRepository updates a repository
func (p *GiteaProvider) UpdateRepository(ctx context.Context, repoID string, opts UpdateRepoOptions) (*models.GitRepository, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := gitea.EditRepoOptions{
		Name:          opts.Name,
		Description:   opts.Description,
		Private:       opts.Private,
		Archived:      opts.Archived,
		DefaultBranch: opts.DefaultBranch,
	}

	repo, err := p.client.EditRepository(ctx, owner, name, apiOpts)
	if err != nil {
		return nil, err
	}

	result := giteaRepoToModel(*repo)
	return &result, nil
}

// DeleteRepository deletes a repository
func (p *GiteaProvider) DeleteRepository(ctx context.Context, repoID string) error {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return err
	}
	return p.client.DeleteRepository(ctx, owner, name)
}

// ListBranches lists branches
func (p *GiteaProvider) ListBranches(ctx context.Context, repoID string) ([]models.GitBranch, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	branches, err := p.client.ListBranches(ctx, owner, name)
	if err != nil {
		return nil, err
	}

	result := make([]models.GitBranch, len(branches))
	for i, b := range branches {
		result[i] = models.GitBranch{
			Name:      b.Name,
			CommitSHA: b.Commit.ID,
			Protected: b.Protected,
		}
	}
	return result, nil
}

// GetBranch gets a branch
func (p *GiteaProvider) GetBranch(ctx context.Context, repoID, branch string) (*models.GitBranch, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	b, err := p.client.GetBranch(ctx, owner, name, branch)
	if err != nil {
		return nil, err
	}

	return &models.GitBranch{
		Name:      b.Name,
		CommitSHA: b.Commit.ID,
		Protected: b.Protected,
	}, nil
}

// CreateBranch creates a branch
func (p *GiteaProvider) CreateBranch(ctx context.Context, repoID string, opts CreateBranchOptions) (*models.GitBranch, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := gitea.CreateBranchOptions{
		NewBranchName: opts.Name,
		OldBranchName: opts.Source,
	}

	b, err := p.client.CreateBranch(ctx, owner, name, apiOpts)
	if err != nil {
		return nil, err
	}

	return &models.GitBranch{
		Name:      b.Name,
		CommitSHA: b.Commit.ID,
		Protected: b.Protected,
	}, nil
}

// DeleteBranch deletes a branch
func (p *GiteaProvider) DeleteBranch(ctx context.Context, repoID, branch string) error {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return err
	}
	return p.client.DeleteBranch(ctx, owner, name, branch)
}

// ListTags lists tags
func (p *GiteaProvider) ListTags(ctx context.Context, repoID string) ([]models.GitTag, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	tags, err := p.client.ListTags(ctx, owner, name, 1, 100)
	if err != nil {
		return nil, err
	}

	result := make([]models.GitTag, len(tags))
	for i, t := range tags {
		commitSHA := t.ID // The tag ID is the commit SHA
		if t.Commit != nil {
			commitSHA = t.Commit.ID
		}
		result[i] = models.GitTag{
			Name:      t.Name,
			CommitSHA: commitSHA,
			Message:   t.Message,
		}
	}
	return result, nil
}

// CreateTag creates a tag
func (p *GiteaProvider) CreateTag(ctx context.Context, repoID string, opts CreateTagOptions) (*models.GitTag, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := gitea.CreateTagOptions{
		TagName: opts.Name,
		Target:  opts.Target,
		Message: opts.Message,
	}

	t, err := p.client.CreateTag(ctx, owner, name, apiOpts)
	if err != nil {
		return nil, err
	}

	commitSHA := t.ID
	if t.Commit != nil {
		commitSHA = t.Commit.ID
	}

	return &models.GitTag{
		Name:      t.Name,
		CommitSHA: commitSHA,
		Message:   t.Message,
	}, nil
}

// DeleteTag deletes a tag
func (p *GiteaProvider) DeleteTag(ctx context.Context, repoID, tag string) error {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return err
	}
	return p.client.DeleteTag(ctx, owner, name, tag)
}

// ListCommits lists commits
func (p *GiteaProvider) ListCommits(ctx context.Context, repoID string, opts ListCommitsOptions) ([]models.GitCommit, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 30
	}

	// Use SHA as ref, or empty for default branch
	ref := opts.SHA

	commits, err := p.client.ListCommits(ctx, owner, name, ref, perPage)
	if err != nil {
		return nil, err
	}

	result := make([]models.GitCommit, len(commits))
	for i, c := range commits {
		var date time.Time
		if c.Commit.Author != nil && c.Commit.Author.Date != "" {
			date, _ = time.Parse(time.RFC3339, c.Commit.Author.Date)
		}
		authorName := ""
		authorEmail := ""
		if c.Commit.Author != nil {
			authorName = c.Commit.Author.Name
			authorEmail = c.Commit.Author.Email
		}
		result[i] = models.GitCommit{
			SHA:     c.SHA,
			Message: c.Commit.Message,
			Author:  authorName,
			Email:   authorEmail,
			Date:    date,
			HTMLURL: c.HTMLURL,
		}
	}
	return result, nil
}

// GetCommit gets a commit
func (p *GiteaProvider) GetCommit(ctx context.Context, repoID, sha string) (*models.GitCommit, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	c, err := p.client.GetCommit(ctx, owner, name, sha)
	if err != nil {
		return nil, err
	}

	var date time.Time
	if c.Commit.Author != nil && c.Commit.Author.Date != "" {
		date, _ = time.Parse(time.RFC3339, c.Commit.Author.Date)
	}
	authorName := ""
	authorEmail := ""
	if c.Commit.Author != nil {
		authorName = c.Commit.Author.Name
		authorEmail = c.Commit.Author.Email
	}

	return &models.GitCommit{
		SHA:     c.SHA,
		Message: c.Commit.Message,
		Author:  authorName,
		Email:   authorEmail,
		Date:    date,
		HTMLURL: c.HTMLURL,
	}, nil
}

// GetFileContent gets file content
func (p *GiteaProvider) GetFileContent(ctx context.Context, repoID, path, ref string) (*models.GitFileContent, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	content, err := p.client.GetRawFile(ctx, owner, name, path, ref)
	if err != nil {
		return nil, err
	}

	// Extract filename from path
	fileName := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		fileName = path[idx+1:]
	}

	return &models.GitFileContent{
		Path:    path,
		Name:    fileName,
		Content: content,
	}, nil
}

// ListTree lists directory contents
func (p *GiteaProvider) ListTree(ctx context.Context, repoID, path, ref string) ([]models.GitTreeEntry, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	entries, err := p.client.ListContents(ctx, owner, name, path, ref)
	if err != nil {
		return nil, err
	}

	result := make([]models.GitTreeEntry, len(entries))
	for i, e := range entries {
		result[i] = models.GitTreeEntry{
			Path: e.Path,
			Name: e.Name,
			Type: e.Type,
			Size: e.Size,
			SHA:  e.SHA,
		}
	}
	return result, nil
}

// CreateOrUpdateFile creates or updates a file
func (p *GiteaProvider) CreateOrUpdateFile(ctx context.Context, repoID, path string, opts UpdateFileOptions) error {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return err
	}

	// Content must be base64 encoded
	content := base64.StdEncoding.EncodeToString(opts.Content)

	apiOpts := gitea.UpdateFileOptions{
		Branch:  opts.Branch,
		Message: opts.Message,
		Content: content,
		SHA:     opts.SHA,
	}

	return p.client.UpdateFile(ctx, owner, name, path, apiOpts)
}

// ListPullRequests lists pull requests
func (p *GiteaProvider) ListPullRequests(ctx context.Context, repoID string, opts ListPROptions) ([]models.GitPullRequest, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := gitea.PRListOptions{
		State: opts.State,
		Page:  opts.Page,
		Limit: opts.PerPage,
	}

	prs, err := p.client.ListPullRequests(ctx, owner, name, apiOpts)
	if err != nil {
		return nil, err
	}

	result := make([]models.GitPullRequest, len(prs))
	for i, pr := range prs {
		result[i] = giteaPRToModel(pr)
	}
	return result, nil
}

// GetPullRequest gets a pull request
func (p *GiteaProvider) GetPullRequest(ctx context.Context, repoID string, number int64) (*models.GitPullRequest, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	pr, err := p.client.GetPullRequest(ctx, owner, name, number)
	if err != nil {
		return nil, err
	}

	result := giteaPRToModel(*pr)
	return &result, nil
}

// CreatePullRequest creates a pull request
func (p *GiteaProvider) CreatePullRequest(ctx context.Context, repoID string, opts CreatePROptions) (*models.GitPullRequest, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := gitea.CreatePullRequestOptions{
		Title: opts.Title,
		Body:  opts.Body,
		Head:  opts.HeadBranch,
		Base:  opts.BaseBranch,
	}

	pr, err := p.client.CreatePullRequest(ctx, owner, name, apiOpts)
	if err != nil {
		return nil, err
	}

	result := giteaPRToModel(*pr)
	return &result, nil
}

// MergePullRequest merges a pull request
func (p *GiteaProvider) MergePullRequest(ctx context.Context, repoID string, number int64, opts MergePROptions) error {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return err
	}

	apiOpts := gitea.MergePullRequestOptions{
		MergeStyle:        opts.MergeMethod,
		MergeTitleField:   opts.CommitTitle,
		MergeMessageField: opts.CommitMessage,
	}

	return p.client.MergePullRequest(ctx, owner, name, number, apiOpts)
}

// ListIssues lists issues
func (p *GiteaProvider) ListIssues(ctx context.Context, repoID string, opts ListIssueOptions) ([]models.GitIssue, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := gitea.IssueListOptions{
		State: opts.State,
		Page:  opts.Page,
		Limit: opts.PerPage,
	}

	issues, err := p.client.ListIssues(ctx, owner, name, apiOpts)
	if err != nil {
		return nil, err
	}

	result := make([]models.GitIssue, len(issues))
	for i, issue := range issues {
		result[i] = giteaIssueToModel(issue)
	}
	return result, nil
}

// GetIssue gets an issue
func (p *GiteaProvider) GetIssue(ctx context.Context, repoID string, number int64) (*models.GitIssue, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	issue, err := p.client.GetIssue(ctx, owner, name, number)
	if err != nil {
		return nil, err
	}

	result := giteaIssueToModel(*issue)
	return &result, nil
}

// CreateIssue creates an issue
func (p *GiteaProvider) CreateIssue(ctx context.Context, repoID string, opts CreateIssueOptions) (*models.GitIssue, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	// Note: Labels in the abstract interface are []string, but Gitea API requires []int64 (label IDs).
	// For now, we skip labels. A proper implementation would need to look up label IDs first.
	apiOpts := gitea.CreateIssueOptions{
		Title:     opts.Title,
		Body:      opts.Body,
		Assignees: opts.Assignees,
	}

	issue, err := p.client.CreateIssue(ctx, owner, name, apiOpts)
	if err != nil {
		return nil, err
	}

	result := giteaIssueToModel(*issue)
	return &result, nil
}

// ListReleases lists releases
func (p *GiteaProvider) ListReleases(ctx context.Context, repoID string) ([]models.GitRelease, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	releases, err := p.client.ListReleases(ctx, owner, name, 1, 30)
	if err != nil {
		return nil, err
	}

	result := make([]models.GitRelease, len(releases))
	for i, r := range releases {
		result[i] = giteaReleaseToModel(r)
	}
	return result, nil
}

// GetLatestRelease gets the latest release
func (p *GiteaProvider) GetLatestRelease(ctx context.Context, repoID string) (*models.GitRelease, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	r, err := p.client.GetLatestRelease(ctx, owner, name)
	if err != nil {
		return nil, err
	}

	result := giteaReleaseToModel(*r)
	return &result, nil
}

// CreateRelease creates a release
func (p *GiteaProvider) CreateRelease(ctx context.Context, repoID string, opts CreateReleaseOptions) (*models.GitRelease, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := gitea.CreateReleaseOptions{
		TagName:    opts.TagName,
		Name:       opts.Name,
		Body:       opts.Body,
		IsDraft:    opts.Draft,
		IsPrerelease: opts.Prerelease,
		Target:     opts.Target,
	}

	r, err := p.client.CreateRelease(ctx, owner, name, apiOpts)
	if err != nil {
		return nil, err
	}

	result := giteaReleaseToModel(*r)
	return &result, nil
}

// ListWebhooks lists webhooks
func (p *GiteaProvider) ListWebhooks(ctx context.Context, repoID string) ([]models.GitWebhook, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	hooks, err := p.client.ListHooks(ctx, owner, name)
	if err != nil {
		return nil, err
	}

	result := make([]models.GitWebhook, len(hooks))
	for i, h := range hooks {
		// URL is in Config map for Gitea hooks
		url := h.URL
		if url == "" && h.Config != nil {
			url = h.Config["url"]
		}
		result[i] = models.GitWebhook{
			ID:        h.ID,
			URL:       url,
			Events:    h.Events,
			Active:    h.Active,
			CreatedAt: h.CreatedAt,
		}
	}
	return result, nil
}

// CreateWebhook creates a webhook
func (p *GiteaProvider) CreateWebhook(ctx context.Context, repoID string, opts CreateWebhookOptions) (*models.GitWebhook, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := gitea.CreateHookOptions{
		Type: "gitea",
		Config: map[string]string{
			"url":          opts.URL,
			"secret":       opts.Secret,
			"content_type": "json",
		},
		Events: opts.Events,
		Active: opts.Active,
	}

	h, err := p.client.CreateHook(ctx, owner, name, apiOpts)
	if err != nil {
		return nil, err
	}

	url := h.URL
	if url == "" && h.Config != nil {
		url = h.Config["url"]
	}

	return &models.GitWebhook{
		ID:        h.ID,
		URL:       url,
		Events:    h.Events,
		Active:    h.Active,
		CreatedAt: h.CreatedAt,
	}, nil
}

// DeleteWebhook deletes a webhook
func (p *GiteaProvider) DeleteWebhook(ctx context.Context, repoID string, hookID int64) error {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return err
	}
	return p.client.DeleteHook(ctx, owner, name, hookID)
}

// ListDeployKeys lists deploy keys
func (p *GiteaProvider) ListDeployKeys(ctx context.Context, repoID string) ([]models.GitDeployKey, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	keys, err := p.client.ListDeployKeys(ctx, owner, name)
	if err != nil {
		return nil, err
	}

	result := make([]models.GitDeployKey, len(keys))
	for i, k := range keys {
		result[i] = models.GitDeployKey{
			ID:        k.ID,
			Title:     k.Title,
			Key:       k.Key,
			ReadOnly:  k.ReadOnly,
			CreatedAt: k.CreatedAt,
		}
	}
	return result, nil
}

// CreateDeployKey creates a deploy key
func (p *GiteaProvider) CreateDeployKey(ctx context.Context, repoID string, opts CreateDeployKeyOptions) (*models.GitDeployKey, error) {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := gitea.CreateDeployKeyOptions{
		Title:    opts.Title,
		Key:      opts.Key,
		ReadOnly: opts.ReadOnly,
	}

	k, err := p.client.CreateDeployKey(ctx, owner, name, apiOpts)
	if err != nil {
		return nil, err
	}

	return &models.GitDeployKey{
		ID:        k.ID,
		Title:     k.Title,
		Key:       k.Key,
		ReadOnly:  k.ReadOnly,
		CreatedAt: k.CreatedAt,
	}, nil
}

// DeleteDeployKey deletes a deploy key
func (p *GiteaProvider) DeleteDeployKey(ctx context.Context, repoID string, keyID int64) error {
	owner, name, err := giteaParseRepoID(repoID)
	if err != nil {
		return err
	}
	return p.client.DeleteDeployKey(ctx, owner, name, keyID)
}

// ListGitignoreTemplates lists gitignore templates
func (p *GiteaProvider) ListGitignoreTemplates(ctx context.Context) ([]string, error) {
	return p.client.ListGitignoreTemplates(ctx)
}

// ListLicenseTemplates lists license templates
func (p *GiteaProvider) ListLicenseTemplates(ctx context.Context) ([]LicenseTemplate, error) {
	licenses, err := p.client.ListLicenseTemplates(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]LicenseTemplate, len(licenses))
	for i, l := range licenses {
		result[i] = LicenseTemplate{
			Key:  l.Key,
			Name: l.Name,
			URL:  l.HTMLURL,
		}
	}
	return result, nil
}

// ============================================================================
// Helpers
// ============================================================================

func giteaParseRepoID(repoID string) (owner, name string, err error) {
	parts := strings.SplitN(repoID, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repo ID format, expected owner/name: %s", repoID)
	}
	return parts[0], parts[1], nil
}

func giteaRepoToModel(r gitea.APIRepository) models.GitRepository {
	var desc *string
	if r.Description != "" {
		desc = &r.Description
	}
	return models.GitRepository{
		ProviderType:  models.GitProviderGitea,
		ProviderID:    r.ID,
		FullName:      r.FullName,
		Description:   desc,
		CloneURL:      r.CloneURL,
		HTMLURL:       r.HTMLURL,
		DefaultBranch: r.DefaultBranch,
		IsPrivate:     r.Private,
		IsFork:        r.Fork,
		IsArchived:    r.Archived,
		StarsCount:    r.Stars,
		ForksCount:    r.Forks,
		OpenIssues:    r.OpenIssues,
		SizeKB:        int64(r.Size),
	}
}

func giteaPRToModel(pr gitea.APIPullRequest) models.GitPullRequest {
	return models.GitPullRequest{
		ID:          pr.ID,
		Number:      pr.Number,
		Title:       pr.Title,
		Body:        pr.Body,
		State:       pr.State,
		HeadBranch:  pr.Head.Ref,
		HeadSHA:     pr.Head.SHA,
		BaseBranch:  pr.Base.Ref,
		AuthorName:  pr.User.FullName,
		AuthorLogin: pr.User.Login,
		AvatarURL:   pr.User.AvatarURL,
		Mergeable:   pr.Mergeable,
		Merged:      pr.Merged,
		HTMLURL:     pr.HTMLURL,
		CreatedAt:   pr.CreatedAt,
		UpdatedAt:   pr.UpdatedAt,
	}
}

func giteaIssueToModel(i gitea.APIIssue) models.GitIssue {
	labels := make([]string, len(i.Labels))
	for j, l := range i.Labels {
		labels[j] = l.Name
	}
	return models.GitIssue{
		ID:          i.ID,
		Number:      i.Number,
		Title:       i.Title,
		Body:        i.Body,
		State:       i.State,
		AuthorName:  i.User.FullName,
		AuthorLogin: i.User.Login,
		AvatarURL:   i.User.AvatarURL,
		Labels:      labels,
		Comments:    i.Comments,
		HTMLURL:     i.HTMLURL,
		CreatedAt:   i.CreatedAt,
		UpdatedAt:   i.UpdatedAt,
	}
}

func giteaReleaseToModel(r gitea.APIRelease) models.GitRelease {
	return models.GitRelease{
		ID:           r.ID,
		TagName:      r.TagName,
		Name:         r.Name,
		Body:         r.Body,
		IsDraft:      r.IsDraft,
		IsPrerelease: r.IsPrerelease,
		AuthorLogin:  r.Author.Login,
		HTMLURL:      r.HTMLURL,
		CreatedAt:    r.CreatedAt,
		PublishedAt:  &r.PublishedAt,
	}
}
