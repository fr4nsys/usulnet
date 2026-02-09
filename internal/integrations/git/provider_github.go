// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package git

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/fr4nsys/usulnet/internal/integrations/github"
	"github.com/fr4nsys/usulnet/internal/models"
)

// GitHubProvider implements the Provider interface for GitHub
type GitHubProvider struct {
	client *github.Client
}

// NewGitHubProvider creates a new GitHub provider
func NewGitHubProvider(baseURL, token string) (*GitHubProvider, error) {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	client := github.NewClient(baseURL, token)
	return &GitHubProvider{client: client}, nil
}

// githubParseRepoID splits "owner/repo" into owner and repo
func githubParseRepoID(repoID string) (owner, repo string, err error) {
	parts := strings.SplitN(repoID, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repository ID format, expected 'owner/repo': %s", repoID)
	}
	return parts[0], parts[1], nil
}

// ============================================================================
// Connection
// ============================================================================

func (p *GitHubProvider) TestConnection(ctx context.Context) error {
	_, err := p.client.GetAuthenticatedUser(ctx)
	return err
}

func (p *GitHubProvider) GetVersion(ctx context.Context) (string, error) {
	// GitHub doesn't have a version endpoint, return "github.com"
	return "github.com", nil
}

// ============================================================================
// Repositories
// ============================================================================

func (p *GitHubProvider) ListRepositories(ctx context.Context) ([]models.GitRepository, error) {
	apiRepos, err := p.client.ListAllUserRepos(ctx)
	if err != nil {
		return nil, err
	}

	repos := make([]models.GitRepository, len(apiRepos))
	for i, r := range apiRepos {
		repos[i] = githubRepoToModel(r)
	}
	return repos, nil
}

func (p *GitHubProvider) GetRepository(ctx context.Context, repoID string) (*models.GitRepository, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiRepo, err := p.client.GetRepository(ctx, owner, repo)
	if err != nil {
		return nil, err
	}

	result := githubRepoToModel(*apiRepo)
	return &result, nil
}

func (p *GitHubProvider) CreateRepository(ctx context.Context, opts CreateRepoOptions) (*models.GitRepository, error) {
	apiOpts := github.CreateRepoOptions{
		Name:              opts.Name,
		Description:       opts.Description,
		Private:           opts.Private,
		AutoInit:          opts.AutoInit,
		GitignoreTemplate: opts.Gitignore,
		LicenseTemplate:   opts.License,
	}

	apiRepo, err := p.client.CreateUserRepo(ctx, apiOpts)
	if err != nil {
		return nil, err
	}

	result := githubRepoToModel(*apiRepo)
	return &result, nil
}

func (p *GitHubProvider) UpdateRepository(ctx context.Context, repoID string, opts UpdateRepoOptions) (*models.GitRepository, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := github.UpdateRepoOptions{
		Name:          opts.Name,
		Description:   opts.Description,
		Private:       opts.Private,
		Archived:      opts.Archived,
		DefaultBranch: opts.DefaultBranch,
	}

	apiRepo, err := p.client.UpdateRepository(ctx, owner, repo, apiOpts)
	if err != nil {
		return nil, err
	}

	result := githubRepoToModel(*apiRepo)
	return &result, nil
}

func (p *GitHubProvider) DeleteRepository(ctx context.Context, repoID string) error {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return err
	}
	return p.client.DeleteRepository(ctx, owner, repo)
}

// ============================================================================
// Branches
// ============================================================================

func (p *GitHubProvider) ListBranches(ctx context.Context, repoID string) ([]models.GitBranch, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiBranches, err := p.client.ListBranches(ctx, owner, repo, 1, 100)
	if err != nil {
		return nil, err
	}

	branches := make([]models.GitBranch, len(apiBranches))
	for i, b := range apiBranches {
		branches[i] = models.GitBranch{
			Name:      b.Name,
			CommitSHA: b.Commit.SHA,
			Protected: b.Protected,
		}
	}
	return branches, nil
}

func (p *GitHubProvider) GetBranch(ctx context.Context, repoID, branch string) (*models.GitBranch, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiBranch, err := p.client.GetBranch(ctx, owner, repo, branch)
	if err != nil {
		return nil, err
	}

	return &models.GitBranch{
		Name:      apiBranch.Name,
		CommitSHA: apiBranch.Commit.SHA,
		Protected: apiBranch.Protected,
	}, nil
}

func (p *GitHubProvider) CreateBranch(ctx context.Context, repoID string, opts CreateBranchOptions) (*models.GitBranch, error) {
	// GitHub doesn't have a direct "create branch" API
	// You need to create a reference: POST /repos/{owner}/{repo}/git/refs
	// For now, return not implemented
	return nil, fmt.Errorf("create branch not implemented for GitHub - use git push")
}

func (p *GitHubProvider) DeleteBranch(ctx context.Context, repoID, branch string) error {
	// GitHub uses: DELETE /repos/{owner}/{repo}/git/refs/heads/{branch}
	return fmt.Errorf("delete branch not implemented for GitHub - use git push")
}

// ============================================================================
// Tags
// ============================================================================

func (p *GitHubProvider) ListTags(ctx context.Context, repoID string) ([]models.GitTag, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiTags, err := p.client.ListTags(ctx, owner, repo, 1, 100)
	if err != nil {
		return nil, err
	}

	tags := make([]models.GitTag, len(apiTags))
	for i, t := range apiTags {
		tags[i] = models.GitTag{
			Name:      t.Name,
			CommitSHA: t.Commit.SHA,
		}
	}
	return tags, nil
}

func (p *GitHubProvider) CreateTag(ctx context.Context, repoID string, opts CreateTagOptions) (*models.GitTag, error) {
	return nil, fmt.Errorf("create tag not implemented for GitHub - use git push")
}

func (p *GitHubProvider) DeleteTag(ctx context.Context, repoID, tag string) error {
	return fmt.Errorf("delete tag not implemented for GitHub - use git push")
}

// ============================================================================
// Commits
// ============================================================================

func (p *GitHubProvider) ListCommits(ctx context.Context, repoID string, opts ListCommitsOptions) ([]models.GitCommit, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 30
	}

	apiCommits, err := p.client.ListCommits(ctx, owner, repo, opts.SHA, opts.Page, perPage)
	if err != nil {
		return nil, err
	}

	commits := make([]models.GitCommit, len(apiCommits))
	for i, c := range apiCommits {
		commits[i] = models.GitCommit{
			SHA:     c.SHA,
			Message: c.Commit.Message,
			Author:  c.Commit.Author.Name,
			Email:   c.Commit.Author.Email,
			Date:    c.Commit.Author.Date,
			HTMLURL: c.HTMLURL,
		}
		if c.Stats != nil {
			commits[i].Additions = c.Stats.Additions
			commits[i].Deletions = c.Stats.Deletions
		}
	}
	return commits, nil
}

func (p *GitHubProvider) GetCommit(ctx context.Context, repoID, sha string) (*models.GitCommit, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	c, err := p.client.GetCommit(ctx, owner, repo, sha)
	if err != nil {
		return nil, err
	}

	commit := &models.GitCommit{
		SHA:     c.SHA,
		Message: c.Commit.Message,
		Author:  c.Commit.Author.Name,
		Email:   c.Commit.Author.Email,
		Date:    c.Commit.Author.Date,
		HTMLURL: c.HTMLURL,
	}
	if c.Stats != nil {
		commit.Additions = c.Stats.Additions
		commit.Deletions = c.Stats.Deletions
	}
	return commit, nil
}

// ============================================================================
// Files
// ============================================================================

func (p *GitHubProvider) GetFileContent(ctx context.Context, repoID, path, ref string) (*models.GitFileContent, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	content, err := p.client.GetFileContent(ctx, owner, repo, path, ref)
	if err != nil {
		return nil, err
	}

	return &models.GitFileContent{
		Path:    path,
		Name:    path[strings.LastIndex(path, "/")+1:],
		Type:    "file",
		Content: content,
	}, nil
}

func (p *GitHubProvider) ListTree(ctx context.Context, repoID, path, ref string) ([]models.GitTreeEntry, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	contents, err := p.client.GetContents(ctx, owner, repo, path, ref)
	if err != nil {
		return nil, err
	}

	entries := make([]models.GitTreeEntry, len(contents))
	for i, c := range contents {
		entries[i] = models.GitTreeEntry{
			Path: c.Path,
			Name: c.Name,
			Type: c.Type,
			Size: c.Size,
			SHA:  c.SHA,
		}
	}
	return entries, nil
}

func (p *GitHubProvider) CreateOrUpdateFile(ctx context.Context, repoID, path string, opts UpdateFileOptions) error {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return err
	}

	// Base64 encode content
	encoded := base64.StdEncoding.EncodeToString(opts.Content)

	apiOpts := github.CreateFileOptions{
		Message: opts.Message,
		Content: encoded,
		Branch:  opts.Branch,
		SHA:     opts.SHA,
	}

	return p.client.CreateOrUpdateFile(ctx, owner, repo, path, apiOpts)
}

// ============================================================================
// Pull Requests
// ============================================================================

func (p *GitHubProvider) ListPullRequests(ctx context.Context, repoID string, opts ListPROptions) ([]models.GitPullRequest, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	state := opts.State
	if state == "" {
		state = "open"
	}
	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 30
	}

	apiPRs, err := p.client.ListPullRequests(ctx, owner, repo, state, opts.Page, perPage)
	if err != nil {
		return nil, err
	}

	prs := make([]models.GitPullRequest, len(apiPRs))
	for i, pr := range apiPRs {
		prs[i] = githubPRToModel(pr)
	}
	return prs, nil
}

func (p *GitHubProvider) GetPullRequest(ctx context.Context, repoID string, number int64) (*models.GitPullRequest, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiPR, err := p.client.GetPullRequest(ctx, owner, repo, int(number))
	if err != nil {
		return nil, err
	}

	result := githubPRToModel(*apiPR)
	return &result, nil
}

func (p *GitHubProvider) CreatePullRequest(ctx context.Context, repoID string, opts CreatePROptions) (*models.GitPullRequest, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := github.CreatePROptions{
		Title: opts.Title,
		Body:  opts.Body,
		Head:  opts.HeadBranch,
		Base:  opts.BaseBranch,
		Draft: opts.Draft,
	}

	apiPR, err := p.client.CreatePullRequest(ctx, owner, repo, apiOpts)
	if err != nil {
		return nil, err
	}

	result := githubPRToModel(*apiPR)
	return &result, nil
}

func (p *GitHubProvider) MergePullRequest(ctx context.Context, repoID string, number int64, opts MergePROptions) error {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return err
	}

	method := opts.MergeMethod
	if method == "" {
		method = "merge"
	}

	return p.client.MergePullRequest(ctx, owner, repo, int(number), opts.CommitTitle, opts.CommitMessage, method)
}

// ============================================================================
// Issues
// ============================================================================

func (p *GitHubProvider) ListIssues(ctx context.Context, repoID string, opts ListIssueOptions) ([]models.GitIssue, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	state := opts.State
	if state == "" {
		state = "open"
	}
	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 30
	}

	apiIssues, err := p.client.ListIssues(ctx, owner, repo, state, opts.Page, perPage)
	if err != nil {
		return nil, err
	}

	issues := make([]models.GitIssue, len(apiIssues))
	for i, issue := range apiIssues {
		issues[i] = githubIssueToModel(issue)
	}
	return issues, nil
}

func (p *GitHubProvider) GetIssue(ctx context.Context, repoID string, number int64) (*models.GitIssue, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiIssue, err := p.client.GetIssue(ctx, owner, repo, int(number))
	if err != nil {
		return nil, err
	}

	result := githubIssueToModel(*apiIssue)
	return &result, nil
}

func (p *GitHubProvider) CreateIssue(ctx context.Context, repoID string, opts CreateIssueOptions) (*models.GitIssue, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := github.CreateIssueOptions{
		Title:     opts.Title,
		Body:      opts.Body,
		Labels:    opts.Labels,
		Assignees: opts.Assignees,
	}

	apiIssue, err := p.client.CreateIssue(ctx, owner, repo, apiOpts)
	if err != nil {
		return nil, err
	}

	result := githubIssueToModel(*apiIssue)
	return &result, nil
}

// ============================================================================
// Releases
// ============================================================================

func (p *GitHubProvider) ListReleases(ctx context.Context, repoID string) ([]models.GitRelease, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiReleases, err := p.client.ListReleases(ctx, owner, repo, 1, 30)
	if err != nil {
		return nil, err
	}

	releases := make([]models.GitRelease, len(apiReleases))
	for i, r := range apiReleases {
		releases[i] = githubReleaseToModel(r)
	}
	return releases, nil
}

func (p *GitHubProvider) GetLatestRelease(ctx context.Context, repoID string) (*models.GitRelease, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiRelease, err := p.client.GetLatestRelease(ctx, owner, repo)
	if err != nil {
		return nil, err
	}

	result := githubReleaseToModel(*apiRelease)
	return &result, nil
}

func (p *GitHubProvider) CreateRelease(ctx context.Context, repoID string, opts CreateReleaseOptions) (*models.GitRelease, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := github.CreateReleaseOptions{
		TagName:         opts.TagName,
		Name:            opts.Name,
		Body:            opts.Body,
		Draft:           opts.Draft,
		Prerelease:      opts.Prerelease,
		TargetCommitish: opts.Target,
	}

	apiRelease, err := p.client.CreateRelease(ctx, owner, repo, apiOpts)
	if err != nil {
		return nil, err
	}

	result := githubReleaseToModel(*apiRelease)
	return &result, nil
}

// ============================================================================
// Webhooks
// ============================================================================

func (p *GitHubProvider) ListWebhooks(ctx context.Context, repoID string) ([]models.GitWebhook, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiHooks, err := p.client.ListHooks(ctx, owner, repo)
	if err != nil {
		return nil, err
	}

	hooks := make([]models.GitWebhook, len(apiHooks))
	for i, h := range apiHooks {
		hooks[i] = models.GitWebhook{
			ID:        h.ID,
			URL:       h.Config.URL,
			Events:    h.Events,
			Active:    h.Active,
			CreatedAt: h.CreatedAt,
		}
	}
	return hooks, nil
}

func (p *GitHubProvider) CreateWebhook(ctx context.Context, repoID string, opts CreateWebhookOptions) (*models.GitWebhook, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	contentType := opts.ContentType
	if contentType == "" {
		contentType = "json"
	}

	apiOpts := github.CreateHookOptions{
		Name:   "web",
		Active: opts.Active,
		Events: opts.Events,
		Config: github.APIHookConfig{
			URL:         opts.URL,
			ContentType: contentType,
			Secret:      opts.Secret,
		},
	}

	apiHook, err := p.client.CreateHook(ctx, owner, repo, apiOpts)
	if err != nil {
		return nil, err
	}

	return &models.GitWebhook{
		ID:        apiHook.ID,
		URL:       apiHook.Config.URL,
		Events:    apiHook.Events,
		Active:    apiHook.Active,
		CreatedAt: apiHook.CreatedAt,
	}, nil
}

func (p *GitHubProvider) DeleteWebhook(ctx context.Context, repoID string, hookID int64) error {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return err
	}
	return p.client.DeleteHook(ctx, owner, repo, hookID)
}

// ============================================================================
// Deploy Keys
// ============================================================================

func (p *GitHubProvider) ListDeployKeys(ctx context.Context, repoID string) ([]models.GitDeployKey, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiKeys, err := p.client.ListDeployKeys(ctx, owner, repo)
	if err != nil {
		return nil, err
	}

	keys := make([]models.GitDeployKey, len(apiKeys))
	for i, k := range apiKeys {
		keys[i] = models.GitDeployKey{
			ID:        k.ID,
			Title:     k.Title,
			Key:       k.Key,
			ReadOnly:  k.ReadOnly,
			CreatedAt: k.CreatedAt,
		}
	}
	return keys, nil
}

func (p *GitHubProvider) CreateDeployKey(ctx context.Context, repoID string, opts CreateDeployKeyOptions) (*models.GitDeployKey, error) {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return nil, err
	}

	apiOpts := github.CreateDeployKeyOptions{
		Title:    opts.Title,
		Key:      opts.Key,
		ReadOnly: opts.ReadOnly,
	}

	apiKey, err := p.client.CreateDeployKey(ctx, owner, repo, apiOpts)
	if err != nil {
		return nil, err
	}

	return &models.GitDeployKey{
		ID:        apiKey.ID,
		Title:     apiKey.Title,
		Key:       apiKey.Key,
		ReadOnly:  apiKey.ReadOnly,
		CreatedAt: apiKey.CreatedAt,
	}, nil
}

func (p *GitHubProvider) DeleteDeployKey(ctx context.Context, repoID string, keyID int64) error {
	owner, repo, err := githubParseRepoID(repoID)
	if err != nil {
		return err
	}
	return p.client.DeleteDeployKey(ctx, owner, repo, keyID)
}

// ============================================================================
// Templates
// ============================================================================

func (p *GitHubProvider) ListGitignoreTemplates(ctx context.Context) ([]string, error) {
	// GitHub has a gitignore API but it's rarely used
	// Return common templates
	return []string{
		"Go", "Python", "Node", "Java", "Rust", "Ruby",
		"C", "C++", "Objective-C", "Swift",
		"VisualStudio", "JetBrains", "Vim", "Emacs",
	}, nil
}

func (p *GitHubProvider) ListLicenseTemplates(ctx context.Context) ([]LicenseTemplate, error) {
	return []LicenseTemplate{
		{Key: "mit", Name: "MIT License"},
		{Key: "apache-2.0", Name: "Apache License 2.0"},
		{Key: "gpl-3.0", Name: "GNU GPLv3"},
		{Key: "bsd-3-clause", Name: "BSD 3-Clause"},
		{Key: "unlicense", Name: "The Unlicense"},
		{Key: "mpl-2.0", Name: "Mozilla Public License 2.0"},
	}, nil
}

// ============================================================================
// Conversion helpers
// ============================================================================

func githubRepoToModel(r github.APIRepository) models.GitRepository {
	var desc *string
	if r.Description != "" {
		desc = &r.Description
	}

	return models.GitRepository{
		ProviderType:  models.GitProviderGitHub,
		ProviderID:    r.ID,
		FullName:      r.FullName,
		Description:   desc,
		CloneURL:      r.CloneURL,
		HTMLURL:       r.HTMLURL,
		DefaultBranch: r.DefaultBranch,
		IsPrivate:     r.Private,
		IsFork:        r.Fork,
		IsArchived:    r.Archived,
		StarsCount:    r.StarCount,
		ForksCount:    r.ForkCount,
		OpenIssues:    r.OpenIssues,
		SizeKB:        r.Size,
	}
}

func githubPRToModel(pr github.APIPullRequest) models.GitPullRequest {
	mergeable := false
	if pr.Mergeable != nil {
		mergeable = *pr.Mergeable
	}

	return models.GitPullRequest{
		ID:          pr.ID,
		Number:      int64(pr.Number),
		Title:       pr.Title,
		Body:        pr.Body,
		State:       pr.State,
		HeadBranch:  pr.Head.Ref,
		HeadSHA:     pr.Head.SHA,
		BaseBranch:  pr.Base.Ref,
		AuthorName:  pr.User.Name,
		AuthorLogin: pr.User.Login,
		AvatarURL:   pr.User.AvatarURL,
		Mergeable:   mergeable,
		Merged:      pr.Merged,
		Comments:    pr.Comments,
		HTMLURL:     pr.HTMLURL,
		CreatedAt:   pr.CreatedAt,
		UpdatedAt:   pr.UpdatedAt,
	}
}

func githubIssueToModel(issue github.APIIssue) models.GitIssue {
	labels := make([]string, len(issue.Labels))
	for i, l := range issue.Labels {
		labels[i] = l.Name
	}

	return models.GitIssue{
		ID:          issue.ID,
		Number:      int64(issue.Number),
		Title:       issue.Title,
		Body:        issue.Body,
		State:       issue.State,
		AuthorName:  issue.User.Name,
		AuthorLogin: issue.User.Login,
		AvatarURL:   issue.User.AvatarURL,
		Labels:      labels,
		Comments:    issue.Comments,
		HTMLURL:     issue.HTMLURL,
		CreatedAt:   issue.CreatedAt,
		UpdatedAt:   issue.UpdatedAt,
	}
}

func githubReleaseToModel(r github.APIRelease) models.GitRelease {
	return models.GitRelease{
		ID:           r.ID,
		TagName:      r.TagName,
		Name:         r.Name,
		Body:         r.Body,
		IsDraft:      r.Draft,
		IsPrerelease: r.Prerelease,
		AuthorLogin:  r.Author.Login,
		HTMLURL:      r.HTMLURL,
		CreatedAt:    r.CreatedAt,
		PublishedAt:  r.PublishedAt,
	}
}
