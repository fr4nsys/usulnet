// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package git

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/fr4nsys/usulnet/internal/integrations/gitlab"
	"github.com/fr4nsys/usulnet/internal/models"
)

// GitLabProvider implements the Provider interface for GitLab
type GitLabProvider struct {
	client *gitlab.Client
}

// NewGitLabProvider creates a new GitLab provider
func NewGitLabProvider(baseURL, token string) (*GitLabProvider, error) {
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	client := gitlab.NewClient(baseURL, token)
	return &GitLabProvider{client: client}, nil
}

// ============================================================================
// Connection
// ============================================================================

func (p *GitLabProvider) TestConnection(ctx context.Context) error {
	_, err := p.client.GetCurrentUser(ctx)
	return err
}

func (p *GitLabProvider) GetVersion(ctx context.Context) (string, error) {
	return p.client.GetVersion(ctx)
}

// ============================================================================
// Repositories (Projects)
// ============================================================================

func (p *GitLabProvider) ListRepositories(ctx context.Context) ([]models.GitRepository, error) {
	apiProjects, err := p.client.ListAllProjects(ctx, false)
	if err != nil {
		return nil, err
	}

	repos := make([]models.GitRepository, len(apiProjects))
	for i, proj := range apiProjects {
		repos[i] = gitlabProjectToModel(proj)
	}
	return repos, nil
}

func (p *GitLabProvider) GetRepository(ctx context.Context, repoID string) (*models.GitRepository, error) {
	apiProject, err := p.client.GetProject(ctx, repoID)
	if err != nil {
		return nil, err
	}

	result := gitlabProjectToModel(*apiProject)
	return &result, nil
}

func (p *GitLabProvider) CreateRepository(ctx context.Context, opts CreateRepoOptions) (*models.GitRepository, error) {
	visibility := "private"
	if !opts.Private {
		visibility = "public"
	}

	apiOpts := gitlab.CreateProjectOptions{
		Name:                 opts.Name,
		Description:          opts.Description,
		Visibility:           visibility,
		InitializeWithReadme: opts.AutoInit,
	}

	apiProject, err := p.client.CreateProject(ctx, apiOpts)
	if err != nil {
		return nil, err
	}

	result := gitlabProjectToModel(*apiProject)
	return &result, nil
}

func (p *GitLabProvider) UpdateRepository(ctx context.Context, repoID string, opts UpdateRepoOptions) (*models.GitRepository, error) {
	var visibility *string
	if opts.Private != nil {
		if *opts.Private {
			v := "private"
			visibility = &v
		} else {
			v := "public"
			visibility = &v
		}
	}

	apiOpts := gitlab.UpdateProjectOptions{
		Name:          opts.Name,
		Description:   opts.Description,
		Visibility:    visibility,
		DefaultBranch: opts.DefaultBranch,
		Archived:      opts.Archived,
	}

	apiProject, err := p.client.UpdateProject(ctx, repoID, apiOpts)
	if err != nil {
		return nil, err
	}

	result := gitlabProjectToModel(*apiProject)
	return &result, nil
}

func (p *GitLabProvider) DeleteRepository(ctx context.Context, repoID string) error {
	return p.client.DeleteProject(ctx, repoID)
}

// ============================================================================
// Branches
// ============================================================================

func (p *GitLabProvider) ListBranches(ctx context.Context, repoID string) ([]models.GitBranch, error) {
	apiBranches, err := p.client.ListBranches(ctx, repoID, 1, 100)
	if err != nil {
		return nil, err
	}

	branches := make([]models.GitBranch, len(apiBranches))
	for i, b := range apiBranches {
		branches[i] = models.GitBranch{
			Name:      b.Name,
			CommitSHA: b.Commit.ID,
			Protected: b.Protected,
		}
	}
	return branches, nil
}

func (p *GitLabProvider) GetBranch(ctx context.Context, repoID, branch string) (*models.GitBranch, error) {
	apiBranch, err := p.client.GetBranch(ctx, repoID, branch)
	if err != nil {
		return nil, err
	}

	return &models.GitBranch{
		Name:      apiBranch.Name,
		CommitSHA: apiBranch.Commit.ID,
		Protected: apiBranch.Protected,
	}, nil
}

func (p *GitLabProvider) CreateBranch(ctx context.Context, repoID string, opts CreateBranchOptions) (*models.GitBranch, error) {
	apiBranch, err := p.client.CreateBranch(ctx, repoID, opts.Name, opts.Source)
	if err != nil {
		return nil, err
	}

	return &models.GitBranch{
		Name:      apiBranch.Name,
		CommitSHA: apiBranch.Commit.ID,
		Protected: apiBranch.Protected,
	}, nil
}

func (p *GitLabProvider) DeleteBranch(ctx context.Context, repoID, branch string) error {
	return p.client.DeleteBranch(ctx, repoID, branch)
}

// ============================================================================
// Tags
// ============================================================================

func (p *GitLabProvider) ListTags(ctx context.Context, repoID string) ([]models.GitTag, error) {
	apiTags, err := p.client.ListTags(ctx, repoID, 1, 100)
	if err != nil {
		return nil, err
	}

	tags := make([]models.GitTag, len(apiTags))
	for i, t := range apiTags {
		tags[i] = models.GitTag{
			Name:      t.Name,
			CommitSHA: t.Target,
			Message:   t.Message,
		}
	}
	return tags, nil
}

func (p *GitLabProvider) CreateTag(ctx context.Context, repoID string, opts CreateTagOptions) (*models.GitTag, error) {
	// GitLab: POST /projects/:id/repository/tags
	return nil, fmt.Errorf("create tag not implemented for GitLab via API")
}

func (p *GitLabProvider) DeleteTag(ctx context.Context, repoID, tag string) error {
	// GitLab: DELETE /projects/:id/repository/tags/:tag_name
	return fmt.Errorf("delete tag not implemented for GitLab via API")
}

// ============================================================================
// Commits
// ============================================================================

func (p *GitLabProvider) ListCommits(ctx context.Context, repoID string, opts ListCommitsOptions) ([]models.GitCommit, error) {
	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 30
	}

	apiCommits, err := p.client.ListCommits(ctx, repoID, opts.SHA, opts.Page, perPage)
	if err != nil {
		return nil, err
	}

	commits := make([]models.GitCommit, len(apiCommits))
	for i, c := range apiCommits {
		commits[i] = models.GitCommit{
			SHA:     c.ID,
			Message: c.Message,
			Author:  c.AuthorName,
			Email:   c.AuthorEmail,
			Date:    c.AuthoredDate,
			HTMLURL: c.WebURL,
		}
		if c.Stats != nil {
			commits[i].Additions = c.Stats.Additions
			commits[i].Deletions = c.Stats.Deletions
		}
	}
	return commits, nil
}

func (p *GitLabProvider) GetCommit(ctx context.Context, repoID, sha string) (*models.GitCommit, error) {
	c, err := p.client.GetCommit(ctx, repoID, sha)
	if err != nil {
		return nil, err
	}

	commit := &models.GitCommit{
		SHA:     c.ID,
		Message: c.Message,
		Author:  c.AuthorName,
		Email:   c.AuthorEmail,
		Date:    c.AuthoredDate,
		HTMLURL: c.WebURL,
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

func (p *GitLabProvider) GetFileContent(ctx context.Context, repoID, path, ref string) (*models.GitFileContent, error) {
	content, err := p.client.GetFileContent(ctx, repoID, path, ref)
	if err != nil {
		return nil, err
	}

	name := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		name = path[idx+1:]
	}

	return &models.GitFileContent{
		Path:    path,
		Name:    name,
		Type:    "file",
		Content: content,
	}, nil
}

func (p *GitLabProvider) ListTree(ctx context.Context, repoID, path, ref string) ([]models.GitTreeEntry, error) {
	apiTree, err := p.client.ListTree(ctx, repoID, path, ref, 1, 100)
	if err != nil {
		return nil, err
	}

	entries := make([]models.GitTreeEntry, len(apiTree))
	for i, t := range apiTree {
		entryType := "file"
		if t.Type == "tree" {
			entryType = "dir"
		}
		entries[i] = models.GitTreeEntry{
			Path: t.Path,
			Name: t.Name,
			Type: entryType,
			SHA:  t.ID,
		}
	}
	return entries, nil
}

func (p *GitLabProvider) CreateOrUpdateFile(ctx context.Context, repoID, path string, opts UpdateFileOptions) error {
	// Base64 encode content
	encoded := base64.StdEncoding.EncodeToString(opts.Content)

	if opts.SHA == "" {
		// Create new file
		createOpts := gitlab.CreateFileOptions{
			Branch:        opts.Branch,
			Content:       encoded,
			CommitMessage: opts.Message,
			Encoding:      "base64",
		}
		return p.client.CreateFile(ctx, repoID, path, createOpts)
	}

	// Update existing file
	updateOpts := gitlab.UpdateFileOptions{
		Branch:        opts.Branch,
		Content:       encoded,
		CommitMessage: opts.Message,
		Encoding:      "base64",
		LastCommitID:  opts.SHA,
	}
	return p.client.UpdateFile(ctx, repoID, path, updateOpts)
}

// ============================================================================
// Merge Requests
// ============================================================================

func (p *GitLabProvider) ListPullRequests(ctx context.Context, repoID string, opts ListPROptions) ([]models.GitPullRequest, error) {
	state := opts.State
	if state == "" {
		state = "opened"
	}
	// Convert GitHub states to GitLab states
	if state == "open" {
		state = "opened"
	}

	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 30
	}

	apiMRs, err := p.client.ListMergeRequests(ctx, repoID, state, opts.Page, perPage)
	if err != nil {
		return nil, err
	}

	prs := make([]models.GitPullRequest, len(apiMRs))
	for i, mr := range apiMRs {
		prs[i] = gitlabMRToModel(mr)
	}
	return prs, nil
}

func (p *GitLabProvider) GetPullRequest(ctx context.Context, repoID string, number int64) (*models.GitPullRequest, error) {
	apiMR, err := p.client.GetMergeRequest(ctx, repoID, number)
	if err != nil {
		return nil, err
	}

	result := gitlabMRToModel(*apiMR)
	return &result, nil
}

func (p *GitLabProvider) CreatePullRequest(ctx context.Context, repoID string, opts CreatePROptions) (*models.GitPullRequest, error) {
	apiOpts := gitlab.CreateMROptions{
		Title:        opts.Title,
		Description:  opts.Body,
		SourceBranch: opts.HeadBranch,
		TargetBranch: opts.BaseBranch,
		Draft:        opts.Draft,
	}

	apiMR, err := p.client.CreateMergeRequest(ctx, repoID, apiOpts)
	if err != nil {
		return nil, err
	}

	result := gitlabMRToModel(*apiMR)
	return &result, nil
}

func (p *GitLabProvider) MergePullRequest(ctx context.Context, repoID string, number int64, opts MergePROptions) error {
	_, err := p.client.MergeMergeRequest(ctx, repoID, number, opts.Squash, opts.CommitMessage)
	return err
}

// ============================================================================
// Issues
// ============================================================================

func (p *GitLabProvider) ListIssues(ctx context.Context, repoID string, opts ListIssueOptions) ([]models.GitIssue, error) {
	state := opts.State
	if state == "" {
		state = "opened"
	}
	if state == "open" {
		state = "opened"
	}

	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 30
	}

	apiIssues, err := p.client.ListIssues(ctx, repoID, state, opts.Page, perPage)
	if err != nil {
		return nil, err
	}

	issues := make([]models.GitIssue, len(apiIssues))
	for i, issue := range apiIssues {
		issues[i] = apiIssueToModelGL(issue)
	}
	return issues, nil
}

func (p *GitLabProvider) GetIssue(ctx context.Context, repoID string, number int64) (*models.GitIssue, error) {
	apiIssue, err := p.client.GetIssue(ctx, repoID, number)
	if err != nil {
		return nil, err
	}

	result := apiIssueToModelGL(*apiIssue)
	return &result, nil
}

func (p *GitLabProvider) CreateIssue(ctx context.Context, repoID string, opts CreateIssueOptions) (*models.GitIssue, error) {
	// Convert assignees to IDs (would need user lookup)
	apiOpts := gitlab.CreateIssueOptions{
		Title:       opts.Title,
		Description: opts.Body,
		Labels:      opts.Labels,
	}

	apiIssue, err := p.client.CreateIssue(ctx, repoID, apiOpts)
	if err != nil {
		return nil, err
	}

	result := apiIssueToModelGL(*apiIssue)
	return &result, nil
}

// ============================================================================
// Releases
// ============================================================================

func (p *GitLabProvider) ListReleases(ctx context.Context, repoID string) ([]models.GitRelease, error) {
	apiReleases, err := p.client.ListReleases(ctx, repoID, 1, 30)
	if err != nil {
		return nil, err
	}

	releases := make([]models.GitRelease, len(apiReleases))
	for i, r := range apiReleases {
		releases[i] = apiReleaseToModelGL(r)
	}
	return releases, nil
}

func (p *GitLabProvider) GetLatestRelease(ctx context.Context, repoID string) (*models.GitRelease, error) {
	apiRelease, err := p.client.GetLatestRelease(ctx, repoID)
	if err != nil {
		return nil, err
	}

	result := apiReleaseToModelGL(*apiRelease)
	return &result, nil
}

func (p *GitLabProvider) CreateRelease(ctx context.Context, repoID string, opts CreateReleaseOptions) (*models.GitRelease, error) {
	apiOpts := gitlab.CreateReleaseOptions{
		TagName:     opts.TagName,
		Name:        opts.Name,
		Description: opts.Body,
		Ref:         opts.Target,
	}

	apiRelease, err := p.client.CreateRelease(ctx, repoID, apiOpts)
	if err != nil {
		return nil, err
	}

	result := apiReleaseToModelGL(*apiRelease)
	return &result, nil
}

// ============================================================================
// Webhooks
// ============================================================================

func (p *GitLabProvider) ListWebhooks(ctx context.Context, repoID string) ([]models.GitWebhook, error) {
	apiHooks, err := p.client.ListHooks(ctx, repoID)
	if err != nil {
		return nil, err
	}

	hooks := make([]models.GitWebhook, len(apiHooks))
	for i, h := range apiHooks {
		events := gitlabHookEvents(h)
		hooks[i] = models.GitWebhook{
			ID:        h.ID,
			URL:       h.URL,
			Events:    events,
			Active:    true, // GitLab doesn't have an active flag in the same way
			CreatedAt: h.CreatedAt,
		}
	}
	return hooks, nil
}

func (p *GitLabProvider) CreateWebhook(ctx context.Context, repoID string, opts CreateWebhookOptions) (*models.GitWebhook, error) {
	// Convert events to GitLab-specific bools
	pushEvents := containsEvent(opts.Events, "push")
	issuesEvents := containsEvent(opts.Events, "issues")
	mrEvents := containsEvent(opts.Events, "merge_request", "pull_request")
	tagEvents := containsEvent(opts.Events, "tag_push")
	pipelineEvents := containsEvent(opts.Events, "pipeline")
	releaseEvents := containsEvent(opts.Events, "release")

	apiOpts := gitlab.CreateHookOptions{
		URL:                   opts.URL,
		Token:                 opts.Secret,
		PushEvents:            &pushEvents,
		IssuesEvents:          &issuesEvents,
		MergeRequestsEvents:   &mrEvents,
		TagPushEvents:         &tagEvents,
		PipelineEvents:        &pipelineEvents,
		ReleasesEvents:        &releaseEvents,
		EnableSSLVerification: boolPtr(true),
	}

	apiHook, err := p.client.CreateHook(ctx, repoID, apiOpts)
	if err != nil {
		return nil, err
	}

	return &models.GitWebhook{
		ID:        apiHook.ID,
		URL:       apiHook.URL,
		Events:    opts.Events,
		Active:    true,
		CreatedAt: apiHook.CreatedAt,
	}, nil
}

func (p *GitLabProvider) DeleteWebhook(ctx context.Context, repoID string, hookID int64) error {
	return p.client.DeleteHook(ctx, repoID, hookID)
}

// ============================================================================
// Deploy Keys
// ============================================================================

func (p *GitLabProvider) ListDeployKeys(ctx context.Context, repoID string) ([]models.GitDeployKey, error) {
	apiKeys, err := p.client.ListDeployKeys(ctx, repoID)
	if err != nil {
		return nil, err
	}

	keys := make([]models.GitDeployKey, len(apiKeys))
	for i, k := range apiKeys {
		keys[i] = models.GitDeployKey{
			ID:        k.ID,
			Title:     k.Title,
			Key:       k.Key,
			ReadOnly:  !k.CanPush,
			CreatedAt: k.CreatedAt,
		}
	}
	return keys, nil
}

func (p *GitLabProvider) CreateDeployKey(ctx context.Context, repoID string, opts CreateDeployKeyOptions) (*models.GitDeployKey, error) {
	apiOpts := gitlab.CreateDeployKeyOptions{
		Title:   opts.Title,
		Key:     opts.Key,
		CanPush: !opts.ReadOnly,
	}

	apiKey, err := p.client.CreateDeployKey(ctx, repoID, apiOpts)
	if err != nil {
		return nil, err
	}

	return &models.GitDeployKey{
		ID:        apiKey.ID,
		Title:     apiKey.Title,
		Key:       apiKey.Key,
		ReadOnly:  !apiKey.CanPush,
		CreatedAt: apiKey.CreatedAt,
	}, nil
}

func (p *GitLabProvider) DeleteDeployKey(ctx context.Context, repoID string, keyID int64) error {
	return p.client.DeleteDeployKey(ctx, repoID, keyID)
}

// ============================================================================
// Templates
// ============================================================================

func (p *GitLabProvider) ListGitignoreTemplates(ctx context.Context) ([]string, error) {
	// GitLab has a gitignore templates API
	return []string{
		"Go", "Python", "Node", "Java", "Rust", "Ruby",
		"C", "C++", "Objective-C", "Swift",
		"VisualStudio", "JetBrains", "Vim", "Emacs",
	}, nil
}

func (p *GitLabProvider) ListLicenseTemplates(ctx context.Context) ([]LicenseTemplate, error) {
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

func gitlabProjectToModel(proj gitlab.APIProject) models.GitRepository {
	var desc *string
	if proj.Description != "" {
		desc = &proj.Description
	}

	isPrivate := proj.Visibility == "private"
	isFork := proj.ForkedFromProject != nil

	var sizeKB int64
	if proj.Statistics != nil {
		sizeKB = proj.Statistics.RepositorySize / 1024
	}

	return models.GitRepository{
		ProviderType:  models.GitProviderGitLab,
		ProviderID:    proj.ID,
		FullName:      proj.PathWithNamespace,
		Description:   desc,
		CloneURL:      proj.HTTPURLToRepo,
		HTMLURL:       proj.WebURL,
		DefaultBranch: proj.DefaultBranch,
		IsPrivate:     isPrivate,
		IsFork:        isFork,
		IsArchived:    proj.Archived,
		StarsCount:    proj.StarCount,
		ForksCount:    proj.ForksCount,
		OpenIssues:    proj.OpenIssuesCount,
		SizeKB:        sizeKB,
	}
}

func gitlabMRToModel(mr gitlab.APIMergeRequest) models.GitPullRequest {
	state := mr.State
	if state == "opened" {
		state = "open"
	}

	var headSHA string
	if mr.DiffRefs != nil {
		headSHA = mr.DiffRefs.HeadSHA
	}

	mergeable := mr.MergeStatus == "can_be_merged"
	merged := mr.State == "merged"

	return models.GitPullRequest{
		ID:          mr.ID,
		Number:      mr.IID,
		Title:       mr.Title,
		Body:        mr.Description,
		State:       state,
		HeadBranch:  mr.SourceBranch,
		HeadSHA:     headSHA,
		BaseBranch:  mr.TargetBranch,
		AuthorName:  mr.Author.Name,
		AuthorLogin: mr.Author.Username,
		AvatarURL:   mr.Author.AvatarURL,
		Mergeable:   mergeable,
		Merged:      merged,
		Comments:    mr.UserNotesCount,
		HTMLURL:     mr.WebURL,
		CreatedAt:   mr.CreatedAt,
		UpdatedAt:   mr.UpdatedAt,
	}
}

func apiIssueToModelGL(issue gitlab.APIIssue) models.GitIssue {
	state := issue.State
	if state == "opened" {
		state = "open"
	}

	return models.GitIssue{
		ID:          issue.ID,
		Number:      issue.IID,
		Title:       issue.Title,
		Body:        issue.Description,
		State:       state,
		AuthorName:  issue.Author.Name,
		AuthorLogin: issue.Author.Username,
		AvatarURL:   issue.Author.AvatarURL,
		Labels:      issue.Labels,
		Comments:    issue.UserNotesCount,
		HTMLURL:     issue.WebURL,
		CreatedAt:   issue.CreatedAt,
		UpdatedAt:   issue.UpdatedAt,
	}
}

func apiReleaseToModelGL(r gitlab.APIRelease) models.GitRelease {
	publishedAt := &r.ReleasedAt

	return models.GitRelease{
		ID:           0, // GitLab releases don't have numeric IDs
		TagName:      r.TagName,
		Name:         r.Name,
		Body:         r.Description,
		IsDraft:      r.UpcomingRelease,
		IsPrerelease: false,
		AuthorLogin:  r.Author.Username,
		HTMLURL:      "", // Construct from project URL + tag
		CreatedAt:    r.CreatedAt,
		PublishedAt:  publishedAt,
	}
}

// gitlabHookEvents extracts event names from a GitLab hook
func gitlabHookEvents(h gitlab.APIHook) []string {
	var events []string
	if h.PushEvents {
		events = append(events, "push")
	}
	if h.IssuesEvents {
		events = append(events, "issues")
	}
	if h.MergeRequestsEvents {
		events = append(events, "merge_request")
	}
	if h.TagPushEvents {
		events = append(events, "tag_push")
	}
	if h.PipelineEvents {
		events = append(events, "pipeline")
	}
	if h.ReleasesEvents {
		events = append(events, "release")
	}
	return events
}

// containsEvent checks if any of the events match
func containsEvent(events []string, matches ...string) bool {
	for _, e := range events {
		for _, m := range matches {
			if e == m {
				return true
			}
		}
	}
	return false
}

// boolPtr returns a pointer to a bool
func boolPtr(b bool) *bool {
	return &b
}

// strconvAtoi64 converts string to int64 safely
func strconvAtoi64(s string) int64 {
	i, _ := strconv.ParseInt(s, 10, 64)
	return i
}
