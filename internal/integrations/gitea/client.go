// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package gitea

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a lightweight HTTP client for the Gitea API v1.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient creates a new Gitea API client.
func NewClient(baseURL, token string) *Client {
	baseURL = strings.TrimRight(baseURL, "/")
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetVersion returns the Gitea server version.
func (c *Client) GetVersion(ctx context.Context) (*APIVersion, error) {
	var v APIVersion
	if err := c.get(ctx, "/api/v1/version", &v); err != nil {
		return nil, fmt.Errorf("get version: %w", err)
	}
	return &v, nil
}

// GetCurrentUser returns the authenticated user.
func (c *Client) GetCurrentUser(ctx context.Context) (*APIUser, error) {
	var u APIUser
	if err := c.get(ctx, "/api/v1/user", &u); err != nil {
		return nil, fmt.Errorf("get current user: %w", err)
	}
	return &u, nil
}

// ListUserRepos returns repositories accessible to the authenticated user.
// page starts at 1, limit max 50.
func (c *Client) ListUserRepos(ctx context.Context, page, limit int) ([]APIRepository, error) {
	if page < 1 {
		page = 1
	}
	if limit <= 0 || limit > 50 {
		limit = 50
	}

	var repos []APIRepository
	path := fmt.Sprintf("/api/v1/user/repos?page=%d&limit=%d&sort=updated&order=desc", page, limit)
	if err := c.get(ctx, path, &repos); err != nil {
		return nil, fmt.Errorf("list user repos: %w", err)
	}
	return repos, nil
}

// ListAllRepos paginates through all user repos.
func (c *Client) ListAllRepos(ctx context.Context) ([]APIRepository, error) {
	var all []APIRepository
	page := 1
	for {
		repos, err := c.ListUserRepos(ctx, page, 50)
		if err != nil {
			return nil, err
		}
		all = append(all, repos...)
		if len(repos) < 50 {
			break
		}
		page++
		if page > 100 { // Safety limit
			break
		}
	}
	return all, nil
}

// GetRepository returns a specific repository.
func (c *Client) GetRepository(ctx context.Context, owner, repo string) (*APIRepository, error) {
	var r APIRepository
	path := fmt.Sprintf("/api/v1/repos/%s/%s", owner, repo)
	if err := c.get(ctx, path, &r); err != nil {
		return nil, fmt.Errorf("get repository %s/%s: %w", owner, repo, err)
	}
	return &r, nil
}

// GetBranch returns branch info including latest commit.
func (c *Client) GetBranch(ctx context.Context, owner, repo, branch string) (*APIBranch, error) {
	var b APIBranch
	path := fmt.Sprintf("/api/v1/repos/%s/%s/branches/%s", owner, repo, branch)
	if err := c.get(ctx, path, &b); err != nil {
		return nil, fmt.Errorf("get branch %s/%s/%s: %w", owner, repo, branch, err)
	}
	return &b, nil
}

// CreateRepoWebhook creates a webhook on a repository.
func (c *Client) CreateRepoWebhook(ctx context.Context, owner, repo string, opts CreateWebhookOptions) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/hooks", owner, repo)
	if err := c.post(ctx, path, opts, nil); err != nil {
		return fmt.Errorf("create webhook %s/%s: %w", owner, repo, err)
	}
	return nil
}

// TestConnection verifies the API token works.
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.GetCurrentUser(ctx)
	return err
}

// ListContents lists files/dirs at a path in a repo.
// If path is empty, lists the root directory.
func (c *Client) ListContents(ctx context.Context, owner, repo, path, ref string) ([]APIContentEntry, error) {
	if path == "" {
		path = ""
	}
	p := fmt.Sprintf("/api/v1/repos/%s/%s/contents/%s", owner, repo, path)
	if ref != "" {
		p += "?ref=" + ref
	}
	var entries []APIContentEntry
	if err := c.get(ctx, p, &entries); err != nil {
		return nil, fmt.Errorf("list contents %s/%s/%s: %w", owner, repo, path, err)
	}
	return entries, nil
}

// GetRawFile returns the raw content of a file.
func (c *Client) GetRawFile(ctx context.Context, owner, repo, path, ref string) ([]byte, error) {
	p := fmt.Sprintf("/api/v1/repos/%s/%s/raw/%s", owner, repo, path)
	if ref != "" {
		p += "?ref=" + ref
	}
	return c.getRaw(ctx, p)
}

// UpdateFile creates or updates a file in a repo.
func (c *Client) UpdateFile(ctx context.Context, owner, repo, path string, opts UpdateFileOptions) error {
	p := fmt.Sprintf("/api/v1/repos/%s/%s/contents/%s", owner, repo, path)
	if err := c.put(ctx, p, opts, nil); err != nil {
		return fmt.Errorf("update file %s/%s/%s: %w", owner, repo, path, err)
	}
	return nil
}

// ListBranches returns all branches of a repo.
func (c *Client) ListBranches(ctx context.Context, owner, repo string) ([]APIBranch, error) {
	var branches []APIBranch
	p := fmt.Sprintf("/api/v1/repos/%s/%s/branches?limit=50", owner, repo)
	if err := c.get(ctx, p, &branches); err != nil {
		return nil, fmt.Errorf("list branches %s/%s: %w", owner, repo, err)
	}
	return branches, nil
}

// ListCommits returns recent commits for a branch.
func (c *Client) ListCommits(ctx context.Context, owner, repo, ref string, limit int) ([]APICommitListItem, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	p := fmt.Sprintf("/api/v1/repos/%s/%s/commits?limit=%d", owner, repo, limit)
	if ref != "" {
		p += "&sha=" + ref
	}
	var commits []APICommitListItem
	if err := c.get(ctx, p, &commits); err != nil {
		return nil, fmt.Errorf("list commits %s/%s: %w", owner, repo, err)
	}
	return commits, nil
}

// GetFileSHA returns the SHA of a specific file (needed for updates).
func (c *Client) GetFileSHA(ctx context.Context, owner, repo, path, ref string) (string, error) {
	p := fmt.Sprintf("/api/v1/repos/%s/%s/contents/%s", owner, repo, path)
	if ref != "" {
		p += "?ref=" + ref
	}
	var entry APIContentEntry
	if err := c.get(ctx, p, &entry); err != nil {
		return "", fmt.Errorf("get file SHA %s/%s/%s: %w", owner, repo, path, err)
	}
	return entry.SHA, nil
}

// ============================================================================
// Tier 1: Repository Management
// ============================================================================

// CreateUserRepository creates a new repository for the authenticated user.
func (c *Client) CreateUserRepository(ctx context.Context, opts CreateRepoOptions) (*APIRepository, error) {
	var repo APIRepository
	if err := c.post(ctx, "/api/v1/user/repos", opts, &repo); err != nil {
		return nil, fmt.Errorf("create repository: %w", err)
	}
	return &repo, nil
}

// CreateOrgRepository creates a new repository in an organization.
func (c *Client) CreateOrgRepository(ctx context.Context, org string, opts CreateRepoOptions) (*APIRepository, error) {
	var repo APIRepository
	path := fmt.Sprintf("/api/v1/orgs/%s/repos", org)
	if err := c.post(ctx, path, opts, &repo); err != nil {
		return nil, fmt.Errorf("create org repository %s: %w", org, err)
	}
	return &repo, nil
}

// EditRepository updates repository settings.
func (c *Client) EditRepository(ctx context.Context, owner, repo string, opts EditRepoOptions) (*APIRepository, error) {
	var result APIRepository
	path := fmt.Sprintf("/api/v1/repos/%s/%s", owner, repo)
	if err := c.patch(ctx, path, opts, &result); err != nil {
		return nil, fmt.Errorf("edit repository %s/%s: %w", owner, repo, err)
	}
	return &result, nil
}

// DeleteRepository permanently deletes a repository.
func (c *Client) DeleteRepository(ctx context.Context, owner, repo string) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s", owner, repo)
	if err := c.delete(ctx, path); err != nil {
		return fmt.Errorf("delete repository %s/%s: %w", owner, repo, err)
	}
	return nil
}

// ============================================================================
// Tier 1: Branch Management
// ============================================================================

// CreateBranch creates a new branch.
func (c *Client) CreateBranch(ctx context.Context, owner, repo string, opts CreateBranchOptions) (*APIBranch, error) {
	var branch APIBranch
	path := fmt.Sprintf("/api/v1/repos/%s/%s/branches", owner, repo)
	if err := c.post(ctx, path, opts, &branch); err != nil {
		return nil, fmt.Errorf("create branch %s/%s: %w", owner, repo, err)
	}
	return &branch, nil
}

// DeleteBranch deletes a branch.
func (c *Client) DeleteBranch(ctx context.Context, owner, repo, branch string) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/branches/%s", owner, repo, branch)
	if err := c.delete(ctx, path); err != nil {
		return fmt.Errorf("delete branch %s/%s/%s: %w", owner, repo, branch, err)
	}
	return nil
}

// ============================================================================
// Tier 1: Tag Management
// ============================================================================

// ListTags returns all tags of a repository.
func (c *Client) ListTags(ctx context.Context, owner, repo string, page, limit int) ([]APITag, error) {
	if page < 1 {
		page = 1
	}
	if limit <= 0 || limit > 50 {
		limit = 50
	}
	var tags []APITag
	path := fmt.Sprintf("/api/v1/repos/%s/%s/tags?page=%d&limit=%d", owner, repo, page, limit)
	if err := c.get(ctx, path, &tags); err != nil {
		return nil, fmt.Errorf("list tags %s/%s: %w", owner, repo, err)
	}
	return tags, nil
}

// CreateTag creates a new tag.
func (c *Client) CreateTag(ctx context.Context, owner, repo string, opts CreateTagOptions) (*APITag, error) {
	var tag APITag
	path := fmt.Sprintf("/api/v1/repos/%s/%s/tags", owner, repo)
	if err := c.post(ctx, path, opts, &tag); err != nil {
		return nil, fmt.Errorf("create tag %s/%s: %w", owner, repo, err)
	}
	return &tag, nil
}

// DeleteTag deletes a tag.
func (c *Client) DeleteTag(ctx context.Context, owner, repo, tag string) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/tags/%s", owner, repo, tag)
	if err := c.delete(ctx, path); err != nil {
		return fmt.Errorf("delete tag %s/%s/%s: %w", owner, repo, tag, err)
	}
	return nil
}

// ============================================================================
// Tier 1: Commit & Diff
// ============================================================================

// GetCommit returns details of a single commit including files changed.
func (c *Client) GetCommit(ctx context.Context, owner, repo, sha string) (*APICommitListItem, error) {
	var commit APICommitListItem
	path := fmt.Sprintf("/api/v1/repos/%s/%s/git/commits/%s", owner, repo, sha)
	if err := c.get(ctx, path, &commit); err != nil {
		return nil, fmt.Errorf("get commit %s/%s/%s: %w", owner, repo, sha, err)
	}
	return &commit, nil
}

// ListCommitsFiltered returns commits with filtering options.
func (c *Client) ListCommitsFiltered(ctx context.Context, owner, repo string, opts CommitListOptions) ([]APICommitListItem, error) {
	if opts.Limit <= 0 || opts.Limit > 50 {
		opts.Limit = 20
	}
	if opts.Page < 1 {
		opts.Page = 1
	}
	
	path := fmt.Sprintf("/api/v1/repos/%s/%s/commits?page=%d&limit=%d", owner, repo, opts.Page, opts.Limit)
	if opts.SHA != "" {
		path += "&sha=" + opts.SHA
	}
	if opts.Path != "" {
		path += "&path=" + opts.Path
	}
	if opts.Author != "" {
		path += "&author=" + opts.Author
	}
	if opts.Since != "" {
		path += "&since=" + opts.Since
	}
	if opts.Until != "" {
		path += "&until=" + opts.Until
	}
	
	var commits []APICommitListItem
	if err := c.get(ctx, path, &commits); err != nil {
		return nil, fmt.Errorf("list commits filtered %s/%s: %w", owner, repo, err)
	}
	return commits, nil
}

// Compare compares two refs (branches, tags, or commits).
// basehead format: "base...head" e.g., "main...feature" or "abc123...def456"
func (c *Client) Compare(ctx context.Context, owner, repo, basehead string) (*APICompare, error) {
	var result APICompare
	path := fmt.Sprintf("/api/v1/repos/%s/%s/compare/%s", owner, repo, basehead)
	if err := c.get(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("compare %s/%s %s: %w", owner, repo, basehead, err)
	}
	return &result, nil
}

// GetDiff returns raw diff between two refs.
func (c *Client) GetDiff(ctx context.Context, owner, repo, basehead string) ([]byte, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/compare/%s.diff", owner, repo, basehead)
	return c.getRaw(ctx, path)
}

// GetPatch returns raw patch between two refs.
func (c *Client) GetPatch(ctx context.Context, owner, repo, basehead string) ([]byte, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/compare/%s.patch", owner, repo, basehead)
	return c.getRaw(ctx, path)
}

// ============================================================================
// Templates (for repo creation)
// ============================================================================

// ListGitignoreTemplates returns available gitignore templates.
func (c *Client) ListGitignoreTemplates(ctx context.Context) ([]string, error) {
	var templates []string
	if err := c.get(ctx, "/api/v1/gitignore/templates", &templates); err != nil {
		return nil, fmt.Errorf("list gitignore templates: %w", err)
	}
	return templates, nil
}

// ListLicenseTemplates returns available license templates.
func (c *Client) ListLicenseTemplates(ctx context.Context) ([]APILicenseTemplate, error) {
	var templates []APILicenseTemplate
	if err := c.get(ctx, "/api/v1/licenses", &templates); err != nil {
		return nil, fmt.Errorf("list license templates: %w", err)
	}
	return templates, nil
}

// ============================================================================
// Tier 2: Pull Requests
// ============================================================================

// ListPullRequests returns pull requests for a repository.
func (c *Client) ListPullRequests(ctx context.Context, owner, repo string, opts PRListOptions) ([]APIPullRequest, error) {
	if opts.Limit <= 0 || opts.Limit > 50 {
		opts.Limit = 20
	}
	if opts.Page < 1 {
		opts.Page = 1
	}
	
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls?page=%d&limit=%d", owner, repo, opts.Page, opts.Limit)
	if opts.State != "" {
		path += "&state=" + opts.State
	}
	if opts.Sort != "" {
		path += "&sort=" + opts.Sort
	}
	if opts.Labels != "" {
		path += "&labels=" + opts.Labels
	}
	
	var prs []APIPullRequest
	if err := c.get(ctx, path, &prs); err != nil {
		return nil, fmt.Errorf("list pull requests %s/%s: %w", owner, repo, err)
	}
	return prs, nil
}

// GetPullRequest returns a single pull request.
func (c *Client) GetPullRequest(ctx context.Context, owner, repo string, index int64) (*APIPullRequest, error) {
	var pr APIPullRequest
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d", owner, repo, index)
	if err := c.get(ctx, path, &pr); err != nil {
		return nil, fmt.Errorf("get pull request %s/%s#%d: %w", owner, repo, index, err)
	}
	return &pr, nil
}

// CreatePullRequest creates a new pull request.
func (c *Client) CreatePullRequest(ctx context.Context, owner, repo string, opts CreatePullRequestOptions) (*APIPullRequest, error) {
	var pr APIPullRequest
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls", owner, repo)
	if err := c.post(ctx, path, opts, &pr); err != nil {
		return nil, fmt.Errorf("create pull request %s/%s: %w", owner, repo, err)
	}
	return &pr, nil
}

// EditPullRequest updates a pull request.
func (c *Client) EditPullRequest(ctx context.Context, owner, repo string, index int64, opts EditPullRequestOptions) (*APIPullRequest, error) {
	var pr APIPullRequest
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d", owner, repo, index)
	if err := c.patch(ctx, path, opts, &pr); err != nil {
		return nil, fmt.Errorf("edit pull request %s/%s#%d: %w", owner, repo, index, err)
	}
	return &pr, nil
}

// MergePullRequest merges a pull request.
func (c *Client) MergePullRequest(ctx context.Context, owner, repo string, index int64, opts MergePullRequestOptions) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/merge", owner, repo, index)
	if err := c.post(ctx, path, opts, nil); err != nil {
		return fmt.Errorf("merge pull request %s/%s#%d: %w", owner, repo, index, err)
	}
	return nil
}

// GetPullRequestDiff returns the diff for a pull request.
func (c *Client) GetPullRequestDiff(ctx context.Context, owner, repo string, index int64) ([]byte, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d.diff", owner, repo, index)
	return c.getRaw(ctx, path)
}

// ListPRReviews returns reviews for a pull request.
func (c *Client) ListPRReviews(ctx context.Context, owner, repo string, index int64) ([]APIPRReview, error) {
	var reviews []APIPRReview
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/reviews", owner, repo, index)
	if err := c.get(ctx, path, &reviews); err != nil {
		return nil, fmt.Errorf("list PR reviews %s/%s#%d: %w", owner, repo, index, err)
	}
	return reviews, nil
}

// CreatePRReview creates a review on a pull request.
func (c *Client) CreatePRReview(ctx context.Context, owner, repo string, index int64, opts CreatePRReviewOptions) (*APIPRReview, error) {
	var review APIPRReview
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/reviews", owner, repo, index)
	if err := c.post(ctx, path, opts, &review); err != nil {
		return nil, fmt.Errorf("create PR review %s/%s#%d: %w", owner, repo, index, err)
	}
	return &review, nil
}

// ListPRComments returns comments on a pull request.
func (c *Client) ListPRComments(ctx context.Context, owner, repo string, index int64) ([]APIComment, error) {
	var comments []APIComment
	path := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/comments", owner, repo, index)
	if err := c.get(ctx, path, &comments); err != nil {
		// Try issues comments endpoint as fallback (PR is also an issue)
		path = fmt.Sprintf("/api/v1/repos/%s/%s/issues/%d/comments", owner, repo, index)
		if err2 := c.get(ctx, path, &comments); err2 != nil {
			return nil, fmt.Errorf("list PR comments %s/%s#%d: %w", owner, repo, index, err)
		}
	}
	return comments, nil
}

// ============================================================================
// Tier 2: Issues
// ============================================================================

// ListIssues returns issues for a repository.
func (c *Client) ListIssues(ctx context.Context, owner, repo string, opts IssueListOptions) ([]APIIssue, error) {
	if opts.Limit <= 0 || opts.Limit > 50 {
		opts.Limit = 20
	}
	if opts.Page < 1 {
		opts.Page = 1
	}
	
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues?page=%d&limit=%d", owner, repo, opts.Page, opts.Limit)
	if opts.State != "" {
		path += "&state=" + opts.State
	}
	if opts.Labels != "" {
		path += "&labels=" + opts.Labels
	}
	if opts.Milestone != "" {
		path += "&milestone=" + opts.Milestone
	}
	if opts.Assignee != "" {
		path += "&assignee=" + opts.Assignee
	}
	if opts.Creator != "" {
		path += "&creator=" + opts.Creator
	}
	if opts.Since != "" {
		path += "&since=" + opts.Since
	}
	if opts.Before != "" {
		path += "&before=" + opts.Before
	}
	
	var issues []APIIssue
	if err := c.get(ctx, path, &issues); err != nil {
		return nil, fmt.Errorf("list issues %s/%s: %w", owner, repo, err)
	}
	return issues, nil
}

// GetIssue returns a single issue.
func (c *Client) GetIssue(ctx context.Context, owner, repo string, index int64) (*APIIssue, error) {
	var issue APIIssue
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues/%d", owner, repo, index)
	if err := c.get(ctx, path, &issue); err != nil {
		return nil, fmt.Errorf("get issue %s/%s#%d: %w", owner, repo, index, err)
	}
	return &issue, nil
}

// CreateIssue creates a new issue.
func (c *Client) CreateIssue(ctx context.Context, owner, repo string, opts CreateIssueOptions) (*APIIssue, error) {
	var issue APIIssue
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues", owner, repo)
	if err := c.post(ctx, path, opts, &issue); err != nil {
		return nil, fmt.Errorf("create issue %s/%s: %w", owner, repo, err)
	}
	return &issue, nil
}

// EditIssue updates an issue.
func (c *Client) EditIssue(ctx context.Context, owner, repo string, index int64, opts EditIssueOptions) (*APIIssue, error) {
	var issue APIIssue
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues/%d", owner, repo, index)
	if err := c.patch(ctx, path, opts, &issue); err != nil {
		return nil, fmt.Errorf("edit issue %s/%s#%d: %w", owner, repo, index, err)
	}
	return &issue, nil
}

// ListIssueComments returns comments on an issue.
func (c *Client) ListIssueComments(ctx context.Context, owner, repo string, index int64) ([]APIComment, error) {
	var comments []APIComment
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues/%d/comments", owner, repo, index)
	if err := c.get(ctx, path, &comments); err != nil {
		return nil, fmt.Errorf("list issue comments %s/%s#%d: %w", owner, repo, index, err)
	}
	return comments, nil
}

// CreateIssueComment creates a comment on an issue.
func (c *Client) CreateIssueComment(ctx context.Context, owner, repo string, index int64, opts CreateCommentOptions) (*APIComment, error) {
	var comment APIComment
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues/%d/comments", owner, repo, index)
	if err := c.post(ctx, path, opts, &comment); err != nil {
		return nil, fmt.Errorf("create comment %s/%s#%d: %w", owner, repo, index, err)
	}
	return &comment, nil
}

// EditIssueComment updates a comment.
func (c *Client) EditIssueComment(ctx context.Context, owner, repo string, commentID int64, opts CreateCommentOptions) (*APIComment, error) {
	var comment APIComment
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues/comments/%d", owner, repo, commentID)
	if err := c.patch(ctx, path, opts, &comment); err != nil {
		return nil, fmt.Errorf("edit comment %s/%s/%d: %w", owner, repo, commentID, err)
	}
	return &comment, nil
}

// DeleteIssueComment deletes a comment.
func (c *Client) DeleteIssueComment(ctx context.Context, owner, repo string, commentID int64) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/issues/comments/%d", owner, repo, commentID)
	if err := c.delete(ctx, path); err != nil {
		return fmt.Errorf("delete comment %s/%s/%d: %w", owner, repo, commentID, err)
	}
	return nil
}

// ListLabels returns labels for a repository.
func (c *Client) ListLabels(ctx context.Context, owner, repo string) ([]APILabel, error) {
	var labels []APILabel
	path := fmt.Sprintf("/api/v1/repos/%s/%s/labels", owner, repo)
	if err := c.get(ctx, path, &labels); err != nil {
		return nil, fmt.Errorf("list labels %s/%s: %w", owner, repo, err)
	}
	return labels, nil
}

// ListMilestones returns milestones for a repository.
func (c *Client) ListMilestones(ctx context.Context, owner, repo string, state string) ([]APIMilestone, error) {
	var milestones []APIMilestone
	path := fmt.Sprintf("/api/v1/repos/%s/%s/milestones", owner, repo)
	if state != "" {
		path += "?state=" + state
	}
	if err := c.get(ctx, path, &milestones); err != nil {
		return nil, fmt.Errorf("list milestones %s/%s: %w", owner, repo, err)
	}
	return milestones, nil
}

// ============================================================================
// Tier 2: Collaborators
// ============================================================================

// ListCollaborators returns collaborators for a repository.
func (c *Client) ListCollaborators(ctx context.Context, owner, repo string) ([]APICollaborator, error) {
	var collaborators []APICollaborator
	path := fmt.Sprintf("/api/v1/repos/%s/%s/collaborators", owner, repo)
	if err := c.get(ctx, path, &collaborators); err != nil {
		return nil, fmt.Errorf("list collaborators %s/%s: %w", owner, repo, err)
	}
	return collaborators, nil
}

// IsCollaborator checks if a user is a collaborator.
func (c *Client) IsCollaborator(ctx context.Context, owner, repo, user string) (bool, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/collaborators/%s", owner, repo, user)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "token "+c.token)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("check collaborator: %w", err)
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusNoContent, nil
}

// AddCollaborator adds a user as a collaborator.
func (c *Client) AddCollaborator(ctx context.Context, owner, repo, user string, opts AddCollaboratorOptions) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/collaborators/%s", owner, repo, user)
	if err := c.put(ctx, path, opts, nil); err != nil {
		return fmt.Errorf("add collaborator %s/%s/%s: %w", owner, repo, user, err)
	}
	return nil
}

// RemoveCollaborator removes a collaborator from a repository.
func (c *Client) RemoveCollaborator(ctx context.Context, owner, repo, user string) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/collaborators/%s", owner, repo, user)
	if err := c.delete(ctx, path); err != nil {
		return fmt.Errorf("remove collaborator %s/%s/%s: %w", owner, repo, user, err)
	}
	return nil
}

// GetCollaboratorPermission returns the permission level for a collaborator.
func (c *Client) GetCollaboratorPermission(ctx context.Context, owner, repo, user string) (*APIPermissions, error) {
	var result struct {
		Permission  string         `json:"permission"`
		RoleName    string         `json:"role_name"`
		User        *APIUser       `json:"user"`
	}
	path := fmt.Sprintf("/api/v1/repos/%s/%s/collaborators/%s/permission", owner, repo, user)
	if err := c.get(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("get collaborator permission %s/%s/%s: %w", owner, repo, user, err)
	}
	
	perms := &APIPermissions{}
	switch result.Permission {
	case "admin", "owner":
		perms.Admin = true
		perms.Push = true
		perms.Pull = true
	case "write":
		perms.Push = true
		perms.Pull = true
	case "read":
		perms.Pull = true
	}
	return perms, nil
}

// ListRepoTeams returns teams with access to a repository (for org repos).
func (c *Client) ListRepoTeams(ctx context.Context, owner, repo string) ([]APITeam, error) {
	var teams []APITeam
	path := fmt.Sprintf("/api/v1/repos/%s/%s/teams", owner, repo)
	if err := c.get(ctx, path, &teams); err != nil {
		return nil, fmt.Errorf("list repo teams %s/%s: %w", owner, repo, err)
	}
	return teams, nil
}

// ============================================================================
// Tier 3: Webhooks
// ============================================================================

// ListHooks returns webhooks for a repository.
func (c *Client) ListHooks(ctx context.Context, owner, repo string) ([]APIHook, error) {
	var hooks []APIHook
	path := fmt.Sprintf("/api/v1/repos/%s/%s/hooks", owner, repo)
	if err := c.get(ctx, path, &hooks); err != nil {
		return nil, fmt.Errorf("list hooks %s/%s: %w", owner, repo, err)
	}
	return hooks, nil
}

// GetHook returns a single webhook.
func (c *Client) GetHook(ctx context.Context, owner, repo string, id int64) (*APIHook, error) {
	var hook APIHook
	path := fmt.Sprintf("/api/v1/repos/%s/%s/hooks/%d", owner, repo, id)
	if err := c.get(ctx, path, &hook); err != nil {
		return nil, fmt.Errorf("get hook %s/%s/%d: %w", owner, repo, id, err)
	}
	return &hook, nil
}

// CreateHook creates a webhook.
func (c *Client) CreateHook(ctx context.Context, owner, repo string, opts CreateHookOptions) (*APIHook, error) {
	var hook APIHook
	path := fmt.Sprintf("/api/v1/repos/%s/%s/hooks", owner, repo)
	if err := c.post(ctx, path, opts, &hook); err != nil {
		return nil, fmt.Errorf("create hook %s/%s: %w", owner, repo, err)
	}
	return &hook, nil
}

// EditHook updates a webhook.
func (c *Client) EditHook(ctx context.Context, owner, repo string, id int64, opts EditHookOptions) (*APIHook, error) {
	var hook APIHook
	path := fmt.Sprintf("/api/v1/repos/%s/%s/hooks/%d", owner, repo, id)
	if err := c.patch(ctx, path, opts, &hook); err != nil {
		return nil, fmt.Errorf("edit hook %s/%s/%d: %w", owner, repo, id, err)
	}
	return &hook, nil
}

// DeleteHook deletes a webhook.
func (c *Client) DeleteHook(ctx context.Context, owner, repo string, id int64) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/hooks/%d", owner, repo, id)
	if err := c.delete(ctx, path); err != nil {
		return fmt.Errorf("delete hook %s/%s/%d: %w", owner, repo, id, err)
	}
	return nil
}

// TestHook tests a webhook by sending a test payload.
func (c *Client) TestHook(ctx context.Context, owner, repo string, id int64) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/hooks/%d/tests", owner, repo, id)
	if err := c.post(ctx, path, nil, nil); err != nil {
		return fmt.Errorf("test hook %s/%s/%d: %w", owner, repo, id, err)
	}
	return nil
}

// ============================================================================
// Tier 3: Deploy Keys
// ============================================================================

// ListDeployKeys returns deploy keys for a repository.
func (c *Client) ListDeployKeys(ctx context.Context, owner, repo string) ([]APIDeployKey, error) {
	var keys []APIDeployKey
	path := fmt.Sprintf("/api/v1/repos/%s/%s/keys", owner, repo)
	if err := c.get(ctx, path, &keys); err != nil {
		return nil, fmt.Errorf("list deploy keys %s/%s: %w", owner, repo, err)
	}
	return keys, nil
}

// GetDeployKey returns a single deploy key.
func (c *Client) GetDeployKey(ctx context.Context, owner, repo string, id int64) (*APIDeployKey, error) {
	var key APIDeployKey
	path := fmt.Sprintf("/api/v1/repos/%s/%s/keys/%d", owner, repo, id)
	if err := c.get(ctx, path, &key); err != nil {
		return nil, fmt.Errorf("get deploy key %s/%s/%d: %w", owner, repo, id, err)
	}
	return &key, nil
}

// CreateDeployKey creates a deploy key.
func (c *Client) CreateDeployKey(ctx context.Context, owner, repo string, opts CreateDeployKeyOptions) (*APIDeployKey, error) {
	var key APIDeployKey
	path := fmt.Sprintf("/api/v1/repos/%s/%s/keys", owner, repo)
	if err := c.post(ctx, path, opts, &key); err != nil {
		return nil, fmt.Errorf("create deploy key %s/%s: %w", owner, repo, err)
	}
	return &key, nil
}

// DeleteDeployKey deletes a deploy key.
func (c *Client) DeleteDeployKey(ctx context.Context, owner, repo string, id int64) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/keys/%d", owner, repo, id)
	if err := c.delete(ctx, path); err != nil {
		return fmt.Errorf("delete deploy key %s/%s/%d: %w", owner, repo, id, err)
	}
	return nil
}

// ============================================================================
// Tier 3: Releases
// ============================================================================

// ListReleases returns releases for a repository.
func (c *Client) ListReleases(ctx context.Context, owner, repo string, page, limit int) ([]APIRelease, error) {
	var releases []APIRelease
	path := fmt.Sprintf("/api/v1/repos/%s/%s/releases?page=%d&limit=%d", owner, repo, page, limit)
	if err := c.get(ctx, path, &releases); err != nil {
		return nil, fmt.Errorf("list releases %s/%s: %w", owner, repo, err)
	}
	return releases, nil
}

// GetRelease returns a single release.
func (c *Client) GetRelease(ctx context.Context, owner, repo string, id int64) (*APIRelease, error) {
	var release APIRelease
	path := fmt.Sprintf("/api/v1/repos/%s/%s/releases/%d", owner, repo, id)
	if err := c.get(ctx, path, &release); err != nil {
		return nil, fmt.Errorf("get release %s/%s/%d: %w", owner, repo, id, err)
	}
	return &release, nil
}

// GetReleaseByTag returns a release by tag name.
func (c *Client) GetReleaseByTag(ctx context.Context, owner, repo, tag string) (*APIRelease, error) {
	var release APIRelease
	path := fmt.Sprintf("/api/v1/repos/%s/%s/releases/tags/%s", owner, repo, tag)
	if err := c.get(ctx, path, &release); err != nil {
		return nil, fmt.Errorf("get release by tag %s/%s/%s: %w", owner, repo, tag, err)
	}
	return &release, nil
}

// GetLatestRelease returns the latest release.
func (c *Client) GetLatestRelease(ctx context.Context, owner, repo string) (*APIRelease, error) {
	var release APIRelease
	path := fmt.Sprintf("/api/v1/repos/%s/%s/releases/latest", owner, repo)
	if err := c.get(ctx, path, &release); err != nil {
		return nil, fmt.Errorf("get latest release %s/%s: %w", owner, repo, err)
	}
	return &release, nil
}

// CreateRelease creates a release.
func (c *Client) CreateRelease(ctx context.Context, owner, repo string, opts CreateReleaseOptions) (*APIRelease, error) {
	var release APIRelease
	path := fmt.Sprintf("/api/v1/repos/%s/%s/releases", owner, repo)
	if err := c.post(ctx, path, opts, &release); err != nil {
		return nil, fmt.Errorf("create release %s/%s: %w", owner, repo, err)
	}
	return &release, nil
}

// EditRelease updates a release.
func (c *Client) EditRelease(ctx context.Context, owner, repo string, id int64, opts EditReleaseOptions) (*APIRelease, error) {
	var release APIRelease
	path := fmt.Sprintf("/api/v1/repos/%s/%s/releases/%d", owner, repo, id)
	if err := c.patch(ctx, path, opts, &release); err != nil {
		return nil, fmt.Errorf("edit release %s/%s/%d: %w", owner, repo, id, err)
	}
	return &release, nil
}

// DeleteRelease deletes a release.
func (c *Client) DeleteRelease(ctx context.Context, owner, repo string, id int64) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/releases/%d", owner, repo, id)
	if err := c.delete(ctx, path); err != nil {
		return fmt.Errorf("delete release %s/%s/%d: %w", owner, repo, id, err)
	}
	return nil
}

// ListReleaseAssets returns assets for a release.
func (c *Client) ListReleaseAssets(ctx context.Context, owner, repo string, releaseID int64) ([]APIReleaseAsset, error) {
	var assets []APIReleaseAsset
	path := fmt.Sprintf("/api/v1/repos/%s/%s/releases/%d/assets", owner, repo, releaseID)
	if err := c.get(ctx, path, &assets); err != nil {
		return nil, fmt.Errorf("list release assets %s/%s/%d: %w", owner, repo, releaseID, err)
	}
	return assets, nil
}

// DeleteReleaseAsset deletes a release asset.
func (c *Client) DeleteReleaseAsset(ctx context.Context, owner, repo string, releaseID, assetID int64) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/releases/%d/assets/%d", owner, repo, releaseID, assetID)
	if err := c.delete(ctx, path); err != nil {
		return fmt.Errorf("delete release asset %s/%s/%d/%d: %w", owner, repo, releaseID, assetID, err)
	}
	return nil
}

// ============================================================================
// Tier 3: Actions / CI Status
// ============================================================================

// ListWorkflows returns workflows for a repository.
func (c *Client) ListWorkflows(ctx context.Context, owner, repo string) ([]APIWorkflow, error) {
	var result struct {
		Workflows []APIWorkflow `json:"workflows"`
	}
	path := fmt.Sprintf("/api/v1/repos/%s/%s/actions/workflows", owner, repo)
	if err := c.get(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("list workflows %s/%s: %w", owner, repo, err)
	}
	return result.Workflows, nil
}

// ListActionRuns returns workflow runs for a repository.
func (c *Client) ListActionRuns(ctx context.Context, owner, repo string, opts ActionRunListOptions) ([]APIActionRun, error) {
	var result struct {
		Runs []APIActionRun `json:"workflow_runs"`
	}
	path := fmt.Sprintf("/api/v1/repos/%s/%s/actions/runs?page=%d&limit=%d", owner, repo, opts.Page, opts.Limit)
	if opts.Branch != "" {
		path += "&branch=" + opts.Branch
	}
	if opts.Status != "" {
		path += "&status=" + opts.Status
	}
	if opts.Event != "" {
		path += "&event=" + opts.Event
	}
	if err := c.get(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("list action runs %s/%s: %w", owner, repo, err)
	}
	return result.Runs, nil
}

// GetActionRun returns a single workflow run.
func (c *Client) GetActionRun(ctx context.Context, owner, repo string, runID int64) (*APIActionRun, error) {
	var run APIActionRun
	path := fmt.Sprintf("/api/v1/repos/%s/%s/actions/runs/%d", owner, repo, runID)
	if err := c.get(ctx, path, &run); err != nil {
		return nil, fmt.Errorf("get action run %s/%s/%d: %w", owner, repo, runID, err)
	}
	return &run, nil
}

// ListActionJobs returns jobs for a workflow run.
func (c *Client) ListActionJobs(ctx context.Context, owner, repo string, runID int64) ([]APIActionJob, error) {
	var result struct {
		Jobs []APIActionJob `json:"jobs"`
	}
	path := fmt.Sprintf("/api/v1/repos/%s/%s/actions/runs/%d/jobs", owner, repo, runID)
	if err := c.get(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("list action jobs %s/%s/%d: %w", owner, repo, runID, err)
	}
	return result.Jobs, nil
}

// GetActionJobLogs returns logs for a job (raw text).
func (c *Client) GetActionJobLogs(ctx context.Context, owner, repo string, jobID int64) ([]byte, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/actions/jobs/%d/logs", owner, repo, jobID)
	return c.getRaw(ctx, path)
}

// CancelActionRun cancels a workflow run.
func (c *Client) CancelActionRun(ctx context.Context, owner, repo string, runID int64) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/actions/runs/%d/cancel", owner, repo, runID)
	if err := c.post(ctx, path, nil, nil); err != nil {
		return fmt.Errorf("cancel action run %s/%s/%d: %w", owner, repo, runID, err)
	}
	return nil
}

// RerunActionRun reruns a workflow run.
func (c *Client) RerunActionRun(ctx context.Context, owner, repo string, runID int64) error {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/actions/runs/%d/rerun", owner, repo, runID)
	if err := c.post(ctx, path, nil, nil); err != nil {
		return fmt.Errorf("rerun action run %s/%s/%d: %w", owner, repo, runID, err)
	}
	return nil
}

// GetCombinedStatus returns the combined status for a commit.
func (c *Client) GetCombinedStatus(ctx context.Context, owner, repo, ref string) (*APICombinedStatus, error) {
	var status APICombinedStatus
	path := fmt.Sprintf("/api/v1/repos/%s/%s/commits/%s/status", owner, repo, ref)
	if err := c.get(ctx, path, &status); err != nil {
		return nil, fmt.Errorf("get combined status %s/%s/%s: %w", owner, repo, ref, err)
	}
	return &status, nil
}

// ListCommitStatuses returns statuses for a commit.
func (c *Client) ListCommitStatuses(ctx context.Context, owner, repo, ref string, page, limit int) ([]APICommitStatus, error) {
	var statuses []APICommitStatus
	path := fmt.Sprintf("/api/v1/repos/%s/%s/commits/%s/statuses?page=%d&limit=%d", owner, repo, ref, page, limit)
	if err := c.get(ctx, path, &statuses); err != nil {
		return nil, fmt.Errorf("list commit statuses %s/%s/%s: %w", owner, repo, ref, err)
	}
	return statuses, nil
}

// CreateCommitStatus creates a status for a commit.
func (c *Client) CreateCommitStatus(ctx context.Context, owner, repo, sha string, opts CreateStatusOptions) (*APICommitStatus, error) {
	var status APICommitStatus
	path := fmt.Sprintf("/api/v1/repos/%s/%s/statuses/%s", owner, repo, sha)
	if err := c.post(ctx, path, opts, &status); err != nil {
		return nil, fmt.Errorf("create commit status %s/%s/%s: %w", owner, repo, sha, err)
	}
	return &status, nil
}

// ============================================================================
// HTTP helpers
// ============================================================================

func (c *Client) get(ctx context.Context, path string, result interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, result)
}

func (c *Client) post(ctx context.Context, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = strings.NewReader(string(data))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.do(req, result)
}

func (c *Client) put(ctx context.Context, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = strings.NewReader(string(data))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.do(req, result)
}

func (c *Client) patch(ctx context.Context, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = strings.NewReader(string(data))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.do(req, result)
}

func (c *Client) delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

func (c *Client) getRaw(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
}

func (c *Client) do(req *http.Request, result interface{}) error {
	req.Header.Set("Authorization", "token "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
