// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// Client
// ============================================================================

// Client is a GitHub API client
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient creates a new GitHub API client
func NewClient(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ============================================================================
// HTTP Helpers
// ============================================================================

func (c *Client) request(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	u := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	return resp, nil
}

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	return c.request(ctx, http.MethodGet, path, nil)
}

func (c *Client) post(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return c.request(ctx, http.MethodPost, path, body)
}

func (c *Client) patch(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return c.request(ctx, http.MethodPatch, path, body)
}

func (c *Client) put(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return c.request(ctx, http.MethodPut, path, body)
}

func (c *Client) delete(ctx context.Context, path string) (*http.Response, error) {
	return c.request(ctx, http.MethodDelete, path, nil)
}

func decodeJSON[T any](resp *http.Response) (T, error) {
	var result T
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var apiErr APIError
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil && apiErr.Message != "" {
			return result, fmt.Errorf("github api error (%d): %s", resp.StatusCode, apiErr.Message)
		}
		return result, fmt.Errorf("github api error: %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return result, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

// ============================================================================
// User / Auth
// ============================================================================

// GetAuthenticatedUser returns the authenticated user
func (c *Client) GetAuthenticatedUser(ctx context.Context) (*APIUser, error) {
	resp, err := c.get(ctx, "/user")
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIUser](resp)
}

// ============================================================================
// Repositories
// ============================================================================

// ListUserRepos lists repositories for the authenticated user
func (c *Client) ListUserRepos(ctx context.Context, page, perPage int) ([]APIRepository, error) {
	if perPage <= 0 {
		perPage = 100
	}
	path := fmt.Sprintf("/user/repos?per_page=%d&page=%d&sort=updated", perPage, page)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIRepository](resp)
}

// ListAllUserRepos fetches all repositories (handles pagination)
func (c *Client) ListAllUserRepos(ctx context.Context) ([]APIRepository, error) {
	var all []APIRepository
	page := 1
	for {
		repos, err := c.ListUserRepos(ctx, page, 100)
		if err != nil {
			return nil, err
		}
		if len(repos) == 0 {
			break
		}
		all = append(all, repos...)
		if len(repos) < 100 {
			break
		}
		page++
	}
	return all, nil
}

// GetRepository gets a repository by owner and name
func (c *Client) GetRepository(ctx context.Context, owner, repo string) (*APIRepository, error) {
	path := fmt.Sprintf("/repos/%s/%s", owner, repo)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIRepository](resp)
}

// CreateUserRepo creates a new repository for the authenticated user
func (c *Client) CreateUserRepo(ctx context.Context, opts CreateRepoOptions) (*APIRepository, error) {
	resp, err := c.post(ctx, "/user/repos", opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIRepository](resp)
}

// UpdateRepository updates a repository
func (c *Client) UpdateRepository(ctx context.Context, owner, repo string, opts UpdateRepoOptions) (*APIRepository, error) {
	path := fmt.Sprintf("/repos/%s/%s", owner, repo)
	resp, err := c.patch(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIRepository](resp)
}

// DeleteRepository deletes a repository
func (c *Client) DeleteRepository(ctx context.Context, owner, repo string) error {
	path := fmt.Sprintf("/repos/%s/%s", owner, repo)
	resp, err := c.delete(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("delete repository failed: %d", resp.StatusCode)
	}
	return nil
}

// ============================================================================
// Branches
// ============================================================================

// ListBranches lists branches for a repository
func (c *Client) ListBranches(ctx context.Context, owner, repo string, page, perPage int) ([]APIBranch, error) {
	if perPage <= 0 {
		perPage = 100
	}
	path := fmt.Sprintf("/repos/%s/%s/branches?per_page=%d&page=%d", owner, repo, perPage, page)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIBranch](resp)
}

// GetBranch gets a specific branch
func (c *Client) GetBranch(ctx context.Context, owner, repo, branch string) (*APIBranch, error) {
	path := fmt.Sprintf("/repos/%s/%s/branches/%s", owner, repo, url.PathEscape(branch))
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIBranch](resp)
}

// ============================================================================
// Commits
// ============================================================================

// ListCommits lists commits for a repository
func (c *Client) ListCommits(ctx context.Context, owner, repo, sha string, page, perPage int) ([]APICommit, error) {
	if perPage <= 0 {
		perPage = 30
	}
	path := fmt.Sprintf("/repos/%s/%s/commits?per_page=%d&page=%d", owner, repo, perPage, page)
	if sha != "" {
		path += "&sha=" + url.QueryEscape(sha)
	}
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APICommit](resp)
}

// GetCommit gets a specific commit
func (c *Client) GetCommit(ctx context.Context, owner, repo, sha string) (*APICommit, error) {
	path := fmt.Sprintf("/repos/%s/%s/commits/%s", owner, repo, sha)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APICommit](resp)
}

// ============================================================================
// Tags
// ============================================================================

// ListTags lists tags for a repository
func (c *Client) ListTags(ctx context.Context, owner, repo string, page, perPage int) ([]APITag, error) {
	if perPage <= 0 {
		perPage = 100
	}
	path := fmt.Sprintf("/repos/%s/%s/tags?per_page=%d&page=%d", owner, repo, perPage, page)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APITag](resp)
}

// ============================================================================
// Contents (Files)
// ============================================================================

// GetContents gets file or directory contents
func (c *Client) GetContents(ctx context.Context, owner, repo, path, ref string) ([]APIContent, error) {
	reqPath := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path)
	if ref != "" {
		reqPath += "?ref=" + url.QueryEscape(ref)
	}
	resp, err := c.get(ctx, reqPath)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("get contents failed: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// GitHub returns an array for directories, single object for files
	var contents []APIContent
	if err := json.Unmarshal(body, &contents); err != nil {
		// Try single file
		var single APIContent
		if err := json.Unmarshal(body, &single); err != nil {
			return nil, fmt.Errorf("decode contents: %w", err)
		}
		return []APIContent{single}, nil
	}
	return contents, nil
}

// GetFileContent gets the raw content of a file
func (c *Client) GetFileContent(ctx context.Context, owner, repo, path, ref string) ([]byte, error) {
	contents, err := c.GetContents(ctx, owner, repo, path, ref)
	if err != nil {
		return nil, err
	}
	if len(contents) == 0 {
		return nil, fmt.Errorf("file not found: %s", path)
	}

	content := contents[0]
	if content.Type != "file" {
		return nil, fmt.Errorf("path is not a file: %s", path)
	}

	if content.Encoding == "base64" {
		decoded, err := base64.StdEncoding.DecodeString(content.Content)
		if err != nil {
			return nil, fmt.Errorf("decode base64: %w", err)
		}
		return decoded, nil
	}

	return []byte(content.Content), nil
}

// CreateOrUpdateFile creates or updates a file
func (c *Client) CreateOrUpdateFile(ctx context.Context, owner, repo, path string, opts CreateFileOptions) error {
	reqPath := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path)
	resp, err := c.put(ctx, reqPath, opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create/update file failed (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// ============================================================================
// Pull Requests
// ============================================================================

// ListPullRequests lists pull requests
func (c *Client) ListPullRequests(ctx context.Context, owner, repo, state string, page, perPage int) ([]APIPullRequest, error) {
	if perPage <= 0 {
		perPage = 30
	}
	if state == "" {
		state = "open"
	}
	path := fmt.Sprintf("/repos/%s/%s/pulls?state=%s&per_page=%d&page=%d", owner, repo, state, perPage, page)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIPullRequest](resp)
}

// GetPullRequest gets a specific pull request
func (c *Client) GetPullRequest(ctx context.Context, owner, repo string, number int) (*APIPullRequest, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, number)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIPullRequest](resp)
}

// CreatePullRequest creates a pull request
func (c *Client) CreatePullRequest(ctx context.Context, owner, repo string, opts CreatePROptions) (*APIPullRequest, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls", owner, repo)
	resp, err := c.post(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIPullRequest](resp)
}

// MergePullRequest merges a pull request
func (c *Client) MergePullRequest(ctx context.Context, owner, repo string, number int, commitTitle, commitMessage, mergeMethod string) error {
	if mergeMethod == "" {
		mergeMethod = "merge" // merge, squash, rebase
	}
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d/merge", owner, repo, number)
	body := map[string]string{
		"merge_method": mergeMethod,
	}
	if commitTitle != "" {
		body["commit_title"] = commitTitle
	}
	if commitMessage != "" {
		body["commit_message"] = commitMessage
	}
	resp, err := c.put(ctx, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("merge failed: %d", resp.StatusCode)
	}
	return nil
}

// ============================================================================
// Issues
// ============================================================================

// ListIssues lists issues (excludes pull requests)
func (c *Client) ListIssues(ctx context.Context, owner, repo, state string, page, perPage int) ([]APIIssue, error) {
	if perPage <= 0 {
		perPage = 30
	}
	if state == "" {
		state = "open"
	}
	path := fmt.Sprintf("/repos/%s/%s/issues?state=%s&per_page=%d&page=%d", owner, repo, state, perPage, page)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	issues, err := decodeJSON[[]APIIssue](resp)
	if err != nil {
		return nil, err
	}

	// Filter out pull requests (GitHub includes them in issues endpoint)
	var result []APIIssue
	for _, issue := range issues {
		if issue.PullRequest == nil {
			result = append(result, issue)
		}
	}
	return result, nil
}

// GetIssue gets a specific issue
func (c *Client) GetIssue(ctx context.Context, owner, repo string, number int) (*APIIssue, error) {
	path := fmt.Sprintf("/repos/%s/%s/issues/%d", owner, repo, number)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIIssue](resp)
}

// CreateIssue creates an issue
func (c *Client) CreateIssue(ctx context.Context, owner, repo string, opts CreateIssueOptions) (*APIIssue, error) {
	path := fmt.Sprintf("/repos/%s/%s/issues", owner, repo)
	resp, err := c.post(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIIssue](resp)
}

// ============================================================================
// Releases
// ============================================================================

// ListReleases lists releases
func (c *Client) ListReleases(ctx context.Context, owner, repo string, page, perPage int) ([]APIRelease, error) {
	if perPage <= 0 {
		perPage = 30
	}
	path := fmt.Sprintf("/repos/%s/%s/releases?per_page=%d&page=%d", owner, repo, perPage, page)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIRelease](resp)
}

// GetLatestRelease gets the latest release
func (c *Client) GetLatestRelease(ctx context.Context, owner, repo string) (*APIRelease, error) {
	path := fmt.Sprintf("/repos/%s/%s/releases/latest", owner, repo)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIRelease](resp)
}

// CreateRelease creates a release
func (c *Client) CreateRelease(ctx context.Context, owner, repo string, opts CreateReleaseOptions) (*APIRelease, error) {
	path := fmt.Sprintf("/repos/%s/%s/releases", owner, repo)
	resp, err := c.post(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIRelease](resp)
}

// ============================================================================
// Webhooks
// ============================================================================

// ListHooks lists repository webhooks
func (c *Client) ListHooks(ctx context.Context, owner, repo string) ([]APIHook, error) {
	path := fmt.Sprintf("/repos/%s/%s/hooks", owner, repo)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIHook](resp)
}

// CreateHook creates a webhook
func (c *Client) CreateHook(ctx context.Context, owner, repo string, opts CreateHookOptions) (*APIHook, error) {
	path := fmt.Sprintf("/repos/%s/%s/hooks", owner, repo)
	resp, err := c.post(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIHook](resp)
}

// DeleteHook deletes a webhook
func (c *Client) DeleteHook(ctx context.Context, owner, repo string, hookID int64) error {
	path := fmt.Sprintf("/repos/%s/%s/hooks/%d", owner, repo, hookID)
	resp, err := c.delete(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("delete hook failed: %d", resp.StatusCode)
	}
	return nil
}

// ============================================================================
// Deploy Keys
// ============================================================================

// ListDeployKeys lists deploy keys
func (c *Client) ListDeployKeys(ctx context.Context, owner, repo string) ([]APIDeployKey, error) {
	path := fmt.Sprintf("/repos/%s/%s/keys", owner, repo)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIDeployKey](resp)
}

// CreateDeployKey creates a deploy key
func (c *Client) CreateDeployKey(ctx context.Context, owner, repo string, opts CreateDeployKeyOptions) (*APIDeployKey, error) {
	path := fmt.Sprintf("/repos/%s/%s/keys", owner, repo)
	resp, err := c.post(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIDeployKey](resp)
}

// DeleteDeployKey deletes a deploy key
func (c *Client) DeleteDeployKey(ctx context.Context, owner, repo string, keyID int64) error {
	path := fmt.Sprintf("/repos/%s/%s/keys/%d", owner, repo, keyID)
	resp, err := c.delete(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("delete key failed: %d", resp.StatusCode)
	}
	return nil
}

// ============================================================================
// Collaborators
// ============================================================================

// ListCollaborators lists repository collaborators
func (c *Client) ListCollaborators(ctx context.Context, owner, repo string) ([]APICollaborator, error) {
	path := fmt.Sprintf("/repos/%s/%s/collaborators", owner, repo)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APICollaborator](resp)
}

// AddCollaborator adds a collaborator
func (c *Client) AddCollaborator(ctx context.Context, owner, repo, username, permission string) error {
	if permission == "" {
		permission = "push"
	}
	path := fmt.Sprintf("/repos/%s/%s/collaborators/%s", owner, repo, username)
	body := map[string]string{"permission": permission}
	resp, err := c.put(ctx, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("add collaborator failed: %d", resp.StatusCode)
	}
	return nil
}

// RemoveCollaborator removes a collaborator
func (c *Client) RemoveCollaborator(ctx context.Context, owner, repo, username string) error {
	path := fmt.Sprintf("/repos/%s/%s/collaborators/%s", owner, repo, username)
	resp, err := c.delete(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("remove collaborator failed: %d", resp.StatusCode)
	}
	return nil
}

// ============================================================================
// Rate Limit
// ============================================================================

// RateLimitInfo contains rate limit information
type RateLimitInfo struct {
	Limit     int
	Remaining int
	Reset     time.Time
}

// GetRateLimit returns rate limit info from last response
func (c *Client) GetRateLimit(ctx context.Context) (*RateLimitInfo, error) {
	resp, err := c.get(ctx, "/rate_limit")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limit, _ := strconv.Atoi(resp.Header.Get("X-RateLimit-Limit"))
	remaining, _ := strconv.Atoi(resp.Header.Get("X-RateLimit-Remaining"))
	resetUnix, _ := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)

	return &RateLimitInfo{
		Limit:     limit,
		Remaining: remaining,
		Reset:     time.Unix(resetUnix, 0),
	}, nil
}
