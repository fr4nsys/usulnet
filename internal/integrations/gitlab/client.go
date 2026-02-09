// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package gitlab

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ============================================================================
// Client
// ============================================================================

// Client is a GitLab API client
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient creates a new GitLab API client
func NewClient(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	
	// Ensure we use the API endpoint
	if !strings.Contains(baseURL, "/api/v4") {
		baseURL = baseURL + "/api/v4"
	}

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

	req.Header.Set("PRIVATE-TOKEN", c.token)
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
		body, _ := io.ReadAll(resp.Body)
		var apiErr APIError
		if err := json.Unmarshal(body, &apiErr); err == nil {
			if apiErr.Message != "" {
				return result, fmt.Errorf("gitlab api error (%d): %s", resp.StatusCode, apiErr.Message)
			}
			if apiErr.Error != "" {
				return result, fmt.Errorf("gitlab api error (%d): %s", resp.StatusCode, apiErr.Error)
			}
		}
		return result, fmt.Errorf("gitlab api error: %d - %s", resp.StatusCode, string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return result, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

// encodeProjectID URL-encodes a project path or returns the ID as-is
func encodeProjectID(projectID string) string {
	// If it's a numeric ID, return as-is
	if _, err := fmt.Sscanf(projectID, "%d", new(int)); err == nil {
		return projectID
	}
	// Otherwise URL-encode the path
	return url.PathEscape(projectID)
}

// ============================================================================
// User / Auth
// ============================================================================

// GetCurrentUser returns the authenticated user
func (c *Client) GetCurrentUser(ctx context.Context) (*APIUser, error) {
	resp, err := c.get(ctx, "/user")
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIUser](resp)
}

// GetVersion returns the GitLab version
func (c *Client) GetVersion(ctx context.Context) (string, error) {
	resp, err := c.get(ctx, "/version")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Version, nil
}

// ============================================================================
// Projects (Repositories)
// ============================================================================

// ListProjects lists projects accessible to the authenticated user
func (c *Client) ListProjects(ctx context.Context, page, perPage int, owned bool) ([]APIProject, error) {
	if perPage <= 0 {
		perPage = 100
	}
	path := fmt.Sprintf("/projects?per_page=%d&page=%d&order_by=updated_at&sort=desc", perPage, page)
	if owned {
		path += "&owned=true"
	} else {
		path += "&membership=true"
	}
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIProject](resp)
}

// ListAllProjects fetches all accessible projects (handles pagination)
func (c *Client) ListAllProjects(ctx context.Context, owned bool) ([]APIProject, error) {
	var all []APIProject
	page := 1
	for {
		projects, err := c.ListProjects(ctx, page, 100, owned)
		if err != nil {
			return nil, err
		}
		if len(projects) == 0 {
			break
		}
		all = append(all, projects...)
		if len(projects) < 100 {
			break
		}
		page++
	}
	return all, nil
}

// GetProject gets a project by ID or path
func (c *Client) GetProject(ctx context.Context, projectID string) (*APIProject, error) {
	path := fmt.Sprintf("/projects/%s", encodeProjectID(projectID))
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIProject](resp)
}

// CreateProject creates a new project
func (c *Client) CreateProject(ctx context.Context, opts CreateProjectOptions) (*APIProject, error) {
	resp, err := c.post(ctx, "/projects", opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIProject](resp)
}

// UpdateProject updates a project
func (c *Client) UpdateProject(ctx context.Context, projectID string, opts UpdateProjectOptions) (*APIProject, error) {
	path := fmt.Sprintf("/projects/%s", encodeProjectID(projectID))
	resp, err := c.put(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIProject](resp)
}

// DeleteProject deletes a project
func (c *Client) DeleteProject(ctx context.Context, projectID string) error {
	path := fmt.Sprintf("/projects/%s", encodeProjectID(projectID))
	resp, err := c.delete(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("delete project failed: %d", resp.StatusCode)
	}
	return nil
}

// ============================================================================
// Branches
// ============================================================================

// ListBranches lists branches for a project
func (c *Client) ListBranches(ctx context.Context, projectID string, page, perPage int) ([]APIBranch, error) {
	if perPage <= 0 {
		perPage = 100
	}
	path := fmt.Sprintf("/projects/%s/repository/branches?per_page=%d&page=%d", encodeProjectID(projectID), perPage, page)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIBranch](resp)
}

// GetBranch gets a specific branch
func (c *Client) GetBranch(ctx context.Context, projectID, branch string) (*APIBranch, error) {
	path := fmt.Sprintf("/projects/%s/repository/branches/%s", encodeProjectID(projectID), url.PathEscape(branch))
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIBranch](resp)
}

// CreateBranch creates a new branch
func (c *Client) CreateBranch(ctx context.Context, projectID, branch, ref string) (*APIBranch, error) {
	path := fmt.Sprintf("/projects/%s/repository/branches", encodeProjectID(projectID))
	body := map[string]string{
		"branch": branch,
		"ref":    ref,
	}
	resp, err := c.post(ctx, path, body)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIBranch](resp)
}

// DeleteBranch deletes a branch
func (c *Client) DeleteBranch(ctx context.Context, projectID, branch string) error {
	path := fmt.Sprintf("/projects/%s/repository/branches/%s", encodeProjectID(projectID), url.PathEscape(branch))
	resp, err := c.delete(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("delete branch failed: %d", resp.StatusCode)
	}
	return nil
}

// ============================================================================
// Commits
// ============================================================================

// ListCommits lists commits for a project
func (c *Client) ListCommits(ctx context.Context, projectID, refName string, page, perPage int) ([]APICommit, error) {
	if perPage <= 0 {
		perPage = 30
	}
	path := fmt.Sprintf("/projects/%s/repository/commits?per_page=%d&page=%d", encodeProjectID(projectID), perPage, page)
	if refName != "" {
		path += "&ref_name=" + url.QueryEscape(refName)
	}
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APICommit](resp)
}

// GetCommit gets a specific commit
func (c *Client) GetCommit(ctx context.Context, projectID, sha string) (*APICommit, error) {
	path := fmt.Sprintf("/projects/%s/repository/commits/%s", encodeProjectID(projectID), sha)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APICommit](resp)
}

// ============================================================================
// Tags
// ============================================================================

// ListTags lists tags for a project
func (c *Client) ListTags(ctx context.Context, projectID string, page, perPage int) ([]APITag, error) {
	if perPage <= 0 {
		perPage = 100
	}
	path := fmt.Sprintf("/projects/%s/repository/tags?per_page=%d&page=%d", encodeProjectID(projectID), perPage, page)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APITag](resp)
}

// ============================================================================
// Files / Repository Tree
// ============================================================================

// ListTree lists files and directories in a repository
func (c *Client) ListTree(ctx context.Context, projectID, path, ref string, page, perPage int) ([]APITreeItem, error) {
	if perPage <= 0 {
		perPage = 100
	}
	reqPath := fmt.Sprintf("/projects/%s/repository/tree?per_page=%d&page=%d", encodeProjectID(projectID), perPage, page)
	if path != "" {
		reqPath += "&path=" + url.QueryEscape(path)
	}
	if ref != "" {
		reqPath += "&ref=" + url.QueryEscape(ref)
	}
	resp, err := c.get(ctx, reqPath)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APITreeItem](resp)
}

// GetFile gets a file's content
func (c *Client) GetFile(ctx context.Context, projectID, filePath, ref string) (*APIFileContent, error) {
	reqPath := fmt.Sprintf("/projects/%s/repository/files/%s", encodeProjectID(projectID), url.PathEscape(filePath))
	if ref != "" {
		reqPath += "?ref=" + url.QueryEscape(ref)
	}
	resp, err := c.get(ctx, reqPath)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIFileContent](resp)
}

// GetFileContent gets the raw content of a file
func (c *Client) GetFileContent(ctx context.Context, projectID, filePath, ref string) ([]byte, error) {
	file, err := c.GetFile(ctx, projectID, filePath, ref)
	if err != nil {
		return nil, err
	}

	if file.Encoding == "base64" {
		decoded, err := base64.StdEncoding.DecodeString(file.Content)
		if err != nil {
			return nil, fmt.Errorf("decode base64: %w", err)
		}
		return decoded, nil
	}

	return []byte(file.Content), nil
}

// CreateFile creates a new file
func (c *Client) CreateFile(ctx context.Context, projectID, filePath string, opts CreateFileOptions) error {
	reqPath := fmt.Sprintf("/projects/%s/repository/files/%s", encodeProjectID(projectID), url.PathEscape(filePath))
	resp, err := c.post(ctx, reqPath, opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create file failed (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// UpdateFile updates an existing file
func (c *Client) UpdateFile(ctx context.Context, projectID, filePath string, opts UpdateFileOptions) error {
	reqPath := fmt.Sprintf("/projects/%s/repository/files/%s", encodeProjectID(projectID), url.PathEscape(filePath))
	resp, err := c.put(ctx, reqPath, opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update file failed (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// ============================================================================
// Merge Requests
// ============================================================================

// ListMergeRequests lists merge requests
func (c *Client) ListMergeRequests(ctx context.Context, projectID, state string, page, perPage int) ([]APIMergeRequest, error) {
	if perPage <= 0 {
		perPage = 30
	}
	if state == "" {
		state = "opened"
	}
	path := fmt.Sprintf("/projects/%s/merge_requests?state=%s&per_page=%d&page=%d", encodeProjectID(projectID), state, perPage, page)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIMergeRequest](resp)
}

// GetMergeRequest gets a specific merge request
func (c *Client) GetMergeRequest(ctx context.Context, projectID string, mrIID int64) (*APIMergeRequest, error) {
	path := fmt.Sprintf("/projects/%s/merge_requests/%d", encodeProjectID(projectID), mrIID)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIMergeRequest](resp)
}

// CreateMergeRequest creates a merge request
func (c *Client) CreateMergeRequest(ctx context.Context, projectID string, opts CreateMROptions) (*APIMergeRequest, error) {
	path := fmt.Sprintf("/projects/%s/merge_requests", encodeProjectID(projectID))
	resp, err := c.post(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIMergeRequest](resp)
}

// MergeMergeRequest accepts/merges a merge request
func (c *Client) MergeMergeRequest(ctx context.Context, projectID string, mrIID int64, squash bool, message string) (*APIMergeRequest, error) {
	path := fmt.Sprintf("/projects/%s/merge_requests/%d/merge", encodeProjectID(projectID), mrIID)
	body := map[string]interface{}{
		"squash": squash,
	}
	if message != "" {
		body["merge_commit_message"] = message
	}
	resp, err := c.put(ctx, path, body)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIMergeRequest](resp)
}

// ============================================================================
// Issues
// ============================================================================

// ListIssues lists issues
func (c *Client) ListIssues(ctx context.Context, projectID, state string, page, perPage int) ([]APIIssue, error) {
	if perPage <= 0 {
		perPage = 30
	}
	if state == "" {
		state = "opened"
	}
	path := fmt.Sprintf("/projects/%s/issues?state=%s&per_page=%d&page=%d", encodeProjectID(projectID), state, perPage, page)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIIssue](resp)
}

// GetIssue gets a specific issue
func (c *Client) GetIssue(ctx context.Context, projectID string, issueIID int64) (*APIIssue, error) {
	path := fmt.Sprintf("/projects/%s/issues/%d", encodeProjectID(projectID), issueIID)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIIssue](resp)
}

// CreateIssue creates an issue
func (c *Client) CreateIssue(ctx context.Context, projectID string, opts CreateIssueOptions) (*APIIssue, error) {
	path := fmt.Sprintf("/projects/%s/issues", encodeProjectID(projectID))
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
func (c *Client) ListReleases(ctx context.Context, projectID string, page, perPage int) ([]APIRelease, error) {
	if perPage <= 0 {
		perPage = 30
	}
	path := fmt.Sprintf("/projects/%s/releases?per_page=%d&page=%d", encodeProjectID(projectID), perPage, page)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIRelease](resp)
}

// GetLatestRelease gets the latest release
func (c *Client) GetLatestRelease(ctx context.Context, projectID string) (*APIRelease, error) {
	releases, err := c.ListReleases(ctx, projectID, 1, 1)
	if err != nil {
		return nil, err
	}
	if len(releases) == 0 {
		return nil, fmt.Errorf("no releases found")
	}
	return &releases[0], nil
}

// CreateRelease creates a release
func (c *Client) CreateRelease(ctx context.Context, projectID string, opts CreateReleaseOptions) (*APIRelease, error) {
	path := fmt.Sprintf("/projects/%s/releases", encodeProjectID(projectID))
	resp, err := c.post(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIRelease](resp)
}

// ============================================================================
// Webhooks
// ============================================================================

// ListHooks lists project webhooks
func (c *Client) ListHooks(ctx context.Context, projectID string) ([]APIHook, error) {
	path := fmt.Sprintf("/projects/%s/hooks", encodeProjectID(projectID))
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIHook](resp)
}

// CreateHook creates a webhook
func (c *Client) CreateHook(ctx context.Context, projectID string, opts CreateHookOptions) (*APIHook, error) {
	path := fmt.Sprintf("/projects/%s/hooks", encodeProjectID(projectID))
	resp, err := c.post(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIHook](resp)
}

// DeleteHook deletes a webhook
func (c *Client) DeleteHook(ctx context.Context, projectID string, hookID int64) error {
	path := fmt.Sprintf("/projects/%s/hooks/%d", encodeProjectID(projectID), hookID)
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
func (c *Client) ListDeployKeys(ctx context.Context, projectID string) ([]APIDeployKey, error) {
	path := fmt.Sprintf("/projects/%s/deploy_keys", encodeProjectID(projectID))
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIDeployKey](resp)
}

// CreateDeployKey creates a deploy key
func (c *Client) CreateDeployKey(ctx context.Context, projectID string, opts CreateDeployKeyOptions) (*APIDeployKey, error) {
	path := fmt.Sprintf("/projects/%s/deploy_keys", encodeProjectID(projectID))
	resp, err := c.post(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIDeployKey](resp)
}

// DeleteDeployKey deletes a deploy key
func (c *Client) DeleteDeployKey(ctx context.Context, projectID string, keyID int64) error {
	path := fmt.Sprintf("/projects/%s/deploy_keys/%d", encodeProjectID(projectID), keyID)
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
// Project Members
// ============================================================================

// ListMembers lists project members
func (c *Client) ListMembers(ctx context.Context, projectID string) ([]APIProjectMember, error) {
	path := fmt.Sprintf("/projects/%s/members", encodeProjectID(projectID))
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIProjectMember](resp)
}

// AddMember adds a member to a project
func (c *Client) AddMember(ctx context.Context, projectID string, userID int64, accessLevel int) (*APIProjectMember, error) {
	path := fmt.Sprintf("/projects/%s/members", encodeProjectID(projectID))
	body := map[string]interface{}{
		"user_id":      userID,
		"access_level": accessLevel,
	}
	resp, err := c.post(ctx, path, body)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIProjectMember](resp)
}

// RemoveMember removes a member from a project
func (c *Client) RemoveMember(ctx context.Context, projectID string, userID int64) error {
	path := fmt.Sprintf("/projects/%s/members/%d", encodeProjectID(projectID), userID)
	resp, err := c.delete(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("remove member failed: %d", resp.StatusCode)
	}
	return nil
}

// ============================================================================
// Pipelines
// ============================================================================

// ListPipelines lists pipelines
func (c *Client) ListPipelines(ctx context.Context, projectID string, page, perPage int) ([]APIPipeline, error) {
	if perPage <= 0 {
		perPage = 30
	}
	path := fmt.Sprintf("/projects/%s/pipelines?per_page=%d&page=%d", encodeProjectID(projectID), perPage, page)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIPipeline](resp)
}

// GetPipeline gets a specific pipeline
func (c *Client) GetPipeline(ctx context.Context, projectID string, pipelineID int64) (*APIPipeline, error) {
	path := fmt.Sprintf("/projects/%s/pipelines/%d", encodeProjectID(projectID), pipelineID)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*APIPipeline](resp)
}

// ListPipelineJobs lists jobs for a pipeline
func (c *Client) ListPipelineJobs(ctx context.Context, projectID string, pipelineID int64) ([]APIJob, error) {
	path := fmt.Sprintf("/projects/%s/pipelines/%d/jobs", encodeProjectID(projectID), pipelineID)
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]APIJob](resp)
}
