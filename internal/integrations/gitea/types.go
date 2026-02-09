// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package gitea

import "time"

// APIVersion holds Gitea version info from /api/v1/version
type APIVersion struct {
	Version string `json:"version"`
}

// APIUser represents a Gitea user from /api/v1/user
type APIUser struct {
	ID        int64     `json:"id"`
	Login     string    `json:"login"`
	FullName  string    `json:"full_name"`
	Email     string    `json:"email"`
	AvatarURL string    `json:"avatar_url"`
	IsAdmin   bool      `json:"is_admin"`
	Created   time.Time `json:"created"`
}

// APIRepository represents a Gitea repository from /api/v1/repos/*
type APIRepository struct {
	ID            int64     `json:"id"`
	Owner         APIUser   `json:"owner"`
	Name          string    `json:"name"`
	FullName      string    `json:"full_name"`
	Description   string    `json:"description"`
	Empty         bool      `json:"empty"`
	Private       bool      `json:"private"`
	Fork          bool      `json:"fork"`
	Archived      bool      `json:"archived"`
	HTMLURL       string    `json:"html_url"`
	CloneURL      string    `json:"clone_url"`
	SSHURL        string    `json:"ssh_url"`
	DefaultBranch string    `json:"default_branch"`
	Stars         int       `json:"stars_count"`
	Forks         int       `json:"forks_count"`
	OpenIssues    int       `json:"open_issues_count"`
	Size          int64     `json:"size"` // KB
	Created       time.Time `json:"created_at"`
	Updated       time.Time `json:"updated_at"`
}

// APIBranch represents a branch from /api/v1/repos/{owner}/{repo}/branches/{branch}
type APIBranch struct {
	Name      string    `json:"name"`
	Commit    APICommit `json:"commit"`
	Protected bool      `json:"protected"`
}

// APICommit represents a commit
type APICommit struct {
	ID        string       `json:"id"`
	Message   string       `json:"message"`
	URL       string       `json:"url"`
	Author    *APIIdentity `json:"author"`
	Committer *APIIdentity `json:"committer"`
	Timestamp time.Time    `json:"timestamp"`
}

// APIIdentity is commit author/committer
type APIIdentity struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Date  string `json:"date"`
}

// ============================================================================
// Repository Management Types (Tier 1)
// ============================================================================

// CreateRepoOptions holds parameters for creating a repository
type CreateRepoOptions struct {
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	Private       bool   `json:"private"`
	AutoInit      bool   `json:"auto_init"`
	Gitignores    string `json:"gitignores,omitempty"`    // e.g., "Go", "Python"
	License       string `json:"license,omitempty"`       // e.g., "MIT", "Apache-2.0"
	Readme        string `json:"readme,omitempty"`        // e.g., "Default"
	DefaultBranch string `json:"default_branch,omitempty"`
	TrustModel    string `json:"trust_model,omitempty"`   // default, collaborator, committer, collaboratorcommitter
}

// EditRepoOptions holds parameters for editing a repository
type EditRepoOptions struct {
	Name                      *string `json:"name,omitempty"`
	Description               *string `json:"description,omitempty"`
	Website                   *string `json:"website,omitempty"`
	Private                   *bool   `json:"private,omitempty"`
	Archived                  *bool   `json:"archived,omitempty"`
	DefaultBranch             *string `json:"default_branch,omitempty"`
	HasIssues                 *bool   `json:"has_issues,omitempty"`
	HasWiki                   *bool   `json:"has_wiki,omitempty"`
	HasPullRequests           *bool   `json:"has_pull_requests,omitempty"`
	HasProjects               *bool   `json:"has_projects,omitempty"`
	AllowMergeCommits         *bool   `json:"allow_merge_commits,omitempty"`
	AllowRebase               *bool   `json:"allow_rebase,omitempty"`
	AllowRebaseMerge          *bool   `json:"allow_rebase_explicit,omitempty"`
	AllowSquashMerge          *bool   `json:"allow_squash_merge,omitempty"`
	DefaultMergeStyle         *string `json:"default_merge_style,omitempty"` // merge, rebase, rebase-merge, squash
	DefaultDeleteBranchAfterMerge *bool `json:"default_delete_branch_after_merge,omitempty"`
}

// ============================================================================
// Branch Management Types (Tier 1)
// ============================================================================

// CreateBranchOptions holds parameters for creating a branch
type CreateBranchOptions struct {
	NewBranchName string `json:"new_branch_name"`
	OldBranchName string `json:"old_branch_name,omitempty"` // source branch, defaults to default branch
	OldRefName    string `json:"old_ref_name,omitempty"`    // alternative: specific commit SHA
}

// ============================================================================
// Tag Management Types (Tier 1)
// ============================================================================

// APITag represents a tag from /api/v1/repos/{owner}/{repo}/tags
type APITag struct {
	Name       string     `json:"name"`
	ID         string     `json:"id"`          // commit SHA
	Message    string     `json:"message"`     // annotated tag message
	Commit     *APICommit `json:"commit"`
	ZipballURL string     `json:"zipball_url"`
	TarballURL string     `json:"tarball_url"`
}

// CreateTagOptions holds parameters for creating a tag
type CreateTagOptions struct {
	TagName string `json:"tag_name"`
	Target  string `json:"target,omitempty"` // branch name or commit SHA, defaults to default branch
	Message string `json:"message,omitempty"` // for annotated tags
}

// ============================================================================
// Commit & Diff Types (Tier 1)
// ============================================================================

// CommitListOptions holds filtering options for listing commits
type CommitListOptions struct {
	SHA    string `url:"sha,omitempty"`    // branch or commit SHA to start from
	Path   string `url:"path,omitempty"`   // filter by file path
	Author string `url:"author,omitempty"` // filter by author (email or name)
	Since  string `url:"since,omitempty"`  // ISO 8601 date
	Until  string `url:"until,omitempty"`  // ISO 8601 date
	Page   int    `url:"page,omitempty"`
	Limit  int    `url:"limit,omitempty"`
}

// APICompare represents the result of comparing two refs
type APICompare struct {
	URL         string            `json:"url"`
	HTMLURL     string            `json:"html_url"`
	DiffURL     string            `json:"diff_url"`
	PatchURL    string            `json:"patch_url"`
	BaseCommit  APICommitListItem `json:"base_commit"`
	MergeBase   string            `json:"merge_base_commit"`
	Commits     []APICommitListItem `json:"commits"`
	TotalCommits int              `json:"total_commits"`
}

// APIDiffFile represents a changed file in a diff
type APIDiffFile struct {
	Filename    string `json:"filename"`
	OldFilename string `json:"previous_filename,omitempty"`
	Status      string `json:"status"` // added, removed, modified, renamed
	Additions   int    `json:"additions"`
	Deletions   int    `json:"deletions"`
	Changes     int    `json:"changes"`
	HTMLURL     string `json:"html_url"`
	ContentsURL string `json:"contents_url"`
	RawURL      string `json:"raw_url"`
	Patch       string `json:"patch,omitempty"` // unified diff
}

// ============================================================================
// Webhook Types (existing)
// ============================================================================

// WebhookPushPayload represents a push webhook event payload
type WebhookPushPayload struct {
	Ref        string         `json:"ref"`
	Before     string         `json:"before"`
	After      string         `json:"after"`
	CompareURL string         `json:"compare_url"`
	Commits    []WebhookCommit `json:"commits"`
	HeadCommit *WebhookCommit `json:"head_commit"`
	Repository APIRepository  `json:"repository"`
	Pusher     APIUser        `json:"pusher"`
	Sender     APIUser        `json:"sender"`
}

// WebhookCommit represents a commit in a webhook payload
type WebhookCommit struct {
	ID        string    `json:"id"`
	Message   string    `json:"message"`
	URL       string    `json:"url"`
	Author    APIIdentity `json:"author"`
	Committer APIIdentity `json:"committer"`
	Timestamp time.Time `json:"timestamp"`
	Added     []string  `json:"added"`
	Removed   []string  `json:"removed"`
	Modified  []string  `json:"modified"`
}

// WebhookReleasePayload represents a release webhook payload
type WebhookReleasePayload struct {
	Action     string        `json:"action"`
	Release    APIRelease    `json:"release"`
	Repository APIRepository `json:"repository"`
	Sender     APIUser       `json:"sender"`
}

// CreateWebhookOptions holds parameters for creating a webhook in Gitea
type CreateWebhookOptions struct {
	Type         string            `json:"type"` // "gitea"
	Config       WebhookConfig     `json:"config"`
	Events       []string          `json:"events"`
	Active       bool              `json:"active"`
	BranchFilter string            `json:"branch_filter,omitempty"`
}

// WebhookConfig holds webhook configuration
type WebhookConfig struct {
	URL         string `json:"url"`
	ContentType string `json:"content_type"` // "json"
	Secret      string `json:"secret,omitempty"`
}

// ============================================================================
// Content Types (existing)
// ============================================================================

// APIContentEntry represents a file/dir entry from /api/v1/repos/{owner}/{repo}/contents/{path}
type APIContentEntry struct {
	Name        string  `json:"name"`
	Path        string  `json:"path"`
	SHA         string  `json:"sha"`
	Type        string  `json:"type"` // "file" | "dir" | "symlink" | "submodule"
	Size        int64   `json:"size"`
	HTMLURL     string  `json:"html_url"`
	DownloadURL *string `json:"download_url,omitempty"`
}

// UpdateFileOptions holds parameters for creating/updating a file via Gitea API
type UpdateFileOptions struct {
	Content string                `json:"content"` // base64 encoded
	Message string                `json:"message"`
	Branch  string                `json:"branch,omitempty"`
	SHA     string                `json:"sha,omitempty"` // required for updates
	Author  *UpdateFileIdentity   `json:"author,omitempty"`
	NewBranch string              `json:"new_branch,omitempty"`
}

// UpdateFileIdentity identifies the author/committer
type UpdateFileIdentity struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// APICommitListItem represents a commit in the list endpoint (different shape from branch commit)
type APICommitListItem struct {
	SHA         string             `json:"sha"`
	URL         string             `json:"url"`
	HTMLURL     string             `json:"html_url"`
	Commit      APICommitDetail    `json:"commit"`
	Author      *APIUser           `json:"author"`
	Committer   *APIUser           `json:"committer"`
	Parents     []APICommitParent  `json:"parents"`
	Files       []APIDiffFile      `json:"files,omitempty"` // only in single commit endpoint
	Stats       *APICommitStats    `json:"stats,omitempty"` // only in single commit endpoint
}

// APICommitDetail is the inner commit object in list response
type APICommitDetail struct {
	Message   string       `json:"message"`
	Author    *APIIdentity `json:"author"`
	Committer *APIIdentity `json:"committer"`
}

// APICommitParent represents a parent commit reference
type APICommitParent struct {
	SHA string `json:"sha"`
	URL string `json:"url"`
}

// APICommitStats represents commit statistics
type APICommitStats struct {
	Total     int `json:"total"`
	Additions int `json:"additions"`
	Deletions int `json:"deletions"`
}

// ============================================================================
// Gitignore & License Templates
// ============================================================================

// APIGitignoreTemplate represents a gitignore template
type APIGitignoreTemplate struct {
	Name   string `json:"name"`
	Source string `json:"source,omitempty"`
}

// APILicenseTemplate represents a license template
type APILicenseTemplate struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	URL     string `json:"url,omitempty"`
	HTMLURL string `json:"html_url,omitempty"`
}

// ============================================================================
// Tier 2: Pull Requests
// ============================================================================

// APIPullRequest represents a pull request
type APIPullRequest struct {
	ID          int64         `json:"id"`
	Number      int64         `json:"number"`
	Title       string        `json:"title"`
	Body        string        `json:"body"`
	State       string        `json:"state"` // "open", "closed"
	HTMLURL     string        `json:"html_url"`
	DiffURL     string        `json:"diff_url"`
	PatchURL    string        `json:"patch_url"`
	Mergeable   bool          `json:"mergeable"`
	Merged      bool          `json:"merged"`
	MergedAt    *time.Time    `json:"merged_at"`
	MergeBase   string        `json:"merge_base"`
	Head        APIPRBranch   `json:"head"`
	Base        APIPRBranch   `json:"base"`
	User        APIUser       `json:"user"`
	Assignee    *APIUser      `json:"assignee"`
	Assignees   []APIUser     `json:"assignees"`
	Labels      []APILabel    `json:"labels"`
	Milestone   *APIMilestone `json:"milestone"`
	Comments    int           `json:"comments"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	ClosedAt    *time.Time    `json:"closed_at"`
}

// APIPRBranch represents head/base branch in a PR
type APIPRBranch struct {
	Label string        `json:"label"`
	Ref   string        `json:"ref"`
	SHA   string        `json:"sha"`
	Repo  *APIRepository `json:"repo"`
}

// CreatePullRequestOptions holds parameters for creating a PR
type CreatePullRequestOptions struct {
	Title     string   `json:"title"`
	Body      string   `json:"body,omitempty"`
	Head      string   `json:"head"`      // source branch
	Base      string   `json:"base"`      // target branch
	Assignees []string `json:"assignees,omitempty"`
	Labels    []int64  `json:"labels,omitempty"`
	Milestone int64    `json:"milestone,omitempty"`
}

// EditPullRequestOptions holds parameters for editing a PR
type EditPullRequestOptions struct {
	Title     *string  `json:"title,omitempty"`
	Body      *string  `json:"body,omitempty"`
	Assignees []string `json:"assignees,omitempty"`
	Labels    []int64  `json:"labels,omitempty"`
	Milestone *int64   `json:"milestone,omitempty"`
	State     *string  `json:"state,omitempty"` // "open", "closed"
	Base      *string  `json:"base,omitempty"`
}

// MergePullRequestOptions holds parameters for merging a PR
type MergePullRequestOptions struct {
	MergeStyle        string `json:"Do"`                           // "merge", "rebase", "rebase-merge", "squash"
	MergeCommitID     string `json:"MergeCommitID,omitempty"`
	MergeMessageField string `json:"MergeMessageField,omitempty"`
	MergeTitleField   string `json:"MergeTitleField,omitempty"`
	DeleteBranchAfter bool   `json:"delete_branch_after_merge,omitempty"`
	ForceMerge        bool   `json:"force_merge,omitempty"`
	HeadCommitID      string `json:"head_commit_id,omitempty"`
}

// APIPRReview represents a review on a PR
type APIPRReview struct {
	ID          int64     `json:"id"`
	Body        string    `json:"body"`
	State       string    `json:"state"` // "PENDING", "APPROVED", "REQUEST_CHANGES", "COMMENT"
	HTMLURL     string    `json:"html_url"`
	User        APIUser   `json:"user"`
	CommitID    string    `json:"commit_id"`
	Stale       bool      `json:"stale"`
	Official    bool      `json:"official"`
	Dismissed   bool      `json:"dismissed"`
	SubmittedAt time.Time `json:"submitted_at"`
}

// CreatePRReviewOptions holds parameters for creating a review
type CreatePRReviewOptions struct {
	Body     string              `json:"body"`
	Event    string              `json:"event"` // "APPROVE", "REQUEST_CHANGES", "COMMENT"
	CommitID string              `json:"commit_id,omitempty"`
	Comments []PRReviewComment   `json:"comments,omitempty"`
}

// PRReviewComment is a comment on a specific line in a review
type PRReviewComment struct {
	Path        string `json:"path"`
	Body        string `json:"body"`
	OldPosition int    `json:"old_position,omitempty"`
	NewPosition int    `json:"new_position,omitempty"`
}

// ============================================================================
// Tier 2: Issues
// ============================================================================

// APIIssue represents an issue
type APIIssue struct {
	ID          int64         `json:"id"`
	Number      int64         `json:"number"`
	Title       string        `json:"title"`
	Body        string        `json:"body"`
	State       string        `json:"state"` // "open", "closed"
	HTMLURL     string        `json:"html_url"`
	User        APIUser       `json:"user"`
	Assignee    *APIUser      `json:"assignee"`
	Assignees   []APIUser     `json:"assignees"`
	Labels      []APILabel    `json:"labels"`
	Milestone   *APIMilestone `json:"milestone"`
	Comments    int           `json:"comments"`
	IsLocked    bool          `json:"is_locked"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	ClosedAt    *time.Time    `json:"closed_at"`
	DueDate     *time.Time    `json:"due_date"`
	PullRequest *APIPullRequest `json:"pull_request,omitempty"` // if issue is a PR
}

// APILabel represents a label
type APILabel struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

// APIMilestone represents a milestone
type APIMilestone struct {
	ID           int64      `json:"id"`
	Title        string     `json:"title"`
	Description  string     `json:"description"`
	State        string     `json:"state"` // "open", "closed"
	OpenIssues   int        `json:"open_issues"`
	ClosedIssues int        `json:"closed_issues"`
	DueOn        *time.Time `json:"due_on"`
	ClosedAt     *time.Time `json:"closed_at"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// CreateIssueOptions holds parameters for creating an issue
type CreateIssueOptions struct {
	Title     string   `json:"title"`
	Body      string   `json:"body,omitempty"`
	Assignees []string `json:"assignees,omitempty"`
	Labels    []int64  `json:"labels,omitempty"`
	Milestone int64    `json:"milestone,omitempty"`
	DueDate   string   `json:"due_date,omitempty"` // ISO 8601
	Closed    bool     `json:"closed,omitempty"`
}

// EditIssueOptions holds parameters for editing an issue
type EditIssueOptions struct {
	Title     *string  `json:"title,omitempty"`
	Body      *string  `json:"body,omitempty"`
	Assignees []string `json:"assignees,omitempty"`
	Labels    []int64  `json:"labels,omitempty"`
	Milestone *int64   `json:"milestone,omitempty"`
	State     *string  `json:"state,omitempty"` // "open", "closed"
	DueDate   *string  `json:"due_date,omitempty"`
}

// APIComment represents a comment on an issue or PR
type APIComment struct {
	ID        int64     `json:"id"`
	Body      string    `json:"body"`
	HTMLURL   string    `json:"html_url"`
	User      APIUser   `json:"user"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateCommentOptions holds parameters for creating a comment
type CreateCommentOptions struct {
	Body string `json:"body"`
}

// IssueListOptions holds filtering options for listing issues
type IssueListOptions struct {
	State     string `url:"state,omitempty"`     // "open", "closed", "all"
	Labels    string `url:"labels,omitempty"`    // comma-separated label names
	Milestone string `url:"milestone,omitempty"` // milestone name or ID
	Assignee  string `url:"assignee,omitempty"`  // username
	Creator   string `url:"creator,omitempty"`   // username
	Since     string `url:"since,omitempty"`     // ISO 8601 date
	Before    string `url:"before,omitempty"`    // ISO 8601 date
	Page      int    `url:"page,omitempty"`
	Limit     int    `url:"limit,omitempty"`
}

// PRListOptions holds filtering options for listing PRs
type PRListOptions struct {
	State  string `url:"state,omitempty"` // "open", "closed", "all"
	Sort   string `url:"sort,omitempty"`  // "oldest", "recentupdate", "leastupdate", "mostcomment", "leastcomment", "priority"
	Labels string `url:"labels,omitempty"`
	Page   int    `url:"page,omitempty"`
	Limit  int    `url:"limit,omitempty"`
}

// ============================================================================
// Tier 2: Collaborators
// ============================================================================

// APICollaborator represents a repository collaborator
type APICollaborator struct {
	ID          int64             `json:"id"`
	Login       string            `json:"login"`
	FullName    string            `json:"full_name"`
	Email       string            `json:"email"`
	AvatarURL   string            `json:"avatar_url"`
	Permissions APIPermissions    `json:"permissions"`
}

// APIPermissions represents permission levels
type APIPermissions struct {
	Admin bool `json:"admin"`
	Push  bool `json:"push"`
	Pull  bool `json:"pull"`
}

// AddCollaboratorOptions holds parameters for adding a collaborator
type AddCollaboratorOptions struct {
	Permission string `json:"permission"` // "read", "write", "admin"
}

// APITeam represents a team (for org repos)
type APITeam struct {
	ID                      int64  `json:"id"`
	Name                    string `json:"name"`
	Description             string `json:"description"`
	Organization            *APIUser `json:"organization"`
	Permission              string `json:"permission"` // "none", "read", "write", "admin", "owner"
	Units                   []string `json:"units"`
	IncludesAllRepositories bool   `json:"includes_all_repositories"`
	CanCreateOrgRepo        bool   `json:"can_create_org_repo"`
}

// ============================================================================
// Tier 3: Webhooks
// ============================================================================

// APIHook represents a webhook
type APIHook struct {
	ID          int64             `json:"id"`
	Type        string            `json:"type"` // "gitea", "slack", "discord", etc.
	URL         string            `json:"url,omitempty"`
	Config      map[string]string `json:"config"`
	Events      []string          `json:"events"`
	Active      bool              `json:"active"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// CreateHookOptions holds parameters for creating a webhook
type CreateHookOptions struct {
	Type                string            `json:"type"` // "gitea", "slack", "discord", "dingtalk", "telegram", "msteams", "feishu", "matrix", "wechatwork", "packagist"
	Config              map[string]string `json:"config"` // url, content_type, secret
	Events              []string          `json:"events"` // push, pull_request, issues, etc.
	BranchFilter        string            `json:"branch_filter,omitempty"`
	Active              bool              `json:"active"`
	AuthorizationHeader string            `json:"authorization_header,omitempty"`
}

// EditHookOptions holds parameters for editing a webhook
type EditHookOptions struct {
	Config              map[string]string `json:"config,omitempty"`
	Events              []string          `json:"events,omitempty"`
	BranchFilter        string            `json:"branch_filter,omitempty"`
	Active              *bool             `json:"active,omitempty"`
	AuthorizationHeader string            `json:"authorization_header,omitempty"`
}

// HookEventType defines valid webhook event types
var HookEventTypes = []string{
	"create",
	"delete",
	"fork",
	"push",
	"issues",
	"issue_assign",
	"issue_label",
	"issue_milestone",
	"issue_comment",
	"pull_request",
	"pull_request_assign",
	"pull_request_label",
	"pull_request_milestone",
	"pull_request_comment",
	"pull_request_review",
	"pull_request_sync",
	"pull_request_review_request",
	"wiki",
	"repository",
	"release",
	"package",
}

// ============================================================================
// Tier 3: Deploy Keys
// ============================================================================

// APIDeployKey represents a deploy key (SSH key for CI/CD)
type APIDeployKey struct {
	ID          int64     `json:"id"`
	KeyID       int64     `json:"key_id"`
	Key         string    `json:"key"`
	URL         string    `json:"url"`
	Title       string    `json:"title"`
	Fingerprint string    `json:"fingerprint"`
	ReadOnly    bool      `json:"read_only"`
	CreatedAt   time.Time `json:"created_at"`
	Repository  *APIRepository `json:"repository,omitempty"`
}

// CreateDeployKeyOptions holds parameters for creating a deploy key
type CreateDeployKeyOptions struct {
	Title    string `json:"title"`
	Key      string `json:"key"`      // SSH public key
	ReadOnly bool   `json:"read_only"` // true = read-only, false = read-write
}

// ============================================================================
// Tier 3: Releases
// ============================================================================

// APIRelease represents a release
type APIRelease struct {
	ID              int64            `json:"id"`
	TagName         string           `json:"tag_name"`
	Target          string           `json:"target_commitish"`
	Name            string           `json:"name"`
	Body            string           `json:"body"`
	URL             string           `json:"url"`
	HTMLURL         string           `json:"html_url"`
	TarballURL      string           `json:"tarball_url"`
	ZipballURL      string           `json:"zipball_url"`
	IsDraft         bool             `json:"draft"`
	IsPrerelease    bool             `json:"prerelease"`
	CreatedAt       time.Time        `json:"created_at"`
	PublishedAt     time.Time        `json:"published_at"`
	Author          APIUser          `json:"author"`
	Assets          []APIReleaseAsset `json:"assets"`
}

// APIReleaseAsset represents an asset attached to a release
type APIReleaseAsset struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	Size          int64     `json:"size"`
	DownloadCount int64     `json:"download_count"`
	CreatedAt     time.Time `json:"created_at"`
	UUID          string    `json:"uuid"`
	DownloadURL   string    `json:"browser_download_url"`
}

// CreateReleaseOptions holds parameters for creating a release
type CreateReleaseOptions struct {
	TagName      string `json:"tag_name"`
	Target       string `json:"target_commitish,omitempty"` // branch or commit SHA
	Name         string `json:"name,omitempty"`
	Body         string `json:"body,omitempty"`
	IsDraft      bool   `json:"draft"`
	IsPrerelease bool   `json:"prerelease"`
}

// EditReleaseOptions holds parameters for editing a release
type EditReleaseOptions struct {
	TagName      *string `json:"tag_name,omitempty"`
	Target       *string `json:"target_commitish,omitempty"`
	Name         *string `json:"name,omitempty"`
	Body         *string `json:"body,omitempty"`
	IsDraft      *bool   `json:"draft,omitempty"`
	IsPrerelease *bool   `json:"prerelease,omitempty"`
}

// ============================================================================
// Tier 3: Actions / CI Status
// ============================================================================

// APIActionRun represents a workflow run (Gitea Actions)
type APIActionRun struct {
	ID           int64     `json:"id"`
	Title        string    `json:"title"`
	WorkflowID   string    `json:"workflow_id"`
	WorkflowName string    `json:"workflow_name,omitempty"`
	Event        string    `json:"event"` // push, pull_request, etc.
	Status       string    `json:"status"` // waiting, running, success, failure, cancelled, skipped
	Conclusion   string    `json:"conclusion,omitempty"`
	HeadBranch   string    `json:"head_branch"`
	HeadSHA      string    `json:"head_sha"`
	RunNumber    int64     `json:"run_number"`
	HTMLURL      string    `json:"html_url"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	RunStartedAt time.Time `json:"run_started_at,omitempty"`
	Actor        *APIUser  `json:"actor,omitempty"`
}

// APIActionJob represents a job within a workflow run
type APIActionJob struct {
	ID          int64           `json:"id"`
	RunID       int64           `json:"run_id"`
	Name        string          `json:"name"`
	Status      string          `json:"status"`
	Conclusion  string          `json:"conclusion,omitempty"`
	StartedAt   time.Time       `json:"started_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	Steps       []APIActionStep `json:"steps,omitempty"`
	HTMLURL     string          `json:"html_url"`
}

// APIActionStep represents a step within a job
type APIActionStep struct {
	Name        string     `json:"name"`
	Number      int        `json:"number"`
	Status      string     `json:"status"`
	Conclusion  string     `json:"conclusion,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// APIWorkflow represents a workflow definition
type APIWorkflow struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	State     string    `json:"state"` // active, disabled
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	HTMLURL   string    `json:"html_url"`
	BadgeURL  string    `json:"badge_url,omitempty"`
}

// ActionRunListOptions holds filtering options for listing runs
type ActionRunListOptions struct {
	Branch     string `url:"branch,omitempty"`
	Event      string `url:"event,omitempty"`
	Status     string `url:"status,omitempty"` // waiting, running, success, failure
	Actor      string `url:"actor,omitempty"`
	Page       int    `url:"page,omitempty"`
	Limit      int    `url:"limit,omitempty"`
}

// APICommitStatus represents a commit status (traditional status API)
type APICommitStatus struct {
	ID          int64     `json:"id"`
	State       string    `json:"state"` // pending, success, error, failure
	TargetURL   string    `json:"target_url"`
	Description string    `json:"description"`
	Context     string    `json:"context"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Creator     *APIUser  `json:"creator"`
}

// APICombinedStatus represents combined status for a commit
type APICombinedStatus struct {
	State      string            `json:"state"` // pending, success, error, failure
	SHA        string            `json:"sha"`
	TotalCount int               `json:"total_count"`
	Statuses   []APICommitStatus `json:"statuses"`
	Repository *APIRepository    `json:"repository"`
	CommitURL  string            `json:"commit_url"`
	URL        string            `json:"url"`
}

// CreateStatusOptions holds parameters for creating a commit status
type CreateStatusOptions struct {
	State       string `json:"state"` // pending, success, error, failure
	TargetURL   string `json:"target_url,omitempty"`
	Description string `json:"description,omitempty"`
	Context     string `json:"context,omitempty"`
}
