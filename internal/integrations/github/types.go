// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package github

import "time"

// ============================================================================
// GitHub API Response Types
// ============================================================================

// APIUser represents a GitHub user
type APIUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
	Type      string `json:"type"` // User, Organization
}

// APIRepository represents a GitHub repository
type APIRepository struct {
	ID            int64     `json:"id"`
	NodeID        string    `json:"node_id"`
	Name          string    `json:"name"`
	FullName      string    `json:"full_name"`
	Owner         APIUser   `json:"owner"`
	Description   string    `json:"description"`
	Private       bool      `json:"private"`
	Fork          bool      `json:"fork"`
	Archived      bool      `json:"archived"`
	Disabled      bool      `json:"disabled"`
	HTMLURL       string    `json:"html_url"`
	CloneURL      string    `json:"clone_url"`
	SSHURL        string    `json:"ssh_url"`
	DefaultBranch string    `json:"default_branch"`
	Language      string    `json:"language"`
	Size          int64     `json:"size"` // KB
	StarCount     int       `json:"stargazers_count"`
	ForkCount     int       `json:"forks_count"`
	WatchersCount int       `json:"watchers_count"`
	OpenIssues    int       `json:"open_issues_count"`
	Topics        []string  `json:"topics"`
	Visibility    string    `json:"visibility"` // public, private, internal
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	PushedAt      time.Time `json:"pushed_at"`
}

// APIBranch represents a GitHub branch
type APIBranch struct {
	Name      string          `json:"name"`
	Commit    APIBranchCommit `json:"commit"`
	Protected bool            `json:"protected"`
}

// APIBranchCommit is the commit info in a branch response
type APIBranchCommit struct {
	SHA string `json:"sha"`
	URL string `json:"url"`
}

// APICommit represents a GitHub commit
type APICommit struct {
	SHA       string          `json:"sha"`
	NodeID    string          `json:"node_id"`
	Commit    APICommitDetail `json:"commit"`
	HTMLURL   string          `json:"html_url"`
	Author    *APIUser        `json:"author"`
	Committer *APIUser        `json:"committer"`
	Stats     *APICommitStats `json:"stats,omitempty"`
}

// APICommitDetail contains the commit message and author info
type APICommitDetail struct {
	Message   string           `json:"message"`
	Author    APICommitAuthor  `json:"author"`
	Committer APICommitAuthor  `json:"committer"`
	Tree      APICommitTree    `json:"tree"`
}

// APICommitAuthor is the author/committer info
type APICommitAuthor struct {
	Name  string    `json:"name"`
	Email string    `json:"email"`
	Date  time.Time `json:"date"`
}

// APICommitTree is the tree reference in a commit
type APICommitTree struct {
	SHA string `json:"sha"`
	URL string `json:"url"`
}

// APICommitStats contains additions/deletions stats
type APICommitStats struct {
	Additions int `json:"additions"`
	Deletions int `json:"deletions"`
	Total     int `json:"total"`
}

// APITag represents a GitHub tag
type APITag struct {
	Name       string     `json:"name"`
	ZipballURL string     `json:"zipball_url"`
	TarballURL string     `json:"tarball_url"`
	Commit     APITagRef  `json:"commit"`
	NodeID     string     `json:"node_id"`
}

// APITagRef is the commit reference in a tag
type APITagRef struct {
	SHA string `json:"sha"`
	URL string `json:"url"`
}

// APIContent represents file/directory content
type APIContent struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	SHA         string `json:"sha"`
	Size        int64  `json:"size"`
	Type        string `json:"type"` // file, dir, symlink, submodule
	Content     string `json:"content,omitempty"`
	Encoding    string `json:"encoding,omitempty"` // base64
	HTMLURL     string `json:"html_url"`
	DownloadURL string `json:"download_url,omitempty"`
}

// APIPullRequest represents a GitHub pull request
type APIPullRequest struct {
	ID                int64        `json:"id"`
	Number            int          `json:"number"`
	State             string       `json:"state"` // open, closed
	Title             string       `json:"title"`
	Body              string       `json:"body"`
	User              APIUser      `json:"user"`
	Head              APIPRBranch  `json:"head"`
	Base              APIPRBranch  `json:"base"`
	HTMLURL           string       `json:"html_url"`
	DiffURL           string       `json:"diff_url"`
	Mergeable         *bool        `json:"mergeable"`
	MergeableState    string       `json:"mergeable_state"`
	Merged            bool         `json:"merged"`
	MergedBy          *APIUser     `json:"merged_by"`
	MergedAt          *time.Time   `json:"merged_at"`
	Comments          int          `json:"comments"`
	ReviewComments    int          `json:"review_comments"`
	Commits           int          `json:"commits"`
	Additions         int          `json:"additions"`
	Deletions         int          `json:"deletions"`
	ChangedFiles      int          `json:"changed_files"`
	Draft             bool         `json:"draft"`
	Labels            []APILabel   `json:"labels"`
	Milestone         *APIMilestone `json:"milestone"`
	Assignees         []APIUser    `json:"assignees"`
	RequestedReviewers []APIUser   `json:"requested_reviewers"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
	ClosedAt          *time.Time   `json:"closed_at"`
}

// APIPRBranch is branch info in a PR
type APIPRBranch struct {
	Label string        `json:"label"`
	Ref   string        `json:"ref"`
	SHA   string        `json:"sha"`
	User  APIUser       `json:"user"`
	Repo  *APIRepository `json:"repo"`
}

// APIIssue represents a GitHub issue
type APIIssue struct {
	ID          int64         `json:"id"`
	Number      int           `json:"number"`
	State       string        `json:"state"` // open, closed
	Title       string        `json:"title"`
	Body        string        `json:"body"`
	User        APIUser       `json:"user"`
	Labels      []APILabel    `json:"labels"`
	Assignees   []APIUser     `json:"assignees"`
	Milestone   *APIMilestone `json:"milestone"`
	Comments    int           `json:"comments"`
	HTMLURL     string        `json:"html_url"`
	Locked      bool          `json:"locked"`
	ClosedBy    *APIUser      `json:"closed_by"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	ClosedAt    *time.Time    `json:"closed_at"`
	// GitHub includes PRs in issues endpoint, this field distinguishes them
	PullRequest *APIPRLink `json:"pull_request,omitempty"`
}

// APIPRLink indicates an issue is actually a PR
type APIPRLink struct {
	URL     string `json:"url"`
	HTMLURL string `json:"html_url"`
}

// APILabel represents a label
type APILabel struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
	Default     bool   `json:"default"`
}

// APIMilestone represents a milestone
type APIMilestone struct {
	ID           int64      `json:"id"`
	Number       int        `json:"number"`
	Title        string     `json:"title"`
	Description  string     `json:"description"`
	State        string     `json:"state"` // open, closed
	DueOn        *time.Time `json:"due_on"`
	OpenIssues   int        `json:"open_issues"`
	ClosedIssues int        `json:"closed_issues"`
}

// APIRelease represents a GitHub release
type APIRelease struct {
	ID              int64             `json:"id"`
	TagName         string            `json:"tag_name"`
	TargetCommitish string            `json:"target_commitish"`
	Name            string            `json:"name"`
	Body            string            `json:"body"`
	Draft           bool              `json:"draft"`
	Prerelease      bool              `json:"prerelease"`
	Author          APIUser           `json:"author"`
	Assets          []APIReleaseAsset `json:"assets"`
	HTMLURL         string            `json:"html_url"`
	TarballURL      string            `json:"tarball_url"`
	ZipballURL      string            `json:"zipball_url"`
	CreatedAt       time.Time         `json:"created_at"`
	PublishedAt     *time.Time        `json:"published_at"`
}

// APIReleaseAsset represents a release asset
type APIReleaseAsset struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	ContentType   string    `json:"content_type"`
	Size          int64     `json:"size"`
	DownloadCount int       `json:"download_count"`
	DownloadURL   string    `json:"browser_download_url"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// APIHook represents a webhook
type APIHook struct {
	ID        int64             `json:"id"`
	Name      string            `json:"name"` // always "web"
	Active    bool              `json:"active"`
	Events    []string          `json:"events"`
	Config    APIHookConfig     `json:"config"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// APIHookConfig is the webhook configuration
type APIHookConfig struct {
	URL         string `json:"url"`
	ContentType string `json:"content_type"`
	InsecureSSL string `json:"insecure_ssl"`
	Secret      string `json:"secret,omitempty"`
}

// APIDeployKey represents a deploy key
type APIDeployKey struct {
	ID        int64     `json:"id"`
	Title     string    `json:"title"`
	Key       string    `json:"key"`
	ReadOnly  bool      `json:"read_only"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

// APICollaborator represents a repository collaborator
type APICollaborator struct {
	ID          int64             `json:"id"`
	Login       string            `json:"login"`
	AvatarURL   string            `json:"avatar_url"`
	Permissions APIPermissions    `json:"permissions"`
	RoleName    string            `json:"role_name"`
}

// APIPermissions represents permission levels
type APIPermissions struct {
	Admin    bool `json:"admin"`
	Maintain bool `json:"maintain"`
	Push     bool `json:"push"`
	Triage   bool `json:"triage"`
	Pull     bool `json:"pull"`
}

// APIError represents a GitHub API error response
type APIError struct {
	Message          string      `json:"message"`
	DocumentationURL string      `json:"documentation_url"`
	Errors           []APIErrorDetail `json:"errors,omitempty"`
}

// APIErrorDetail contains error details
type APIErrorDetail struct {
	Resource string `json:"resource"`
	Field    string `json:"field"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// ============================================================================
// Request Types
// ============================================================================

// CreateRepoOptions for creating a new repository
type CreateRepoOptions struct {
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	Private       bool   `json:"private"`
	AutoInit      bool   `json:"auto_init"`
	GitignoreTemplate string `json:"gitignore_template,omitempty"`
	LicenseTemplate   string `json:"license_template,omitempty"`
}

// UpdateRepoOptions for updating a repository
type UpdateRepoOptions struct {
	Name          *string `json:"name,omitempty"`
	Description   *string `json:"description,omitempty"`
	Private       *bool   `json:"private,omitempty"`
	Archived      *bool   `json:"archived,omitempty"`
	DefaultBranch *string `json:"default_branch,omitempty"`
	HasIssues     *bool   `json:"has_issues,omitempty"`
	HasWiki       *bool   `json:"has_wiki,omitempty"`
	HasProjects   *bool   `json:"has_projects,omitempty"`
}

// CreateFileOptions for creating/updating a file
type CreateFileOptions struct {
	Message string `json:"message"`
	Content string `json:"content"` // Base64 encoded
	Branch  string `json:"branch,omitempty"`
	SHA     string `json:"sha,omitempty"` // Required for updates
}

// CreatePROptions for creating a pull request
type CreatePROptions struct {
	Title string `json:"title"`
	Body  string `json:"body,omitempty"`
	Head  string `json:"head"` // branch name or user:branch
	Base  string `json:"base"`
	Draft bool   `json:"draft,omitempty"`
}

// CreateIssueOptions for creating an issue
type CreateIssueOptions struct {
	Title     string   `json:"title"`
	Body      string   `json:"body,omitempty"`
	Labels    []string `json:"labels,omitempty"`
	Assignees []string `json:"assignees,omitempty"`
	Milestone *int     `json:"milestone,omitempty"`
}

// CreateHookOptions for creating a webhook
type CreateHookOptions struct {
	Name   string          `json:"name"` // always "web"
	Active bool            `json:"active"`
	Events []string        `json:"events"`
	Config APIHookConfig   `json:"config"`
}

// CreateReleaseOptions for creating a release
type CreateReleaseOptions struct {
	TagName         string `json:"tag_name"`
	TargetCommitish string `json:"target_commitish,omitempty"`
	Name            string `json:"name,omitempty"`
	Body            string `json:"body,omitempty"`
	Draft           bool   `json:"draft"`
	Prerelease      bool   `json:"prerelease"`
}

// CreateDeployKeyOptions for creating a deploy key
type CreateDeployKeyOptions struct {
	Title    string `json:"title"`
	Key      string `json:"key"`
	ReadOnly bool   `json:"read_only"`
}
