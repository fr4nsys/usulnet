// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package gitlab

import "time"

// ============================================================================
// GitLab API Response Types
// ============================================================================

// APIUser represents a GitLab user
type APIUser struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	State     string `json:"state"`
	AvatarURL string `json:"avatar_url"`
	WebURL    string `json:"web_url"`
}

// APINamespace represents a GitLab namespace (user or group)
type APINamespace struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Kind     string `json:"kind"` // user, group
	FullPath string `json:"full_path"`
	WebURL   string `json:"web_url"`
}

// APIProject represents a GitLab project (repository)
type APIProject struct {
	ID                int64        `json:"id"`
	Name              string       `json:"name"`
	NameWithNamespace string       `json:"name_with_namespace"`
	Path              string       `json:"path"`
	PathWithNamespace string       `json:"path_with_namespace"`
	Description       string       `json:"description"`
	DefaultBranch     string       `json:"default_branch"`
	Visibility        string       `json:"visibility"` // private, internal, public
	Archived          bool         `json:"archived"`
	ForksCount        int          `json:"forks_count"`
	StarCount         int          `json:"star_count"`
	OpenIssuesCount   int          `json:"open_issues_count"`
	WebURL            string       `json:"web_url"`
	SSHURLToRepo      string       `json:"ssh_url_to_repo"`
	HTTPURLToRepo     string       `json:"http_url_to_repo"`
	Namespace         APINamespace `json:"namespace"`
	Owner             *APIUser     `json:"owner"`
	ForkedFromProject *APIProject  `json:"forked_from_project"`
	CreatedAt         time.Time    `json:"created_at"`
	LastActivityAt    time.Time    `json:"last_activity_at"`
	// Statistics (only if requested)
	Statistics *APIProjectStats `json:"statistics,omitempty"`
}

// APIProjectStats contains project statistics
type APIProjectStats struct {
	CommitCount      int   `json:"commit_count"`
	StorageSize      int64 `json:"storage_size"`
	RepositorySize   int64 `json:"repository_size"`
	WikiSize         int64 `json:"wiki_size"`
	LFSObjectsSize   int64 `json:"lfs_objects_size"`
	JobArtifactsSize int64 `json:"job_artifacts_size"`
}

// APIBranch represents a GitLab branch
type APIBranch struct {
	Name      string        `json:"name"`
	Commit    APIBranchHead `json:"commit"`
	Protected bool          `json:"protected"`
	Default   bool          `json:"default"`
	WebURL    string        `json:"web_url"`
}

// APIBranchHead is the commit at the head of a branch
type APIBranchHead struct {
	ID             string    `json:"id"`
	ShortID        string    `json:"short_id"`
	Title          string    `json:"title"`
	Message        string    `json:"message"`
	AuthorName     string    `json:"author_name"`
	AuthorEmail    string    `json:"author_email"`
	CommitterName  string    `json:"committer_name"`
	CommitterEmail string    `json:"committer_email"`
	AuthoredDate   time.Time `json:"authored_date"`
	CommittedDate  time.Time `json:"committed_date"`
	WebURL         string    `json:"web_url"`
}

// APICommit represents a GitLab commit
type APICommit struct {
	ID             string    `json:"id"`
	ShortID        string    `json:"short_id"`
	Title          string    `json:"title"`
	Message        string    `json:"message"`
	AuthorName     string    `json:"author_name"`
	AuthorEmail    string    `json:"author_email"`
	CommitterName  string    `json:"committer_name"`
	CommitterEmail string    `json:"committer_email"`
	AuthoredDate   time.Time `json:"authored_date"`
	CommittedDate  time.Time `json:"committed_date"`
	WebURL         string    `json:"web_url"`
	ParentIDs      []string  `json:"parent_ids"`
	Stats          *APICommitStats `json:"stats,omitempty"`
}

// APICommitStats contains commit statistics
type APICommitStats struct {
	Additions int `json:"additions"`
	Deletions int `json:"deletions"`
	Total     int `json:"total"`
}

// APITag represents a GitLab tag
type APITag struct {
	Name      string          `json:"name"`
	Message   string          `json:"message"`
	Target    string          `json:"target"` // commit SHA
	Commit    APIBranchHead   `json:"commit"`
	Release   *APITagRelease  `json:"release,omitempty"`
	Protected bool            `json:"protected"`
}

// APITagRelease is release info attached to a tag
type APITagRelease struct {
	TagName     string `json:"tag_name"`
	Description string `json:"description"`
}

// APITreeItem represents an item in a repository tree
type APITreeItem struct {
	ID   string `json:"id"` // SHA
	Name string `json:"name"`
	Type string `json:"type"` // blob, tree
	Path string `json:"path"`
	Mode string `json:"mode"`
}

// APIFileContent represents file content from a repository
type APIFileContent struct {
	FileName      string `json:"file_name"`
	FilePath      string `json:"file_path"`
	Size          int64  `json:"size"`
	Encoding      string `json:"encoding"` // base64
	Content       string `json:"content"`
	ContentSHA256 string `json:"content_sha256"`
	Ref           string `json:"ref"`
	BlobID        string `json:"blob_id"`
	CommitID      string `json:"commit_id"`
	LastCommitID  string `json:"last_commit_id"`
}

// APIMergeRequest represents a GitLab merge request
type APIMergeRequest struct {
	ID             int64       `json:"id"`
	IID            int64       `json:"iid"` // Internal ID (what users see)
	Title          string      `json:"title"`
	Description    string      `json:"description"`
	State          string      `json:"state"` // opened, closed, merged, locked
	SourceBranch   string      `json:"source_branch"`
	TargetBranch   string      `json:"target_branch"`
	Author         APIUser     `json:"author"`
	Assignees      []APIUser   `json:"assignees"`
	Reviewers      []APIUser   `json:"reviewers"`
	Labels         []string    `json:"labels"`
	Milestone      *APIMilestone `json:"milestone"`
	MergeStatus    string      `json:"merge_status"` // can_be_merged, cannot_be_merged, etc
	Draft          bool        `json:"draft"` // or work_in_progress
	WebURL         string      `json:"web_url"`
	DiffRefs       *APIDiffRefs `json:"diff_refs"`
	UserNotesCount int         `json:"user_notes_count"`
	Upvotes        int         `json:"upvotes"`
	Downvotes      int         `json:"downvotes"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
	MergedAt       *time.Time  `json:"merged_at"`
	ClosedAt       *time.Time  `json:"closed_at"`
	MergedBy       *APIUser    `json:"merged_by"`
	ClosedBy       *APIUser    `json:"closed_by"`
	ChangesCount   string      `json:"changes_count"`
	HasConflicts   bool        `json:"has_conflicts"`
}

// APIDiffRefs contains diff references
type APIDiffRefs struct {
	BaseSHA  string `json:"base_sha"`
	HeadSHA  string `json:"head_sha"`
	StartSHA string `json:"start_sha"`
}

// APIIssue represents a GitLab issue
type APIIssue struct {
	ID          int64       `json:"id"`
	IID         int64       `json:"iid"` // Internal ID
	Title       string      `json:"title"`
	Description string      `json:"description"`
	State       string      `json:"state"` // opened, closed
	Author      APIUser     `json:"author"`
	Assignees   []APIUser   `json:"assignees"`
	Labels      []string    `json:"labels"`
	Milestone   *APIMilestone `json:"milestone"`
	WebURL      string      `json:"web_url"`
	Confidential bool       `json:"confidential"`
	Weight      *int        `json:"weight"`
	UserNotesCount int      `json:"user_notes_count"`
	Upvotes     int         `json:"upvotes"`
	Downvotes   int         `json:"downvotes"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	ClosedAt    *time.Time  `json:"closed_at"`
	ClosedBy    *APIUser    `json:"closed_by"`
	DueDate     *string     `json:"due_date"` // YYYY-MM-DD
}

// APIMilestone represents a milestone
type APIMilestone struct {
	ID          int64      `json:"id"`
	IID         int64      `json:"iid"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	State       string     `json:"state"` // active, closed
	StartDate   *string    `json:"start_date"`
	DueDate     *string    `json:"due_date"`
	WebURL      string     `json:"web_url"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// APILabel represents a label
type APILabel struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
	TextColor   string `json:"text_color"`
}

// APIRelease represents a GitLab release
type APIRelease struct {
	TagName         string              `json:"tag_name"`
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	DescriptionHTML string              `json:"description_html"`
	CreatedAt       time.Time           `json:"created_at"`
	ReleasedAt      time.Time           `json:"released_at"`
	Author          APIUser             `json:"author"`
	Commit          APIBranchHead       `json:"commit"`
	UpcomingRelease bool                `json:"upcoming_release"`
	Assets          APIReleaseAssets    `json:"assets"`
}

// APIReleaseAssets contains release assets
type APIReleaseAssets struct {
	Count   int              `json:"count"`
	Sources []APIAssetSource `json:"sources"`
	Links   []APIAssetLink   `json:"links"`
}

// APIAssetSource is a source archive
type APIAssetSource struct {
	Format string `json:"format"` // zip, tar.gz, etc
	URL    string `json:"url"`
}

// APIAssetLink is a linked asset
type APIAssetLink struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	LinkType string `json:"link_type"` // other, runbook, image, package
}

// APIHook represents a project webhook
type APIHook struct {
	ID                    int64     `json:"id"`
	URL                   string    `json:"url"`
	ProjectID             int64     `json:"project_id"`
	PushEvents            bool      `json:"push_events"`
	PushEventsBranchFilter string   `json:"push_events_branch_filter"`
	IssuesEvents          bool      `json:"issues_events"`
	MergeRequestsEvents   bool      `json:"merge_requests_events"`
	TagPushEvents         bool      `json:"tag_push_events"`
	NoteEvents            bool      `json:"note_events"`
	JobEvents             bool      `json:"job_events"`
	PipelineEvents        bool      `json:"pipeline_events"`
	WikiPageEvents        bool      `json:"wiki_page_events"`
	DeploymentEvents      bool      `json:"deployment_events"`
	ReleasesEvents        bool      `json:"releases_events"`
	EnableSSLVerification bool      `json:"enable_ssl_verification"`
	CreatedAt             time.Time `json:"created_at"`
}

// APIDeployKey represents a deploy key
type APIDeployKey struct {
	ID        int64     `json:"id"`
	Title     string    `json:"title"`
	Key       string    `json:"key"`
	CanPush   bool      `json:"can_push"`
	CreatedAt time.Time `json:"created_at"`
}

// APIProjectMember represents a project member
type APIProjectMember struct {
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	Name        string    `json:"name"`
	State       string    `json:"state"`
	AvatarURL   string    `json:"avatar_url"`
	WebURL      string    `json:"web_url"`
	AccessLevel int       `json:"access_level"` // 10=guest, 20=reporter, 30=developer, 40=maintainer, 50=owner
	ExpiresAt   *string   `json:"expires_at"`
}

// APIPipeline represents a CI/CD pipeline
type APIPipeline struct {
	ID        int64     `json:"id"`
	IID       int64     `json:"iid"`
	ProjectID int64     `json:"project_id"`
	SHA       string    `json:"sha"`
	Ref       string    `json:"ref"`
	Status    string    `json:"status"` // created, waiting_for_resource, preparing, pending, running, success, failed, canceled, skipped, manual, scheduled
	Source    string    `json:"source"` // push, web, trigger, schedule, api, external, pipeline, chat, etc
	WebURL    string    `json:"web_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	StartedAt *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Duration  *int       `json:"duration"` // seconds
	User      APIUser   `json:"user"`
}

// APIJob represents a CI/CD job
type APIJob struct {
	ID           int64         `json:"id"`
	Name         string        `json:"name"`
	Stage        string        `json:"stage"`
	Status       string        `json:"status"`
	Ref          string        `json:"ref"`
	Tag          bool          `json:"tag"`
	Coverage     *float64      `json:"coverage"`
	AllowFailure bool          `json:"allow_failure"`
	CreatedAt    time.Time     `json:"created_at"`
	StartedAt    *time.Time    `json:"started_at"`
	FinishedAt   *time.Time    `json:"finished_at"`
	Duration     *float64      `json:"duration"`
	User         APIUser       `json:"user"`
	Pipeline     APIPipeline   `json:"pipeline"`
	WebURL       string        `json:"web_url"`
}

// APIError represents a GitLab API error response
type APIError struct {
	Message string   `json:"message"`
	Error   string   `json:"error"`
	Errors  []string `json:"errors,omitempty"`
}

// ============================================================================
// Request Types
// ============================================================================

// CreateProjectOptions for creating a new project
type CreateProjectOptions struct {
	Name                 string `json:"name"`
	Path                 string `json:"path,omitempty"`
	Description          string `json:"description,omitempty"`
	Visibility           string `json:"visibility,omitempty"` // private, internal, public
	InitializeWithReadme bool   `json:"initialize_with_readme,omitempty"`
	DefaultBranch        string `json:"default_branch,omitempty"`
}

// UpdateProjectOptions for updating a project
type UpdateProjectOptions struct {
	Name          *string `json:"name,omitempty"`
	Description   *string `json:"description,omitempty"`
	Visibility    *string `json:"visibility,omitempty"`
	DefaultBranch *string `json:"default_branch,omitempty"`
	Archived      *bool   `json:"archived,omitempty"`
	IssuesEnabled *bool   `json:"issues_enabled,omitempty"`
	WikiEnabled   *bool   `json:"wiki_enabled,omitempty"`
	MREnabled     *bool   `json:"merge_requests_enabled,omitempty"`
}

// CreateFileOptions for creating/updating a file
type CreateFileOptions struct {
	Branch        string `json:"branch"`
	Content       string `json:"content"` // Base64 encoded
	CommitMessage string `json:"commit_message"`
	Encoding      string `json:"encoding,omitempty"` // text or base64
}

// UpdateFileOptions for updating a file
type UpdateFileOptions struct {
	Branch        string `json:"branch"`
	Content       string `json:"content"`
	CommitMessage string `json:"commit_message"`
	Encoding      string `json:"encoding,omitempty"`
	LastCommitID  string `json:"last_commit_id,omitempty"`
}

// CreateMROptions for creating a merge request
type CreateMROptions struct {
	Title              string `json:"title"`
	Description        string `json:"description,omitempty"`
	SourceBranch       string `json:"source_branch"`
	TargetBranch       string `json:"target_branch"`
	RemoveSourceBranch bool   `json:"remove_source_branch,omitempty"`
	Draft              bool   `json:"draft,omitempty"`
}

// CreateIssueOptions for creating an issue
type CreateIssueOptions struct {
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Labels      []string `json:"labels,omitempty"`
	AssigneeIDs []int64  `json:"assignee_ids,omitempty"`
	MilestoneID *int64   `json:"milestone_id,omitempty"`
	DueDate     *string  `json:"due_date,omitempty"`
}

// CreateHookOptions for creating a webhook
type CreateHookOptions struct {
	URL                   string `json:"url"`
	Token                 string `json:"token,omitempty"`
	PushEvents            *bool  `json:"push_events,omitempty"`
	IssuesEvents          *bool  `json:"issues_events,omitempty"`
	MergeRequestsEvents   *bool  `json:"merge_requests_events,omitempty"`
	TagPushEvents         *bool  `json:"tag_push_events,omitempty"`
	NoteEvents            *bool  `json:"note_events,omitempty"`
	PipelineEvents        *bool  `json:"pipeline_events,omitempty"`
	ReleasesEvents        *bool  `json:"releases_events,omitempty"`
	EnableSSLVerification *bool  `json:"enable_ssl_verification,omitempty"`
}

// CreateReleaseOptions for creating a release
type CreateReleaseOptions struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Ref         string `json:"ref,omitempty"` // tag, branch, or SHA
}

// CreateDeployKeyOptions for creating a deploy key
type CreateDeployKeyOptions struct {
	Title   string `json:"title"`
	Key     string `json:"key"`
	CanPush bool   `json:"can_push,omitempty"`
}

// Access level constants
const (
	AccessLevelGuest      = 10
	AccessLevelReporter   = 20
	AccessLevelDeveloper  = 30
	AccessLevelMaintainer = 40
	AccessLevelOwner      = 50
)

// AccessLevelName returns the name for an access level
func AccessLevelName(level int) string {
	switch level {
	case AccessLevelGuest:
		return "Guest"
	case AccessLevelReporter:
		return "Reporter"
	case AccessLevelDeveloper:
		return "Developer"
	case AccessLevelMaintainer:
		return "Maintainer"
	case AccessLevelOwner:
		return "Owner"
	default:
		return "Unknown"
	}
}
