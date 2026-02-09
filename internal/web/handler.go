// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/integrations/gitea"
	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	totppkg "github.com/fr4nsys/usulnet/internal/pkg/totp"
	"github.com/fr4nsys/usulnet/internal/scheduler"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
	gitsvc "github.com/fr4nsys/usulnet/internal/services/git"
	swarmsvc "github.com/fr4nsys/usulnet/internal/services/swarm"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/images"
)

// Services interface aggregates all service interfaces needed by handlers.
type Services interface {
	Containers() ContainerService
	Images() ImageService
	Volumes() VolumeService
	Networks() NetworkService
	Stacks() StackService
	Backups() BackupService
	Config() ConfigService
	Security() SecurityService
	Updates() UpdateService
	Hosts() HostService
	Events() EventService
	Proxy() ProxyService
	Storage() StorageService
	Auth() AuthService
	Stats() StatsService
	Users() UserService
	Teams() TeamService
	Gitea() GiteaService
	Git() GitService
	Metrics() MetricsServiceFull
	Alerts() AlertsService
	Scheduler() *scheduler.Scheduler
}

// Service interfaces (defined here for compilation, actual implementations in services package)
type ContainerService interface {
	List(ctx context.Context, filters map[string]string) ([]ContainerView, error)
	Get(ctx context.Context, id string) (*ContainerView, error)
	Create(ctx context.Context, input *ContainerCreateInput) (string, error)
	Start(ctx context.Context, id string) error
	Stop(ctx context.Context, id string) error
	Restart(ctx context.Context, id string) error
	Pause(ctx context.Context, id string) error
	Unpause(ctx context.Context, id string) error
	Kill(ctx context.Context, id string) error
	Remove(ctx context.Context, id string, force bool) error
	Rename(ctx context.Context, id, name string) error
	GetLogs(ctx context.Context, id string, tail int) ([]string, error)
	GetDockerClient(ctx context.Context) (docker.ClientAPI, error)
	GetHostID() uuid.UUID
	// Bulk operations
	BulkStart(ctx context.Context, containerIDs []string) (*BulkOperationResults, error)
	BulkStop(ctx context.Context, containerIDs []string) (*BulkOperationResults, error)
	BulkRestart(ctx context.Context, containerIDs []string) (*BulkOperationResults, error)
	BulkPause(ctx context.Context, containerIDs []string) (*BulkOperationResults, error)
	BulkUnpause(ctx context.Context, containerIDs []string) (*BulkOperationResults, error)
	BulkKill(ctx context.Context, containerIDs []string) (*BulkOperationResults, error)
	BulkRemove(ctx context.Context, containerIDs []string, force bool) (*BulkOperationResults, error)
	// File browser
	BrowseFiles(ctx context.Context, containerID, path string) ([]ContainerFileView, error)
	ReadFile(ctx context.Context, containerID, path string) (*ContainerFileContentView, error)
	WriteFile(ctx context.Context, containerID, path, content string) error
	DeleteFile(ctx context.Context, containerID, path string, recursive bool) error
	CreateDirectory(ctx context.Context, containerID, path string) error
}

// ContainerFileView for file browser display.
type ContainerFileView struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	IsDir      bool   `json:"is_dir"`
	Size       int64  `json:"size"`
	SizeHuman  string `json:"size_human"`
	Mode       string `json:"mode"`
	ModTime    string `json:"mod_time"`
	ModTimeAgo string `json:"mod_time_ago"`
	Owner      string `json:"owner"`
	Group      string `json:"group"`
	LinkTarget string `json:"link_target,omitempty"`
	IsSymlink  bool   `json:"is_symlink"`
}

// ContainerFileContentView for file content display.
type ContainerFileContentView struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
	Binary    bool   `json:"binary"`
}

type ImageService interface {
	List(ctx context.Context) ([]ImageView, error)
	Get(ctx context.Context, id string) (*ImageView, error)
	Remove(ctx context.Context, id string, force bool) error
	Prune(ctx context.Context) (int64, error)
	Pull(ctx context.Context, reference string) error
}

// VolumeFileEntry represents a file/directory inside a volume for browsing.
type VolumeFileEntry struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	IsDir     bool   `json:"is_dir"`
	Size      int64  `json:"size"`
	SizeHuman string `json:"size_human"`
	Mode      string `json:"mode"`
	ModTime   string `json:"mod_time"`
}

type VolumeService interface {
	List(ctx context.Context) ([]VolumeView, error)
	Get(ctx context.Context, name string) (*VolumeView, error)
	Create(ctx context.Context, name, driver string, labels map[string]string) error
	Remove(ctx context.Context, name string, force bool) error
	Prune(ctx context.Context) (int64, error)
	Browse(ctx context.Context, volumeName, path string) ([]VolumeFileEntry, error)
}

type NetworkService interface {
	List(ctx context.Context) ([]NetworkView, error)
	Get(ctx context.Context, id string) (*NetworkView, error)
	GetModel(ctx context.Context, id string) (*models.Network, error)
	Create(ctx context.Context, name, driver string, opts map[string]string) error
	Remove(ctx context.Context, id string) error
	Connect(ctx context.Context, networkID, containerID string) error
	Disconnect(ctx context.Context, networkID, containerID string) error
	Prune(ctx context.Context) (int64, error)
	GetTopology(ctx context.Context) (*TopologyData, error)
}

type StackService interface {
	List(ctx context.Context) ([]StackView, error)
	Get(ctx context.Context, name string) (*StackView, error)
	GetServices(ctx context.Context, name string) ([]StackServiceView, error)
	GetComposeConfig(ctx context.Context, name string) (string, error)
	Deploy(ctx context.Context, name, composeFile string) error
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Restart(ctx context.Context, name string) error
	Remove(ctx context.Context, name string) error
	ListVersions(ctx context.Context, name string) ([]StackVersionView, error)
}

// StackVersionView represents a stack version for the web UI.
type StackVersionView struct {
	Version    int
	Comment    string
	CreatedAt  string
	CreatedBy  string
	IsDeployed bool
}

type BackupService interface {
	List(ctx context.Context, containerID string) ([]BackupView, error)
	Get(ctx context.Context, id string) (*BackupView, error)
	Create(ctx context.Context, containerID string) (*BackupView, error)
	CreateWithOptions(ctx context.Context, opts BackupCreateInput) (*BackupView, error)
	Restore(ctx context.Context, id string) error
	Remove(ctx context.Context, id string) error
	Download(ctx context.Context, id string) (string, error)
	DownloadStream(ctx context.Context, id string) (io.ReadCloser, string, int64, error)
	GetStats(ctx context.Context) (*BackupStatsView, error)
	GetStorageInfo(ctx context.Context) (*BackupStorageView, error)
	// Schedules
	ListSchedules(ctx context.Context) ([]BackupScheduleView, error)
	CreateSchedule(ctx context.Context, input BackupScheduleInput) (*BackupScheduleView, error)
	DeleteSchedule(ctx context.Context, id string) error
	RunSchedule(ctx context.Context, id string) error
}

type ConfigService interface {
	ListVariables(ctx context.Context, scope, scopeID string) ([]ConfigVarView, error)
	GetVariable(ctx context.Context, id string) (*ConfigVarView, error)
	CreateVariable(ctx context.Context, v *ConfigVarView) error
	UpdateVariable(ctx context.Context, v *ConfigVarView) error
	DeleteVariable(ctx context.Context, id string) error
	ListTemplates(ctx context.Context) ([]interface{}, error)
	GetAuditLogs(ctx context.Context, limit int) ([]interface{}, error)
}

type SecurityService interface {
	GetOverview(ctx context.Context) (*SecurityOverviewData, error)
	ListScans(ctx context.Context) ([]SecurityScanView, error)
	ListContainersWithSecurity(ctx context.Context) ([]ContainerSecurityView, error)
	GetScan(ctx context.Context, containerID string) (*SecurityScanView, error)
	Scan(ctx context.Context, containerID string) (*SecurityScanView, error)
	ScanAll(ctx context.Context) error
	ListIssues(ctx context.Context) ([]IssueView, error)
	IgnoreIssue(ctx context.Context, id string) error
	ResolveIssue(ctx context.Context, id string) error
	GetTrends(ctx context.Context, days int) (*SecurityTrendsViewData, error)
	GenerateReport(ctx context.Context, format string) ([]byte, string, error) // data, contentType, error
	IsTrivyAvailable() bool
}

type UpdateService interface {
	ListAvailable(ctx context.Context) ([]UpdateView, error)
	CheckAll(ctx context.Context) error
	GetChangelog(ctx context.Context, containerID string) (string, error)
	Apply(ctx context.Context, containerID string, backup bool, targetVersion string) error
	Rollback(ctx context.Context, updateID string) error
	GetHistory(ctx context.Context) ([]UpdateHistoryView, error)
}

type HostService interface {
	List(ctx context.Context) ([]HostView, error)
	Get(ctx context.Context, id string) (*HostView, error)
	GetDockerInfo(ctx context.Context) (*DockerInfoView, error)
	Create(ctx context.Context, h *HostView) (string, error) // returns host ID
	Update(ctx context.Context, h *HostView) error
	Remove(ctx context.Context, id string) error
	Test(ctx context.Context, id string) error
	GenerateAgentToken(ctx context.Context, id string) (string, error)
}

// DockerInfoView contains Docker daemon information for templates.
type DockerInfoView struct {
	ID                string
	Name              string
	ServerVersion     string
	APIVersion        string
	OS                string
	OSType            string
	Architecture      string
	KernelVersion     string
	Containers        int
	ContainersRunning int
	ContainersPaused  int
	ContainersStopped int
	Images            int
	MemTotal          int64
	NCPU              int
	DockerRootDir     string
	Swarm             bool
}

type EventService interface {
	List(ctx context.Context, limit int) ([]EventView, error)
	Stream(ctx context.Context) (<-chan EventView, error)
}

type ProxyService interface {
	// Proxy Hosts
	ListHosts(ctx context.Context) ([]ProxyHostView, error)
	GetHost(ctx context.Context, id int) (*ProxyHostView, error)
	CreateHost(ctx context.Context, h *ProxyHostView) error
	UpdateHost(ctx context.Context, h *ProxyHostView) error
	RemoveHost(ctx context.Context, id int) error
	EnableHost(ctx context.Context, id int) error
	DisableHost(ctx context.Context, id int) error
	Sync(ctx context.Context) error
	// Redirection Hosts
	ListRedirections(ctx context.Context) ([]RedirectionHostView, error)
	CreateRedirection(ctx context.Context, r *RedirectionHostView) error
	UpdateRedirection(ctx context.Context, r *RedirectionHostView) error
	DeleteRedirection(ctx context.Context, id int) error
	GetRedirection(ctx context.Context, id int) (*RedirectionHostView, error)
	// Streams
	ListStreams(ctx context.Context) ([]StreamView, error)
	CreateStream(ctx context.Context, s *StreamView) error
	UpdateStream(ctx context.Context, s *StreamView) error
	DeleteStream(ctx context.Context, id int) error
	GetStream(ctx context.Context, id int) (*StreamView, error)
	// Dead Hosts
	ListDeadHosts(ctx context.Context) ([]DeadHostView, error)
	CreateDeadHost(ctx context.Context, d *DeadHostView) error
	DeleteDeadHost(ctx context.Context, id int) error
	// Certificates
	ListCertificates(ctx context.Context) ([]CertificateView, error)
	GetCertificate(ctx context.Context, id int) (*CertificateView, error)
	RequestLECertificate(ctx context.Context, domains []string, email string, agree bool, dnsChallenge bool, dnsProvider, dnsCredentials string, propagation int) error
	UploadCustomCertificate(ctx context.Context, niceName string, cert, key, intermediate []byte) error
	RenewCertificate(ctx context.Context, id int) error
	DeleteCertificate(ctx context.Context, id int) error
	// Access Lists
	ListAccessLists(ctx context.Context) ([]AccessListView, error)
	GetAccessList(ctx context.Context, id int) (*AccessListDetailView, error)
	CreateAccessList(ctx context.Context, a *AccessListDetailView) error
	UpdateAccessList(ctx context.Context, a *AccessListDetailView) error
	DeleteAccessList(ctx context.Context, id int) error
	// Audit
	ListAuditLogs(ctx context.Context, limit, offset int) ([]AuditLogView, int, error)
	// Connection management
	GetConnection(ctx context.Context) (*models.NPMConnection, error)
	SetupConnection(ctx context.Context, baseURL, email, password, userID string) error
	UpdateConnectionConfig(ctx context.Context, connID string, baseURL, email, password *string, enabled *bool, userID string) error
	DeleteConnection(ctx context.Context, connID string) error
	// IsConnected
	IsConnected(ctx context.Context) bool
}

// StorageService provides S3-compatible storage operations for the web layer.
type StorageService interface {
	// Connections
	ListConnections(ctx context.Context) ([]StorageConnectionView, error)
	GetConnection(connID string) (*StorageConnectionView, error)
	CreateConnection(ctx context.Context, name, endpoint, region, accessKey, secretKey string, usePathStyle, useSSL, isDefault bool, userID string) (*StorageConnectionView, error)
	UpdateConnection(ctx context.Context, connID string, name, endpoint, region, accessKey, secretKey *string, usePathStyle, useSSL, isDefault *bool, userID string) error
	DeleteConnection(ctx context.Context, connID, userID string) error
	TestConnection(ctx context.Context, connID string) error
	// Buckets
	ListBuckets(ctx context.Context, connID string) ([]StorageBucketView, error)
	CreateBucket(ctx context.Context, connID, name, region string, isPublic, versioning bool, userID string) error
	DeleteBucket(ctx context.Context, connID, name, userID string) error
	// Objects
	ListObjects(ctx context.Context, connID, bucket, prefix string) ([]StorageObjectView, error)
	UploadObject(ctx context.Context, connID, bucket, key string, reader io.Reader, size int64, contentType, userID string) error
	DeleteObject(ctx context.Context, connID, bucket, key, userID string) error
	CreateFolder(ctx context.Context, connID, bucket, prefix, userID string) error
	PresignDownload(ctx context.Context, connID, bucket, key string) (string, error)
	PresignUpload(ctx context.Context, connID, bucket, key string) (string, error)
	// Audit
	ListAuditLogs(ctx context.Context, connID string, limit, offset int) ([]StorageAuditView, int64, error)
}

type UserService interface {
	List(ctx context.Context, search string, role string) ([]UserView, int64, error)
	Get(ctx context.Context, id string) (*UserView, error)
	Create(ctx context.Context, username, email, password, role string) (*UserView, error)
	Update(ctx context.Context, id string, email *string, role *string, isActive *bool) error
	Delete(ctx context.Context, id string) error
	Enable(ctx context.Context, id string) error
	Disable(ctx context.Context, id string) error
	Unlock(ctx context.Context, id string) error
	ResetPassword(ctx context.Context, id string, newPassword string) error
	GetStats(ctx context.Context) (*UserStatsView, error)
	// TOTP 2FA
	SetupTOTP(ctx context.Context, userID string) (secret string, qrURI string, err error)
	VerifyAndEnableTOTP(ctx context.Context, userID string, code string) error
	ValidateTOTPCode(ctx context.Context, userID string, code string) (bool, error)
	DisableTOTP(ctx context.Context, userID string, code string) error
	HasTOTP(ctx context.Context, userID string) (bool, error)
}

// TeamService provides team management operations.
type TeamService interface {
	CreateTeam(ctx context.Context, name, description string, createdBy uuid.UUID) (*models.Team, error)
	GetTeam(ctx context.Context, id uuid.UUID) (*models.Team, error)
	ListTeams(ctx context.Context) ([]*models.Team, error)
	UpdateTeam(ctx context.Context, id uuid.UUID, name, description string) (*models.Team, error)
	DeleteTeam(ctx context.Context, id uuid.UUID) error
	AddMember(ctx context.Context, teamID, userID uuid.UUID, role models.TeamRole, addedBy uuid.UUID) error
	RemoveMember(ctx context.Context, teamID, userID uuid.UUID) error
	ListMembers(ctx context.Context, teamID uuid.UUID) ([]*models.TeamMember, error)
	ListTeamsForUser(ctx context.Context, userID uuid.UUID) ([]*models.Team, error)
	GrantAccess(ctx context.Context, teamID uuid.UUID, resourceType models.ResourceType, resourceID string, level models.AccessLevel, grantedBy uuid.UUID) error
	RevokeAccess(ctx context.Context, teamID uuid.UUID, resourceType models.ResourceType, resourceID string) error
	RevokeAccessByID(ctx context.Context, permID uuid.UUID) error
	ListPermissions(ctx context.Context, teamID uuid.UUID) ([]*models.ResourcePermission, error)
	TeamsExist(ctx context.Context) (bool, error)
	TeamCount(ctx context.Context) (int, error)
}

// GitService defines the interface for the unified Git multi-provider service.
type GitService interface {
	CreateConnection(ctx context.Context, input *gitsvc.CreateConnectionInput) (*models.GitConnection, error)
	TestConnection(ctx context.Context, id uuid.UUID) (*gitsvc.TestResult, error)
	SyncRepositories(ctx context.Context, connID uuid.UUID) (int, error)
	DeleteConnection(ctx context.Context, id uuid.UUID) error
}

// GiteaService defines the interface for Gitea integration operations.
type GiteaService interface {
	// Connections
	CreateConnection(ctx context.Context, input *gitea.CreateConnectionInput) (*models.GiteaConnection, error)
	GetConnection(ctx context.Context, id uuid.UUID) (*models.GiteaConnection, error)
	ListConnections(ctx context.Context, hostID uuid.UUID) ([]*models.GiteaConnection, error)
	ListAllConnections(ctx context.Context) ([]*models.GiteaConnection, error)
	DeleteConnection(ctx context.Context, id uuid.UUID) error
	TestConnection(ctx context.Context, id uuid.UUID) (*gitea.TestResult, error)

	// Repositories
	SyncRepositories(ctx context.Context, connectionID uuid.UUID) (int, error)
	ListRepositories(ctx context.Context, connectionID uuid.UUID) ([]*models.GiteaRepository, error)
	GetRepository(ctx context.Context, repoID uuid.UUID) (*models.GiteaRepository, error)

	// Tier 1: Repository management
	CreateRepository(ctx context.Context, input *gitea.CreateRepositoryInput) (*models.GiteaRepository, error)
	EditRepository(ctx context.Context, input *gitea.EditRepositoryInput) (*models.GiteaRepository, error)
	DeleteRepository(ctx context.Context, repoID uuid.UUID) error

	// File operations
	ListFiles(ctx context.Context, repoID uuid.UUID, path, ref string) ([]gitea.APIContentEntry, error)
	GetFileContent(ctx context.Context, repoID uuid.UUID, path, ref string) ([]byte, error)
	UpdateFile(ctx context.Context, repoID uuid.UUID, path, ref, content, message string) error

	// Tier 1: Branches
	ListBranches(ctx context.Context, repoID uuid.UUID) ([]gitea.APIBranch, error)
	GetBranch(ctx context.Context, repoID uuid.UUID, branch string) (*gitea.APIBranch, error)
	CreateBranch(ctx context.Context, repoID uuid.UUID, newBranch, sourceBranch string) (*gitea.APIBranch, error)
	DeleteBranch(ctx context.Context, repoID uuid.UUID, branch string) error

	// Tier 1: Tags
	ListTags(ctx context.Context, repoID uuid.UUID, page, limit int) ([]gitea.APITag, error)
	CreateTag(ctx context.Context, repoID uuid.UUID, tagName, target, message string) (*gitea.APITag, error)
	DeleteTag(ctx context.Context, repoID uuid.UUID, tag string) error

	// Tier 1: Commits & Diff
	ListCommits(ctx context.Context, repoID uuid.UUID, ref string, limit int) ([]gitea.APICommitListItem, error)
	ListCommitsFiltered(ctx context.Context, repoID uuid.UUID, opts gitea.CommitListOptions) ([]gitea.APICommitListItem, error)
	GetCommit(ctx context.Context, repoID uuid.UUID, sha string) (*gitea.APICommitListItem, error)
	Compare(ctx context.Context, repoID uuid.UUID, base, head string) (*gitea.APICompare, error)
	GetDiff(ctx context.Context, repoID uuid.UUID, base, head string) ([]byte, error)

	// Tier 1: Templates (for repo creation)
	ListGitignoreTemplates(ctx context.Context, connectionID uuid.UUID) ([]string, error)
	ListLicenseTemplates(ctx context.Context, connectionID uuid.UUID) ([]gitea.APILicenseTemplate, error)

	// Tier 2: Pull Requests
	ListPullRequests(ctx context.Context, repoID uuid.UUID, opts gitea.PRListOptions) ([]gitea.APIPullRequest, error)
	GetPullRequest(ctx context.Context, repoID uuid.UUID, number int64) (*gitea.APIPullRequest, error)
	CreatePullRequest(ctx context.Context, repoID uuid.UUID, opts gitea.CreatePullRequestOptions) (*gitea.APIPullRequest, error)
	EditPullRequest(ctx context.Context, repoID uuid.UUID, number int64, opts gitea.EditPullRequestOptions) (*gitea.APIPullRequest, error)
	MergePullRequest(ctx context.Context, repoID uuid.UUID, number int64, opts gitea.MergePullRequestOptions) error
	GetPullRequestDiff(ctx context.Context, repoID uuid.UUID, number int64) ([]byte, error)
	ListPRReviews(ctx context.Context, repoID uuid.UUID, number int64) ([]gitea.APIPRReview, error)
	CreatePRReview(ctx context.Context, repoID uuid.UUID, number int64, opts gitea.CreatePRReviewOptions) (*gitea.APIPRReview, error)
	ListPRComments(ctx context.Context, repoID uuid.UUID, number int64) ([]gitea.APIComment, error)

	// Tier 2: Issues
	ListIssues(ctx context.Context, repoID uuid.UUID, opts gitea.IssueListOptions) ([]gitea.APIIssue, error)
	GetIssue(ctx context.Context, repoID uuid.UUID, number int64) (*gitea.APIIssue, error)
	CreateIssue(ctx context.Context, repoID uuid.UUID, opts gitea.CreateIssueOptions) (*gitea.APIIssue, error)
	EditIssue(ctx context.Context, repoID uuid.UUID, number int64, opts gitea.EditIssueOptions) (*gitea.APIIssue, error)
	ListIssueComments(ctx context.Context, repoID uuid.UUID, number int64) ([]gitea.APIComment, error)
	CreateIssueComment(ctx context.Context, repoID uuid.UUID, number int64, body string) (*gitea.APIComment, error)
	EditIssueComment(ctx context.Context, repoID uuid.UUID, commentID int64, body string) (*gitea.APIComment, error)
	DeleteIssueComment(ctx context.Context, repoID uuid.UUID, commentID int64) error
	ListLabels(ctx context.Context, repoID uuid.UUID) ([]gitea.APILabel, error)
	ListMilestones(ctx context.Context, repoID uuid.UUID, state string) ([]gitea.APIMilestone, error)

	// Tier 2: Collaborators
	ListCollaborators(ctx context.Context, repoID uuid.UUID) ([]gitea.APICollaborator, error)
	IsCollaborator(ctx context.Context, repoID uuid.UUID, username string) (bool, error)
	AddCollaborator(ctx context.Context, repoID uuid.UUID, username, permission string) error
	RemoveCollaborator(ctx context.Context, repoID uuid.UUID, username string) error
	GetCollaboratorPermission(ctx context.Context, repoID uuid.UUID, username string) (*gitea.APIPermissions, error)
	ListRepoTeams(ctx context.Context, repoID uuid.UUID) ([]gitea.APITeam, error)

	// Tier 3: Webhooks (repo webhooks management)
	ListHooks(ctx context.Context, repoID uuid.UUID) ([]gitea.APIHook, error)
	GetHook(ctx context.Context, repoID uuid.UUID, hookID int64) (*gitea.APIHook, error)
	CreateHook(ctx context.Context, repoID uuid.UUID, opts gitea.CreateHookOptions) (*gitea.APIHook, error)
	EditHook(ctx context.Context, repoID uuid.UUID, hookID int64, opts gitea.EditHookOptions) (*gitea.APIHook, error)
	DeleteHook(ctx context.Context, repoID uuid.UUID, hookID int64) error
	TestHook(ctx context.Context, repoID uuid.UUID, hookID int64) error

	// Tier 3: Deploy Keys
	ListDeployKeys(ctx context.Context, repoID uuid.UUID) ([]gitea.APIDeployKey, error)
	GetDeployKey(ctx context.Context, repoID uuid.UUID, keyID int64) (*gitea.APIDeployKey, error)
	CreateDeployKey(ctx context.Context, repoID uuid.UUID, opts gitea.CreateDeployKeyOptions) (*gitea.APIDeployKey, error)
	DeleteDeployKey(ctx context.Context, repoID uuid.UUID, keyID int64) error

	// Tier 3: Releases
	ListReleases(ctx context.Context, repoID uuid.UUID, page, limit int) ([]gitea.APIRelease, error)
	GetRelease(ctx context.Context, repoID uuid.UUID, releaseID int64) (*gitea.APIRelease, error)
	GetReleaseByTag(ctx context.Context, repoID uuid.UUID, tag string) (*gitea.APIRelease, error)
	GetLatestRelease(ctx context.Context, repoID uuid.UUID) (*gitea.APIRelease, error)
	CreateRelease(ctx context.Context, repoID uuid.UUID, opts gitea.CreateReleaseOptions) (*gitea.APIRelease, error)
	EditRelease(ctx context.Context, repoID uuid.UUID, releaseID int64, opts gitea.EditReleaseOptions) (*gitea.APIRelease, error)
	DeleteRelease(ctx context.Context, repoID uuid.UUID, releaseID int64) error
	ListReleaseAssets(ctx context.Context, repoID uuid.UUID, releaseID int64) ([]gitea.APIReleaseAsset, error)
	DeleteReleaseAsset(ctx context.Context, repoID uuid.UUID, releaseID, assetID int64) error

	// Tier 3: Actions / CI Status
	ListWorkflows(ctx context.Context, repoID uuid.UUID) ([]gitea.APIWorkflow, error)
	ListActionRuns(ctx context.Context, repoID uuid.UUID, opts gitea.ActionRunListOptions) ([]gitea.APIActionRun, error)
	GetActionRun(ctx context.Context, repoID uuid.UUID, runID int64) (*gitea.APIActionRun, error)
	ListActionJobs(ctx context.Context, repoID uuid.UUID, runID int64) ([]gitea.APIActionJob, error)
	GetActionJobLogs(ctx context.Context, repoID uuid.UUID, jobID int64) ([]byte, error)
	CancelActionRun(ctx context.Context, repoID uuid.UUID, runID int64) error
	RerunActionRun(ctx context.Context, repoID uuid.UUID, runID int64) error
	GetCombinedStatus(ctx context.Context, repoID uuid.UUID, ref string) (*gitea.APICombinedStatus, error)
	ListCommitStatuses(ctx context.Context, repoID uuid.UUID, ref string, page, limit int) ([]gitea.APICommitStatus, error)
	CreateCommitStatus(ctx context.Context, repoID uuid.UUID, sha string, opts gitea.CreateStatusOptions) (*gitea.APICommitStatus, error)

	// Internal Webhooks (usulnet sync)
	RegisterWebhook(ctx context.Context, connID, repoID uuid.UUID, callbackURL string) error
	HandleWebhook(ctx context.Context, connectionID uuid.UUID, eventType, deliveryID string, payload []byte) error
	GetWebhookSecret(ctx context.Context, connectionID uuid.UUID) (string, error)
	ListWebhookEvents(ctx context.Context, connectionID uuid.UUID, limit int) ([]*models.GiteaWebhookEvent, error)
}

// MetricsServiceFull defines the interface for metrics collection, storage, and querying.
type MetricsServiceFull interface {
	// Live collection (from scheduler worker interface)
	CollectHostMetrics(ctx context.Context, hostID uuid.UUID) (*workers.HostMetrics, error)
	CollectContainerMetrics(ctx context.Context, hostID uuid.UUID) ([]*workers.ContainerMetrics, error)
	StoreMetrics(ctx context.Context, metrics *workers.MetricsSnapshot) error

	// Current (with cache)
	GetCurrentHostMetrics(ctx context.Context, hostID uuid.UUID) (*workers.HostMetrics, error)
	GetCurrentContainerMetrics(ctx context.Context, hostID uuid.UUID) ([]*workers.ContainerMetrics, error)

	// History
	GetHostHistory(ctx context.Context, hostID uuid.UUID, from, to time.Time, interval string) ([]*models.MetricsSnapshot, error)
	GetContainerHistory(ctx context.Context, containerID string, from, to time.Time, interval string) ([]*models.MetricsSnapshot, error)

	// Retention
	CleanupOldMetrics(ctx context.Context, retentionDays int) (int64, error)

	// Prometheus
	GetPrometheusMetrics(ctx context.Context) (string, error)
}

// LicenseProviderWeb provides license state to web handlers.
type LicenseProviderWeb interface {
	GetInfo() *license.Info
	Activate(licenseKey string) error
	Deactivate() error
	InstanceID() string
	Edition() license.Edition
}

// Handler manages all web page handlers.
type Handler struct {
	services       Services
	version        string
	sessionStore   SessionStore
	totpSigningKey []byte
	// Optional profile repositories (set via SetXxxRepo methods)
	userRepo        UserRepository
	prefsRepo       PreferencesRepository
	sessionRepo     SessionRepository
	snippetRepo     SnippetRepository
	oauthConfigRepo OAuthConfigRepository
	ldapConfigRepo  LDAPConfigRepository
	roleRepo        RoleRepository
	encryptor       Encryptor
	logger           Logger
	sshService             SSHService
	shortcutsService       ShortcutsService
	databaseService        DatabaseService
	ldapBrowserService     LDAPBrowserService
	terminalSessionRepo    TerminalSessionRepository
	notificationConfigRepo NotificationConfigRepository
	captureService         CaptureService
	customLogUploadRepo    CustomLogUploadRepository
	deployService          DeployService
	swarmService           *swarmsvc.Service
	licenseProvider        LicenseProviderWeb
	registryRepo           RegistryRepo
	webhookRepo            WebhookRepo
	runbookRepo            RunbookRepo
	autoDeployRepo         AutoDeployRepo
}

// NewTemplHandler creates a new web handler using Templ templates.
func NewTemplHandler(services Services, version string, sessionStore SessionStore) *Handler {
	return &Handler{
		services:     services,
		version:      version,
		sessionStore: sessionStore,
	}
}

// SetTOTPSigningKey sets the key used to sign TOTP pending tokens.
func (h *Handler) SetTOTPSigningKey(key []byte) {
	h.totpSigningKey = key
}

// SetUserRepo sets the optional user repository for profile operations.
func (h *Handler) SetUserRepo(repo UserRepository) { h.userRepo = repo }

// SetPrefsRepo sets the optional preferences repository for profile operations.
func (h *Handler) SetPrefsRepo(repo PreferencesRepository) { h.prefsRepo = repo }

// SetSessionRepo sets the optional session repository for profile operations.
func (h *Handler) SetSessionRepo(repo SessionRepository) { h.sessionRepo = repo }

// SetLicenseProvider sets the license provider for edition-aware rendering.
func (h *Handler) SetLicenseProvider(lp LicenseProviderWeb) { h.licenseProvider = lp }

// requireFeature returns Chi middleware that blocks requests when the current
// edition does not include the given feature flag. Returns HTTP 402 for web
// requests and an HTMX-compatible response for HTMX requests.
// This is the web-layer equivalent of api/middleware.RequireFeature.
func (h *Handler) requireFeature(feature license.Feature) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowed := false
			if h.licenseProvider != nil {
				info := h.licenseProvider.GetInfo()
				if info != nil && info.HasFeature(feature) {
					allowed = true
				}
			}
			if !allowed {
				if r.Header.Get("HX-Request") == "true" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusPaymentRequired)
					_, _ = w.Write([]byte(`<div class="alert alert-warning">This feature requires a Business or Enterprise license.</div>`))
					return
				}
				h.RenderError(w, r, http.StatusPaymentRequired,
					"License Required",
					"This feature requires a Business or Enterprise license. Visit usulnet.com/#pricing to upgrade.",
				)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RenderError renders an error page using Templ.
func (h *Handler) RenderError(w http.ResponseWriter, r *http.Request, code int, title, message string) {
	component := pages.Error(pages.ErrorData{
		Code:    code,
		Title:   title,
		Message: message,
		Version: h.version,
	})
	h.renderTemplWithStatus(w, r, code, component)
}

// redirect redirects to a URL with optional flash message.
func (h *Handler) redirect(w http.ResponseWriter, r *http.Request, url string) {
	// For HTMX requests, use HX-Redirect header
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", url)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, url, http.StatusSeeOther)
}

// htmxTrigger sends an HTMX trigger header.
func (h *Handler) htmxTrigger(w http.ResponseWriter, event string) {
	w.Header().Set("HX-Trigger", event)
}

// getIDParam extracts ID parameter from URL.
func getIDParam(r *http.Request) string {
	return chi.URLParam(r, "id")
}

// getNameParam extracts name parameter from URL.
func getNameParam(r *http.Request) string {
	return chi.URLParam(r, "name")
}

// ============================================================================
// Auth Handlers
// ============================================================================

// LoginSubmit handles login form submission.
func (h *Handler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirect(w, r, "/login?error=Invalid+form+data")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	returnURL := r.FormValue("return_url")

	if username == "" || password == "" {
		h.redirect(w, r, "/login?error=Username+and+password+required&username="+url.QueryEscape(username))
		return
	}

	// Step 1: Verify credentials only (no session created yet)
	userCtx, err := h.services.Auth().VerifyCredentials(r.Context(), username, password, r.UserAgent(), getClientIP(r))
	if err != nil {
		h.redirect(w, r, "/login?error=Invalid+username+or+password&username="+url.QueryEscape(username))
		return
	}

	// Step 2: Check if user has TOTP 2FA enabled
	hasTOTP, _ := h.services.Users().HasTOTP(r.Context(), userCtx.ID)
	if hasTOTP && len(h.totpSigningKey) > 0 {
		// Generate pending token and redirect to TOTP verification
		token := totppkg.GeneratePendingToken(userCtx.ID, h.totpSigningKey)
		redirectURL := "/login/totp?token=" + token
		if returnURL != "" {
			redirectURL += "&return=" + returnURL
		}
		h.redirect(w, r, redirectURL)
		return
	}

	// Step 3: No TOTP — create session now
	userCtx, err = h.services.Auth().CreateSessionForUser(r.Context(), userCtx.ID, r.UserAgent(), getClientIP(r))
	if err != nil {
		h.redirect(w, r, "/login?error=Session+creation+failed")
		return
	}

	session := &Session{
		UserID:   userCtx.ID,
		Username: userCtx.Username,
		Role:     userCtx.Role,
	}

	if err := h.sessionStore.Save(r, w, session); err != nil {
		h.redirect(w, r, "/login?error=Session+creation+failed")
		return
	}

	// Redirect to return URL or dashboard (validate to prevent open redirect)
	if returnURL != "" && returnURL != "/login" && strings.HasPrefix(returnURL, "/") && !strings.HasPrefix(returnURL, "//") {
		h.redirect(w, r, returnURL)
		return
	}
	h.redirect(w, r, "/")
}

// Logout handles user logout.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// Get session to retrieve session ID for auth service logout
	session, _ := h.sessionStore.Get(r, "usulnet_session")
	if session != nil && session.ID != "" {
		_ = h.services.Auth().Logout(r.Context(), session.ID)
	}

	// Delete session cookie
	_ = h.sessionStore.Delete(r, w, "usulnet_session")
	h.redirect(w, r, "/login")
}

// HealthCheck returns health status.
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// ============================================================================
// Container Action Handlers
// ============================================================================

func (h *Handler) ContainerStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	if err := h.services.Containers().Start(ctx, id); err != nil {
		h.setFlash(w, r, "error", "Failed to start container: "+err.Error())
		http.Redirect(w, r, "/containers/"+id, http.StatusSeeOther)
		return
	}
	h.htmxTrigger(w, `{"showToast":{"type":"success","message":"Container started"}}`)
	h.redirect(w, r, "/containers/"+id)
}

func (h *Handler) ContainerStop(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	if err := h.services.Containers().Stop(ctx, id); err != nil {
		h.setFlash(w, r, "error", "Failed to stop container: "+err.Error())
		http.Redirect(w, r, "/containers/"+id, http.StatusSeeOther)
		return
	}
	h.htmxTrigger(w, `{"showToast":{"type":"success","message":"Container stopped"}}`)
	h.redirect(w, r, "/containers/"+id)
}

func (h *Handler) ContainerRestart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	if err := h.services.Containers().Restart(ctx, id); err != nil {
		h.setFlash(w, r, "error", "Failed to restart container: "+err.Error())
		http.Redirect(w, r, "/containers/"+id, http.StatusSeeOther)
		return
	}
	h.htmxTrigger(w, `{"showToast":{"type":"success","message":"Container restarted"}}`)
	h.redirect(w, r, "/containers/"+id)
}

func (h *Handler) ContainerPause(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	if err := h.services.Containers().Pause(ctx, id); err != nil {
		h.setFlash(w, r, "error", "Failed to pause container: "+err.Error())
		http.Redirect(w, r, "/containers/"+id, http.StatusSeeOther)
		return
	}
	h.htmxTrigger(w, `{"showToast":{"type":"success","message":"Container paused"}}`)
	h.redirect(w, r, "/containers/"+id)
}

func (h *Handler) ContainerUnpause(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	if err := h.services.Containers().Unpause(ctx, id); err != nil {
		h.setFlash(w, r, "error", "Failed to unpause container: "+err.Error())
		http.Redirect(w, r, "/containers/"+id, http.StatusSeeOther)
		return
	}
	h.htmxTrigger(w, `{"showToast":{"type":"success","message":"Container unpaused"}}`)
	h.redirect(w, r, "/containers/"+id)
}

func (h *Handler) ContainerKill(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	if err := h.services.Containers().Kill(ctx, id); err != nil {
		h.setFlash(w, r, "error", "Failed to kill container: "+err.Error())
		http.Redirect(w, r, "/containers/"+id, http.StatusSeeOther)
		return
	}
	h.htmxTrigger(w, `{"showToast":{"type":"success","message":"Container killed"}}`)
	h.redirect(w, r, "/containers/"+id)
}

func (h *Handler) ContainerRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	force := r.FormValue("force") == "true"
	if err := h.services.Containers().Remove(ctx, id, force); err != nil {
		h.setFlash(w, r, "error", "Failed to remove container: "+err.Error())
		http.Redirect(w, r, "/containers/"+id, http.StatusSeeOther)
		return
	}
	h.htmxTrigger(w, `{"showToast":{"type":"success","message":"Container removed"}}`)
	h.redirect(w, r, "/containers")
}

// Bulk container operations
func (h *Handler) ContainerBulkStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	containerIDs := h.getContainerIDsFromForm(r)
	if len(containerIDs) == 0 {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"No containers selected"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	results, err := h.services.Containers().BulkStart(ctx, containerIDs)
	if err != nil {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"Bulk start failed: `+err.Error()+`"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	h.sendBulkResultToast(w, "started", results)
	h.redirect(w, r, "/containers")
}

func (h *Handler) ContainerBulkStop(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	containerIDs := h.getContainerIDsFromForm(r)
	if len(containerIDs) == 0 {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"No containers selected"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	results, err := h.services.Containers().BulkStop(ctx, containerIDs)
	if err != nil {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"Bulk stop failed: `+err.Error()+`"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	h.sendBulkResultToast(w, "stopped", results)
	h.redirect(w, r, "/containers")
}

func (h *Handler) ContainerBulkRestart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	containerIDs := h.getContainerIDsFromForm(r)
	if len(containerIDs) == 0 {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"No containers selected"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	results, err := h.services.Containers().BulkRestart(ctx, containerIDs)
	if err != nil {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"Bulk restart failed: `+err.Error()+`"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	h.sendBulkResultToast(w, "restarted", results)
	h.redirect(w, r, "/containers")
}

func (h *Handler) ContainerBulkPause(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	containerIDs := h.getContainerIDsFromForm(r)
	if len(containerIDs) == 0 {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"No containers selected"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	results, err := h.services.Containers().BulkPause(ctx, containerIDs)
	if err != nil {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"Bulk pause failed: `+err.Error()+`"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	h.sendBulkResultToast(w, "paused", results)
	h.redirect(w, r, "/containers")
}

func (h *Handler) ContainerBulkUnpause(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	containerIDs := h.getContainerIDsFromForm(r)
	if len(containerIDs) == 0 {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"No containers selected"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	results, err := h.services.Containers().BulkUnpause(ctx, containerIDs)
	if err != nil {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"Bulk unpause failed: `+err.Error()+`"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	h.sendBulkResultToast(w, "unpaused", results)
	h.redirect(w, r, "/containers")
}

func (h *Handler) ContainerBulkKill(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	containerIDs := h.getContainerIDsFromForm(r)
	if len(containerIDs) == 0 {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"No containers selected"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	results, err := h.services.Containers().BulkKill(ctx, containerIDs)
	if err != nil {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"Bulk kill failed: `+err.Error()+`"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	h.sendBulkResultToast(w, "killed", results)
	h.redirect(w, r, "/containers")
}

func (h *Handler) ContainerBulkRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	containerIDs := h.getContainerIDsFromForm(r)
	force := r.FormValue("force") == "true"
	if len(containerIDs) == 0 {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"No containers selected"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	results, err := h.services.Containers().BulkRemove(ctx, containerIDs, force)
	if err != nil {
		h.htmxTrigger(w, `{"showToast":{"type":"error","message":"Bulk remove failed: `+err.Error()+`"}}`)
		h.redirect(w, r, "/containers")
		return
	}

	h.sendBulkResultToast(w, "removed", results)
	h.redirect(w, r, "/containers")
}

func (h *Handler) getContainerIDsFromForm(r *http.Request) []string {
	r.ParseForm()
	ids := r.Form["container_ids"]
	if len(ids) == 0 {
		// Try JSON body
		ids = r.Form["container_ids[]"]
	}
	return ids
}

func (h *Handler) sendBulkResultToast(w http.ResponseWriter, action string, results *BulkOperationResults) {
	var msg string
	var toastType string

	if results.Failed == 0 {
		msg = fmt.Sprintf("%d containers %s successfully", results.Successful, action)
		toastType = "success"
	} else if results.Successful == 0 {
		msg = fmt.Sprintf("Failed to %s %d containers", action[:len(action)-2], results.Failed)
		toastType = "error"
	} else {
		msg = fmt.Sprintf("%d containers %s, %d failed", results.Successful, action, results.Failed)
		toastType = "warning"
	}

	h.htmxTrigger(w, fmt.Sprintf(`{"showToast":{"type":"%s","message":"%s"}}`, toastType, msg))
}

func (h *Handler) ContainerRename(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	name := r.FormValue("name")
	if err := h.services.Containers().Rename(ctx, id, name); err != nil {
		h.setFlash(w, r, "error", "Failed to rename container: "+err.Error())
		http.Redirect(w, r, "/containers/"+id, http.StatusSeeOther)
		return
	}
	h.htmxTrigger(w, `{"showToast":{"type":"success","message":"Container renamed"}}`)
	h.redirect(w, r, "/containers/"+id)
}

// ============================================================================
// Image Action Handlers
// ============================================================================

// ImagePull renders the image pull page.
func (h *Handler) ImagePull(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Pull Image", "images")
	data := images.PullImageData{
		PageData: pageData,
	}
	h.renderTempl(w, r, images.Pull(data))
}

func (h *Handler) ImageRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	force := r.FormValue("force") == "true"
	if err := h.services.Images().Remove(ctx, id, force); err != nil {
		h.setFlash(w, r, "error", "Failed to remove image: "+err.Error())
		http.Redirect(w, r, "/images", http.StatusSeeOther)
		return
	}
	h.setFlash(w, r, "success", "Image removed successfully")
	http.Redirect(w, r, "/images", http.StatusSeeOther)
}

func (h *Handler) ImagesPrune(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, err := h.services.Images().Prune(ctx)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to prune images: "+err.Error())
		http.Redirect(w, r, "/images", http.StatusSeeOther)
		return
	}
	h.setFlash(w, r, "success", "Unused images pruned")
	http.Redirect(w, r, "/images", http.StatusSeeOther)
}

// ============================================================================
// Volume Action Handlers
// ============================================================================

func (h *Handler) VolumeCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.FormValue("name")
	driver := r.FormValue("driver")
	if driver == "" {
		driver = "local"
	}
	if name == "" {
		h.setFlash(w, r, "error", "Volume name is required")
		http.Redirect(w, r, "/volumes/new", http.StatusSeeOther)
		return
	}
	if err := h.services.Volumes().Create(ctx, name, driver, nil); err != nil {
		h.setFlash(w, r, "error", "Failed to create volume: "+err.Error())
		http.Redirect(w, r, "/volumes/new", http.StatusSeeOther)
		return
	}
	h.setFlash(w, r, "success", "Volume '"+name+"' created successfully")
	http.Redirect(w, r, "/volumes", http.StatusSeeOther)
}

func (h *Handler) VolumeRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := getNameParam(r)
	force := r.FormValue("force") == "true"
	if err := h.services.Volumes().Remove(ctx, name, force); err != nil {
		h.setFlash(w, r, "error", "Failed to remove volume: "+err.Error())
		http.Redirect(w, r, "/volumes", http.StatusSeeOther)
		return
	}
	h.setFlash(w, r, "success", "Volume removed successfully")
	http.Redirect(w, r, "/volumes", http.StatusSeeOther)
}

func (h *Handler) VolumesPrune(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h.services.Volumes().Prune(ctx)
	h.setFlash(w, r, "success", "Unused volumes pruned")
	http.Redirect(w, r, "/volumes", http.StatusSeeOther)
}

// VolumeBrowseAPI returns files inside a volume as JSON (for frontend AJAX).
func (h *Handler) VolumeBrowseAPI(w http.ResponseWriter, r *http.Request) {
	volumeName := chi.URLParam(r, "name")
	if volumeName == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"volume name required"}`))
		return
	}

	path := chi.URLParam(r, "*")
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	files, err := h.services.Volumes().Browse(r.Context(), volumeName, path)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":%q}`, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"files": files,
		"path":  path,
	})
}

// ============================================================================
// Network Action Handlers
// ============================================================================

func (h *Handler) NetworkCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.FormValue("name")
	driver := r.FormValue("driver")
	if driver == "" {
		driver = "bridge"
	}
	if name == "" {
		h.setFlash(w, r, "error", "Network name is required")
		http.Redirect(w, r, "/networks/new", http.StatusSeeOther)
		return
	}
	if err := h.services.Networks().Create(ctx, name, driver, nil); err != nil {
		h.setFlash(w, r, "error", "Failed to create network: "+err.Error())
		http.Redirect(w, r, "/networks/new", http.StatusSeeOther)
		return
	}
	h.setFlash(w, r, "success", "Network '"+name+"' created successfully")
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (h *Handler) NetworkRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	if err := h.services.Networks().Remove(ctx, id); err != nil {
		h.setFlash(w, r, "error", "Failed to remove network: "+err.Error())
		http.Redirect(w, r, "/networks/"+id, http.StatusSeeOther)
		return
	}
	h.setFlash(w, r, "success", "Network removed successfully")
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (h *Handler) NetworkConnect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	containerID := r.FormValue("container_id")

	// Determine redirect target: back to container detail if called from container page
	redirectURL := "/networks/" + id
	if ref := r.Header.Get("Referer"); containerID != "" && strings.Contains(ref, "/containers/") {
		redirectURL = "/containers/" + containerID
	}

	if err := h.services.Networks().Connect(ctx, id, containerID); err != nil {
		h.setFlash(w, r, "error", "Failed to connect container: "+err.Error())
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}
	h.setFlash(w, r, "success", "Container connected to network")
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (h *Handler) NetworkDisconnect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	containerID := r.FormValue("container_id")

	// Determine redirect target: back to container detail if called from container page
	redirectURL := "/networks/" + id
	if ref := r.Header.Get("Referer"); containerID != "" && strings.Contains(ref, "/containers/") {
		redirectURL = "/containers/" + containerID
	}

	if err := h.services.Networks().Disconnect(ctx, id, containerID); err != nil {
		h.setFlash(w, r, "error", "Failed to disconnect container: "+err.Error())
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}
	h.setFlash(w, r, "success", "Container disconnected from network")
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (h *Handler) NetworksPrune(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h.services.Networks().Prune(ctx)
	h.setFlash(w, r, "success", "Unused networks pruned")
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

// ============================================================================
// Stack Action Handlers
// ============================================================================

func (h *Handler) StackDeploy(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("PANIC in StackDeploy",
				"panic", fmt.Sprintf("%v", rec),
				"stack", string(debug.Stack()),
			)
			http.Error(w, "Internal server error (panic recovered)", http.StatusInternalServerError)
		}
	}()

	ctx := r.Context()
	name := r.FormValue("name")
	composeFile := r.FormValue("compose")

	if name == "" || composeFile == "" {
		http.Error(w, "Name and compose content are required", http.StatusBadRequest)
		return
	}

	if err := h.services.Stacks().Deploy(ctx, name, composeFile); err != nil {
		slog.Error("stack deploy failed", "name", name, "error", err)
		http.Error(w, "Error deploying stack: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.redirect(w, r, "/stacks/"+name)
}

func (h *Handler) StackStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := getNameParam(r)
	h.services.Stacks().Start(ctx, name)
	h.redirect(w, r, "/stacks/"+name)
}

func (h *Handler) StackStop(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := getNameParam(r)
	h.services.Stacks().Stop(ctx, name)
	h.redirect(w, r, "/stacks/"+name)
}

func (h *Handler) StackRestart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := getNameParam(r)
	h.services.Stacks().Restart(ctx, name)
	h.redirect(w, r, "/stacks/"+name)
}

func (h *Handler) StackRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := getNameParam(r)
	h.services.Stacks().Remove(ctx, name)
	h.redirect(w, r, "/stacks")
}

// ============================================================================
// Security Action Handlers
// ============================================================================

func (h *Handler) SecurityScan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h.services.Security().ScanAll(ctx)
	h.redirect(w, r, "/security")
}

func (h *Handler) SecurityScanContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	h.services.Security().Scan(ctx, id)
	h.redirect(w, r, "/security")
}

func (h *Handler) SecurityIssueIgnore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	h.services.Security().IgnoreIssue(ctx, id)
	h.redirect(w, r, "/security")
}

func (h *Handler) SecurityIssueResolve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	h.services.Security().ResolveIssue(ctx, id)
	h.redirect(w, r, "/security")
}

// ============================================================================
// Update Action Handlers
// ============================================================================

func (h *Handler) UpdateChangelog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	changelog, _ := h.services.Updates().GetChangelog(ctx, id)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(changelog))
}

func (h *Handler) UpdateBatch(w http.ResponseWriter, r *http.Request) {
	h.redirect(w, r, "/updates")
}

// ============================================================================
// Backup Action Handlers
// ============================================================================

func (h *Handler) BackupCreate(w http.ResponseWriter, r *http.Request) {
	backupType := r.FormValue("type")
	targetID := r.FormValue("target_id")
	compression := r.FormValue("compression")
	encrypt := r.FormValue("encrypt") == "true"
	stopContainer := r.FormValue("stop_container") == "true"
	retentionDays := 30
	if rd := r.FormValue("retention_days"); rd != "" {
		if v, err := strconv.Atoi(rd); err == nil && v > 0 {
			retentionDays = v
		}
	}

	// Resolve target ID based on type
	switch backupType {
	case "volume":
		if v := r.FormValue("target_volume"); v != "" {
			targetID = v
		}
	case "stack":
		if v := r.FormValue("target_stack"); v != "" {
			targetID = v
		}
	}

	if targetID == "" {
		h.setFlash(w, r, "error", "Please select a backup target")
		http.Redirect(w, r, "/backups/new", http.StatusSeeOther)
		return
	}

	opts := BackupCreateInput{
		Type:          backupType,
		TargetID:      targetID,
		TargetName:    targetID,
		Compression:   compression,
		Encrypt:       encrypt,
		RetentionDays: retentionDays,
		StopContainer: stopContainer,
	}

	// Use a background context so the backup operation is not canceled
	// when the HTTP response is sent (redirect). The request context dies
	// on redirect, which kills long-running operations like container stop.
	bgCtx := context.Background()
	if activeHost := GetActiveHostIDFromContext(r.Context()); activeHost != "" {
		bgCtx = context.WithValue(bgCtx, ContextKeyActiveHost, activeHost)
	}

	// Run backup asynchronously - redirect immediately so the user can
	// monitor progress on the backups list page.
	go func() {
		if _, err := h.services.Backups().CreateWithOptions(bgCtx, opts); err != nil {
			h.logger.Error("backup failed", "type", backupType, "target", targetID, "error", err)
		}
	}()

	h.setFlash(w, r, "success", "Backup started. Check the backups list for progress.")
	h.redirect(w, r, "/backups")
}

func (h *Handler) BackupDownload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	reader, filename, size, err := h.services.Backups().DownloadStream(ctx, id)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to download backup: "+err.Error())
		http.Redirect(w, r, "/backups", http.StatusSeeOther)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	if size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	io.Copy(w, reader)
}

func (h *Handler) BackupRestore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	if err := h.services.Backups().Restore(ctx, id); err != nil {
		h.setFlash(w, r, "error", "Failed to restore backup: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Backup restored successfully")
	}
	h.redirect(w, r, "/backups/"+id)
}

func (h *Handler) BackupRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	if err := h.services.Backups().Remove(ctx, id); err != nil {
		h.setFlash(w, r, "error", "Failed to delete backup: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Backup deleted successfully")
	}
	h.redirect(w, r, "/backups")
}

func (h *Handler) BackupScheduleCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	backupType := r.FormValue("type")
	targetID := r.FormValue("target_id")
	schedule := r.FormValue("schedule")
	compression := r.FormValue("compression")
	encrypted := r.FormValue("encrypted") == "true"
	retentionDays := 30
	maxBackups := 10

	if rd := r.FormValue("retention_days"); rd != "" {
		if v, err := strconv.Atoi(rd); err == nil && v > 0 {
			retentionDays = v
		}
	}
	if mb := r.FormValue("max_backups"); mb != "" {
		if v, err := strconv.Atoi(mb); err == nil && v > 0 {
			maxBackups = v
		}
	}

	// Resolve target ID based on type
	switch backupType {
	case "volume":
		if v := r.FormValue("target_volume"); v != "" {
			targetID = v
		}
	case "stack":
		if v := r.FormValue("target_stack"); v != "" {
			targetID = v
		}
	}

	if targetID == "" || schedule == "" {
		h.setFlash(w, r, "error", "Target and schedule are required")
		http.Redirect(w, r, "/backups/schedules", http.StatusSeeOther)
		return
	}

	input := BackupScheduleInput{
		Type:          backupType,
		TargetID:      targetID,
		TargetName:    targetID,
		Schedule:      schedule,
		Compression:   compression,
		Encrypted:     encrypted,
		RetentionDays: retentionDays,
		MaxBackups:    maxBackups,
	}

	_, err := h.services.Backups().CreateSchedule(ctx, input)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to create schedule: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Backup schedule created successfully")
	}
	http.Redirect(w, r, "/backups/schedules", http.StatusSeeOther)
}

func (h *Handler) BackupScheduleDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	if err := h.services.Backups().DeleteSchedule(ctx, id); err != nil {
		h.setFlash(w, r, "error", "Failed to delete schedule: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Schedule deleted")
	}
	http.Redirect(w, r, "/backups/schedules", http.StatusSeeOther)
}

func (h *Handler) BackupScheduleRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	if err := h.services.Backups().RunSchedule(ctx, id); err != nil {
		h.setFlash(w, r, "error", "Failed to run schedule: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Backup started from schedule")
	}
	http.Redirect(w, r, "/backups/schedules", http.StatusSeeOther)
}

// ============================================================================
// Config Action Handlers
// ============================================================================

func (h *Handler) ConfigVarCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	value := r.FormValue("value")
	isSecret := r.FormValue("is_secret") == "on"

	if name == "" {
		h.setFlash(w, r, "error", "Variable name is required")
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	varType := "string"
	if isSecret {
		varType = "secret"
	}

	v := &ConfigVarView{
		Name:     name,
		Value:    value,
		IsSecret: isSecret,
		VarType:  varType,
		Scope:    "global",
	}

	if err := h.services.Config().CreateVariable(ctx, v); err != nil {
		h.logger.Error("failed to create config variable", "error", err)
		h.setFlash(w, r, "error", "Failed to create variable: "+err.Error())
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "Variable created successfully")
	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

func (h *Handler) ConfigVarUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	value := r.FormValue("value")

	v := &ConfigVarView{
		ID:    id,
		Value: value,
	}

	if err := h.services.Config().UpdateVariable(ctx, v); err != nil {
		h.logger.Error("failed to update config variable", "error", err)
		h.setFlash(w, r, "error", "Failed to update variable: "+err.Error())
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "Variable updated successfully")
	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

func (h *Handler) ConfigVarDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	if err := h.services.Config().DeleteVariable(ctx, id); err != nil {
		h.logger.Error("failed to delete config variable", "error", err)
		// For HTMX delete requests, return error status
		if r.Header.Get("HX-Request") == "true" {
			http.Error(w, "Failed to delete variable", http.StatusInternalServerError)
			return
		}
		h.setFlash(w, r, "error", "Failed to delete variable: "+err.Error())
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	// For HTMX requests, trigger a page refresh
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/config")
		w.WriteHeader(http.StatusOK)
		return
	}

	h.setFlash(w, r, "success", "Variable deleted successfully")
	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

func (h *Handler) ConfigTemplateCreate(w http.ResponseWriter, r *http.Request) {
	h.redirect(w, r, "/config/templates")
}

func (h *Handler) ConfigTemplateUpdate(w http.ResponseWriter, r *http.Request) {
	h.redirect(w, r, "/config/templates")
}

func (h *Handler) ConfigSync(w http.ResponseWriter, r *http.Request) {
	h.redirect(w, r, "/config")
}

func (h *Handler) ConfigExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
}

func (h *Handler) ConfigImport(w http.ResponseWriter, r *http.Request) {
	h.redirect(w, r, "/config")
}

// ============================================================================
// Host Action Handlers
// ============================================================================

func (h *Handler) HostTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := getIDParam(r)
	h.services.Hosts().Test(ctx, id)
	h.redirect(w, r, "/hosts/"+id)
}

// ============================================================================
// User Action Handlers
// ============================================================================

func (h *Handler) UserCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", "error", err)
		h.redirect(w, r, "/users/new")
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	role := r.FormValue("role")
	if role == "" {
		role = r.FormValue("role_id") // form uses role_id select field
	}

	if username == "" || password == "" || role == "" {
		h.redirect(w, r, "/users/new")
		return
	}

	_, err := h.services.Users().Create(ctx, username, email, password, role)
	if err != nil {
		slog.Error("Failed to create user", "username", username, "error", err)
		h.redirect(w, r, "/users/new")
		return
	}

	h.redirect(w, r, "/users")
}

func (h *Handler) UserUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", "error", err)
		h.redirect(w, r, "/users/"+id)
		return
	}

	email := r.FormValue("email")
	role := r.FormValue("role")
	password := r.FormValue("password")

	// Update email and role
	var emailPtr, rolePtr *string
	if email != "" {
		emailPtr = &email
	}
	if role != "" {
		rolePtr = &role
	}

	if err := h.services.Users().Update(ctx, id, emailPtr, rolePtr, nil); err != nil {
		slog.Error("Failed to update user", "id", id, "error", err)
		h.redirect(w, r, "/users/"+id)
		return
	}

	// Update password if provided
	if password != "" {
		if err := h.services.Users().ResetPassword(ctx, id, password); err != nil {
			slog.Error("Failed to reset password", "id", id, "error", err)
		}
	}

	h.redirect(w, r, "/users")
}

func (h *Handler) UserDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	if err := h.services.Users().Delete(ctx, id); err != nil {
		slog.Error("Failed to delete user", "id", id, "error", err)
	}

	h.redirect(w, r, "/users")
}

func (h *Handler) UserDisable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	if err := h.services.Users().Disable(ctx, id); err != nil {
		slog.Error("Failed to disable user", "id", id, "error", err)
	}

	h.redirect(w, r, "/users")
}

func (h *Handler) UserEnable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	// Enable also unlocks
	if err := h.services.Users().Unlock(ctx, id); err != nil {
		slog.Warn("Failed to unlock user (may not be locked)", "id", id, "error", err)
	}

	if err := h.services.Users().Enable(ctx, id); err != nil {
		slog.Error("Failed to enable user", "id", id, "error", err)
	}

	h.redirect(w, r, "/users")
}
