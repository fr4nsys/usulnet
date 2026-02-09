// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"time"
)

// PageData contains all data passed to page templates.
type PageData struct {
	// Page metadata
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Active      string `json:"active"` // Active nav item

	// Breadcrumb navigation
	Breadcrumb []BreadcrumbItem `json:"breadcrumb,omitempty"`

	// User context (injected by middleware)
	User *UserContext `json:"user,omitempty"`

	// Global stats (for sidebar badges)
	Stats *GlobalStats `json:"stats,omitempty"`

	// Notifications count
	NotificationsCount int `json:"notifications_count,omitempty"`

	// Flash messages
	Flash *FlashMessage `json:"flash,omitempty"`

	// CSRF token
	CSRFToken string `json:"csrf_token,omitempty"`

	// Theme preference
	Theme string `json:"theme,omitempty"`

	// Version info
	Version string `json:"version,omitempty"`

	// Page-specific data
	Data             interface{} `json:"data,omitempty"`
	Containers       interface{} `json:"containers,omitempty"`
	Container        interface{} `json:"container,omitempty"`
	Images           interface{} `json:"images,omitempty"`
	Volumes          interface{} `json:"volumes,omitempty"`
	Volume           interface{} `json:"volume,omitempty"`
	Networks         interface{} `json:"networks,omitempty"`
	Network          interface{} `json:"network,omitempty"`
	Stacks           interface{} `json:"stacks,omitempty"`
	Backups          interface{} `json:"backups,omitempty"`
	Variables        interface{} `json:"variables,omitempty"`
	ConfigTemplates  interface{} `json:"config_templates,omitempty"`
	AuditLogs        interface{} `json:"audit_logs,omitempty"`
	SecurityScans    interface{} `json:"security_scans,omitempty"`
	SecurityIssues   interface{} `json:"security_issues,omitempty"`
	SecurityOverview interface{} `json:"security_overview,omitempty"`
	Updates          interface{} `json:"updates,omitempty"`
	UpdateHistory    interface{} `json:"update_history,omitempty"`
	Hosts            interface{} `json:"hosts,omitempty"`
	Host             interface{} `json:"host,omitempty"`
	Events           interface{} `json:"events,omitempty"`
	Ports            interface{} `json:"ports,omitempty"`
	Jobs             interface{} `json:"jobs,omitempty"`
	UsersData        interface{} `json:"users_data,omitempty"`
	Notifications    interface{} `json:"notifications,omitempty"`
	Settings         interface{} `json:"settings,omitempty"`
	License          interface{} `json:"license,omitempty"`
	Topology         interface{} `json:"topology,omitempty"`
	Trends           interface{} `json:"trends,omitempty"`
	Recommendations  interface{} `json:"recommendations,omitempty"`
	ProxyHosts       interface{} `json:"proxy_hosts,omitempty"`
	Logs             interface{} `json:"logs,omitempty"`
	LogContainers    interface{} `json:"log_containers,omitempty"`

	// Pagination
	Pagination *PaginationData `json:"pagination,omitempty"`

	// Filters
	Filters map[string]string `json:"filters,omitempty"`

	// Sort
	SortBy    string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty"`

	// Error
	Error     string `json:"error,omitempty"`
	ErrorCode int    `json:"error_code,omitempty"`

	// Available options for dropdowns
	AvailableNetworks []string `json:"available_networks,omitempty"`
	AvailableStacks   []string `json:"available_stacks,omitempty"`
	AvailableHosts    []string `json:"available_hosts,omitempty"`
}

// BreadcrumbItem represents a breadcrumb navigation item.
type BreadcrumbItem struct {
	Label string `json:"label"`
	URL   string `json:"url,omitempty"`
	Icon  string `json:"icon,omitempty"`
}

// UserContext contains user information.
type UserContext struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	Role     string `json:"role"`
	RoleID   string `json:"role_id,omitempty"` // UUID of custom role for permission checking
}

// GlobalStats for sidebar badges.
type GlobalStats struct {
	ContainersRunning int    `json:"containers_running"`
	ContainersStopped int    `json:"containers_stopped"`
	ContainersPaused  int    `json:"containers_paused"`
	ContainersTotal   int    `json:"containers_total"`
	ImagesCount       int    `json:"images_count"`
	VolumesCount      int    `json:"volumes_count"`
	NetworksCount     int    `json:"networks_count"`
	StacksCount       int    `json:"stacks_count"`
	SecurityScore     int    `json:"security_score"`
	SecurityGrade     string `json:"security_grade"`
	SecurityIssues    int    `json:"security_issues"`
	UpdatesAvailable  int    `json:"updates_available"`
	HostsOnline       int    `json:"hosts_online"`
	HostsTotal        int    `json:"hosts_total"`
}

// FlashMessage represents a notification.
type FlashMessage struct {
	Type    string `json:"type"` // success, error, warning, info
	Message string `json:"message"`
}

// PaginationData contains pagination info.
type PaginationData struct {
	CurrentPage  int   `json:"current_page"`
	TotalPages   int   `json:"total_pages"`
	TotalItems   int64 `json:"total_items"`
	ItemsPerPage int   `json:"items_per_page"`
	HasPrev      bool  `json:"has_prev"`
	HasNext      bool  `json:"has_next"`
}

// NewPagination creates pagination data.
func NewPagination(totalItems int64, currentPage, perPage int) *PaginationData {
	if perPage <= 0 {
		perPage = 20
	}
	if currentPage <= 0 {
		currentPage = 1
	}
	totalPages := int((totalItems + int64(perPage) - 1) / int64(perPage))
	if totalPages <= 0 {
		totalPages = 1
	}
	return &PaginationData{
		CurrentPage:  currentPage,
		TotalPages:   totalPages,
		TotalItems:   totalItems,
		ItemsPerPage: perPage,
		HasPrev:      currentPage > 1,
		HasNext:      currentPage < totalPages,
	}
}

// ContainerView for container list/detail templates.
type ContainerView struct {
	ID            string            `json:"id"`
	ShortID       string            `json:"short_id"`
	HostID        string            `json:"host_id"`
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	ImageShort    string            `json:"image_short"`
	State         string            `json:"state"`
	Status        string            `json:"status"`
	Health        string            `json:"health"`
	Created       time.Time         `json:"created"`
	CreatedHuman  string            `json:"created_human"`
	Ports         []PortView        `json:"ports"`
	Networks       []string               `json:"networks"`
	NetworkDetails []NetworkAttachmentView `json:"network_details"`
	Mounts         []MountView            `json:"mounts"`
	Env           []EnvView         `json:"env"`
	Labels        map[string]string `json:"labels"`
	Stack         string            `json:"stack"`
	RestartPolicy string            `json:"restart_policy"`
	CPUPercent    float64           `json:"cpu_percent"`
	MemoryUsage   int64             `json:"memory_usage"`
	MemoryLimit   int64             `json:"memory_limit"`
	MemoryHuman   string            `json:"memory_human"`
	SecurityScore int               `json:"security_score"`
	SecurityGrade string            `json:"security_grade"`
	Command       string            `json:"command"`
	Entrypoint    string            `json:"entrypoint"`
}

// ContainerCreateInput holds form data for creating a container.
type ContainerCreateInput struct {
	Name          string
	Image         string
	Ports         []string // "hostPort:containerPort" format
	Environment   string   // KEY=value per line
	Volumes       []string // "source:target" format
	Network       string
	Command       string
	RestartPolicy string
	Privileged    bool
	AutoRemove    bool
}

// PortView for port display.
type PortView struct {
	ContainerPort int    `json:"container_port"`
	HostPort      int    `json:"host_port"`
	HostIP        string `json:"host_ip"`
	Protocol      string `json:"protocol"`
	Display       string `json:"display"`
}

// MountView for mount display.
type MountView struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
}

// NetworkAttachmentView for container network detail display.
type NetworkAttachmentView struct {
	NetworkID   string   `json:"network_id"`
	NetworkName string   `json:"network_name"`
	IPAddress   string   `json:"ip_address"`
	Gateway     string   `json:"gateway"`
	MacAddress  string   `json:"mac_address"`
	Aliases     []string `json:"aliases"`
}

// EnvView for environment variable display.
type EnvView struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	IsSecret bool   `json:"is_secret"`
}

// ImageView for image list templates.
type ImageView struct {
	ID           string    `json:"id"`
	ShortID      string    `json:"short_id"`
	Tags         []string  `json:"tags"`
	PrimaryTag   string    `json:"primary_tag"`
	Size         int64     `json:"size"`
	SizeHuman    string    `json:"size_human"`
	Created      time.Time `json:"created"`
	CreatedHuman string    `json:"created_human"`
	InUse        bool      `json:"in_use"`
	Containers   int       `json:"containers"`
}

// VolumeView for volume list templates.
type VolumeView struct {
	Name         string            `json:"name"`
	Driver       string            `json:"driver"`
	Mountpoint   string            `json:"mountpoint"`
	Scope        string            `json:"scope"`
	Created      time.Time         `json:"created"`
	CreatedHuman string            `json:"created_human"`
	InUse        bool              `json:"in_use"`
	Size         int64             `json:"size"`
	SizeHuman    string            `json:"size_human"`
	Labels       map[string]string `json:"labels"`
	UsedBy       []string          `json:"used_by"`
}

// NetworkView for network list templates.
type NetworkView struct {
	ID             string    `json:"id"`
	ShortID        string    `json:"short_id"`
	Name           string    `json:"name"`
	Driver         string    `json:"driver"`
	Scope          string    `json:"scope"`
	Internal       bool      `json:"internal"`
	Attachable     bool      `json:"attachable"`
	Subnet         string    `json:"subnet"`
	Gateway        string    `json:"gateway"`
	Created        time.Time `json:"created"`
	CreatedHuman   string    `json:"created_human"`
	ContainerCount int       `json:"container_count"`
	Containers     []string  `json:"containers"`
}

// StackView for stack/compose list templates.
type StackView struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Status         string    `json:"status"`
	ServiceCount   int       `json:"service_count"`
	RunningCount   int       `json:"running_count"`
	Created        time.Time `json:"created"`
	CreatedHuman   string    `json:"created_human"`
	UpdatedHuman   string    `json:"updated_human"`
	Path           string    `json:"path"`
	ComposeFile    string    `json:"compose_file"`
	ContainerNames []string  `json:"container_names"`
	IsExternal     bool      `json:"is_external"` // true if discovered from Docker, not managed by usulnet
}

// StackServiceView represents a service within a stack for templates.
type StackServiceView struct {
	Name            string   `json:"name"`
	Image           string   `json:"image"`
	ContainerID     string   `json:"container_id"`
	ContainerName   string   `json:"container_name"`
	Status          string   `json:"status"`
	State           string   `json:"state"`
	Replicas        string   `json:"replicas"`
	Ports           []string `json:"ports"`
}

// SecurityScanView for security scan results.
type SecurityScanView struct {
	ContainerID   string        `json:"container_id"`
	ContainerName string        `json:"container_name"`
	Image         string        `json:"image"`
	Score         int           `json:"score"`
	Grade         string        `json:"grade"`
	Issues        []IssueView   `json:"issues"`
	IssueCount    int           `json:"issue_count"`
	CriticalCount int           `json:"critical_count"`
	HighCount     int           `json:"high_count"`
	MediumCount   int           `json:"medium_count"`
	LowCount      int           `json:"low_count"`
	ScannedAt     time.Time     `json:"scanned_at"`
	ScannedHuman  string        `json:"scanned_human"`
	CVECount      int           `json:"cve_count"`
	IncludedCVE   bool          `json:"included_cve"`
}

// ContainerSecurityView represents a container with its security scan status.
type ContainerSecurityView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Image       string `json:"image"`
	State       string `json:"state"`
	HasScan     bool   `json:"has_scan"`
	Score       int    `json:"score"`
	Grade       string `json:"grade"`
	IssueCount  int    `json:"issue_count"`
	LastScanned string `json:"last_scanned"`
}

// IssueView for security issue display.
type IssueView struct {
	ID             string  `json:"id"`
	Severity       string  `json:"severity"`
	Category       string  `json:"category"`
	Title          string  `json:"title"`
	Message        string  `json:"message"`
	FixCommand     string  `json:"fix_command"`
	Documentation  string  `json:"documentation"`
	Status         string  `json:"status"`
	CVEID          string  `json:"cve_id,omitempty"`
	CVSSScore      float64 `json:"cvss_score,omitempty"`
	Recommendation string  `json:"recommendation,omitempty"`
}

// SecurityOverviewData for security dashboard.
type SecurityOverviewData struct {
	TotalScanned   int     `json:"total_scanned"`
	AverageScore   float64 `json:"average_score"`
	GradeA         int     `json:"grade_a"`
	GradeB         int     `json:"grade_b"`
	GradeC         int     `json:"grade_c"`
	GradeD         int     `json:"grade_d"`
	GradeF         int     `json:"grade_f"`
	CriticalCount  int     `json:"critical_count"`
	HighCount      int     `json:"high_count"`
	MediumCount    int     `json:"medium_count"`
	LowCount       int     `json:"low_count"`
	TrivyAvailable bool    `json:"trivy_available"`
}

// SecurityTrendsViewData for the trends page.
type SecurityTrendsViewData struct {
	Overview        SecurityOverviewData      `json:"overview"`
	ScoreHistory    []TrendPointView          `json:"score_history"`
	ContainerTrends []ContainerTrendViewData  `json:"container_trends"`
	Days            int                       `json:"days"`
}

// TrendPointView represents a single point in a trends chart.
type TrendPointView struct {
	Date  string  `json:"date"`
	Score float64 `json:"score"`
}

// ContainerTrendViewData shows trend for a single container.
type ContainerTrendViewData struct {
	Name          string `json:"name"`
	CurrentScore  int    `json:"current_score"`
	CurrentGrade  string `json:"current_grade"`
	PreviousScore int    `json:"previous_score"`
	Change        int    `json:"change"`
}

// UpdateView for available updates.
type UpdateView struct {
	ContainerID    string `json:"container_id"`
	ContainerName  string `json:"container_name"`
	Image          string `json:"image"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	Changelog      string `json:"changelog"`
	ChangelogURL   string `json:"changelog_url"`
	SecurityImpact string `json:"security_impact"`
	CheckedAt      string `json:"checked_at"`
}

// UpdateHistoryView for update history list.
type UpdateHistoryView struct {
	ID            string `json:"id"`
	ContainerName string `json:"container_name"`
	FromVersion   string `json:"from_version"`
	ToVersion     string `json:"to_version"`
	Status        string `json:"status"`
	Duration      string `json:"duration"`
	UpdatedAt     string `json:"updated_at"`
}

// BackupView for backup list/detail.
type BackupView struct {
	ID            string    `json:"id"`
	HostID        string    `json:"host_id"`
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	Type          string    `json:"type"`
	Status        string    `json:"status"`
	Trigger       string    `json:"trigger"`
	Size          int64     `json:"size"`
	SizeHuman     string    `json:"size_human"`
	Compression   string    `json:"compression"`
	Encrypted     bool      `json:"encrypted"`
	Verified      bool      `json:"verified"`
	Checksum      string    `json:"checksum"`
	ErrorMessage  string    `json:"error_message"`
	Duration      string    `json:"duration"`
	Created       time.Time `json:"created"`
	CreatedHuman  string    `json:"created_human"`
	CompletedAt   string    `json:"completed_at"`
	ExpiresAt     string    `json:"expires_at"`
	Path          string    `json:"path"`
}

// BackupStatsView for backup statistics dashboard.
type BackupStatsView struct {
	TotalBackups     int    `json:"total_backups"`
	CompletedBackups int    `json:"completed_backups"`
	FailedBackups    int    `json:"failed_backups"`
	TotalSize        int64  `json:"total_size"`
	TotalSizeHuman   string `json:"total_size_human"`
	LastBackupAt     string `json:"last_backup_at"`
}

// BackupStorageView for storage info display.
type BackupStorageView struct {
	Type            string  `json:"type"`
	Path            string  `json:"path"`
	TotalSpace      int64   `json:"total_space"`
	TotalSpaceHuman string  `json:"total_space_human"`
	UsedSpace       int64   `json:"used_space"`
	UsedSpaceHuman  string  `json:"used_space_human"`
	BackupCount     int64   `json:"backup_count"`
	UsagePercent    float64 `json:"usage_percent"`
}

// BackupScheduleView for schedule list.
type BackupScheduleView struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	TargetID      string `json:"target_id"`
	TargetName    string `json:"target_name"`
	Schedule      string `json:"schedule"`
	Compression   string `json:"compression"`
	Encrypted     bool   `json:"encrypted"`
	RetentionDays int    `json:"retention_days"`
	MaxBackups    int    `json:"max_backups"`
	IsEnabled     bool   `json:"is_enabled"`
	LastRunAt     string `json:"last_run_at"`
	LastRunStatus string `json:"last_run_status"`
	NextRunAt     string `json:"next_run_at"`
	CreatedAt     string `json:"created_at"`
}

// BackupCreateInput for creating a backup with full options.
type BackupCreateInput struct {
	Type          string `json:"type"`
	TargetID      string `json:"target_id"`
	TargetName    string `json:"target_name"`
	Compression   string `json:"compression"`
	Encrypt       bool   `json:"encrypt"`
	RetentionDays int    `json:"retention_days"`
	StopContainer bool   `json:"stop_container"`
}

// BackupScheduleInput for creating a backup schedule.
type BackupScheduleInput struct {
	Type          string `json:"type"`
	TargetID      string `json:"target_id"`
	TargetName    string `json:"target_name"`
	Schedule      string `json:"schedule"`
	Compression   string `json:"compression"`
	Encrypted     bool   `json:"encrypted"`
	RetentionDays int    `json:"retention_days"`
	MaxBackups    int    `json:"max_backups"`
}

// ConfigVarView for config variables.
type ConfigVarView struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	IsSecret    bool     `json:"is_secret"`
	VarType     string   `json:"var_type"`
	Scope       string   `json:"scope"`
	ScopeID     string   `json:"scope_id"`
	UsedBy      []string `json:"used_by"`
	UsedByCount int      `json:"used_by_count"`
	UpdatedAt   string   `json:"updated_at"`
	UpdatedBy   string   `json:"updated_by"`
}

// EventView for events list.
type EventView struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Action      string    `json:"action"`
	ActorID     string    `json:"actor_id"`
	ActorName   string    `json:"actor_name"`
	ActorType   string    `json:"actor_type"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	TimeHuman   string    `json:"time_human"`
}

// HostView for hosts list.
type HostView struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	DisplayName       string    `json:"display_name,omitempty"`
	Endpoint          string    `json:"endpoint"`
	EndpointType      string    `json:"endpoint_type"`
	Status            string    `json:"status"`
	DockerVersion     string    `json:"docker_version"`
	KernelVersion     string    `json:"kernel_version"`
	OS                string    `json:"os"`
	Arch              string    `json:"arch"`
	CPUs              int       `json:"cpus"`
	Memory            int64     `json:"memory"`
	MemoryHuman       string    `json:"memory_human"`
	Containers        int       `json:"containers"`
	ContainersRunning int       `json:"containers_running"`
	Images            int       `json:"images"`
	LastSeen          time.Time `json:"last_seen"`
	LastSeenHuman     string    `json:"last_seen_human"`
	TLSEnabled        bool      `json:"tls_enabled,omitempty"`
}

// TopologyData for network visualization.
type TopologyData struct {
	Nodes []TopologyNode `json:"nodes"`
	Edges []TopologyEdge `json:"edges"`
}

// TopologyNode represents a node.
type TopologyNode struct {
	ID    string                 `json:"id"`
	Label string                 `json:"label"`
	Type  string                 `json:"type"`
	State string                 `json:"state,omitempty"`
	Data  map[string]interface{} `json:"data,omitempty"`
}

// TopologyEdge represents a connection.
type TopologyEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label,omitempty"`
}

// PortAnalysisView for ports page.
type PortAnalysisView struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	InternalPort  int    `json:"internal_port"`
	ExternalPort  int    `json:"external_port"`
	HostIP        string `json:"host_ip"`
	Protocol      string `json:"protocol"`
	ExposureLevel string `json:"exposure_level"`
	IsRisky       bool   `json:"is_risky"`
	RiskReason    string `json:"risk_reason,omitempty"`
}

// ProxyHostView for NPM proxy hosts.
type ProxyHostView struct {
	ID          int      `json:"id"`
	Domain      string   `json:"domain"`
	ForwardHost string   `json:"forward_host"`
	ForwardPort int      `json:"forward_port"`
	SSLEnabled  bool     `json:"ssl_enabled"`
	Enabled     bool     `json:"enabled"`
	ContainerID string   `json:"container_id,omitempty"`
	Container   string   `json:"container,omitempty"`
}

// RedirectionHostView for NPM redirections.
type RedirectionHostView struct {
	ID              int      `json:"id"`
	DomainNames     []string `json:"domain_names"`
	Domain          string   `json:"domain"`
	ForwardScheme   string   `json:"forward_scheme"`
	ForwardDomain   string   `json:"forward_domain"`
	ForwardHTTPCode int      `json:"forward_http_code"`
	PreservePath    bool     `json:"preserve_path"`
	SSLForced       bool     `json:"ssl_forced"`
	CertificateID   int      `json:"certificate_id"`
	Enabled         bool     `json:"enabled"`
}

// StreamView for NPM TCP/UDP streams.
type StreamView struct {
	ID             int    `json:"id"`
	IncomingPort   int    `json:"incoming_port"`
	ForwardingHost string `json:"forwarding_host"`
	ForwardingPort int    `json:"forwarding_port"`
	TCPForwarding  bool   `json:"tcp_forwarding"`
	UDPForwarding  bool   `json:"udp_forwarding"`
	Enabled        bool   `json:"enabled"`
}

// DeadHostView for NPM dead hosts (404).
type DeadHostView struct {
	ID          int      `json:"id"`
	DomainNames []string `json:"domain_names"`
	Domain      string   `json:"domain"`
	SSLForced   bool     `json:"ssl_forced"`
	CertID      int      `json:"cert_id"`
	Enabled     bool     `json:"enabled"`
}

// CertificateView for NPM SSL certificates.
type CertificateView struct {
	ID          int      `json:"id"`
	NiceName    string   `json:"nice_name"`
	Provider    string   `json:"provider"`
	DomainNames []string `json:"domain_names"`
	ExpiresOn   string   `json:"expires_on"`
}

// AccessListView for NPM access lists.
type AccessListView struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	SatisfyAny  bool   `json:"satisfy_any"`
	PassAuth    bool   `json:"pass_auth"`
	ItemCount   int    `json:"item_count"`
	ClientCount int    `json:"client_count"`
}

// AccessListDetailView includes items and clients.
type AccessListDetailView struct {
	ID         int                    `json:"id"`
	Name       string                 `json:"name"`
	SatisfyAny bool                   `json:"satisfy_any"`
	PassAuth   bool                   `json:"pass_auth"`
	Items      []AccessListItemView   `json:"items"`
	Clients    []AccessListClientView `json:"clients"`
}

// AccessListItemView for ACL user entries.
type AccessListItemView struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AccessListClientView for ACL IP rules.
type AccessListClientView struct {
	Address   string `json:"address"`
	Directive string `json:"directive"`
}

// AuditLogView for NPM audit log entries.
type AuditLogView struct {
	ID           string `json:"id"`
	Operation    string `json:"operation"`
	ResourceType string `json:"resource_type"`
	ResourceID   int    `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	UserName     string `json:"user_name"`
	CreatedAt    string `json:"created_at"`
}

// UserView for user management pages.
type UserView struct {
	ID        string     `json:"id"`
	Username  string     `json:"username"`
	Email     string     `json:"email,omitempty"`
	Role      string     `json:"role"`
	IsActive  bool       `json:"is_active"`
	IsLDAP    bool       `json:"is_ldap"`
	LDAPDN    string     `json:"ldap_dn,omitempty"`
	IsLocked  bool       `json:"is_locked"`
	HasTOTP   bool       `json:"has_totp"`
	LastLogin *time.Time `json:"last_login_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// UserStatsView for user stats summary.
type UserStatsView struct {
	Total    int64 `json:"total"`
	Active   int64 `json:"active"`
	Inactive int64 `json:"inactive"`
	LDAP     int64 `json:"ldap"`
	Local    int64 `json:"local"`
	Locked   int64 `json:"locked"`
	Admins   int64 `json:"admins"`
}

// JobView for background jobs.
type JobView struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	Progress    int       `json:"progress"`
	Message     string    `json:"message"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
	Duration    string    `json:"duration,omitempty"`
}

// StorageConnectionView represents a storage connection for the UI.
type StorageConnectionView struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Endpoint     string `json:"endpoint"`
	Region       string `json:"region"`
	UsePathStyle bool   `json:"use_path_style"`
	UseSSL       bool   `json:"use_ssl"`
	IsDefault    bool   `json:"is_default"`
	Status       string `json:"status"`
	StatusMsg    string `json:"status_message,omitempty"`
	CreatedAt    string `json:"created_at"`
	LastChecked  string `json:"last_checked,omitempty"`
	BucketCount  int64  `json:"bucket_count"`
	TotalSize    int64  `json:"total_size"`
	TotalObjects int64  `json:"total_objects"`
}

// StorageBucketView represents a bucket for the UI.
type StorageBucketView struct {
	Name        string `json:"name"`
	Region      string `json:"region"`
	SizeBytes   int64  `json:"size_bytes"`
	SizeHuman   string `json:"size_human"`
	ObjectCount int64  `json:"object_count"`
	IsPublic    bool   `json:"is_public"`
	Versioning  bool   `json:"versioning"`
	CreatedAt   string `json:"created_at"`
	LastSynced  string `json:"last_synced,omitempty"`
}

// StorageObjectView represents an object or folder for the UI.
type StorageObjectView struct {
	Key          string `json:"key"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	SizeHuman    string `json:"size_human"`
	LastModified string `json:"last_modified,omitempty"`
	ETag         string `json:"etag,omitempty"`
	ContentType  string `json:"content_type,omitempty"`
	StorageClass string `json:"storage_class,omitempty"`
	IsDir        bool   `json:"is_dir"`
}

// StorageAuditView represents an audit entry for the UI.
type StorageAuditView struct {
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	UserID       string `json:"user_id"`
	CreatedAt    string `json:"created_at"`
}
