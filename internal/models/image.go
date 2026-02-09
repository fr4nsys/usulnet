// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// Image represents a Docker image (cached state)
type Image struct {
	ID          string            `json:"id" db:"id"`
	HostID      uuid.UUID         `json:"host_id" db:"host_id"`
	RepoTags    []string          `json:"repo_tags" db:"repo_tags"`
	RepoDigests []string          `json:"repo_digests,omitempty" db:"repo_digests"`
	ParentID    string            `json:"parent_id,omitempty" db:"parent_id"`
	Size        int64             `json:"size" db:"size"`
	VirtualSize int64             `json:"virtual_size" db:"virtual_size"`
	SharedSize  int64             `json:"shared_size" db:"shared_size"`
	Labels      map[string]string `json:"labels,omitempty" db:"labels"`
	Containers  int64             `json:"containers" db:"containers"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	SyncedAt    time.Time         `json:"synced_at" db:"synced_at"`
}

// GetPrimaryTag returns the first tag or ID if no tags
func (i *Image) GetPrimaryTag() string {
	if len(i.RepoTags) > 0 && i.RepoTags[0] != "<none>:<none>" {
		return i.RepoTags[0]
	}
	if len(i.ID) > 12 {
		return i.ID[:12]
	}
	return i.ID
}

// IsUntagged returns true if image has no tags
func (i *Image) IsUntagged() bool {
	return len(i.RepoTags) == 0 || (len(i.RepoTags) == 1 && i.RepoTags[0] == "<none>:<none>")
}

// IsDangling returns true if image is dangling (untagged and unused)
func (i *Image) IsDangling() bool {
	return i.IsUntagged() && i.Containers == 0
}

// ImageInspect represents detailed image information
type ImageInspect struct {
	Image
	Architecture    string          `json:"architecture"`
	Author          string          `json:"author,omitempty"`
	Comment         string          `json:"comment,omitempty"`
	Config          *ImageConfig    `json:"config,omitempty"`
	Container       string          `json:"container,omitempty"`
	DockerVersion   string          `json:"docker_version,omitempty"`
	OS              string          `json:"os"`
	OSVersion       string          `json:"os_version,omitempty"`
	Variant         string          `json:"variant,omitempty"`
	RootFS          RootFS          `json:"rootfs"`
	GraphDriver     GraphDriverData `json:"graph_driver"`
	Metadata        ImageMetadata   `json:"metadata,omitempty"`
}

// ImageConfig represents image configuration
type ImageConfig struct {
	Hostname     string              `json:"hostname"`
	Domainname   string              `json:"domainname"`
	User         string              `json:"user"`
	AttachStdin  bool                `json:"attach_stdin"`
	AttachStdout bool                `json:"attach_stdout"`
	AttachStderr bool                `json:"attach_stderr"`
	ExposedPorts map[string]struct{} `json:"exposed_ports,omitempty"`
	Tty          bool                `json:"tty"`
	OpenStdin    bool                `json:"open_stdin"`
	StdinOnce    bool                `json:"stdin_once"`
	Env          []string            `json:"env,omitempty"`
	Cmd          []string            `json:"cmd,omitempty"`
	Healthcheck  *HealthConfig       `json:"healthcheck,omitempty"`
	ArgsEscaped  bool                `json:"args_escaped"`
	Image        string              `json:"image"`
	Volumes      map[string]struct{} `json:"volumes,omitempty"`
	WorkingDir   string              `json:"working_dir"`
	Entrypoint   []string            `json:"entrypoint,omitempty"`
	OnBuild      []string            `json:"on_build,omitempty"`
	Labels       map[string]string   `json:"labels,omitempty"`
	StopSignal   string              `json:"stop_signal,omitempty"`
	StopTimeout  *int                `json:"stop_timeout,omitempty"`
	Shell        []string            `json:"shell,omitempty"`
}

// RootFS represents image root filesystem
type RootFS struct {
	Type   string   `json:"type"`
	Layers []string `json:"layers,omitempty"`
}

// ImageMetadata represents image metadata
type ImageMetadata struct {
	LastTagTime time.Time `json:"last_tag_time,omitempty"`
}

// ImageHistory represents image history entry
type ImageHistory struct {
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"created_by"`
	Tags      []string  `json:"tags,omitempty"`
	Size      int64     `json:"size"`
	Comment   string    `json:"comment,omitempty"`
}

// ImagePullInput represents input for pulling an image
type ImagePullInput struct {
	Image        string `json:"image" validate:"required,docker_image"`
	Tag          string `json:"tag,omitempty"`
	Platform     string `json:"platform,omitempty"`
	RegistryAuth string `json:"registry_auth,omitempty"`
}

// ImageBuildInput represents input for building an image
type ImageBuildInput struct {
	Tags        []string          `json:"tags" validate:"required,dive,docker_image"`
	Dockerfile  string            `json:"dockerfile,omitempty"` // Path within context
	Context     string            `json:"context"`              // Path or URL
	BuildArgs   map[string]*string `json:"build_args,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Target      string            `json:"target,omitempty"`
	NoCache     bool              `json:"no_cache,omitempty"`
	Pull        bool              `json:"pull,omitempty"`
	Remove      bool              `json:"remove,omitempty"`
	ForceRemove bool              `json:"force_remove,omitempty"`
	Platform    string            `json:"platform,omitempty"`
	Squash      bool              `json:"squash,omitempty"`
}

// ImagePushInput represents input for pushing an image
type ImagePushInput struct {
	Image        string `json:"image" validate:"required,docker_image"`
	Tag          string `json:"tag,omitempty"`
	RegistryAuth string `json:"registry_auth,omitempty"`
}

// ImageTagInput represents input for tagging an image
type ImageTagInput struct {
	SourceImage string `json:"source_image" validate:"required"`
	TargetImage string `json:"target_image" validate:"required,docker_image"`
	TargetTag   string `json:"target_tag,omitempty"`
}

// ImageSearchResult represents an image search result
type ImageSearchResult struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Stars       int    `json:"stars"`
	Official    bool   `json:"official"`
	Automated   bool   `json:"automated"`
}

// ImagePruneReport represents image prune result
type ImagePruneReport struct {
	ImagesDeleted  []ImageDeleteResponse `json:"images_deleted,omitempty"`
	SpaceReclaimed int64                 `json:"space_reclaimed"`
}

// ImageDeleteResponse represents a deleted image
type ImageDeleteResponse struct {
	Deleted  string `json:"deleted,omitempty"`
	Untagged string `json:"untagged,omitempty"`
}

// ImageProgress represents image pull/push progress
type ImageProgress struct {
	ID             string `json:"id,omitempty"`
	Status         string `json:"status"`
	Progress       string `json:"progress,omitempty"`
	ProgressDetail struct {
		Current int64 `json:"current,omitempty"`
		Total   int64 `json:"total,omitempty"`
	} `json:"progress_detail,omitempty"`
	Error string `json:"error,omitempty"`
}

// Registry represents a container registry
type Registry struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	URL         string    `json:"url" db:"url"`
	Username    *string   `json:"username,omitempty" db:"username"`
	Password    *string   `json:"-" db:"password"` // Encrypted
	IsDefault   bool      `json:"is_default" db:"is_default"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// CreateRegistryInput represents input for creating a registry
type CreateRegistryInput struct {
	Name      string  `json:"name" validate:"required,min=1,max=100"`
	URL       string  `json:"url" validate:"required,url"`
	Username  *string `json:"username,omitempty"`
	Password  *string `json:"password,omitempty"`
	IsDefault bool    `json:"is_default,omitempty"`
}

// ImageListOptions represents options for listing images
type ImageListOptions struct {
	All      bool              `json:"all"`
	Filters  map[string][]string `json:"filters"`
	Digests  bool              `json:"digests"`
}

// ImageLayer represents a layer in the image history.
type ImageLayer struct {
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"created_by"`
	Size      int64     `json:"size"`
	Comment   string    `json:"comment,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
}

// ImageUpdateInfo holds information about available image updates.
type ImageUpdateInfo struct {
	CurrentDigest string    `json:"current_digest"`
	LatestDigest  string    `json:"latest_digest"`
	CurrentTag    string    `json:"current_tag"`
	LatestTag     string    `json:"latest_tag,omitempty"`
	UpdateAvailable bool    `json:"update_available"`
	CheckedAt     time.Time `json:"checked_at"`
}

// RegistryAuthConfig represents registry authentication configuration.
type RegistryAuthConfig struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	ServerAddress string `json:"server_address,omitempty"`
	IdentityToken string `json:"identity_token,omitempty"`
}
