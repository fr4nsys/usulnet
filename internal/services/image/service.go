// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package image provides Docker image management services.
package image

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/docker/docker/api/types/registry"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	hostservice "github.com/fr4nsys/usulnet/internal/services/host"
)

// Service provides Docker image management operations.
type Service struct {
	hostService *hostservice.Service
	logger      *logger.Logger
}

// NewService creates a new image service.
func NewService(hostService *hostservice.Service, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		hostService: hostService,
		logger:      log,
	}
}

// List returns all images on a host.
func (s *Service) List(ctx context.Context, hostID uuid.UUID) ([]*models.Image, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	images, err := client.ImageList(ctx, docker.ImageListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list images: %w", err)
	}

	result := make([]*models.Image, 0, len(images))
	for _, img := range images {
		result = append(result, s.dockerToModel(img, hostID))
	}
	return result, nil
}

// ListDangling returns dangling images on a host.
func (s *Service) ListDangling(ctx context.Context, hostID uuid.UUID) ([]*models.Image, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	images, err := client.ImageList(ctx, docker.ImageListOptions{
		Filters: map[string][]string{"dangling": {"true"}},
	})
	if err != nil {
		return nil, fmt.Errorf("list dangling images: %w", err)
	}

	result := make([]*models.Image, 0, len(images))
	for _, img := range images {
		result = append(result, s.dockerToModel(img, hostID))
	}
	return result, nil
}

// ListByReference returns images matching a reference pattern.
func (s *Service) ListByReference(ctx context.Context, hostID uuid.UUID, reference string) ([]*models.Image, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	images, err := client.ImageList(ctx, docker.ImageListOptions{
		Filters: map[string][]string{"reference": {reference}},
	})
	if err != nil {
		return nil, fmt.Errorf("list images by reference: %w", err)
	}

	result := make([]*models.Image, 0, len(images))
	for _, img := range images {
		result = append(result, s.dockerToModel(img, hostID))
	}
	return result, nil
}

// Get returns a specific image by ID.
func (s *Service) Get(ctx context.Context, hostID uuid.UUID, imageID string) (*models.Image, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	details, err := client.ImageGet(ctx, imageID)
	if err != nil {
		return nil, fmt.Errorf("get image: %w", err)
	}

	return s.detailsToModel(details, hostID), nil
}

// GetHistory retrieves image layer history.
func (s *Service) GetHistory(ctx context.Context, hostID uuid.UUID, imageID string) ([]*models.ImageLayer, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	history, err := client.ImageHistory(ctx, imageID)
	if err != nil {
		return nil, fmt.Errorf("get image history: %w", err)
	}

	layers := make([]*models.ImageLayer, 0, len(history))
	for _, h := range history {
		layers = append(layers, &models.ImageLayer{
			ID:        h.ID,
			Created:   time.Unix(h.Created, 0),
			CreatedBy: h.CreatedBy,
			Size:      h.Size,
			Comment:   h.Comment,
			Tags:      h.Tags,
		})
	}
	return layers, nil
}

// Pull pulls an image from a registry.
func (s *Service) Pull(ctx context.Context, hostID uuid.UUID, reference string, auth *models.RegistryAuthConfig) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	opts := docker.ImagePullOptions{}
	if auth != nil {
		opts.RegistryAuth = encodeAuth(auth)
	}

	if err := client.ImagePullSync(ctx, reference, opts); err != nil {
		return fmt.Errorf("pull image: %w", err)
	}

	s.logger.Info("image pulled", "reference", reference)
	return nil
}

// PullWithProgress pulls an image and returns a progress channel.
func (s *Service) PullWithProgress(ctx context.Context, hostID uuid.UUID, reference string, auth *models.RegistryAuthConfig) (<-chan docker.PullProgress, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	opts := docker.ImagePullOptions{}
	if auth != nil {
		opts.RegistryAuth = encodeAuth(auth)
	}

	progress, err := client.ImagePull(ctx, reference, opts)
	if err != nil {
		return nil, fmt.Errorf("pull image: %w", err)
	}

	return progress, nil
}

// Push pushes an image to a registry.
func (s *Service) Push(ctx context.Context, hostID uuid.UUID, reference string, auth *models.RegistryAuthConfig) (<-chan docker.PullProgress, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	var registryAuth string
	if auth != nil {
		registryAuth = encodeAuth(auth)
	}

	progress, err := client.ImagePush(ctx, reference, registryAuth)
	if err != nil {
		return nil, fmt.Errorf("push image: %w", err)
	}

	s.logger.Info("image push started", "reference", reference)
	return progress, nil
}

// Tag tags an image.
func (s *Service) Tag(ctx context.Context, hostID uuid.UUID, source, target string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.ImageTag(ctx, source, target); err != nil {
		return fmt.Errorf("tag image: %w", err)
	}

	s.logger.Info("image tagged", "source", source, "target", target)
	return nil
}

// Remove removes an image.
func (s *Service) Remove(ctx context.Context, hostID uuid.UUID, imageID string, force bool) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	_, err = client.ImageRemove(ctx, imageID, force, true)
	if err != nil {
		return fmt.Errorf("remove image: %w", err)
	}

	s.logger.Info("image removed", "image", imageID, "force", force)
	return nil
}

// Prune removes unused images.
func (s *Service) Prune(ctx context.Context, hostID uuid.UUID, dangling bool) (*models.PruneResult, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	spaceReclaimed, deleted, err := client.ImagePrune(ctx, dangling, nil)
	if err != nil {
		return nil, fmt.Errorf("prune images: %w", err)
	}

	items := make([]string, 0, len(deleted))
	for _, d := range deleted {
		if d.Deleted != "" {
			items = append(items, d.Deleted)
		} else if d.Untagged != "" {
			items = append(items, d.Untagged)
		}
	}

	s.logger.Info("images pruned", "count", len(items), "space_reclaimed", spaceReclaimed)
	return &models.PruneResult{
		ItemsDeleted:   items,
		SpaceReclaimed: int64(spaceReclaimed),
	}, nil
}

// Search searches for images in registries.
func (s *Service) Search(ctx context.Context, hostID uuid.UUID, term string, limit int, auth *models.RegistryAuthConfig) ([]registry.SearchResult, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	var registryAuth string
	if auth != nil {
		registryAuth = encodeAuth(auth)
	}

	results, err := client.ImageSearch(ctx, term, limit, registryAuth)
	if err != nil {
		return nil, fmt.Errorf("search images: %w", err)
	}

	return results, nil
}

// Exists checks if an image exists.
func (s *Service) Exists(ctx context.Context, hostID uuid.UUID, reference string) (bool, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return false, err
	}
	return client.ImageExists(ctx, reference)
}

// GetDigest returns the digest of an image.
func (s *Service) GetDigest(ctx context.Context, hostID uuid.UUID, reference string) (string, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return "", err
	}
	return client.ImageDigest(ctx, reference)
}

// GetSize returns the size of an image.
func (s *Service) GetSize(ctx context.Context, hostID uuid.UUID, reference string) (int64, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return 0, err
	}
	return client.ImageSize(ctx, reference)
}

// CheckUpdate checks if a newer version of an image is available.
func (s *Service) CheckUpdate(ctx context.Context, hostID uuid.UUID, reference string) (*models.ImageUpdateInfo, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Get local image info
	localDetails, err := client.ImageGet(ctx, reference)
	if err != nil {
		return nil, fmt.Errorf("get local image: %w", err)
	}

	// Get local digest
	var currentDigest string
	if len(localDetails.RepoDigests) > 0 {
		parts := strings.SplitN(localDetails.RepoDigests[0], "@", 2)
		if len(parts) == 2 {
			currentDigest = parts[1]
		}
	}

	// Get current tag
	var currentTag string
	if len(localDetails.RepoTags) > 0 {
		parts := strings.SplitN(localDetails.RepoTags[0], ":", 2)
		if len(parts) == 2 {
			currentTag = parts[1]
		}
	}

	info := &models.ImageUpdateInfo{
		CurrentDigest:   currentDigest,
		CurrentTag:      currentTag,
		UpdateAvailable: false,
		CheckedAt:       time.Now(),
	}

	// Pull manifest to check for updates (without actually pulling)
	// This is a simplified check - in production you'd query the registry API
	remoteDigest, err := client.ImageDigest(ctx, reference)
	if err == nil && remoteDigest != "" && remoteDigest != currentDigest {
		info.LatestDigest = remoteDigest
		info.UpdateAvailable = true
	}

	return info, nil
}

// dockerToModel converts a Docker image to our model.
func (s *Service) dockerToModel(img docker.Image, hostID uuid.UUID) *models.Image {
	return &models.Image{
		ID:          img.ID,
		HostID:      hostID,
		RepoTags:    img.RepoTags,
		RepoDigests: img.RepoDigests,
		CreatedAt:   img.Created,
		Size:        img.Size,
		VirtualSize: img.VirtualSize,
		Labels:      img.Labels,
		Containers:  img.Containers,
	}
}

// detailsToModel converts ImageDetails to our model.
func (s *Service) detailsToModel(d *docker.ImageDetails, hostID uuid.UUID) *models.Image {
	return &models.Image{
		ID:           d.ID,
		HostID:       hostID,
		RepoTags:     d.RepoTags,
		RepoDigests:  d.RepoDigests,
		CreatedAt:    d.Created,
		Size:         d.Size,
		VirtualSize:  d.VirtualSize,
		Labels:       d.Labels,
	}
}

// encodeAuth encodes registry authentication.
func encodeAuth(auth *models.RegistryAuthConfig) string {
	if auth == nil {
		return ""
	}
	authConfig := struct {
		Username      string `json:"username,omitempty"`
		Password      string `json:"password,omitempty"`
		ServerAddress string `json:"serveraddress,omitempty"`
	}{
		Username:      auth.Username,
		Password:      auth.Password,
		ServerAddress: auth.ServerAddress,
	}
	encoded, _ := json.Marshal(authConfig)
	return base64.URLEncoding.EncodeToString(encoded)
}

// ValidateReference validates an image reference.
func ValidateReference(reference string) error {
	if reference == "" {
		return apperrors.New(apperrors.CodeValidation, "image reference is required")
	}
	return nil
}

// ============================================================================
// Image Build
// ============================================================================

// BuildOptions contains options for building an image.
type BuildOptions struct {
	Tags           []string          `json:"tags"`            // Image tags (e.g., ["myimage:latest"])
	Dockerfile     string            `json:"dockerfile"`      // Path to Dockerfile (default: "Dockerfile")
	BuildArgs      map[string]*string `json:"build_args"`     // Build arguments
	Target         string            `json:"target"`          // Target build stage
	NoCache        bool              `json:"no_cache"`        // Don't use cache
	Pull           bool              `json:"pull"`            // Always pull base images
	Remove         bool              `json:"remove"`          // Remove intermediate containers
	ForceRemove    bool              `json:"force_remove"`    // Always remove intermediate containers
	Labels         map[string]string `json:"labels"`          // Labels to apply to the image
	Platform       string            `json:"platform"`        // Target platform (e.g., "linux/amd64")
	SquashLayers   bool              `json:"squash"`          // Squash layers into one
}

// BuildProgress represents a build progress message.
type BuildProgress struct {
	Stream   string `json:"stream,omitempty"`
	Status   string `json:"status,omitempty"`
	Progress string `json:"progress,omitempty"`
	Error    string `json:"error,omitempty"`
	ID       string `json:"id,omitempty"`
}

// BuildResult contains the result of an image build.
type BuildResult struct {
	ImageID string   `json:"image_id"`
	Tags    []string `json:"tags"`
}

// BuildCallback is called for each build progress event.
type BuildCallback func(progress BuildProgress)

// Build builds a Docker image from a build context.
// The buildContext should be a tar archive containing the Dockerfile and any files needed for the build.
// The callback is called for each progress message from the build.
func (s *Service) Build(ctx context.Context, hostID uuid.UUID, buildContext io.Reader, opts BuildOptions, callback BuildCallback) (*BuildResult, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Set defaults
	if opts.Dockerfile == "" {
		opts.Dockerfile = "Dockerfile"
	}

	// Prepare build options
	buildOpts := docker.ImageBuildOptions{
		Tags:           opts.Tags,
		Dockerfile:     opts.Dockerfile,
		BuildArgs:      opts.BuildArgs,
		Target:         opts.Target,
		NoCache:        opts.NoCache,
		PullParent:     opts.Pull,
		Remove:         true,
		ForceRemove:    opts.ForceRemove,
		Labels:         opts.Labels,
		Platform:       opts.Platform,
		SuppressOutput: false,
	}

	// Build the image
	resp, err := client.ImageBuild(ctx, buildContext, buildOpts)
	if err != nil {
		return nil, fmt.Errorf("build image: %w", err)
	}
	defer resp.Body.Close()

	// Parse build output and call callback
	decoder := json.NewDecoder(resp.Body)
	var imageID string

	for {
		var progress BuildProgress
		if err := decoder.Decode(&progress); err != nil {
			if err == io.EOF {
				break
			}
			// Skip decode errors, continue reading
			continue
		}

		// Extract image ID from stream
		if progress.Stream != "" {
			if strings.HasPrefix(progress.Stream, "Successfully built ") {
				imageID = strings.TrimSpace(strings.TrimPrefix(progress.Stream, "Successfully built "))
			}
			// Also check for newer format
			if strings.Contains(progress.Stream, "writing image sha256:") {
				parts := strings.Split(progress.Stream, "sha256:")
				if len(parts) > 1 {
					imageID = "sha256:" + strings.Split(parts[1], " ")[0]
				}
			}
		}

		if progress.Error != "" {
			if callback != nil {
				callback(progress)
			}
			return nil, fmt.Errorf("build failed: %s", progress.Error)
		}

		if callback != nil {
			callback(progress)
		}
	}

	s.logger.Info("image built",
		"host_id", hostID,
		"image_id", imageID,
		"tags", opts.Tags,
	)

	return &BuildResult{
		ImageID: imageID,
		Tags:    opts.Tags,
	}, nil
}

// BuildFromDockerfile builds an image from a Dockerfile string.
// This is a convenience method that creates a tar context with just the Dockerfile.
func (s *Service) BuildFromDockerfile(ctx context.Context, hostID uuid.UUID, dockerfile string, opts BuildOptions, callback BuildCallback) (*BuildResult, error) {
	// Create a tar archive with just the Dockerfile
	tarContext, err := createTarWithDockerfile(dockerfile)
	if err != nil {
		return nil, fmt.Errorf("create build context: %w", err)
	}

	return s.Build(ctx, hostID, bytes.NewReader(tarContext), opts, callback)
}

// createTarWithDockerfile creates a tar archive containing just a Dockerfile.
func createTarWithDockerfile(dockerfile string) ([]byte, error) {
	var buf bytes.Buffer

	// Create tar header
	header := []byte{
		// tar header for "Dockerfile" (simplified - 512 byte header)
	}

	// For simplicity, we'll use a basic approach
	// In production, use archive/tar package properly
	_ = header

	// Use archive/tar
	tw := newTarWriter(&buf)
	if err := tw.writeFile("Dockerfile", []byte(dockerfile)); err != nil {
		return nil, err
	}
	if err := tw.close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// tarWriter is a simple tar writer helper.
type tarWriter struct {
	w *bytes.Buffer
}

func newTarWriter(buf *bytes.Buffer) *tarWriter {
	return &tarWriter{w: buf}
}

func (tw *tarWriter) writeFile(name string, content []byte) error {
	// Write tar header (512 bytes)
	header := make([]byte, 512)

	// File name (100 bytes)
	copy(header[0:100], []byte(name))

	// File mode (8 bytes) - 0644
	copy(header[100:108], []byte("0000644\x00"))

	// Owner UID (8 bytes)
	copy(header[108:116], []byte("0000000\x00"))

	// Owner GID (8 bytes)
	copy(header[116:124], []byte("0000000\x00"))

	// File size in octal (12 bytes)
	sizeStr := fmt.Sprintf("%011o\x00", len(content))
	copy(header[124:136], []byte(sizeStr))

	// Modification time (12 bytes)
	copy(header[136:148], []byte("00000000000\x00"))

	// Checksum placeholder (8 bytes of spaces)
	copy(header[148:156], []byte("        "))

	// Type flag (1 byte) - '0' for regular file
	header[156] = '0'

	// Calculate checksum
	var sum int
	for _, b := range header {
		sum += int(b)
	}
	checksumStr := fmt.Sprintf("%06o\x00 ", sum)
	copy(header[148:156], []byte(checksumStr))

	// Write header
	tw.w.Write(header)

	// Write content
	tw.w.Write(content)

	// Pad to 512 byte boundary
	padding := 512 - (len(content) % 512)
	if padding < 512 {
		tw.w.Write(make([]byte, padding))
	}

	return nil
}

func (tw *tarWriter) close() error {
	// Write two empty 512-byte blocks to end the tar archive
	tw.w.Write(make([]byte, 1024))
	return nil
}
