// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package volume provides Docker volume management services.
package volume

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	hostservice "github.com/fr4nsys/usulnet/internal/services/host"
)

// Service provides Docker volume management operations.
type Service struct {
	hostService *hostservice.Service
	logger      *logger.Logger
}

// NewService creates a new volume service.
func NewService(hostService *hostservice.Service, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		hostService: hostService,
		logger:      log,
	}
}

// List returns all volumes on a host.
func (s *Service) List(ctx context.Context, hostID uuid.UUID) ([]*models.Volume, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	volumes, err := client.VolumeList(ctx, docker.VolumeListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list volumes: %w", err)
	}

	result := make([]*models.Volume, 0, len(volumes))
	for _, v := range volumes {
		// Inspect each volume to get UsageData (VolumeList doesn't return it)
		detailed, inspectErr := client.VolumeGet(ctx, v.Name)
		if inspectErr == nil {
			result = append(result, s.dockerToModel(detailed, hostID))
		} else {
			result = append(result, s.dockerToModel(&v, hostID))
		}
	}
	return result, nil
}

// ListByDriver returns volumes using a specific driver.
func (s *Service) ListByDriver(ctx context.Context, hostID uuid.UUID, driver string) ([]*models.Volume, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	volumes, err := client.VolumeList(ctx, docker.VolumeListOptions{
		Filters: map[string][]string{"driver": {driver}},
	})
	if err != nil {
		return nil, fmt.Errorf("list volumes by driver: %w", err)
	}

	result := make([]*models.Volume, 0, len(volumes))
	for _, v := range volumes {
		result = append(result, s.dockerToModel(&v, hostID))
	}
	return result, nil
}

// ListByLabel returns volumes with specific labels.
func (s *Service) ListByLabel(ctx context.Context, hostID uuid.UUID, labels map[string]string) ([]*models.Volume, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	labelFilters := make([]string, 0, len(labels))
	for k, v := range labels {
		labelFilters = append(labelFilters, fmt.Sprintf("%s=%s", k, v))
	}

	volumes, err := client.VolumeList(ctx, docker.VolumeListOptions{
		Filters: map[string][]string{"label": labelFilters},
	})
	if err != nil {
		return nil, fmt.Errorf("list volumes by label: %w", err)
	}

	result := make([]*models.Volume, 0, len(volumes))
	for _, v := range volumes {
		result = append(result, s.dockerToModel(&v, hostID))
	}
	return result, nil
}

// Get returns a specific volume by name.
func (s *Service) Get(ctx context.Context, hostID uuid.UUID, name string) (*models.Volume, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	vol, err := client.VolumeGet(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("get volume: %w", err)
	}

	return s.dockerToModel(vol, hostID), nil
}

// Create creates a new volume.
func (s *Service) Create(ctx context.Context, hostID uuid.UUID, input *models.CreateVolumeInput) (*models.Volume, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	opts := docker.VolumeCreateOptions{
		Name:       input.Name,
		Driver:     input.Driver,
		DriverOpts: input.DriverOpts,
		Labels:     input.Labels,
	}

	vol, err := client.VolumeCreate(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("create volume: %w", err)
	}

	s.logger.Info("volume created", "name", vol.Name, "driver", vol.Driver)
	return s.dockerToModel(vol, hostID), nil
}

// Delete removes a volume.
func (s *Service) Delete(ctx context.Context, hostID uuid.UUID, name string, force bool) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	if err := client.VolumeRemove(ctx, name, force); err != nil {
		return fmt.Errorf("remove volume: %w", err)
	}

	s.logger.Info("volume removed", "name", name, "force", force)
	return nil
}

// Prune removes unused volumes.
func (s *Service) Prune(ctx context.Context, hostID uuid.UUID) (*models.PruneResult, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	spaceReclaimed, volumeNames, err := client.VolumePrune(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("prune volumes: %w", err)
	}

	s.logger.Info("volumes pruned", "count", len(volumeNames), "space_reclaimed", spaceReclaimed)
	return &models.PruneResult{
		ItemsDeleted:   volumeNames,
		SpaceReclaimed: int64(spaceReclaimed),
	}, nil
}

// GetStats retrieves volume statistics for a host.
func (s *Service) GetStats(ctx context.Context, hostID uuid.UUID) (*models.VolumeStats, error) {
	volumes, err := s.List(ctx, hostID)
	if err != nil {
		return nil, err
	}

	stats := &models.VolumeStats{
		Total: len(volumes),
	}

	for _, v := range volumes {
		if v.UsageData != nil && v.UsageData.RefCount > 0 {
			stats.InUse++
			stats.UsedSize += v.UsageData.Size
		} else {
			stats.Unused++
			if v.UsageData != nil {
				stats.UnusedSize += v.UsageData.Size
			}
		}
		if v.UsageData != nil {
			stats.TotalSize += v.UsageData.Size
		}
	}

	return stats, nil
}

// VolumeInfo returns information needed for backup.
func (s *Service) VolumeInfo(ctx context.Context, hostID uuid.UUID, name string) (*models.VolumeBackupInfo, error) {
	vol, err := s.Get(ctx, hostID, name)
	if err != nil {
		return nil, err
	}

	var size int64
	if vol.UsageData != nil {
		size = vol.UsageData.Size
	}

	return &models.VolumeBackupInfo{
		Name:       vol.Name,
		Driver:     vol.Driver,
		Mountpoint: vol.Mountpoint,
		Size:       size,
		Labels:     vol.Labels,
	}, nil
}

// Exists checks if a volume exists.
func (s *Service) Exists(ctx context.Context, hostID uuid.UUID, name string) (bool, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return false, err
	}
	return client.VolumeExists(ctx, name)
}

// UsedBy returns containers using a volume.
func (s *Service) UsedBy(ctx context.Context, hostID uuid.UUID, name string) ([]string, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return client.VolumeUsedBy(ctx, name)
}

// OrphanVolume represents a volume not used by any container.
type OrphanVolume struct {
	*models.Volume
	CreatedDaysAgo int    `json:"created_days_ago"`
	Reason         string `json:"reason"`
}

// OrphanVolumeResult contains orphan detection results.
type OrphanVolumeResult struct {
	Orphans           []*OrphanVolume `json:"orphans"`
	TotalVolumes      int             `json:"total_volumes"`
	OrphanCount       int             `json:"orphan_count"`
	TotalOrphanSize   int64           `json:"total_orphan_size"`
	OrphanSizeHuman   string          `json:"orphan_size_human"`
	ScanTime          time.Time       `json:"scan_time"`
	ScanDurationMs    int64           `json:"scan_duration_ms"`
}

// DetectOrphanVolumes finds volumes that are not currently used by any container.
// Options allow filtering by age (minAgeDays) and whether to include anonymous volumes.
func (s *Service) DetectOrphanVolumes(ctx context.Context, hostID uuid.UUID, minAgeDays int, includeAnonymous bool) (*OrphanVolumeResult, error) {
	start := time.Now()

	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Get all volumes
	volumes, err := client.VolumeList(ctx, docker.VolumeListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list volumes: %w", err)
	}

	// Get all containers to check mount usage
	containers, err := client.ContainerList(ctx, docker.ContainerListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	// Build map of volumes used by containers
	usedVolumes := make(map[string]bool)
	for _, c := range containers {
		for _, mount := range c.Mounts {
			if mount.Type == "volume" {
				usedVolumes[mount.Name] = true
			}
		}
	}

	now := time.Now()
	cutoff := now.AddDate(0, 0, -minAgeDays)
	var orphans []*OrphanVolume
	var totalOrphanSize int64

	for _, v := range volumes {
		// Skip if volume is in use
		if usedVolumes[v.Name] {
			continue
		}

		// Skip anonymous volumes (64-char hex names) unless requested
		if !includeAnonymous && isAnonymousVolume(v.Name) {
			continue
		}

		// Skip if too recent
		if minAgeDays > 0 && v.CreatedAt.After(cutoff) {
			continue
		}

		var size int64
		if v.UsageData != nil {
			size = v.UsageData.Size
		}
		totalOrphanSize += size

		reason := "Not mounted by any container"
		if v.UsageData != nil && v.UsageData.RefCount == 0 {
			reason = "Zero reference count"
		}

		daysAgo := int(now.Sub(v.CreatedAt).Hours() / 24)

		orphans = append(orphans, &OrphanVolume{
			Volume:         s.dockerToModel(&v, hostID),
			CreatedDaysAgo: daysAgo,
			Reason:         reason,
		})
	}

	return &OrphanVolumeResult{
		Orphans:         orphans,
		TotalVolumes:    len(volumes),
		OrphanCount:     len(orphans),
		TotalOrphanSize: totalOrphanSize,
		OrphanSizeHuman: humanSize(totalOrphanSize),
		ScanTime:        now,
		ScanDurationMs:  time.Since(start).Milliseconds(),
	}, nil
}

// isAnonymousVolume checks if a volume name looks like an anonymous volume (64 hex chars)
func isAnonymousVolume(name string) bool {
	if len(name) != 64 {
		return false
	}
	for _, c := range name {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// CleanupOrphanVolumes removes orphan volumes and returns cleanup result.
func (s *Service) CleanupOrphanVolumes(ctx context.Context, hostID uuid.UUID, volumeNames []string, dryRun bool) (*models.PruneResult, error) {
	if dryRun {
		// Just return what would be deleted
		var totalSize int64
		for _, name := range volumeNames {
			vol, err := s.Get(ctx, hostID, name)
			if err != nil {
				continue
			}
			if vol.UsageData != nil {
				totalSize += vol.UsageData.Size
			}
		}
		return &models.PruneResult{
			ItemsDeleted:   volumeNames,
			SpaceReclaimed: totalSize,
		}, nil
	}

	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	var deleted []string
	var totalSize int64
	var errs []string

	for _, name := range volumeNames {
		// Get size before deleting
		vol, _ := s.Get(ctx, hostID, name)

		if err := client.VolumeRemove(ctx, name, false); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			continue
		}

		deleted = append(deleted, name)
		if vol != nil && vol.UsageData != nil {
			totalSize += vol.UsageData.Size
		}
	}

	result := &models.PruneResult{
		ItemsDeleted:   deleted,
		SpaceReclaimed: totalSize,
	}

	if len(errs) > 0 {
		s.logger.Warn("some volumes failed to delete", "errors", errs)
	}

	s.logger.Info("orphan volumes cleaned up",
		"deleted_count", len(deleted),
		"space_reclaimed", totalSize,
	)

	return result, nil
}

// ============================================================================
// Volume File Browser
// ============================================================================

// VolumeFile represents a file or directory in a volume.
type VolumeFile struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	IsDir       bool      `json:"is_dir"`
	Size        int64     `json:"size"`
	SizeHuman   string    `json:"size_human"`
	Mode        string    `json:"mode"`
	ModTime     time.Time `json:"mod_time"`
	ModTimeAgo  string    `json:"mod_time_ago"`
	Owner       string    `json:"owner"`
	Group       string    `json:"group"`
	LinkTarget  string    `json:"link_target,omitempty"`
	IsSymlink   bool      `json:"is_symlink"`
}

// VolumeFileContent represents the content of a file in a volume.
type VolumeFileContent struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
	Binary    bool   `json:"binary"`
}

const (
	browserImage = "alpine:latest"
	maxFileSize  = 1024 * 1024 // 1MB max for file content
)

// BrowseVolume lists files in a volume at the given path.
func (s *Service) BrowseVolume(ctx context.Context, hostID uuid.UUID, volumeName, path string) ([]VolumeFile, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	// Sanitize path
	if path == "" {
		path = "/"
	}
	path = filepath.Clean("/" + path)

	// Run a temporary container to list files
	// Using busybox/alpine image with `ls -la` command
	containerID, err := s.createBrowserContainer(ctx, client, volumeName)
	if err != nil {
		return nil, fmt.Errorf("create browser container: %w", err)
	}
	defer s.cleanupContainer(ctx, client, containerID)

	// Execute ls command
	output, err := s.execInContainer(ctx, client, containerID, []string{
		"ls", "-la", "--time-style=+%Y-%m-%dT%H:%M:%S", "/data" + path,
	})
	if err != nil {
		// Check if it's a "not a directory" error - might be a file
		if strings.Contains(err.Error(), "Not a directory") || strings.Contains(err.Error(), "not a directory") {
			return nil, fmt.Errorf("path is a file, not a directory")
		}
		return nil, fmt.Errorf("list directory: %w", err)
	}

	return s.parseLS(output, path), nil
}

// ReadVolumeFile reads the content of a file in a volume.
func (s *Service) ReadVolumeFile(ctx context.Context, hostID uuid.UUID, volumeName, path string, maxSize int64) (*VolumeFileContent, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, err
	}

	if maxSize <= 0 || maxSize > maxFileSize {
		maxSize = maxFileSize
	}

	// Sanitize path
	path = filepath.Clean("/" + path)

	containerID, err := s.createBrowserContainer(ctx, client, volumeName)
	if err != nil {
		return nil, fmt.Errorf("create browser container: %w", err)
	}
	defer s.cleanupContainer(ctx, client, containerID)

	// Get file size first
	sizeOutput, err := s.execInContainer(ctx, client, containerID, []string{
		"stat", "-c", "%s", "/data" + path,
	})
	if err != nil {
		return nil, fmt.Errorf("get file size: %w", err)
	}

	size, _ := strconv.ParseInt(strings.TrimSpace(sizeOutput), 10, 64)

	// Check if file is binary
	fileOutput, err := s.execInContainer(ctx, client, containerID, []string{
		"file", "-b", "/data" + path,
	})
	if err != nil {
		fileOutput = ""
	}
	isBinary := strings.Contains(strings.ToLower(fileOutput), "binary") ||
		strings.Contains(strings.ToLower(fileOutput), "executable") ||
		strings.Contains(strings.ToLower(fileOutput), "data")

	result := &VolumeFileContent{
		Path:   path,
		Size:   size,
		Binary: isBinary,
	}

	if isBinary {
		result.Content = "[Binary file - cannot display]"
		return result, nil
	}

	// Read file content (with size limit)
	var cmd []string
	if size > maxSize {
		result.Truncated = true
		cmd = []string{"head", "-c", strconv.FormatInt(maxSize, 10), "/data" + path}
	} else {
		cmd = []string{"cat", "/data" + path}
	}

	content, err := s.execInContainer(ctx, client, containerID, cmd)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	result.Content = content
	return result, nil
}

// WriteVolumeFile writes content to a file in a volume.
func (s *Service) WriteVolumeFile(ctx context.Context, hostID uuid.UUID, volumeName, path, content string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	path = filepath.Clean("/" + path)

	containerID, err := s.createBrowserContainer(ctx, client, volumeName)
	if err != nil {
		return fmt.Errorf("create browser container: %w", err)
	}
	defer s.cleanupContainer(ctx, client, containerID)

	// Write content using sh -c with heredoc pattern
	// Escape special characters
	escapedContent := strings.ReplaceAll(content, "'", "'\"'\"'")

	_, err = s.execInContainer(ctx, client, containerID, []string{
		"sh", "-c", fmt.Sprintf("cat > '/data%s' << 'USULNET_EOF'\n%s\nUSULNET_EOF", path, escapedContent),
	})
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	s.logger.Info("volume file written", "volume", volumeName, "path", path, "size", len(content))
	return nil
}

// DeleteVolumeFile deletes a file or directory in a volume.
func (s *Service) DeleteVolumeFile(ctx context.Context, hostID uuid.UUID, volumeName, path string, recursive bool) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	path = filepath.Clean("/" + path)

	// Prevent deleting root
	if path == "/" || path == "" {
		return fmt.Errorf("cannot delete volume root")
	}

	containerID, err := s.createBrowserContainer(ctx, client, volumeName)
	if err != nil {
		return fmt.Errorf("create browser container: %w", err)
	}
	defer s.cleanupContainer(ctx, client, containerID)

	var cmd []string
	if recursive {
		cmd = []string{"rm", "-rf", "/data" + path}
	} else {
		cmd = []string{"rm", "/data" + path}
	}

	_, err = s.execInContainer(ctx, client, containerID, cmd)
	if err != nil {
		return fmt.Errorf("delete file: %w", err)
	}

	s.logger.Info("volume file deleted", "volume", volumeName, "path", path, "recursive", recursive)
	return nil
}

// CreateVolumeDirectory creates a directory in a volume.
func (s *Service) CreateVolumeDirectory(ctx context.Context, hostID uuid.UUID, volumeName, path string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return err
	}

	path = filepath.Clean("/" + path)

	containerID, err := s.createBrowserContainer(ctx, client, volumeName)
	if err != nil {
		return fmt.Errorf("create browser container: %w", err)
	}
	defer s.cleanupContainer(ctx, client, containerID)

	_, err = s.execInContainer(ctx, client, containerID, []string{
		"mkdir", "-p", "/data" + path,
	})
	if err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	s.logger.Info("volume directory created", "volume", volumeName, "path", path)
	return nil
}

// DownloadVolumeFile returns the content of a file for download.
func (s *Service) DownloadVolumeFile(ctx context.Context, hostID uuid.UUID, volumeName, path string) (io.ReadCloser, int64, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, 0, err
	}

	path = filepath.Clean("/" + path)

	containerID, err := s.createBrowserContainer(ctx, client, volumeName)
	if err != nil {
		return nil, 0, fmt.Errorf("create browser container: %w", err)
	}

	// Get file size
	sizeOutput, err := s.execInContainer(ctx, client, containerID, []string{
		"stat", "-c", "%s", "/data" + path,
	})
	if err != nil {
		s.cleanupContainer(ctx, client, containerID)
		return nil, 0, fmt.Errorf("get file size: %w", err)
	}
	size, _ := strconv.ParseInt(strings.TrimSpace(sizeOutput), 10, 64)

	// Copy file from container
	reader, _, err := client.ContainerCopyFromContainer(ctx, containerID, "/data"+path)
	if err != nil {
		s.cleanupContainer(ctx, client, containerID)
		return nil, 0, fmt.Errorf("copy from container: %w", err)
	}

	// Wrap reader to cleanup container when done
	return &cleanupReader{
		ReadCloser:  reader,
		cleanup:     func() { s.cleanupContainer(ctx, client, containerID) },
	}, size, nil
}

// Helper: create a temporary container for browsing
func (s *Service) createBrowserContainer(ctx context.Context, client docker.ClientAPI, volumeName string) (string, error) {
	// Create container with volume mounted
	containerID, err := client.ContainerCreate(ctx, docker.ContainerCreateOptions{
		Name:  fmt.Sprintf("usulnet-volume-browser-%d", time.Now().UnixNano()),
		Image: browserImage,
		Cmd:   []string{"sleep", "300"}, // Keep alive for 5 minutes
		Binds: []string{volumeName + ":/data:rw"},
		Labels: map[string]string{
			"usulnet.temporary": "true",
			"usulnet.purpose":   "volume-browser",
		},
	})
	if err != nil {
		// If image doesn't exist, try to pull it
		if strings.Contains(err.Error(), "No such image") {
			if pullErr := client.ImagePullSync(ctx, browserImage, docker.ImagePullOptions{}); pullErr != nil {
				return "", fmt.Errorf("pull browser image: %w", pullErr)
			}
			// Retry create
			containerID, err = client.ContainerCreate(ctx, docker.ContainerCreateOptions{
				Name:  fmt.Sprintf("usulnet-volume-browser-%d", time.Now().UnixNano()),
				Image: browserImage,
				Cmd:   []string{"sleep", "300"},
				Binds: []string{volumeName + ":/data:rw"},
				Labels: map[string]string{
					"usulnet.temporary": "true",
					"usulnet.purpose":   "volume-browser",
				},
			})
			if err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}

	// Start container
	if err := client.ContainerStart(ctx, containerID); err != nil {
		client.ContainerRemove(ctx, containerID, true, false)
		return "", fmt.Errorf("start browser container: %w", err)
	}

	return containerID, nil
}

// Helper: cleanup temporary container
func (s *Service) cleanupContainer(ctx context.Context, client docker.ClientAPI, containerID string) {
	client.ContainerRemove(ctx, containerID, true, false)
}

// Helper: execute command in container
func (s *Service) execInContainer(ctx context.Context, client docker.ClientAPI, containerID string, cmd []string) (string, error) {
	execResp, err := client.ExecCreate(ctx, containerID, docker.ExecConfig{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return "", err
	}

	hijacked, err := client.ExecAttach(ctx, execResp.ID)
	if err != nil {
		return "", err
	}
	defer hijacked.Close()

	output, err := io.ReadAll(hijacked.Reader)
	if err != nil {
		return "", err
	}

	// Remove Docker stream header bytes if present
	result := cleanDockerOutput(string(output))

	// Check exit code
	inspect, err := client.ExecInspectByID(ctx, execResp.ID)
	if err == nil && inspect.ExitCode != 0 {
		return result, fmt.Errorf("command failed with exit code %d: %s", inspect.ExitCode, result)
	}

	return result, nil
}

// Helper: parse ls -la output
func (s *Service) parseLS(output, basePath string) []VolumeFile {
	var files []VolumeFile
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "total ") {
			continue
		}

		file := parseLSLine(line, basePath)
		if file != nil && file.Name != "." && file.Name != ".." {
			files = append(files, *file)
		}
	}

	return files
}

// parseLSLine parses a single line of ls -la output
func parseLSLine(line, basePath string) *VolumeFile {
	// Format: drwxr-xr-x    2 root     root          4096 2025-01-15T10:30:00 dirname
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return nil
	}

	mode := fields[0]
	owner := fields[2]
	group := fields[3]
	sizeStr := fields[4]
	timeStr := fields[5]

	// Name is everything after the date (handles spaces in names)
	nameStart := strings.Index(line, timeStr) + len(timeStr) + 1
	if nameStart >= len(line) {
		return nil
	}
	name := strings.TrimSpace(line[nameStart:])

	// Handle symlinks: name -> target
	var linkTarget string
	isSymlink := mode[0] == 'l'
	if isSymlink && strings.Contains(name, " -> ") {
		parts := strings.SplitN(name, " -> ", 2)
		name = parts[0]
		if len(parts) > 1 {
			linkTarget = parts[1]
		}
	}

	size, _ := strconv.ParseInt(sizeStr, 10, 64)
	modTime, _ := time.Parse("2006-01-02T15:04:05", timeStr)

	path := basePath
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	path += name

	return &VolumeFile{
		Name:        name,
		Path:        path,
		IsDir:       mode[0] == 'd',
		Size:        size,
		SizeHuman:   humanSize(size),
		Mode:        mode,
		ModTime:     modTime,
		ModTimeAgo:  timeAgo(modTime),
		Owner:       owner,
		Group:       group,
		LinkTarget:  linkTarget,
		IsSymlink:   isSymlink,
	}
}

// cleanDockerOutput removes Docker stream header bytes
func cleanDockerOutput(output string) string {
	// Docker multiplexed streams have 8-byte headers
	// Skip any non-printable characters at the start
	result := strings.Builder{}
	for i := 0; i < len(output); i++ {
		if output[i] >= 32 || output[i] == '\n' || output[i] == '\r' || output[i] == '\t' {
			result.WriteByte(output[i])
		}
	}
	return strings.TrimSpace(result.String())
}

// humanSize converts bytes to human-readable format
func humanSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// timeAgo returns a human-readable time difference
func timeAgo(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	default:
		return t.Format("Jan 2, 2006")
	}
}

// cleanupReader wraps a reader with cleanup function
type cleanupReader struct {
	io.ReadCloser
	cleanup func()
	closed  bool
}

func (r *cleanupReader) Close() error {
	if !r.closed {
		r.closed = true
		err := r.ReadCloser.Close()
		if r.cleanup != nil {
			r.cleanup()
		}
		return err
	}
	return nil
}

// dockerToModel converts a Docker volume to our model.
func (s *Service) dockerToModel(v *docker.Volume, hostID uuid.UUID) *models.Volume {
	vol := &models.Volume{
		Name:       v.Name,
		HostID:     hostID,
		Driver:     v.Driver,
		Mountpoint: v.Mountpoint,
		Labels:     v.Labels,
		Scope:      models.VolumeScope(v.Scope),
		Options:    v.Options,
		CreatedAt:  v.CreatedAt,
	}
	if v.UsageData != nil {
		vol.UsageData = &models.VolumeUsageData{
			Size:     v.UsageData.Size,
			RefCount: v.UsageData.RefCount,
		}
	}
	return vol
}
