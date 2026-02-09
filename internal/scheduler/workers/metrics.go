// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// MetricsService interface for metrics collection
type MetricsService interface {
	// CollectHostMetrics collects system metrics for a host
	CollectHostMetrics(ctx context.Context, hostID uuid.UUID) (*HostMetrics, error)

	// CollectContainerMetrics collects metrics for all containers on a host
	CollectContainerMetrics(ctx context.Context, hostID uuid.UUID) ([]*ContainerMetrics, error)

	// StoreMetrics stores collected metrics
	StoreMetrics(ctx context.Context, metrics *MetricsSnapshot) error
}

// HostMetrics holds host-level metrics
type HostMetrics struct {
	HostID          uuid.UUID `json:"host_id"`
	CPUUsagePercent float64   `json:"cpu_usage_percent"`
	MemoryUsed      int64     `json:"memory_used"`
	MemoryTotal     int64     `json:"memory_total"`
	MemoryPercent   float64   `json:"memory_percent"`
	DiskUsed        int64     `json:"disk_used"`
	DiskTotal       int64     `json:"disk_total"`
	DiskPercent     float64   `json:"disk_percent"`
	NetworkRxBytes  int64     `json:"network_rx_bytes"`
	NetworkTxBytes  int64     `json:"network_tx_bytes"`
	ContainersTotal int       `json:"containers_total"`
	ContainersRunning int     `json:"containers_running"`
	ContainersStopped int     `json:"containers_stopped"`
	ImagesTotal     int       `json:"images_total"`
	VolumesTotal    int       `json:"volumes_total"`
	CollectedAt     time.Time `json:"collected_at"`
}

// ContainerMetrics holds container-level metrics
type ContainerMetrics struct {
	ContainerID     string    `json:"container_id"`
	ContainerName   string    `json:"container_name"`
	CPUUsagePercent float64   `json:"cpu_usage_percent"`
	MemoryUsed      int64     `json:"memory_used"`
	MemoryLimit     int64     `json:"memory_limit"`
	MemoryPercent   float64   `json:"memory_percent"`
	NetworkRxBytes  int64     `json:"network_rx_bytes"`
	NetworkTxBytes  int64     `json:"network_tx_bytes"`
	BlockRead       int64     `json:"block_read"`
	BlockWrite      int64     `json:"block_write"`
	PIDs            int       `json:"pids"`
	State           string    `json:"state"`
	Health          string    `json:"health,omitempty"`
	Uptime          int64     `json:"uptime_seconds"`
	CollectedAt     time.Time `json:"collected_at"`
}

// MetricsSnapshot holds a complete metrics snapshot
type MetricsSnapshot struct {
	HostID     uuid.UUID           `json:"host_id"`
	Host       *HostMetrics        `json:"host"`
	Containers []*ContainerMetrics `json:"containers"`
	CollectedAt time.Time          `json:"collected_at"`
}

// MetricsCollectionWorker handles metrics collection jobs
type MetricsCollectionWorker struct {
	BaseWorker
	metricsService MetricsService
	logger         *logger.Logger
}

// MetricsCollectionPayload represents payload for metrics collection job
type MetricsCollectionPayload struct {
	IncludeContainers bool `json:"include_containers"`
	StoreMetrics      bool `json:"store_metrics"`
}

// NewMetricsCollectionWorker creates a new metrics collection worker
func NewMetricsCollectionWorker(metricsService MetricsService, log *logger.Logger) *MetricsCollectionWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &MetricsCollectionWorker{
		BaseWorker:     NewBaseWorker(models.JobTypeMetricsCollection),
		metricsService: metricsService,
		logger:         log.Named("metrics-worker"),
	}
}

// Execute performs the metrics collection job
func (w *MetricsCollectionWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	hostID := job.HostID
	if hostID == nil {
		return nil, errors.New(errors.CodeValidation, "host_id is required for metrics collection")
	}

	// Parse payload
	payload := MetricsCollectionPayload{
		IncludeContainers: true,
		StoreMetrics:      true,
	}
	job.GetPayload(&payload)

	log.Debug("starting metrics collection",
		"host_id", hostID,
		"include_containers", payload.IncludeContainers,
	)

	result := &MetricsCollectionResult{
		HostID:    *hostID,
		StartedAt: time.Now(),
	}

	// Update progress
	job.Progress = 20
	msg := "Collecting host metrics..."
	job.ProgressMessage = &msg

	// Collect host metrics
	hostMetrics, err := w.metricsService.CollectHostMetrics(ctx, *hostID)
	if err != nil {
		log.Error("failed to collect host metrics", "error", err)
		result.Errors = append(result.Errors, "host metrics: "+err.Error())
	} else {
		result.HostMetrics = hostMetrics
	}

	// Collect container metrics if requested
	if payload.IncludeContainers {
		job.Progress = 50
		msg = "Collecting container metrics..."
		job.ProgressMessage = &msg

		containerMetrics, err := w.metricsService.CollectContainerMetrics(ctx, *hostID)
		if err != nil {
			log.Error("failed to collect container metrics", "error", err)
			result.Errors = append(result.Errors, "container metrics: "+err.Error())
		} else {
			result.ContainerMetrics = containerMetrics
			result.ContainersCollected = len(containerMetrics)
		}
	}

	// Store metrics if requested
	if payload.StoreMetrics && w.metricsService != nil {
		job.Progress = 80
		msg = "Storing metrics..."
		job.ProgressMessage = &msg

		snapshot := &MetricsSnapshot{
			HostID:      *hostID,
			Host:        result.HostMetrics,
			Containers:  result.ContainerMetrics,
			CollectedAt: time.Now(),
		}

		if err := w.metricsService.StoreMetrics(ctx, snapshot); err != nil {
			log.Error("failed to store metrics", "error", err)
			result.Errors = append(result.Errors, "store metrics: "+err.Error())
		} else {
			result.MetricsStored = true
		}
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	log.Debug("metrics collection completed",
		"containers_collected", result.ContainersCollected,
		"duration", result.Duration,
	)

	return result, nil
}

// MetricsCollectionResult holds the result of a metrics collection job
type MetricsCollectionResult struct {
	HostID              uuid.UUID           `json:"host_id"`
	StartedAt           time.Time           `json:"started_at"`
	CompletedAt         time.Time           `json:"completed_at"`
	Duration            time.Duration       `json:"duration"`
	HostMetrics         *HostMetrics        `json:"host_metrics,omitempty"`
	ContainerMetrics    []*ContainerMetrics `json:"container_metrics,omitempty"`
	ContainersCollected int                 `json:"containers_collected"`
	MetricsStored       bool                `json:"metrics_stored"`
	Errors              []string            `json:"errors,omitempty"`
}

// ============================================================================
// Host Inventory Worker
// ============================================================================

// InventoryService interface for host inventory operations
type InventoryService interface {
	// CollectInventory collects full inventory of a host
	CollectInventory(ctx context.Context, hostID uuid.UUID) (*HostInventory, error)

	// StoreInventory stores the collected inventory
	StoreInventory(ctx context.Context, inventory *HostInventory) error
}

// HostInventory holds complete host inventory
type HostInventory struct {
	HostID       uuid.UUID          `json:"host_id"`
	DockerInfo   *DockerInfo        `json:"docker_info"`
	Containers   []*ContainerInfo   `json:"containers"`
	Images       []*ImageInfo       `json:"images"`
	Volumes      []*VolumeInfo      `json:"volumes"`
	Networks     []*NetworkInfo     `json:"networks"`
	CollectedAt  time.Time          `json:"collected_at"`
}

// DockerInfo holds Docker daemon information
type DockerInfo struct {
	Version           string `json:"version"`
	APIVersion        string `json:"api_version"`
	OS                string `json:"os"`
	Architecture      string `json:"architecture"`
	KernelVersion     string `json:"kernel_version"`
	NCPU              int    `json:"ncpu"`
	MemoryTotal       int64  `json:"memory_total"`
	StorageDriver     string `json:"storage_driver"`
	LoggingDriver     string `json:"logging_driver"`
	CgroupDriver      string `json:"cgroup_driver"`
	ContainersRunning int    `json:"containers_running"`
	ContainersPaused  int    `json:"containers_paused"`
	ContainersStopped int    `json:"containers_stopped"`
	Images            int    `json:"images"`
}

// ContainerInfo holds container information for inventory
type ContainerInfo struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	State   string            `json:"state"`
	Status  string            `json:"status"`
	Created time.Time         `json:"created"`
	Ports   []string          `json:"ports"`
	Labels  map[string]string `json:"labels"`
}

// ImageInfo holds image information for inventory
type ImageInfo struct {
	ID          string    `json:"id"`
	RepoTags    []string  `json:"repo_tags"`
	Size        int64     `json:"size"`
	Created     time.Time `json:"created"`
	InUse       bool      `json:"in_use"`
}

// VolumeInfo holds volume information for inventory
type VolumeInfo struct {
	Name       string    `json:"name"`
	Driver     string    `json:"driver"`
	Mountpoint string    `json:"mountpoint"`
	CreatedAt  time.Time `json:"created_at"`
	InUse      bool      `json:"in_use"`
}

// NetworkInfo holds network information for inventory
type NetworkInfo struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Driver     string   `json:"driver"`
	Scope      string   `json:"scope"`
	Internal   bool     `json:"internal"`
	Containers []string `json:"containers"`
}

// HostInventoryWorker handles host inventory collection jobs
type HostInventoryWorker struct {
	BaseWorker
	inventoryService InventoryService
	logger           *logger.Logger
}

// NewHostInventoryWorker creates a new host inventory worker
func NewHostInventoryWorker(inventoryService InventoryService, log *logger.Logger) *HostInventoryWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &HostInventoryWorker{
		BaseWorker:       NewBaseWorker(models.JobTypeHostInventory),
		inventoryService: inventoryService,
		logger:           log.Named("inventory-worker"),
	}
}

// Execute performs the host inventory collection job
func (w *HostInventoryWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	hostID := job.HostID
	if hostID == nil {
		return nil, errors.New(errors.CodeValidation, "host_id is required for host inventory")
	}

	log.Info("starting host inventory collection", "host_id", hostID)

	result := &HostInventoryResult{
		HostID:    *hostID,
		StartedAt: time.Now(),
	}

	// Update progress
	job.Progress = 20
	msg := "Collecting inventory..."
	job.ProgressMessage = &msg

	// Collect inventory
	inventory, err := w.inventoryService.CollectInventory(ctx, *hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to collect inventory")
	}

	result.Inventory = inventory
	result.ContainerCount = len(inventory.Containers)
	result.ImageCount = len(inventory.Images)
	result.VolumeCount = len(inventory.Volumes)
	result.NetworkCount = len(inventory.Networks)

	// Update progress
	job.Progress = 70
	msg = "Storing inventory..."
	job.ProgressMessage = &msg

	// Store inventory
	if err := w.inventoryService.StoreInventory(ctx, inventory); err != nil {
		log.Error("failed to store inventory", "error", err)
		result.Errors = append(result.Errors, "store inventory: "+err.Error())
	} else {
		result.Stored = true
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	log.Info("host inventory collection completed",
		"containers", result.ContainerCount,
		"images", result.ImageCount,
		"volumes", result.VolumeCount,
		"networks", result.NetworkCount,
		"duration", result.Duration,
	)

	return result, nil
}

// HostInventoryResult holds the result of a host inventory job
type HostInventoryResult struct {
	HostID         uuid.UUID      `json:"host_id"`
	StartedAt      time.Time      `json:"started_at"`
	CompletedAt    time.Time      `json:"completed_at"`
	Duration       time.Duration  `json:"duration"`
	Inventory      *HostInventory `json:"inventory,omitempty"`
	ContainerCount int            `json:"container_count"`
	ImageCount     int            `json:"image_count"`
	VolumeCount    int            `json:"volume_count"`
	NetworkCount   int            `json:"network_count"`
	Stored         bool           `json:"stored"`
	Errors         []string       `json:"errors,omitempty"`
}
