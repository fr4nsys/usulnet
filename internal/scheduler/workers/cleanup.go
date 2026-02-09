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

// CleanupService interface for cleanup operations
type CleanupService interface {
	// PruneImages removes unused Docker images
	PruneImages(ctx context.Context, hostID uuid.UUID, all bool) (*PruneResult, error)

	// PruneVolumes removes unused Docker volumes
	PruneVolumes(ctx context.Context, hostID uuid.UUID) (*PruneResult, error)

	// PruneNetworks removes unused Docker networks
	PruneNetworks(ctx context.Context, hostID uuid.UUID) (*PruneResult, error)

	// PruneContainers removes stopped containers
	PruneContainers(ctx context.Context, hostID uuid.UUID) (*PruneResult, error)

	// PruneBuildCache removes build cache
	PruneBuildCache(ctx context.Context, hostID uuid.UUID) (*PruneResult, error)
}

// PruneResult holds the result of a prune operation
type PruneResult struct {
	ItemsDeleted int64  `json:"items_deleted"`
	SpaceFreed   int64  `json:"space_freed"` // bytes
	Errors       []string `json:"errors,omitempty"`
}

// JobCleanupService interface for cleaning up old jobs
type JobCleanupService interface {
	// DeleteOldJobs removes jobs older than the specified duration
	DeleteOldJobs(ctx context.Context, olderThan time.Duration) (int64, error)

	// DeleteOldEvents removes job events older than the specified duration
	DeleteOldEvents(ctx context.Context, olderThan time.Duration) (int64, error)
}

// CleanupWorker handles cleanup jobs
type CleanupWorker struct {
	BaseWorker
	cleanupService    CleanupService
	jobCleanupService JobCleanupService
	logger            *logger.Logger
}

// CleanupPayload represents payload for cleanup job
type CleanupPayload struct {
	Type           string `json:"type"` // images, volumes, networks, containers, build_cache, all, jobs
	All            bool   `json:"all"`  // For images: remove all unused, not just dangling
	OlderThanDays  int    `json:"older_than_days,omitempty"` // For jobs cleanup
}

// NewCleanupWorker creates a new cleanup worker
func NewCleanupWorker(
	cleanupService CleanupService,
	jobCleanupService JobCleanupService,
	log *logger.Logger,
) *CleanupWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &CleanupWorker{
		BaseWorker:        NewBaseWorker(models.JobTypeCleanup),
		cleanupService:    cleanupService,
		jobCleanupService: jobCleanupService,
		logger:            log.Named("cleanup-worker"),
	}
}

// Execute performs the cleanup job
func (w *CleanupWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	// Parse payload
	var payload CleanupPayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse payload")
	}

	// Default to "all" if no type specified
	if payload.Type == "" {
		payload.Type = "all"
	}

	log.Info("starting cleanup",
		"type", payload.Type,
		"all", payload.All,
	)

	result := &CleanupJobResult{
		Type:      payload.Type,
		StartedAt: time.Now(),
		Results:   make(map[string]*PruneResult),
	}

	hostID := job.HostID

	switch payload.Type {
	case "images":
		if hostID != nil && w.cleanupService != nil {
			res, err := w.cleanupService.PruneImages(ctx, *hostID, payload.All)
			if err != nil {
				result.Errors = append(result.Errors, "images: "+err.Error())
			} else {
				result.Results["images"] = res
				result.TotalItemsDeleted += res.ItemsDeleted
				result.TotalSpaceFreed += res.SpaceFreed
			}
		}

	case "volumes":
		if hostID != nil && w.cleanupService != nil {
			res, err := w.cleanupService.PruneVolumes(ctx, *hostID)
			if err != nil {
				result.Errors = append(result.Errors, "volumes: "+err.Error())
			} else {
				result.Results["volumes"] = res
				result.TotalItemsDeleted += res.ItemsDeleted
				result.TotalSpaceFreed += res.SpaceFreed
			}
		}

	case "networks":
		if hostID != nil && w.cleanupService != nil {
			res, err := w.cleanupService.PruneNetworks(ctx, *hostID)
			if err != nil {
				result.Errors = append(result.Errors, "networks: "+err.Error())
			} else {
				result.Results["networks"] = res
				result.TotalItemsDeleted += res.ItemsDeleted
			}
		}

	case "containers":
		if hostID != nil && w.cleanupService != nil {
			res, err := w.cleanupService.PruneContainers(ctx, *hostID)
			if err != nil {
				result.Errors = append(result.Errors, "containers: "+err.Error())
			} else {
				result.Results["containers"] = res
				result.TotalItemsDeleted += res.ItemsDeleted
				result.TotalSpaceFreed += res.SpaceFreed
			}
		}

	case "build_cache":
		if hostID != nil && w.cleanupService != nil {
			res, err := w.cleanupService.PruneBuildCache(ctx, *hostID)
			if err != nil {
				result.Errors = append(result.Errors, "build_cache: "+err.Error())
			} else {
				result.Results["build_cache"] = res
				result.TotalSpaceFreed += res.SpaceFreed
			}
		}

	case "jobs":
		if w.jobCleanupService != nil {
			olderThan := 30 * 24 * time.Hour // Default 30 days
			if payload.OlderThanDays > 0 {
				olderThan = time.Duration(payload.OlderThanDays) * 24 * time.Hour
			}

			// Delete old jobs
			jobsDeleted, err := w.jobCleanupService.DeleteOldJobs(ctx, olderThan)
			if err != nil {
				result.Errors = append(result.Errors, "jobs: "+err.Error())
			} else {
				result.Results["jobs"] = &PruneResult{ItemsDeleted: jobsDeleted}
				result.TotalItemsDeleted += jobsDeleted
			}

			// Delete old events
			eventsDeleted, err := w.jobCleanupService.DeleteOldEvents(ctx, olderThan)
			if err != nil {
				result.Errors = append(result.Errors, "job_events: "+err.Error())
			} else {
				result.Results["job_events"] = &PruneResult{ItemsDeleted: eventsDeleted}
				result.TotalItemsDeleted += eventsDeleted
			}
		}

	case "all":
		// Run all cleanup operations
		job.Progress = 10
		msg := "Pruning containers..."
		job.ProgressMessage = &msg

		if hostID != nil && w.cleanupService != nil {
			// Containers
			if res, err := w.cleanupService.PruneContainers(ctx, *hostID); err == nil {
				result.Results["containers"] = res
				result.TotalItemsDeleted += res.ItemsDeleted
				result.TotalSpaceFreed += res.SpaceFreed
			}

			job.Progress = 30
			msg = "Pruning images..."
			job.ProgressMessage = &msg

			// Images
			if res, err := w.cleanupService.PruneImages(ctx, *hostID, payload.All); err == nil {
				result.Results["images"] = res
				result.TotalItemsDeleted += res.ItemsDeleted
				result.TotalSpaceFreed += res.SpaceFreed
			}

			job.Progress = 50
			msg = "Pruning volumes..."
			job.ProgressMessage = &msg

			// Volumes
			if res, err := w.cleanupService.PruneVolumes(ctx, *hostID); err == nil {
				result.Results["volumes"] = res
				result.TotalItemsDeleted += res.ItemsDeleted
				result.TotalSpaceFreed += res.SpaceFreed
			}

			job.Progress = 70
			msg = "Pruning networks..."
			job.ProgressMessage = &msg

			// Networks
			if res, err := w.cleanupService.PruneNetworks(ctx, *hostID); err == nil {
				result.Results["networks"] = res
				result.TotalItemsDeleted += res.ItemsDeleted
			}

			job.Progress = 85
			msg = "Pruning build cache..."
			job.ProgressMessage = &msg

			// Build cache
			if res, err := w.cleanupService.PruneBuildCache(ctx, *hostID); err == nil {
				result.Results["build_cache"] = res
				result.TotalSpaceFreed += res.SpaceFreed
			}
		}

		job.Progress = 95
		msg = "Cleaning up old jobs..."
		job.ProgressMessage = &msg

		// Jobs cleanup
		if w.jobCleanupService != nil {
			olderThan := 30 * 24 * time.Hour
			if payload.OlderThanDays > 0 {
				olderThan = time.Duration(payload.OlderThanDays) * 24 * time.Hour
			}

			if deleted, err := w.jobCleanupService.DeleteOldJobs(ctx, olderThan); err == nil {
				result.Results["jobs"] = &PruneResult{ItemsDeleted: deleted}
				result.TotalItemsDeleted += deleted
			}

			if deleted, err := w.jobCleanupService.DeleteOldEvents(ctx, olderThan); err == nil {
				result.Results["job_events"] = &PruneResult{ItemsDeleted: deleted}
				result.TotalItemsDeleted += deleted
			}
		}

	default:
		return nil, errors.Newf(errors.CodeValidation, "unknown cleanup type: %s", payload.Type)
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	log.Info("cleanup completed",
		"type", payload.Type,
		"items_deleted", result.TotalItemsDeleted,
		"space_freed", result.TotalSpaceFreed,
		"duration", result.Duration,
	)

	return result, nil
}

// CleanupJobResult holds the result of a cleanup job
type CleanupJobResult struct {
	Type              string                   `json:"type"`
	StartedAt         time.Time                `json:"started_at"`
	CompletedAt       time.Time                `json:"completed_at"`
	Duration          time.Duration            `json:"duration"`
	TotalItemsDeleted int64                    `json:"total_items_deleted"`
	TotalSpaceFreed   int64                    `json:"total_space_freed"`
	Results           map[string]*PruneResult  `json:"results"`
	Errors            []string                 `json:"errors,omitempty"`
}

// ============================================================================
// Image Prune Worker
// ============================================================================

// ImagePruneWorker handles image pruning jobs
type ImagePruneWorker struct {
	BaseWorker
	cleanupService CleanupService
	logger         *logger.Logger
}

// NewImagePruneWorker creates a new image prune worker
func NewImagePruneWorker(cleanupService CleanupService, log *logger.Logger) *ImagePruneWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &ImagePruneWorker{
		BaseWorker:     NewBaseWorker(models.JobTypeImagePrune),
		cleanupService: cleanupService,
		logger:         log.Named("image-prune-worker"),
	}
}

// ImagePrunePayload represents payload for image prune job
type ImagePrunePayload struct {
	All bool `json:"all"` // Remove all unused images, not just dangling
}

// Execute performs the image prune job
func (w *ImagePruneWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	hostID := job.HostID
	if hostID == nil {
		return nil, errors.New(errors.CodeValidation, "host_id is required")
	}

	var payload ImagePrunePayload
	job.GetPayload(&payload)

	log.Info("starting image prune", "host_id", hostID, "all", payload.All)

	result, err := w.cleanupService.PruneImages(ctx, *hostID, payload.All)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDocker, "image prune failed")
	}

	log.Info("image prune completed",
		"images_deleted", result.ItemsDeleted,
		"space_freed", result.SpaceFreed,
	)

	return result, nil
}

// ============================================================================
// Volume Prune Worker
// ============================================================================

// VolumePruneWorker handles volume pruning jobs
type VolumePruneWorker struct {
	BaseWorker
	cleanupService CleanupService
	logger         *logger.Logger
}

// NewVolumePruneWorker creates a new volume prune worker
func NewVolumePruneWorker(cleanupService CleanupService, log *logger.Logger) *VolumePruneWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &VolumePruneWorker{
		BaseWorker:     NewBaseWorker(models.JobTypeVolumePrune),
		cleanupService: cleanupService,
		logger:         log.Named("volume-prune-worker"),
	}
}

// Execute performs the volume prune job
func (w *VolumePruneWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	hostID := job.HostID
	if hostID == nil {
		return nil, errors.New(errors.CodeValidation, "host_id is required")
	}

	log.Info("starting volume prune", "host_id", hostID)

	result, err := w.cleanupService.PruneVolumes(ctx, *hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDocker, "volume prune failed")
	}

	log.Info("volume prune completed",
		"volumes_deleted", result.ItemsDeleted,
		"space_freed", result.SpaceFreed,
	)

	return result, nil
}

// ============================================================================
// Network Prune Worker
// ============================================================================

// NetworkPruneWorker handles network pruning jobs
type NetworkPruneWorker struct {
	BaseWorker
	cleanupService CleanupService
	logger         *logger.Logger
}

// NewNetworkPruneWorker creates a new network prune worker
func NewNetworkPruneWorker(cleanupService CleanupService, log *logger.Logger) *NetworkPruneWorker {
	if log == nil {
		log = logger.Nop()
	}

	return &NetworkPruneWorker{
		BaseWorker:     NewBaseWorker(models.JobTypeNetworkPrune),
		cleanupService: cleanupService,
		logger:         log.Named("network-prune-worker"),
	}
}

// Execute performs the network prune job
func (w *NetworkPruneWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	hostID := job.HostID
	if hostID == nil {
		return nil, errors.New(errors.CodeValidation, "host_id is required")
	}

	log.Info("starting network prune", "host_id", hostID)

	result, err := w.cleanupService.PruneNetworks(ctx, *hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDocker, "network prune failed")
	}

	log.Info("network prune completed", "networks_deleted", result.ItemsDeleted)

	return result, nil
}
