// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package drift

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Repository defines the persistence interface for drift detection.
type Repository interface {
	CreateSnapshot(ctx context.Context, s *models.ConfigSnapshot) error
	GetSnapshotByID(ctx context.Context, id uuid.UUID) (*models.ConfigSnapshot, error)
	GetBaseline(ctx context.Context, resourceType, resourceID string) (*models.ConfigSnapshot, error)
	GetLatestSnapshot(ctx context.Context, resourceType, resourceID string) (*models.ConfigSnapshot, error)
	SetBaseline(ctx context.Context, snapshotID uuid.UUID) error
	ListSnapshots(ctx context.Context, resourceType, resourceID string, limit int) ([]*models.ConfigSnapshot, error)
	CreateDrift(ctx context.Context, d *models.DriftDetection) error
	GetDriftByID(ctx context.Context, id uuid.UUID) (*models.DriftDetection, error)
	ListDrifts(ctx context.Context, opts models.DriftListOptions) ([]*models.DriftDetection, int, error)
	GetOpenDrifts(ctx context.Context) ([]*models.DriftDetection, error)
	ResolveDrift(ctx context.Context, id uuid.UUID, status string, resolvedBy *uuid.UUID, note string) error
	GetDriftStats(ctx context.Context) (*models.DriftStats, error)
	CloseExistingDrifts(ctx context.Context, resourceType, resourceID string) error
}

// Service handles configuration drift detection and snapshot management.
type Service struct {
	repo   Repository
	logger *logger.Logger
}

// NewService creates a new drift detection service.
func NewService(repo Repository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		repo:   repo,
		logger: log.Named("drift"),
	}
}

// TakeSnapshot captures the current configuration of a resource as a point-in-time snapshot.
func (s *Service) TakeSnapshot(ctx context.Context, resourceType, resourceID, resourceName string, config any, takenBy *uuid.UUID, note string) (*models.ConfigSnapshot, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("marshaling snapshot config: %w", err)
	}

	msg := json.RawMessage(raw)
	snap := &models.ConfigSnapshot{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		Status:       models.SnapshotStatusCurrent,
		Snapshot:     &msg,
		TakenBy:      takenBy,
		Note:         note,
	}

	if err := s.repo.CreateSnapshot(ctx, snap); err != nil {
		s.logger.Error("failed to create snapshot",
			"resource_type", resourceType,
			"resource_id", resourceID,
			"error", err,
		)
		return nil, fmt.Errorf("creating snapshot: %w", err)
	}

	s.logger.Debug("snapshot taken",
		"id", snap.ID,
		"resource_type", resourceType,
		"resource_id", resourceID,
	)
	return snap, nil
}

// SetBaseline marks a snapshot as the baseline for drift detection.
func (s *Service) SetBaseline(ctx context.Context, snapshotID uuid.UUID) error {
	return s.repo.SetBaseline(ctx, snapshotID)
}

// GetBaseline retrieves the baseline snapshot for a resource.
func (s *Service) GetBaseline(ctx context.Context, resourceType, resourceID string) (*models.ConfigSnapshot, error) {
	return s.repo.GetBaseline(ctx, resourceType, resourceID)
}

// ListSnapshots retrieves snapshots for a resource.
func (s *Service) ListSnapshots(ctx context.Context, resourceType, resourceID string, limit int) ([]*models.ConfigSnapshot, error) {
	return s.repo.ListSnapshots(ctx, resourceType, resourceID, limit)
}

// DetectDrift compares the current configuration against the baseline and records any drift found.
func (s *Service) DetectDrift(ctx context.Context, resourceType, resourceID, resourceName string, currentConfig any) (*models.DriftDetection, error) {
	baseline, err := s.repo.GetBaseline(ctx, resourceType, resourceID)
	if err != nil {
		return nil, fmt.Errorf("getting baseline: %w", err)
	}
	if baseline == nil {
		return nil, nil
	}

	// Unmarshal baseline snapshot into map.
	var baselineMap map[string]any
	if baseline.Snapshot != nil {
		if err := json.Unmarshal(*baseline.Snapshot, &baselineMap); err != nil {
			return nil, fmt.Errorf("unmarshalling baseline snapshot: %w", err)
		}
	}

	// Marshal and unmarshal current config into map.
	currentRaw, err := json.Marshal(currentConfig)
	if err != nil {
		return nil, fmt.Errorf("marshaling current config: %w", err)
	}
	var currentMap map[string]any
	if err := json.Unmarshal(currentRaw, &currentMap); err != nil {
		return nil, fmt.Errorf("unmarshalling current config: %w", err)
	}

	diffs := compareMaps(baselineMap, currentMap)
	if len(diffs) == 0 {
		return nil, nil
	}

	severity := highestSeverity(diffs)

	diffsRaw, err := json.Marshal(diffs)
	if err != nil {
		return nil, fmt.Errorf("marshaling diffs: %w", err)
	}
	diffsMsg := json.RawMessage(diffsRaw)

	detection := &models.DriftDetection{
		ResourceType:       resourceType,
		ResourceID:         resourceID,
		ResourceName:       resourceName,
		BaselineSnapshotID: &baseline.ID,
		Status:             models.DriftStatusOpen,
		Severity:           severity,
		Diffs:              &diffsMsg,
		DiffCount:          len(diffs),
	}

	if err := s.repo.CreateDrift(ctx, detection); err != nil {
		s.logger.Error("failed to create drift detection",
			"resource_type", resourceType,
			"resource_id", resourceID,
			"error", err,
		)
		return nil, fmt.Errorf("creating drift detection: %w", err)
	}

	s.logger.Info("drift detected",
		"id", detection.ID,
		"resource_type", resourceType,
		"resource_id", resourceID,
		"severity", severity,
		"diff_count", len(diffs),
	)
	return detection, nil
}

// AcceptDrift marks a drift detection as accepted (acknowledged, no remediation needed).
func (s *Service) AcceptDrift(ctx context.Context, id uuid.UUID, userID *uuid.UUID, note string) error {
	return s.repo.ResolveDrift(ctx, id, models.DriftStatusAccepted, userID, note)
}

// RemediateDrift marks a drift detection as remediated (configuration corrected).
func (s *Service) RemediateDrift(ctx context.Context, id uuid.UUID, userID *uuid.UUID, note string) error {
	return s.repo.ResolveDrift(ctx, id, models.DriftStatusRemediated, userID, note)
}

// GetDriftByID retrieves a single drift detection by its ID.
func (s *Service) GetDriftByID(ctx context.Context, id uuid.UUID) (*models.DriftDetection, error) {
	return s.repo.GetDriftByID(ctx, id)
}

// ListDrifts retrieves drift detections with filtering and pagination.
func (s *Service) ListDrifts(ctx context.Context, opts models.DriftListOptions) ([]*models.DriftDetection, int, error) {
	return s.repo.ListDrifts(ctx, opts)
}

// GetOpenDrifts retrieves all unresolved drift detections.
func (s *Service) GetOpenDrifts(ctx context.Context) ([]*models.DriftDetection, error) {
	return s.repo.GetOpenDrifts(ctx)
}

// GetStats returns aggregate statistics about detected drifts.
func (s *Service) GetStats(ctx context.Context) (*models.DriftStats, error) {
	return s.repo.GetDriftStats(ctx)
}

// compareMaps compares top-level keys between baseline and current configuration maps
// and returns a slice of diffs describing any detected drift.
func compareMaps(baseline, current map[string]any) []models.DriftDiff {
	var diffs []models.DriftDiff

	// Check keys in baseline: modified or removed.
	for k, baseVal := range baseline {
		curVal, exists := current[k]
		baseStr := fmt.Sprintf("%v", baseVal)
		if !exists {
			dt, sev := classifyDrift(k)
			diffs = append(diffs, models.DriftDiff{
				Type:     dt,
				Field:    k,
				OldValue: baseStr,
				NewValue: "",
				Severity: sev,
			})
			continue
		}
		curStr := fmt.Sprintf("%v", curVal)
		if baseStr != curStr {
			dt, sev := classifyDrift(k)
			diffs = append(diffs, models.DriftDiff{
				Type:     dt,
				Field:    k,
				OldValue: baseStr,
				NewValue: curStr,
				Severity: sev,
			})
		}
	}

	// Check keys in current but not in baseline: added.
	for k, curVal := range current {
		if _, exists := baseline[k]; !exists {
			dt, sev := classifyDrift(k)
			diffs = append(diffs, models.DriftDiff{
				Type:     dt,
				Field:    k,
				OldValue: "",
				NewValue: fmt.Sprintf("%v", curVal),
				Severity: sev,
			})
		}
	}

	return diffs
}

// classifyDrift returns the drift type and severity for a given configuration key.
func classifyDrift(key string) (string, string) {
	switch {
	case key == "image":
		return models.DriftTypeImage, "critical"
	case key == "privileged":
		return models.DriftTypePrivileged, "critical"
	case strings.HasPrefix(key, "env_") || key == "env":
		return models.DriftTypeEnvVar, "warning"
	case key == "ports":
		return models.DriftTypePort, "warning"
	case key == "volumes":
		return models.DriftTypeVolume, "warning"
	case key == "memory_limit" || key == "cpu_limit" || key == "memory_reservation":
		return models.DriftTypeLimit, "warning"
	case key == "labels":
		return models.DriftTypeLabel, "info"
	case key == "networks":
		return models.DriftTypeNetwork, "info"
	case key == "restart_policy":
		return models.DriftTypeRestartPolicy, "warning"
	case key == "healthcheck":
		return models.DriftTypeHealthcheck, "warning"
	default:
		return key + "_changed", "warning"
	}
}

// highestSeverity returns the highest severity level present in the given diffs.
func highestSeverity(diffs []models.DriftDiff) string {
	for _, d := range diffs {
		if d.Severity == "critical" {
			return "critical"
		}
	}
	for _, d := range diffs {
		if d.Severity == "warning" {
			return "warning"
		}
	}
	return "info"
}
