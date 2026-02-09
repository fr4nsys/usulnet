// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package config

import (
	"fmt"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// SyncService handles configuration synchronization to containers
type SyncService struct {
	variableRepo *postgres.ConfigVariableRepository
	templateRepo *postgres.ConfigTemplateRepository
	syncRepo     *postgres.ConfigSyncRepository
	auditRepo    *postgres.ConfigAuditRepository
	interpolator *Interpolator
	logger       *logger.Logger
}

// NewSyncService creates a new SyncService
func NewSyncService(
	variableRepo *postgres.ConfigVariableRepository,
	templateRepo *postgres.ConfigTemplateRepository,
	syncRepo *postgres.ConfigSyncRepository,
	auditRepo *postgres.ConfigAuditRepository,
	log *logger.Logger,
) *SyncService {
	return &SyncService{
		variableRepo: variableRepo,
		templateRepo: templateRepo,
		syncRepo:     syncRepo,
		auditRepo:    auditRepo,
		interpolator: NewInterpolator(),
		logger:       log.Named("config_sync"),
	}
}

// SyncOptions represents options for syncing config to a container
type SyncOptions struct {
	HostID        uuid.UUID
	ContainerID   string
	ContainerName string
	TemplateID    *uuid.UUID
	TemplateName  *string
	Overrides     map[string]string // Additional variables to override
	Force         bool              // Force restart even if config unchanged
	DryRun        bool              // Preview only, don't apply
}

// SyncResult represents the result of a sync operation
type SyncResult struct {
	Success         bool                  `json:"success"`
	ContainerID     string                `json:"container_id"`
	ContainerName   string                `json:"container_name"`
	TemplateName    *string               `json:"template_name,omitempty"`
	VariablesHash   string                `json:"variables_hash"`
	RequiresRestart bool                  `json:"requires_restart"`
	Diff            *models.ConfigDiff    `json:"diff,omitempty"`
	Variables       []*models.ConfigVariable `json:"variables,omitempty"`
	ErrorMessage    *string               `json:"error_message,omitempty"`
}

// Sync synchronizes configuration to a container
func (s *SyncService) Sync(ctx context.Context, opts SyncOptions, userID *uuid.UUID) (*SyncResult, error) {
	log := logger.FromContext(ctx)

	result := &SyncResult{
		ContainerID:   opts.ContainerID,
		ContainerName: opts.ContainerName,
		TemplateName:  opts.TemplateName,
	}

	// Resolve template name if ID provided
	var templateName *string
	if opts.TemplateID != nil {
		t, err := s.templateRepo.GetByID(ctx, *opts.TemplateID)
		if err != nil {
			return nil, err
		}
		templateName = &t.Name
	} else if opts.TemplateName != nil {
		templateName = opts.TemplateName
	}
	result.TemplateName = templateName

	// Get resolved variables for container
	variables, err := s.variableRepo.ResolveForContainer(ctx, opts.ContainerID, templateName)
	if err != nil {
		return nil, err
	}

	// Apply overrides
	if len(opts.Overrides) > 0 {
		variables = s.applyOverrides(variables, opts.Overrides)
	}

	// Interpolate all variables
	varMap := make(map[string]string)
	for _, v := range variables {
		varMap[v.Name] = v.Value
	}

	interpolatedVars := make([]*models.ConfigVariable, 0, len(variables))
	for _, v := range variables {
		interpolated, _, err := s.interpolator.Interpolate(ctx, v.Value, varMap)
		if err != nil {
			log.Warn("Failed to interpolate variable",
				"name", v.Name,
				"error", err)
			interpolated = v.Value // Use original on error
		}

		newVar := *v
		newVar.Value = interpolated
		interpolatedVars = append(interpolatedVars, &newVar)
	}

	// Compute hash
	hash := s.computeVariablesHash(interpolatedVars)
	result.VariablesHash = hash
	result.Variables = interpolatedVars

	// Check if sync is needed
	existingSync, _ := s.syncRepo.GetByContainer(ctx, opts.HostID, opts.ContainerID)
	if existingSync != nil && existingSync.VariablesHash == hash && !opts.Force {
		// Already synced with same config
		result.Success = true
		result.RequiresRestart = false
		return result, nil
	}

	// Calculate diff if existing sync
	if existingSync != nil {
		diff, err := s.calculateDiff(ctx, opts, existingSync, interpolatedVars)
		if err != nil {
			log.Warn("Failed to calculate diff", "error", err)
		} else {
			result.Diff = diff
			result.RequiresRestart = diff.RequiresRestart
		}
	} else {
		result.RequiresRestart = true
	}

	// If dry run, return here
	if opts.DryRun {
		result.Success = true
		return result, nil
	}

	// Create/update sync record
	sync := &models.ConfigSync{
		ID:            uuid.New(),
		HostID:        opts.HostID,
		ContainerID:   opts.ContainerID,
		ContainerName: opts.ContainerName,
		TemplateID:    opts.TemplateID,
		TemplateName:  templateName,
		Status:        "pending",
		VariablesHash: hash,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if existingSync != nil {
		sync.ID = existingSync.ID
		sync.CreatedAt = existingSync.CreatedAt
	}

	if err := s.syncRepo.Create(ctx, sync); err != nil {
		return nil, err
	}

	// The actual container update is done by the caller (Docker service)
	// This service just manages the configuration state
	result.Success = true

	// Audit log
	s.logSyncAudit(ctx, opts.ContainerID, opts.ContainerName, templateName, userID)

	log.Info("Config sync prepared",
		"container_id", opts.ContainerID,
		"container_name", opts.ContainerName,
		"variables", len(interpolatedVars),
		"requires_restart", result.RequiresRestart)

	return result, nil
}

// MarkSynced marks a sync as completed
func (s *SyncService) MarkSynced(ctx context.Context, syncID uuid.UUID) error {
	return s.syncRepo.UpdateStatus(ctx, syncID, "synced", nil)
}

// MarkFailed marks a sync as failed
func (s *SyncService) MarkFailed(ctx context.Context, syncID uuid.UUID, errorMsg string) error {
	return s.syncRepo.UpdateStatus(ctx, syncID, "failed", &errorMsg)
}

// GetSyncStatus retrieves sync status for a container
func (s *SyncService) GetSyncStatus(ctx context.Context, hostID uuid.UUID, containerID string) (*models.ConfigSync, error) {
	return s.syncRepo.GetByContainer(ctx, hostID, containerID)
}

// ListOutdated returns all containers with outdated configuration
func (s *SyncService) ListOutdated(ctx context.Context, hostID *uuid.UUID) ([]*models.ConfigSync, error) {
	return s.syncRepo.ListOutdated(ctx, hostID)
}

// GetSyncStats returns sync statistics
func (s *SyncService) GetSyncStats(ctx context.Context, hostID *uuid.UUID) (map[string]int, error) {
	return s.syncRepo.GetSyncStats(ctx, hostID)
}

// BulkSync synchronizes configuration to multiple containers
func (s *SyncService) BulkSync(ctx context.Context, input models.SyncBulkInput, hostID uuid.UUID, userID *uuid.UUID) ([]*SyncResult, error) {
	log := logger.FromContext(ctx)

	results := make([]*SyncResult, 0, len(input.ContainerIDs))

	// Get template name if ID provided
	var templateName *string
	if input.TemplateID != nil {
		t, err := s.templateRepo.GetByID(ctx, *input.TemplateID)
		if err != nil {
			return nil, err
		}
		templateName = &t.Name
	}

	for _, containerID := range input.ContainerIDs {
		opts := SyncOptions{
			HostID:       hostID,
			ContainerID:  containerID,
			TemplateID:   input.TemplateID,
			TemplateName: templateName,
			Overrides:    input.Variables,
			Force:        input.Force,
		}

		result, err := s.Sync(ctx, opts, userID)
		if err != nil {
			errMsg := err.Error()
			result = &SyncResult{
				ContainerID:  containerID,
				Success:      false,
				ErrorMessage: &errMsg,
			}
		}
		results = append(results, result)
	}

	log.Info("Bulk sync completed",
		"total", len(input.ContainerIDs),
		"success", countSuccess(results))

	return results, nil
}

// PreviewSync previews what would change without applying
func (s *SyncService) PreviewSync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	opts.DryRun = true
	return s.Sync(ctx, opts, nil)
}

// RemoveSync removes sync tracking for a container
func (s *SyncService) RemoveSync(ctx context.Context, hostID uuid.UUID, containerID string) error {
	return s.syncRepo.DeleteByContainer(ctx, hostID, containerID)
}

// ============================================================================
// Helper Functions
// ============================================================================

// applyOverrides applies override values to variables
func (s *SyncService) applyOverrides(variables []*models.ConfigVariable, overrides map[string]string) []*models.ConfigVariable {
	result := make([]*models.ConfigVariable, 0, len(variables)+len(overrides))

	// Create a map for quick lookup
	varMap := make(map[string]*models.ConfigVariable)
	for _, v := range variables {
		varMap[v.Name] = v
	}

	// Apply overrides
	for name, value := range overrides {
		if existing, ok := varMap[name]; ok {
			// Override existing
			newVar := *existing
			newVar.Value = value
			varMap[name] = &newVar
		} else {
			// Add new
			varMap[name] = &models.ConfigVariable{
				ID:    uuid.New(),
				Name:  name,
				Value: value,
				Type:  models.VariableTypePlain,
				Scope: models.VariableScopeContainer,
			}
		}
	}

	// Convert back to slice
	for _, v := range varMap {
		result = append(result, v)
	}

	// Sort by name for consistent ordering
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result
}

// computeVariablesHash computes SHA-256 hash of variables
func (s *SyncService) computeVariablesHash(variables []*models.ConfigVariable) string {
	// Sort by name for consistent hash
	sorted := make([]*models.ConfigVariable, len(variables))
	copy(sorted, variables)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	h := sha256.New()
	for _, v := range sorted {
		h.Write([]byte(v.Name))
		h.Write([]byte("="))
		h.Write([]byte(v.Value))
		h.Write([]byte("\n"))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// calculateDiff calculates the difference between current and new config
func (s *SyncService) calculateDiff(ctx context.Context, opts SyncOptions, existing *models.ConfigSync, newVars []*models.ConfigVariable) (*models.ConfigDiff, error) {
	diff := &models.ConfigDiff{
		ContainerID:     opts.ContainerID,
		ContainerName:   opts.ContainerName,
		Added:           []models.DiffEntry{},
		Modified:        []models.DiffEntry{},
		Removed:         []models.DiffEntry{},
		RequiresRestart: false,
	}

	// Get old variables (we need to reconstruct from template)
	var oldTemplateName *string
	if existing.TemplateName != nil {
		oldTemplateName = existing.TemplateName
	}

	oldVars, err := s.variableRepo.ResolveForContainer(ctx, opts.ContainerID, oldTemplateName)
	if err != nil {
		return diff, err
	}

	// Create maps for comparison
	oldMap := make(map[string]*models.ConfigVariable)
	for _, v := range oldVars {
		oldMap[v.Name] = v
	}

	newMap := make(map[string]*models.ConfigVariable)
	for _, v := range newVars {
		newMap[v.Name] = v
	}

	// Find added and modified
	for name, newVar := range newMap {
		if oldVar, exists := oldMap[name]; exists {
			if oldVar.Value != newVar.Value {
				diff.Modified = append(diff.Modified, models.DiffEntry{
					Name:     name,
					OldValue: maskValue(oldVar.Value, oldVar.Type),
					NewValue: maskValue(newVar.Value, newVar.Type),
					IsSecret: newVar.Type == models.VariableTypeSecret,
				})
				diff.RequiresRestart = true
			}
		} else {
			diff.Added = append(diff.Added, models.DiffEntry{
				Name:     name,
				NewValue: maskValue(newVar.Value, newVar.Type),
				IsSecret: newVar.Type == models.VariableTypeSecret,
			})
			diff.RequiresRestart = true
		}
	}

	// Find removed
	for name, oldVar := range oldMap {
		if _, exists := newMap[name]; !exists {
			diff.Removed = append(diff.Removed, models.DiffEntry{
				Name:     name,
				OldValue: maskValue(oldVar.Value, oldVar.Type),
				IsSecret: oldVar.Type == models.VariableTypeSecret,
			})
			diff.RequiresRestart = true
		}
	}

	return diff, nil
}

// maskValue masks secret values
func maskValue(value string, varType models.VariableType) string {
	if varType == models.VariableTypeSecret {
		return "********"
	}
	return value
}

// logSyncAudit logs a sync operation to audit
func (s *SyncService) logSyncAudit(ctx context.Context, containerID, containerName string, templateName *string, userID *uuid.UUID) {
	entry := &postgres.AuditLogEntry{
		Action:     "sync",
		EntityType: "sync",
		EntityID:   containerID,
		EntityName: containerName,
		UserID:     userID,
	}

	if templateName != nil {
		value := *templateName
		entry.NewValue = &value
	}

	if err := s.auditRepo.Create(ctx, entry); err != nil {
		s.logger.Warn("Failed to create sync audit log", "error", err)
	}
}

// countSuccess counts successful results
func countSuccess(results []*SyncResult) int {
	count := 0
	for _, r := range results {
		if r.Success {
			count++
		}
	}
	return count
}

// ============================================================================
// Validation Helpers
// ============================================================================

// ValidateVariablesForSync validates that all required variables are present
func (s *SyncService) ValidateVariablesForSync(ctx context.Context, variables []*models.ConfigVariable) error {
	// Check for required variables without values
	for _, v := range variables {
		if v.IsRequired && v.Value == "" && v.DefaultValue == nil {
			return errors.InvalidInput(fmt.Sprintf("required variable %s has no value", v.Name))
		}
	}

	// Validate interpolation
	varMap := make(map[string]string)
	for _, v := range variables {
		varMap[v.Name] = v.Value
	}

	for _, v := range variables {
		if s.interpolator.HasReferences(v.Value) {
			if err := s.interpolator.ValidateInterpolation(ctx, v.Value, varMap); err != nil {
				return errors.InvalidInput(fmt.Sprintf("variable %s has invalid interpolation: %s", v.Name, err.Error()))
			}
		}
	}

	return nil
}
