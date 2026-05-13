// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package gitsync

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Interfaces
// ============================================================================

// Repository defines the data access interface for git sync.
type Repository interface {
	CreateConfig(ctx context.Context, cfg *models.GitSyncConfig) error
	GetConfig(ctx context.Context, id uuid.UUID) (*models.GitSyncConfig, error)
	ListConfigs(ctx context.Context) ([]*models.GitSyncConfig, error)
	ListConfigsByConnection(ctx context.Context, connectionID uuid.UUID) ([]*models.GitSyncConfig, error)
	UpdateConfig(ctx context.Context, cfg *models.GitSyncConfig) error
	DeleteConfig(ctx context.Context, id uuid.UUID) error
	UpdateSyncStatus(ctx context.Context, id uuid.UUID, status string, syncError string) error
	ToggleConfig(ctx context.Context, id uuid.UUID) (bool, error)
	CreateEvent(ctx context.Context, evt *models.GitSyncEvent) error
	ListEvents(ctx context.Context, configID uuid.UUID, limit int) ([]*models.GitSyncEvent, error)
	CreateConflict(ctx context.Context, c *models.GitSyncConflict) error
	ListConflicts(ctx context.Context, configID uuid.UUID, resolution string) ([]*models.GitSyncConflict, error)
	ResolveConflict(ctx context.Context, id uuid.UUID, resolution string, resolvedBy uuid.UUID, mergedContent *string) error
	GetConflict(ctx context.Context, id uuid.UUID) (*models.GitSyncConflict, error)
}

// GitProvider abstracts Git operations (reading/writing files via Git hosting API).
type GitProvider interface {
	GetFileContent(ctx context.Context, repoFullName, path, ref string) (*models.GitFileContent, error)
	CreateOrUpdateFile(ctx context.Context, repoFullName, path string, content []byte, message, branch, sha string) error
	ListTree(ctx context.Context, repoFullName, path, ref string) ([]models.GitTreeEntry, error)
	GetLatestCommit(ctx context.Context, repoFullName, branch string) (*models.GitCommit, error)
}

// StackProvider abstracts Docker stack operations.
type StackProvider interface {
	GetStackCompose(ctx context.Context, stackName string) (string, error)
	DeployStack(ctx context.Context, stackName string, composeContent string) error
	ListStacks(ctx context.Context) ([]string, error)
}

// ============================================================================
// Configuration
// ============================================================================

// Config holds service configuration.
type Config struct {
	SyncIntervalSeconds int
	MaxConflicts        int
	DefaultBranch       string
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		SyncIntervalSeconds: 300, // 5 minutes
		MaxConflicts:        100,
		DefaultBranch:       "main",
	}
}

// ============================================================================
// Input / Output Types
// ============================================================================

// CreateSyncInput holds the input for creating a new sync configuration.
type CreateSyncInput struct {
	ConnectionID          uuid.UUID                `json:"connection_id"`
	RepositoryID          uuid.UUID                `json:"repository_id"`
	RepoFullName          string                   `json:"repo_full_name"`
	Name                  string                   `json:"name"`
	SyncDirection         models.SyncDirection     `json:"sync_direction"`
	TargetPath            string                   `json:"target_path"`
	StackName             string                   `json:"stack_name"`
	FilePattern           string                   `json:"file_pattern"`
	Branch                string                   `json:"branch"`
	AutoCommit            bool                     `json:"auto_commit"`
	AutoDeploy            bool                     `json:"auto_deploy"`
	CommitMessageTemplate string                   `json:"commit_message_template"`
	ConflictStrategy      models.ConflictStrategy  `json:"conflict_strategy"`
	CreatedBy             *uuid.UUID               `json:"created_by,omitempty"`
}

// UpdateSyncInput holds editable fields for updating a sync configuration.
type UpdateSyncInput struct {
	Name                  *string
	SyncDirection         *models.SyncDirection
	TargetPath            *string
	StackName             *string
	FilePattern           *string
	Branch                *string
	AutoCommit            *bool
	AutoDeploy            *bool
	CommitMessageTemplate *string
	ConflictStrategy      *models.ConflictStrategy
}

// SyncResult describes the outcome of a sync operation.
type SyncResult struct {
	Direction    models.SyncDirection `json:"direction"`
	Status       string               `json:"status"` // success, no_changes, conflict, error
	CommitSHA    string               `json:"commit_sha,omitempty"`
	FilesChanged []string             `json:"files_changed,omitempty"`
	Message      string               `json:"message"`
}

// SyncStats provides aggregate statistics about sync configurations.
type SyncStats struct {
	TotalConfigs     int `json:"total_configs"`
	ActiveConfigs    int `json:"active_configs"`
	TotalSyncs       int `json:"total_syncs"`
	PendingConflicts int `json:"pending_conflicts"`
}

// ============================================================================
// Service
// ============================================================================

// Service provides bidirectional Git sync operations.
type Service struct {
	repo   Repository
	config Config
	logger *logger.Logger
}

// NewService creates a new git sync service.
func NewService(repo Repository, cfg Config, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		repo:   repo,
		config: cfg,
		logger: log.Named("gitsync"),
	}
}

// ============================================================================
// CRUD Operations
// ============================================================================

// CreateSyncConfig creates a new sync configuration.
func (s *Service) CreateSyncConfig(ctx context.Context, input CreateSyncInput) (*models.GitSyncConfig, error) {
	// Validate required fields.
	if input.Name == "" {
		return nil, errors.New(errors.CodeBadRequest, "name is required")
	}
	if input.ConnectionID == uuid.Nil {
		return nil, errors.New(errors.CodeBadRequest, "connection_id is required")
	}
	if input.RepositoryID == uuid.Nil {
		return nil, errors.New(errors.CodeBadRequest, "repository_id is required")
	}
	if input.RepoFullName == "" {
		return nil, errors.New(errors.CodeBadRequest, "repo_full_name is required (e.g. org/repo)")
	}

	// Validate sync direction.
	switch input.SyncDirection {
	case models.SyncDirectionToGit, models.SyncDirectionFromGit, models.SyncDirectionBidirectional:
		// valid
	default:
		return nil, errors.New(errors.CodeBadRequest, "invalid sync_direction: must be to_git, from_git, or bidirectional")
	}

	// Apply defaults.
	if input.Branch == "" {
		input.Branch = s.config.DefaultBranch
	}
	if input.TargetPath == "" {
		input.TargetPath = "/"
	}
	if input.FilePattern == "" {
		input.FilePattern = "docker-compose.yml"
	}
	if input.CommitMessageTemplate == "" {
		input.CommitMessageTemplate = "chore: sync {{.Resource}} via usulnet at {{.Timestamp}}"
	}
	if input.ConflictStrategy == "" {
		input.ConflictStrategy = models.ConflictStrategyManual
	}

	now := time.Now()
	cfg := &models.GitSyncConfig{
		ID:                    uuid.New(),
		ConnectionID:          input.ConnectionID,
		RepositoryID:          input.RepositoryID,
		RepoFullName:          input.RepoFullName,
		Name:                  input.Name,
		SyncDirection:         input.SyncDirection,
		TargetPath:            input.TargetPath,
		StackName:             input.StackName,
		FilePattern:           input.FilePattern,
		Branch:                input.Branch,
		AutoCommit:            input.AutoCommit,
		AutoDeploy:            input.AutoDeploy,
		CommitMessageTemplate: input.CommitMessageTemplate,
		ConflictStrategy:      input.ConflictStrategy,
		IsEnabled:             true,
		LastSyncStatus:        "pending",
		CreatedBy:             input.CreatedBy,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	if err := s.repo.CreateConfig(ctx, cfg); err != nil {
		s.logger.Error("failed to create sync config", "name", input.Name, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create sync config")
	}

	s.logger.Info("sync config created",
		"id", cfg.ID,
		"name", cfg.Name,
		"direction", cfg.SyncDirection,
		"branch", cfg.Branch,
	)
	return cfg, nil
}

// GetConfig retrieves a sync configuration by ID.
func (s *Service) GetConfig(ctx context.Context, id uuid.UUID) (*models.GitSyncConfig, error) {
	return s.repo.GetConfig(ctx, id)
}

// ListConfigs returns all sync configurations.
func (s *Service) ListConfigs(ctx context.Context) ([]*models.GitSyncConfig, error) {
	return s.repo.ListConfigs(ctx)
}

// UpdateConfig updates editable fields on a sync configuration.
func (s *Service) UpdateConfig(ctx context.Context, id uuid.UUID, input UpdateSyncInput) error {
	cfg, err := s.repo.GetConfig(ctx, id)
	if err != nil {
		return err
	}

	if input.Name != nil {
		if *input.Name == "" {
			return errors.New(errors.CodeBadRequest, "name cannot be empty")
		}
		cfg.Name = *input.Name
	}
	if input.SyncDirection != nil {
		switch *input.SyncDirection {
		case models.SyncDirectionToGit, models.SyncDirectionFromGit, models.SyncDirectionBidirectional:
			cfg.SyncDirection = *input.SyncDirection
		default:
			return errors.New(errors.CodeBadRequest, "invalid sync_direction")
		}
	}
	if input.TargetPath != nil {
		cfg.TargetPath = *input.TargetPath
	}
	if input.StackName != nil {
		cfg.StackName = *input.StackName
	}
	if input.FilePattern != nil {
		cfg.FilePattern = *input.FilePattern
	}
	if input.Branch != nil {
		cfg.Branch = *input.Branch
	}
	if input.AutoCommit != nil {
		cfg.AutoCommit = *input.AutoCommit
	}
	if input.AutoDeploy != nil {
		cfg.AutoDeploy = *input.AutoDeploy
	}
	if input.CommitMessageTemplate != nil {
		cfg.CommitMessageTemplate = *input.CommitMessageTemplate
	}
	if input.ConflictStrategy != nil {
		cfg.ConflictStrategy = *input.ConflictStrategy
	}

	cfg.UpdatedAt = time.Now()

	if err := s.repo.UpdateConfig(ctx, cfg); err != nil {
		s.logger.Error("failed to update sync config", "id", id, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to update sync config")
	}

	s.logger.Info("sync config updated", "id", id, "name", cfg.Name)
	return nil
}

// DeleteConfig removes a sync configuration.
func (s *Service) DeleteConfig(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.DeleteConfig(ctx, id); err != nil {
		s.logger.Error("failed to delete sync config", "id", id, "error", err)
		return err
	}
	s.logger.Info("sync config deleted", "id", id)
	return nil
}

// ToggleConfig enables or disables a sync configuration and returns the new state.
func (s *Service) ToggleConfig(ctx context.Context, id uuid.UUID) (bool, error) {
	enabled, err := s.repo.ToggleConfig(ctx, id)
	if err != nil {
		s.logger.Error("failed to toggle sync config", "id", id, "error", err)
		return false, err
	}
	s.logger.Info("sync config toggled", "id", id, "enabled", enabled)
	return enabled, nil
}

// ============================================================================
// Sync Operations
// ============================================================================

// SyncToGit pushes UI (stack compose) changes to the Git repository.
func (s *Service) SyncToGit(ctx context.Context, configID uuid.UUID, gitProvider GitProvider, stackProvider StackProvider) (*SyncResult, error) {
	cfg, err := s.repo.GetConfig(ctx, configID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "sync config not found")
	}

	result := &SyncResult{
		Direction: models.SyncDirectionToGit,
	}

	// Fetch compose content from the UI / stack provider.
	uiContent, err := stackProvider.GetStackCompose(ctx, cfg.StackName)
	if err != nil {
		s.recordSyncFailure(ctx, cfg, models.SyncDirectionToGit, fmt.Sprintf("failed to get stack compose: %v", err))
		result.Status = "error"
		result.Message = fmt.Sprintf("failed to get stack compose: %v", err)
		s.logger.Error("sync to git: failed to get stack compose",
			"config_id", configID, "stack", cfg.StackName, "error", err)
		return result, err
	}

	// Build the full file path in the repo.
	filePath := buildFilePath(cfg.TargetPath, cfg.FilePattern)

	// Get current file content from Git (may not exist yet).
	var existingSHA string
	gitFile, err := gitProvider.GetFileContent(ctx, cfg.RepoFullName, filePath, cfg.Branch)
	if err == nil && gitFile != nil {
		existingSHA = gitFile.SHA
		// Compare contents: if unchanged, skip.
		if string(gitFile.Content) == uiContent {
			result.Status = "no_changes"
			result.Message = "stack content matches Git; nothing to push"
			s.logger.Info("sync to git: no changes detected", "config_id", configID)
			return result, nil
		}
	}
	// If the file does not exist in Git, existingSHA will be empty and we create a new file.

	// Build commit message from the template.
	commitMsg := buildCommitMessage(cfg.CommitMessageTemplate, cfg.StackName)

	// Push updated content to Git.
	if err := gitProvider.CreateOrUpdateFile(ctx, cfg.RepoFullName, filePath, []byte(uiContent), commitMsg, cfg.Branch, existingSHA); err != nil {
		s.recordSyncFailure(ctx, cfg, models.SyncDirectionToGit, fmt.Sprintf("failed to push file to git: %v", err))
		result.Status = "error"
		result.Message = fmt.Sprintf("failed to push file to git: %v", err)
		s.logger.Error("sync to git: failed to push file",
			"config_id", configID, "path", filePath, "error", err)
		return result, err
	}

	// Attempt to get the latest commit SHA after push.
	var commitSHA string
	latestCommit, err := gitProvider.GetLatestCommit(ctx, cfg.RepoFullName, cfg.Branch)
	if err == nil && latestCommit != nil {
		commitSHA = latestCommit.SHA
	}

	// Record a sync event.
	filesChanged := []string{filePath}
	filesJSON, _ := json.Marshal(filesChanged)

	evt := &models.GitSyncEvent{
		ID:            uuid.New(),
		ConfigID:      configID,
		Direction:     models.SyncDirectionToGit,
		EventType:     models.SyncEventCommitPushed,
		Status:        "success",
		CommitSHA:     commitSHA,
		CommitMessage: commitMsg,
		FilesChanged:  filesJSON,
		CreatedAt:     time.Now(),
	}
	if createErr := s.repo.CreateEvent(ctx, evt); createErr != nil {
		s.logger.Error("failed to record sync event", "config_id", configID, "error", createErr)
	}

	// Update sync status.
	if statusErr := s.repo.UpdateSyncStatus(ctx, configID, "success", ""); statusErr != nil {
		s.logger.Error("failed to update sync status", "config_id", configID, "error", statusErr)
	}

	result.Status = "success"
	result.CommitSHA = commitSHA
	result.FilesChanged = filesChanged
	result.Message = "stack content pushed to Git successfully"

	s.logger.Info("sync to git: completed",
		"config_id", configID,
		"commit_sha", commitSHA,
		"files_changed", filesChanged,
	)
	return result, nil
}

// SyncFromGit pulls file content from Git and optionally deploys it to the UI stack.
func (s *Service) SyncFromGit(ctx context.Context, configID uuid.UUID, gitProvider GitProvider, stackProvider StackProvider) (*SyncResult, error) {
	cfg, err := s.repo.GetConfig(ctx, configID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "sync config not found")
	}

	result := &SyncResult{
		Direction: models.SyncDirectionFromGit,
	}

	filePath := buildFilePath(cfg.TargetPath, cfg.FilePattern)

	// Get file content from Git.
	gitFile, err := gitProvider.GetFileContent(ctx, cfg.RepoFullName, filePath, cfg.Branch)
	if err != nil {
		s.recordSyncFailure(ctx, cfg, models.SyncDirectionFromGit, fmt.Sprintf("failed to get file from git: %v", err))
		result.Status = "error"
		result.Message = fmt.Sprintf("failed to get file from git: %v", err)
		s.logger.Error("sync from git: failed to get file",
			"config_id", configID, "path", filePath, "error", err)
		return result, err
	}

	gitContent := string(gitFile.Content)

	// Get current stack compose content from the UI.
	uiContent, err := stackProvider.GetStackCompose(ctx, cfg.StackName)
	if err != nil {
		s.recordSyncFailure(ctx, cfg, models.SyncDirectionFromGit, fmt.Sprintf("failed to get stack compose: %v", err))
		result.Status = "error"
		result.Message = fmt.Sprintf("failed to get stack compose: %v", err)
		s.logger.Error("sync from git: failed to get stack compose",
			"config_id", configID, "stack", cfg.StackName, "error", err)
		return result, err
	}

	// Compare contents: if the same, skip.
	if gitContent == uiContent {
		result.Status = "no_changes"
		result.Message = "Git content matches UI stack; nothing to pull"
		s.logger.Info("sync from git: no changes detected", "config_id", configID)
		return result, nil
	}

	filesChanged := []string{filePath}
	eventType := models.SyncEventFileUpdated

	// Deploy if auto_deploy is enabled.
	if cfg.AutoDeploy {
		if deployErr := stackProvider.DeployStack(ctx, cfg.StackName, gitContent); deployErr != nil {
			s.recordSyncFailure(ctx, cfg, models.SyncDirectionFromGit, fmt.Sprintf("failed to deploy stack: %v", deployErr))
			result.Status = "error"
			result.Message = fmt.Sprintf("failed to deploy stack from Git content: %v", deployErr)
			s.logger.Error("sync from git: failed to deploy stack",
				"config_id", configID, "stack", cfg.StackName, "error", deployErr)
			return result, deployErr
		}
		eventType = models.SyncEventDeployTriggered
		s.logger.Info("sync from git: stack deployed",
			"config_id", configID, "stack", cfg.StackName)
	}

	// Record event.
	filesJSON, _ := json.Marshal(filesChanged)
	evt := &models.GitSyncEvent{
		ID:           uuid.New(),
		ConfigID:     configID,
		Direction:    models.SyncDirectionFromGit,
		EventType:    eventType,
		Status:       "success",
		CommitSHA:    gitFile.SHA,
		FilesChanged: filesJSON,
		CreatedAt:    time.Now(),
	}
	if createErr := s.repo.CreateEvent(ctx, evt); createErr != nil {
		s.logger.Error("failed to record sync event", "config_id", configID, "error", createErr)
	}

	// Update sync status.
	if statusErr := s.repo.UpdateSyncStatus(ctx, configID, "success", ""); statusErr != nil {
		s.logger.Error("failed to update sync status", "config_id", configID, "error", statusErr)
	}

	result.Status = "success"
	result.CommitSHA = gitFile.SHA
	result.FilesChanged = filesChanged
	if cfg.AutoDeploy {
		result.Message = "Git content pulled and deployed to stack successfully"
	} else {
		result.Message = "Git content differs from UI; recorded event (auto_deploy disabled)"
	}

	s.logger.Info("sync from git: completed",
		"config_id", configID,
		"commit_sha", gitFile.SHA,
		"auto_deploy", cfg.AutoDeploy,
	)
	return result, nil
}

// SyncBidirectional detects changes in both Git and UI, applies the appropriate direction,
// or creates a conflict when both sides have changed.
func (s *Service) SyncBidirectional(ctx context.Context, configID uuid.UUID, gitProvider GitProvider, stackProvider StackProvider) (*SyncResult, error) {
	cfg, err := s.repo.GetConfig(ctx, configID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "sync config not found")
	}

	result := &SyncResult{
		Direction: models.SyncDirectionBidirectional,
	}

	filePath := buildFilePath(cfg.TargetPath, cfg.FilePattern)

	// Get Git content.
	gitFile, gitErr := gitProvider.GetFileContent(ctx, cfg.RepoFullName, filePath, cfg.Branch)
	var gitContent string
	var gitSHA string
	if gitErr == nil && gitFile != nil {
		gitContent = string(gitFile.Content)
		gitSHA = gitFile.SHA
	}

	// Get UI content.
	uiContent, uiErr := stackProvider.GetStackCompose(ctx, cfg.StackName)
	if uiErr != nil {
		s.recordSyncFailure(ctx, cfg, models.SyncDirectionBidirectional, fmt.Sprintf("failed to get stack compose: %v", uiErr))
		result.Status = "error"
		result.Message = fmt.Sprintf("failed to get stack compose: %v", uiErr)
		s.logger.Error("bidirectional sync: failed to get stack compose",
			"config_id", configID, "stack", cfg.StackName, "error", uiErr)
		return result, uiErr
	}

	// Determine what changed relative to each other.
	gitExists := gitErr == nil && gitFile != nil
	gitChanged := !gitExists || gitContent != uiContent
	uiChanged := !gitExists || uiContent != gitContent

	// If both contents are equal, nothing to do.
	if gitExists && gitContent == uiContent {
		result.Status = "no_changes"
		result.Message = "Git and UI content are identical; nothing to sync"
		s.logger.Info("bidirectional sync: no changes detected", "config_id", configID)
		return result, nil
	}

	// If Git file does not exist, push UI content to Git.
	if !gitExists {
		s.logger.Info("bidirectional sync: no Git file found, pushing UI to Git", "config_id", configID)
		return s.SyncToGit(ctx, configID, gitProvider, stackProvider)
	}

	// Both sides differ from each other.  We need to determine which side changed.
	// Without a stored baseline/last-known content we treat any difference as a potential
	// conflict when both sides exist and differ.
	// If only one side has meaningful content, or a conflict strategy auto-resolves, proceed.

	_ = gitChanged
	_ = uiChanged

	// Apply conflict strategy.
	switch cfg.ConflictStrategy {
	case models.ConflictStrategyPreferGit:
		// Use Git content: deploy to UI if auto_deploy.
		s.logger.Info("bidirectional sync: conflict strategy prefer_git, applying Git content",
			"config_id", configID)
		return s.applyFromGit(ctx, cfg, gitContent, gitSHA, filePath, stackProvider)

	case models.ConflictStrategyPreferUI:
		// Use UI content: push to Git.
		s.logger.Info("bidirectional sync: conflict strategy prefer_ui, pushing UI content",
			"config_id", configID)
		return s.applyToGit(ctx, cfg, uiContent, gitSHA, filePath, gitProvider)

	case models.ConflictStrategyManual:
		// Create a conflict record for manual resolution.
		s.logger.Info("bidirectional sync: conflict detected, creating conflict record",
			"config_id", configID)

		conflictEvt := &models.GitSyncEvent{
			ID:        uuid.New(),
			ConfigID:  configID,
			Direction: models.SyncDirectionBidirectional,
			EventType: models.SyncEventConflictDetected,
			Status:    "conflict",
			CommitSHA: gitSHA,
			CreatedAt: time.Now(),
		}
		if createErr := s.repo.CreateEvent(ctx, conflictEvt); createErr != nil {
			s.logger.Error("failed to record conflict event", "config_id", configID, "error", createErr)
		}

		conflict := &models.GitSyncConflict{
			ID:         uuid.New(),
			ConfigID:   configID,
			EventID:    &conflictEvt.ID,
			FilePath:   filePath,
			GitContent: gitContent,
			UIContent:  uiContent,
			Resolution: models.ConflictResolutionPending,
			CreatedAt:  time.Now(),
		}
		if createErr := s.repo.CreateConflict(ctx, conflict); createErr != nil {
			s.logger.Error("failed to create conflict record", "config_id", configID, "error", createErr)
			result.Status = "error"
			result.Message = fmt.Sprintf("failed to create conflict record: %v", createErr)
			return result, createErr
		}

		if statusErr := s.repo.UpdateSyncStatus(ctx, configID, "conflict", "bidirectional conflict detected"); statusErr != nil {
			s.logger.Error("failed to update sync status", "config_id", configID, "error", statusErr)
		}

		result.Status = "conflict"
		result.CommitSHA = gitSHA
		result.FilesChanged = []string{filePath}
		result.Message = "conflict detected between Git and UI; manual resolution required"
		return result, nil

	default:
		result.Status = "error"
		result.Message = fmt.Sprintf("unknown conflict strategy: %s", cfg.ConflictStrategy)
		return result, errors.New(errors.CodeBadRequest, result.Message)
	}
}

// ============================================================================
// Conflict Management
// ============================================================================

// ListConflicts returns conflicts for a sync configuration filtered by resolution status.
func (s *Service) ListConflicts(ctx context.Context, configID uuid.UUID, resolution string) ([]*models.GitSyncConflict, error) {
	return s.repo.ListConflicts(ctx, configID, resolution)
}

// ResolveConflict resolves a sync conflict with the given resolution.
func (s *Service) ResolveConflict(ctx context.Context, conflictID uuid.UUID, resolution models.ConflictResolution, resolvedBy uuid.UUID, mergedContent *string) error {
	// Validate resolution value.
	switch resolution {
	case models.ConflictResolutionUseGit, models.ConflictResolutionUseUI, models.ConflictResolutionMerged, models.ConflictResolutionDismissed:
		// valid
	default:
		return errors.New(errors.CodeBadRequest, "invalid resolution: must be use_git, use_ui, merged, or dismissed")
	}

	// If resolution is "merged", merged content is required.
	if resolution == models.ConflictResolutionMerged {
		if mergedContent == nil || *mergedContent == "" {
			return errors.New(errors.CodeBadRequest, "merged_content is required when resolution is 'merged'")
		}
	}

	// Verify the conflict exists.
	if _, err := s.repo.GetConflict(ctx, conflictID); err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "conflict not found")
	}

	if err := s.repo.ResolveConflict(ctx, conflictID, string(resolution), resolvedBy, mergedContent); err != nil {
		s.logger.Error("failed to resolve conflict", "conflict_id", conflictID, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to resolve conflict")
	}

	s.logger.Info("conflict resolved",
		"conflict_id", conflictID,
		"resolution", resolution,
		"resolved_by", resolvedBy,
	)
	return nil
}

// ============================================================================
// Events
// ============================================================================

// GetSyncEvents returns recent sync events for a configuration.
func (s *Service) GetSyncEvents(ctx context.Context, configID uuid.UUID, limit int) ([]*models.GitSyncEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.repo.ListEvents(ctx, configID, limit)
}

// ============================================================================
// Statistics
// ============================================================================

// GetSyncStats returns aggregate statistics about sync configurations.
func (s *Service) GetSyncStats(ctx context.Context) (*SyncStats, error) {
	configs, err := s.repo.ListConfigs(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list configs for stats")
	}

	stats := &SyncStats{
		TotalConfigs: len(configs),
	}

	for _, cfg := range configs {
		if cfg.IsEnabled {
			stats.ActiveConfigs++
		}
		stats.TotalSyncs += cfg.SyncCount
	}

	// Count pending conflicts across all configs.
	for _, cfg := range configs {
		conflicts, err := s.repo.ListConflicts(ctx, cfg.ID, string(models.ConflictResolutionPending))
		if err != nil {
			s.logger.Error("failed to list conflicts for stats", "config_id", cfg.ID, "error", err)
			continue
		}
		stats.PendingConflicts += len(conflicts)
	}

	return stats, nil
}

// ============================================================================
// Internal Helpers
// ============================================================================

// applyFromGit applies Git content to the UI side (deploys if auto_deploy is set).
func (s *Service) applyFromGit(ctx context.Context, cfg *models.GitSyncConfig, gitContent, gitSHA, filePath string, stackProvider StackProvider) (*SyncResult, error) {
	result := &SyncResult{
		Direction: models.SyncDirectionBidirectional,
	}

	eventType := models.SyncEventFileUpdated

	if cfg.AutoDeploy {
		if deployErr := stackProvider.DeployStack(ctx, cfg.StackName, gitContent); deployErr != nil {
			s.recordSyncFailure(ctx, cfg, models.SyncDirectionBidirectional, fmt.Sprintf("failed to deploy stack: %v", deployErr))
			result.Status = "error"
			result.Message = fmt.Sprintf("failed to deploy stack from Git content: %v", deployErr)
			s.logger.Error("bidirectional sync: failed to deploy stack",
				"config_id", cfg.ID, "stack", cfg.StackName, "error", deployErr)
			return result, deployErr
		}
		eventType = models.SyncEventDeployTriggered
	}

	filesChanged := []string{filePath}
	filesJSON, _ := json.Marshal(filesChanged)
	evt := &models.GitSyncEvent{
		ID:           uuid.New(),
		ConfigID:     cfg.ID,
		Direction:    models.SyncDirectionBidirectional,
		EventType:    eventType,
		Status:       "success",
		CommitSHA:    gitSHA,
		FilesChanged: filesJSON,
		CreatedAt:    time.Now(),
	}
	if createErr := s.repo.CreateEvent(ctx, evt); createErr != nil {
		s.logger.Error("failed to record sync event", "config_id", cfg.ID, "error", createErr)
	}

	if statusErr := s.repo.UpdateSyncStatus(ctx, cfg.ID, "success", ""); statusErr != nil {
		s.logger.Error("failed to update sync status", "config_id", cfg.ID, "error", statusErr)
	}

	result.Status = "success"
	result.CommitSHA = gitSHA
	result.FilesChanged = filesChanged
	if cfg.AutoDeploy {
		result.Message = "Git content applied and deployed to stack (prefer_git strategy)"
	} else {
		result.Message = "Git content recorded (prefer_git strategy, auto_deploy disabled)"
	}

	s.logger.Info("bidirectional sync: applied Git content",
		"config_id", cfg.ID,
		"auto_deploy", cfg.AutoDeploy,
	)
	return result, nil
}

// applyToGit pushes UI content to Git.
func (s *Service) applyToGit(ctx context.Context, cfg *models.GitSyncConfig, uiContent, existingSHA, filePath string, gitProvider GitProvider) (*SyncResult, error) {
	result := &SyncResult{
		Direction: models.SyncDirectionBidirectional,
	}

	commitMsg := buildCommitMessage(cfg.CommitMessageTemplate, cfg.StackName)

	if err := gitProvider.CreateOrUpdateFile(ctx, cfg.RepoFullName, filePath, []byte(uiContent), commitMsg, cfg.Branch, existingSHA); err != nil {
		s.recordSyncFailure(ctx, cfg, models.SyncDirectionBidirectional, fmt.Sprintf("failed to push file to git: %v", err))
		result.Status = "error"
		result.Message = fmt.Sprintf("failed to push UI content to Git: %v", err)
		s.logger.Error("bidirectional sync: failed to push to Git",
			"config_id", cfg.ID, "path", filePath, "error", err)
		return result, err
	}

	var commitSHA string
	latestCommit, err := gitProvider.GetLatestCommit(ctx, cfg.RepoFullName, cfg.Branch)
	if err == nil && latestCommit != nil {
		commitSHA = latestCommit.SHA
	}

	filesChanged := []string{filePath}
	filesJSON, _ := json.Marshal(filesChanged)
	evt := &models.GitSyncEvent{
		ID:            uuid.New(),
		ConfigID:      cfg.ID,
		Direction:     models.SyncDirectionBidirectional,
		EventType:     models.SyncEventCommitPushed,
		Status:        "success",
		CommitSHA:     commitSHA,
		CommitMessage: commitMsg,
		FilesChanged:  filesJSON,
		CreatedAt:     time.Now(),
	}
	if createErr := s.repo.CreateEvent(ctx, evt); createErr != nil {
		s.logger.Error("failed to record sync event", "config_id", cfg.ID, "error", createErr)
	}

	if statusErr := s.repo.UpdateSyncStatus(ctx, cfg.ID, "success", ""); statusErr != nil {
		s.logger.Error("failed to update sync status", "config_id", cfg.ID, "error", statusErr)
	}

	result.Status = "success"
	result.CommitSHA = commitSHA
	result.FilesChanged = filesChanged
	result.Message = "UI content pushed to Git (prefer_ui strategy)"

	s.logger.Info("bidirectional sync: pushed UI content to Git",
		"config_id", cfg.ID,
		"commit_sha", commitSHA,
	)
	return result, nil
}

// recordSyncFailure updates the sync status to "failed" and records a failure event.
func (s *Service) recordSyncFailure(ctx context.Context, cfg *models.GitSyncConfig, direction models.SyncDirection, errMsg string) {
	if statusErr := s.repo.UpdateSyncStatus(ctx, cfg.ID, "failed", errMsg); statusErr != nil {
		s.logger.Error("failed to update sync status on failure", "config_id", cfg.ID, "error", statusErr)
	}

	evt := &models.GitSyncEvent{
		ID:           uuid.New(),
		ConfigID:     cfg.ID,
		Direction:    direction,
		EventType:    models.SyncEventSyncFailed,
		Status:       "failed",
		ErrorMessage: errMsg,
		CreatedAt:    time.Now(),
	}
	if createErr := s.repo.CreateEvent(ctx, evt); createErr != nil {
		s.logger.Error("failed to record failure event", "config_id", cfg.ID, "error", createErr)
	}
}

// buildFilePath constructs the full file path from target path and file pattern.
func buildFilePath(targetPath, filePattern string) string {
	targetPath = strings.TrimRight(targetPath, "/")
	if targetPath == "" || targetPath == "/" {
		return filePattern
	}
	return path.Join(targetPath, filePattern)
}

// buildCommitMessage replaces template placeholders with actual values.
func buildCommitMessage(template, stackName string) string {
	msg := strings.ReplaceAll(template, "{{.Resource}}", stackName)
	msg = strings.ReplaceAll(msg, "{{.Timestamp}}", time.Now().UTC().Format(time.RFC3339))
	return msg
}
