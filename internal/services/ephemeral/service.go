// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package ephemeral

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Interfaces
// ============================================================================

// Repository defines data access for ephemeral environments.
type Repository interface {
	Create(ctx context.Context, env *models.EphemeralEnvironment) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.EphemeralEnvironment, error)
	List(ctx context.Context, opts models.EphemeralEnvListOptions) ([]*models.EphemeralEnvironment, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.EphemeralEnvironmentStatus, errorMsg string) error
	UpdateTTL(ctx context.Context, id uuid.UUID, ttlMinutes int, expiresAt time.Time) error
	SetURL(ctx context.Context, id uuid.UUID, url string) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListExpired(ctx context.Context) ([]*models.EphemeralEnvironment, error)
	CountByStatus(ctx context.Context) (map[string]int, error)
	CreateLog(ctx context.Context, log *models.EphemeralEnvironmentLog) error
	ListLogs(ctx context.Context, environmentID uuid.UUID, limit int) ([]*models.EphemeralEnvironmentLog, error)
}

// GitFileProvider abstracts fetching files from Git repos.
type GitFileProvider interface {
	GetFileContent(ctx context.Context, repoFullName, path, ref string) (*models.GitFileContent, error)
	GetLatestCommit(ctx context.Context, repoFullName, branch string) (*models.GitCommit, error)
}

// StackDeployer abstracts Docker stack deployment operations.
type StackDeployer interface {
	DeployStack(ctx context.Context, stackName string, composeContent string, env map[string]string) error
	RemoveStack(ctx context.Context, stackName string) error
	GetStackStatus(ctx context.Context, stackName string) (string, error)
}

// ============================================================================
// Configuration
// ============================================================================

// Config holds service configuration.
type Config struct {
	MaxEnvironments     int
	DefaultTTLMinutes   int
	MaxTTLMinutes       int
	PortRangeStart      int
	PortRangeEnd        int
	StackPrefix         string
	DefaultComposePath  string
	CleanupIntervalSecs int
	BaseURL             string // base URL for generating env access URLs
}

// DefaultConfig returns the default configuration for the ephemeral environments service.
func DefaultConfig() Config {
	return Config{
		MaxEnvironments:     20,
		DefaultTTLMinutes:   1440,  // 24h
		MaxTTLMinutes:       10080, // 7 days
		PortRangeStart:      30000,
		PortRangeEnd:        32000,
		StackPrefix:         "eph",
		DefaultComposePath:  "docker-compose.yml",
		CleanupIntervalSecs: 300, // 5 minutes
		BaseURL:             "http://localhost",
	}
}

// ============================================================================
// Input / Output Types
// ============================================================================

// CreateEnvInput holds the parameters for creating an ephemeral environment.
type CreateEnvInput struct {
	Name           string            `json:"name"`
	ConnectionID   *uuid.UUID        `json:"connection_id,omitempty"`
	RepositoryID   *uuid.UUID        `json:"repository_id,omitempty"`
	Branch         string            `json:"branch"`
	ComposeContent string            `json:"compose_file"`   // optional: provide compose directly
	RepoFullName   string            `json:"repo_full_name"` // used when fetching from git
	Environment    map[string]string `json:"environment,omitempty"`
	TTLMinutes     int               `json:"ttl_minutes"`
	AutoDestroy    bool              `json:"auto_destroy"`
	ResourceLimits *ResourceLimits   `json:"resource_limits,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	CreatedBy      *uuid.UUID        `json:"created_by,omitempty"`
}

// ResourceLimits defines CPU and memory constraints for the environment.
type ResourceLimits struct {
	CPULimit    string `json:"cpu_limit"`
	MemoryLimit string `json:"memory_limit"`
}

// Dashboard holds aggregated statistics about ephemeral environments.
type Dashboard struct {
	TotalEnvironments int            `json:"total_environments"`
	StatusCounts      map[string]int `json:"status_counts"`
	ActiveCount       int            `json:"active_count"`
	ExpiredCount      int            `json:"expired_count"`
}

// ============================================================================
// Service
// ============================================================================

// Service manages the lifecycle of branch-based ephemeral Docker environments.
type Service struct {
	repo   Repository
	config Config
	logger *logger.Logger
}

// NewService creates a new ephemeral environments service.
func NewService(repo Repository, cfg Config, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		repo:   repo,
		config: cfg,
		logger: log.Named("ephemeral"),
	}
}

// ============================================================================
// CreateEnvironment
// ============================================================================

// CreateEnvironment validates the input, generates a unique stack name, and persists
// a new ephemeral environment record in "pending" status.
func (s *Service) CreateEnvironment(ctx context.Context, input CreateEnvInput) (*models.EphemeralEnvironment, error) {
	// --- validation ---
	if strings.TrimSpace(input.Name) == "" {
		return nil, apperrors.InvalidInput("environment name is required")
	}
	if strings.TrimSpace(input.Branch) == "" {
		return nil, apperrors.InvalidInput("branch is required")
	}
	if input.ComposeContent == "" && input.RepoFullName == "" {
		return nil, apperrors.InvalidInput("either compose content or repository full name must be provided")
	}

	// --- stack name ---
	stackName := generateStackName(s.config.StackPrefix, input.Branch)

	// --- TTL clamping ---
	ttl := input.TTLMinutes
	if ttl <= 0 {
		ttl = s.config.DefaultTTLMinutes
	}
	if ttl < 5 {
		ttl = 5
	}
	if ttl > s.config.MaxTTLMinutes {
		ttl = s.config.MaxTTLMinutes
	}

	expiresAt := time.Now().Add(time.Duration(ttl) * time.Minute)

	// --- marshal JSON fields ---
	envJSON, err := marshalOrNull(input.Environment)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeInternal, "failed to marshal environment variables")
	}

	resourceLimitsJSON, err := marshalOrNull(input.ResourceLimits)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeInternal, "failed to marshal resource limits")
	}

	labelsJSON, err := marshalOrNull(input.Labels)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeInternal, "failed to marshal labels")
	}

	// --- build model ---
	id := uuid.New()
	now := time.Now()

	env := &models.EphemeralEnvironment{
		ID:             id,
		Name:           strings.TrimSpace(input.Name),
		ConnectionID:   input.ConnectionID,
		RepositoryID:   input.RepositoryID,
		Branch:         input.Branch,
		RepoFullName:   input.RepoFullName,
		StackName:      stackName,
		ComposeFile:    input.ComposeContent,
		Environment:    envJSON,
		PortMappings:   json.RawMessage("{}"),
		Status:         models.EphemeralStatusPending,
		TTLMinutes:     ttl,
		AutoDestroy:    input.AutoDestroy,
		ExpiresAt:      &expiresAt,
		ResourceLimits: resourceLimitsJSON,
		Labels:         labelsJSON,
		CreatedBy:      input.CreatedBy,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	// --- persist ---
	if err := s.repo.Create(ctx, env); err != nil {
		s.logger.Error("failed to create ephemeral environment", "error", err, "name", env.Name)
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to create ephemeral environment")
	}

	// --- log creation event ---
	addLog(ctx, s.repo, id, "create", fmt.Sprintf("Environment %q created for branch %s (TTL: %dm)", env.Name, input.Branch, ttl), "info")

	s.logger.Info("ephemeral environment created",
		"id", id.String(),
		"name", env.Name,
		"branch", input.Branch,
		"stack", stackName,
		"ttl_minutes", ttl,
	)

	return env, nil
}

// ============================================================================
// ProvisionEnvironment
// ============================================================================

// ProvisionEnvironment fetches the compose file (from Git if needed), applies
// environment isolation (port offsets, network isolation, unique stack names),
// and deploys the stack via the provided StackDeployer.
func (s *Service) ProvisionEnvironment(ctx context.Context, id uuid.UUID, gitProvider GitFileProvider, deployer StackDeployer) error {
	env, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeNotFound, "ephemeral environment not found")
	}

	if env.Status != models.EphemeralStatusPending {
		return apperrors.InvalidInput(fmt.Sprintf("environment is in %q status, expected %q", env.Status, models.EphemeralStatusPending))
	}

	// --- fetch compose file from Git if needed ---
	composeContent := env.ComposeFile
	if composeContent == "" && env.RepositoryID != nil && gitProvider != nil {
		addLog(ctx, s.repo, id, "provision", "Fetching compose file from Git repository", "info")

		// Use the persisted repo full name (e.g. "org/repo") to fetch the
		// compose file from Git. This was stored at environment creation time.
		repoRef := env.RepoFullName
		if repoRef == "" && env.RepositoryID != nil {
			// Fallback to UUID string if repo_full_name was not populated
			// (e.g., environments created before migration 037).
			repoRef = env.RepositoryID.String()
		}
		composePath := s.config.DefaultComposePath

		fileContent, fetchErr := gitProvider.GetFileContent(ctx, repoRef, composePath, env.Branch)
		if fetchErr != nil {
			s.setFailed(ctx, id, fmt.Sprintf("failed to fetch compose file: %v", fetchErr))
			return apperrors.Wrap(fetchErr, apperrors.CodeExternal, "failed to fetch compose file from Git")
		}
		composeContent = string(fileContent.Content)
		env.CommitSHA = fileContent.SHA

		// Also try to get the latest commit SHA for tracking
		if commit, commitErr := gitProvider.GetLatestCommit(ctx, repoRef, env.Branch); commitErr == nil {
			env.CommitSHA = commit.SHA
		}
	}

	if composeContent == "" {
		s.setFailed(ctx, id, "no compose content available")
		return apperrors.InvalidInput("no compose content available for provisioning")
	}

	// --- apply port offsetting ---
	addLog(ctx, s.repo, id, "provision", "Applying port offset and environment isolation", "info")

	portOffset := s.calculatePortOffset(env.StackName)
	modifiedCompose, portMappings, offsetErr := offsetPorts(composeContent, portOffset)
	if offsetErr != nil {
		s.setFailed(ctx, id, fmt.Sprintf("failed to apply port offsets: %v", offsetErr))
		return apperrors.Wrap(offsetErr, apperrors.CodeInternal, "failed to apply port offsets")
	}

	// Store the port mappings
	portMappingsJSON, _ := json.Marshal(portMappings)
	env.PortMappings = portMappingsJSON

	// --- apply environment isolation: add stack-specific network ---
	networkName := fmt.Sprintf("%s-network", env.StackName)
	modifiedCompose = addNetworkIsolation(modifiedCompose, networkName)

	// --- prepare environment variables ---
	envVars := make(map[string]string)
	if len(env.Environment) > 0 {
		_ = json.Unmarshal(env.Environment, &envVars)
	}
	envVars["EPHEMERAL_ENV_ID"] = id.String()
	envVars["EPHEMERAL_STACK_NAME"] = env.StackName
	envVars["EPHEMERAL_BRANCH"] = env.Branch

	// --- update status to provisioning ---
	if updateErr := s.repo.UpdateStatus(ctx, id, models.EphemeralStatusProvisioning, ""); updateErr != nil {
		s.logger.Error("failed to update status to provisioning", "error", updateErr, "id", id.String())
	}

	addLog(ctx, s.repo, id, "provision", fmt.Sprintf("Deploying stack %q", env.StackName), "info")

	// --- deploy ---
	if deployer == nil {
		s.logger.Warn("no deployer available to deploy stack, marking as provisioning without deployment",
			"id", id.String(), "stack", env.StackName)
		addLog(ctx, s.repo, id, "provision", "No stack deployer configured — environment prepared but not deployed", "warn")
		return nil
	}
	if deployErr := deployer.DeployStack(ctx, env.StackName, modifiedCompose, envVars); deployErr != nil {
		s.setFailed(ctx, id, fmt.Sprintf("stack deployment failed: %v", deployErr))
		return apperrors.Wrap(deployErr, apperrors.CodeComposeFailed, "failed to deploy ephemeral stack")
	}

	// --- update status to running ---
	startedAt := time.Now()
	env.StartedAt = &startedAt
	if updateErr := s.repo.UpdateStatus(ctx, id, models.EphemeralStatusRunning, ""); updateErr != nil {
		s.logger.Error("failed to update status to running", "error", updateErr, "id", id.String())
	}

	// --- generate and set URL ---
	accessURL := s.generateAccessURL(portMappings)
	if accessURL != "" {
		if urlErr := s.repo.SetURL(ctx, id, accessURL); urlErr != nil {
			s.logger.Error("failed to set environment URL", "error", urlErr, "id", id.String())
		}
	}

	addLog(ctx, s.repo, id, "deploy", fmt.Sprintf("Stack deployed successfully, accessible at %s", accessURL), "info")

	s.logger.Info("ephemeral environment provisioned",
		"id", id.String(),
		"stack", env.StackName,
		"url", accessURL,
		"port_offset", portOffset,
	)

	return nil
}

// ============================================================================
// StopEnvironment
// ============================================================================

// StopEnvironment stops a running or provisioning ephemeral environment by
// removing its stack via the deployer. If deployer is nil and the environment
// has a running stack, the status is updated without removing the stack.
func (s *Service) StopEnvironment(ctx context.Context, id uuid.UUID, deployer StackDeployer) error {
	env, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeNotFound, "ephemeral environment not found")
	}

	if env.Status != models.EphemeralStatusRunning && env.Status != models.EphemeralStatusProvisioning {
		return apperrors.InvalidInput(fmt.Sprintf("environment is in %q status, must be running or provisioning to stop", env.Status))
	}

	// --- update status to stopping ---
	if updateErr := s.repo.UpdateStatus(ctx, id, models.EphemeralStatusStopping, ""); updateErr != nil {
		s.logger.Error("failed to update status to stopping", "error", updateErr, "id", id.String())
	}

	// --- remove stack (if deployer available) ---
	if deployer != nil {
		if removeErr := deployer.RemoveStack(ctx, env.StackName); removeErr != nil {
			s.setFailed(ctx, id, fmt.Sprintf("failed to remove stack: %v", removeErr))
			return apperrors.Wrap(removeErr, apperrors.CodeComposeFailed, "failed to remove ephemeral stack")
		}
	} else {
		s.logger.Warn("no deployer available to remove stack, marking as stopped without stack removal",
			"id", id.String(), "stack", env.StackName)
		addLog(ctx, s.repo, id, "stop", "No deployer available — stack not removed, only status updated", "warn")
	}

	// --- update status to stopped ---
	if updateErr := s.repo.UpdateStatus(ctx, id, models.EphemeralStatusStopped, ""); updateErr != nil {
		s.logger.Error("failed to update status to stopped", "error", updateErr, "id", id.String())
	}

	addLog(ctx, s.repo, id, "destroy", fmt.Sprintf("Environment %q stopped", env.Name), "info")

	s.logger.Info("ephemeral environment stopped",
		"id", id.String(),
		"stack", env.StackName,
	)

	return nil
}

// ============================================================================
// DestroyEnvironment
// ============================================================================

// DestroyEnvironment stops the environment if it is running, then deletes
// the record from the database.
func (s *Service) DestroyEnvironment(ctx context.Context, id uuid.UUID, deployer StackDeployer) error {
	env, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeNotFound, "ephemeral environment not found")
	}

	// If running or provisioning, stop first
	if env.Status == models.EphemeralStatusRunning || env.Status == models.EphemeralStatusProvisioning {
		if stopErr := s.StopEnvironment(ctx, id, deployer); stopErr != nil {
			s.logger.Warn("failed to stop environment before destroy, proceeding with deletion",
				"error", stopErr, "id", id.String())
		}
	}

	// Delete from database
	if deleteErr := s.repo.Delete(ctx, id); deleteErr != nil {
		return apperrors.Wrap(deleteErr, apperrors.CodeDatabaseError, "failed to delete ephemeral environment")
	}

	s.logger.Info("ephemeral environment destroyed",
		"id", id.String(),
		"stack", env.StackName,
	)

	return nil
}

// ============================================================================
// Read Operations
// ============================================================================

// GetEnvironment returns a single ephemeral environment by ID.
func (s *Service) GetEnvironment(ctx context.Context, id uuid.UUID) (*models.EphemeralEnvironment, error) {
	env, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeNotFound, "ephemeral environment not found")
	}
	return env, nil
}

// ListEnvironments returns ephemeral environments matching the given filter options.
func (s *Service) ListEnvironments(ctx context.Context, opts models.EphemeralEnvListOptions) ([]*models.EphemeralEnvironment, error) {
	envs, err := s.repo.List(ctx, opts)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to list ephemeral environments")
	}
	return envs, nil
}

// GetLogs returns lifecycle log entries for an ephemeral environment.
func (s *Service) GetLogs(ctx context.Context, envID uuid.UUID, limit int) ([]*models.EphemeralEnvironmentLog, error) {
	if limit <= 0 {
		limit = 100
	}
	logs, err := s.repo.ListLogs(ctx, envID, limit)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to list ephemeral environment logs")
	}
	return logs, nil
}

// ============================================================================
// CleanupExpired
// ============================================================================

// CleanupExpired finds all expired ephemeral environments, stops any that are
// still running, and marks them as expired. It returns the number of
// environments that were cleaned up.
func (s *Service) CleanupExpired(ctx context.Context, deployer StackDeployer) (int, error) {
	expired, err := s.repo.ListExpired(ctx)
	if err != nil {
		return 0, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to list expired environments")
	}

	if len(expired) == 0 {
		return 0, nil
	}

	cleaned := 0
	for _, env := range expired {
		// Stop running stacks
		if env.Status == models.EphemeralStatusRunning || env.Status == models.EphemeralStatusProvisioning {
			if deployer == nil {
				s.logger.Warn("no deployer available to remove expired stack, marking as expired without removal",
					"id", env.ID.String(), "stack", env.StackName)
				addLog(ctx, s.repo, env.ID, "cleanup", "No deployer available — stack not removed", "warn")
			} else if removeErr := deployer.RemoveStack(ctx, env.StackName); removeErr != nil {
				s.logger.Warn("failed to remove expired stack",
					"error", removeErr, "id", env.ID.String(), "stack", env.StackName)
				addLog(ctx, s.repo, env.ID, "cleanup", fmt.Sprintf("Failed to remove expired stack: %v", removeErr), "error")
				continue
			}
		}

		// Update status to expired
		if updateErr := s.repo.UpdateStatus(ctx, env.ID, models.EphemeralStatusExpired, ""); updateErr != nil {
			s.logger.Warn("failed to update expired status",
				"error", updateErr, "id", env.ID.String())
			continue
		}

		addLog(ctx, s.repo, env.ID, "cleanup", "Environment expired and cleaned up", "info")
		cleaned++
	}

	if cleaned > 0 {
		s.logger.Info("cleaned up expired ephemeral environments", "count", cleaned)
	}

	return cleaned, nil
}

// ============================================================================
// GetDashboard
// ============================================================================

// GetDashboard returns aggregated statistics about all ephemeral environments.
func (s *Service) GetDashboard(ctx context.Context) (*Dashboard, error) {
	statusCounts, err := s.repo.CountByStatus(ctx)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeDatabaseError, "failed to count environments by status")
	}

	total := 0
	for _, count := range statusCounts {
		total += count
	}

	activeCount := statusCounts[string(models.EphemeralStatusRunning)] +
		statusCounts[string(models.EphemeralStatusProvisioning)]
	expiredCount := statusCounts[string(models.EphemeralStatusExpired)]

	return &Dashboard{
		TotalEnvironments: total,
		StatusCounts:      statusCounts,
		ActiveCount:       activeCount,
		ExpiredCount:      expiredCount,
	}, nil
}

// ============================================================================
// ExtendTTL
// ============================================================================

// ExtendTTL extends the time-to-live of a running ephemeral environment by the
// given number of additional minutes, clamped to the configured maximum.
func (s *Service) ExtendTTL(ctx context.Context, id uuid.UUID, additionalMinutes int) error {
	env, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeNotFound, "ephemeral environment not found")
	}

	if env.Status != models.EphemeralStatusRunning {
		return apperrors.InvalidInput(fmt.Sprintf("environment is in %q status, must be running to extend TTL", env.Status))
	}

	if additionalMinutes <= 0 {
		return apperrors.InvalidInput("additional minutes must be positive")
	}

	// Calculate new total TTL from creation to new expiry
	newExpiresAt := time.Now().Add(time.Duration(additionalMinutes) * time.Minute)
	if env.ExpiresAt != nil && env.ExpiresAt.After(time.Now()) {
		// Extend from current expiry rather than from now
		newExpiresAt = env.ExpiresAt.Add(time.Duration(additionalMinutes) * time.Minute)
	}

	// Clamp: total elapsed + remaining must not exceed max TTL
	maxExpiresAt := env.CreatedAt.Add(time.Duration(s.config.MaxTTLMinutes) * time.Minute)
	if newExpiresAt.After(maxExpiresAt) {
		newExpiresAt = maxExpiresAt
	}

	// Calculate the new TTL in minutes from creation
	newTTL := int(newExpiresAt.Sub(env.CreatedAt).Minutes())

	// Persist the new TTL and expiry to the database.
	if updateErr := s.repo.UpdateTTL(ctx, id, newTTL, newExpiresAt); updateErr != nil {
		s.logger.Error("failed to persist TTL extension", "error", updateErr, "id", id.String())
		return apperrors.Wrap(updateErr, apperrors.CodeDatabaseError, "failed to persist TTL extension")
	}

	addLog(ctx, s.repo, id, "extend",
		fmt.Sprintf("TTL extended by %d minutes, new expiry: %s (total TTL: %dm)",
			additionalMinutes, newExpiresAt.Format(time.RFC3339), newTTL),
		"info",
	)

	s.logger.Info("ephemeral environment TTL extended",
		"id", id.String(),
		"additional_minutes", additionalMinutes,
		"new_expires_at", newExpiresAt.Format(time.RFC3339),
	)

	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// sanitizeBranchName replaces special characters with hyphens, lowercases the
// result, and truncates it to 20 characters.
func sanitizeBranchName(branch string) string {
	// Replace common separators and special characters with hyphens
	re := regexp.MustCompile(`[^a-zA-Z0-9]+`)
	sanitized := re.ReplaceAllString(branch, "-")

	// Lowercase
	sanitized = strings.ToLower(sanitized)

	// Trim leading/trailing hyphens
	sanitized = strings.Trim(sanitized, "-")

	// Truncate to 20 characters
	if len(sanitized) > 20 {
		sanitized = sanitized[:20]
	}

	// Trim trailing hyphen after truncation
	sanitized = strings.TrimRight(sanitized, "-")

	// Fallback if empty
	if sanitized == "" {
		sanitized = "env"
	}

	return sanitized
}

// generateStackName produces a unique stack name from the prefix and branch:
// {prefix}-{sanitized_branch}-{short_uuid}.
func generateStackName(prefix, branch string) string {
	sanitized := sanitizeBranchName(branch)
	shortID := uuid.New().String()[:8]
	return fmt.Sprintf("%s-%s-%s", prefix, sanitized, shortID)
}

// portPattern matches port mappings in docker-compose files such as
// "8080:80", "3000:3000/tcp", 8080:80, or - 8080:80. It captures an
// optional leading quote, the host port, container port, optional protocol,
// and an optional trailing quote so that existing quoting is preserved.
var portPattern = regexp.MustCompile(`("?)(\d+):(\d+)(/\w+)?("?)`)

// offsetPorts performs simple text-based port replacement on compose content.
// It finds patterns like "XXXX:YYYY" or XXXX:YYYY in ports sections and adds
// the offset to the host port (the left side). It returns the modified content
// and a mapping of original host ports to their offset equivalents.
func offsetPorts(composeContent string, portOffset int) (string, map[string]string, error) {
	portMappings := make(map[string]string)

	modified := portPattern.ReplaceAllStringFunc(composeContent, func(match string) string {
		submatch := portPattern.FindStringSubmatch(match)
		if len(submatch) < 4 {
			return match
		}

		leadingQuote := submatch[1]
		hostPort, parseErr := strconv.Atoi(submatch[2])
		if parseErr != nil {
			return match
		}
		containerPort := submatch[3]
		protocol := ""
		if len(submatch) >= 5 {
			protocol = submatch[4]
		}
		trailingQuote := ""
		if len(submatch) >= 6 {
			trailingQuote = submatch[5]
		}

		newHostPort := hostPort + portOffset
		portMappings[submatch[2]] = strconv.Itoa(newHostPort)

		return fmt.Sprintf(`%s%d:%s%s%s`, leadingQuote, newHostPort, containerPort, protocol, trailingQuote)
	})

	return modified, portMappings, nil
}

// addNetworkIsolation appends a dedicated network definition to the compose
// content and adds it to the top-level networks section. This provides basic
// network isolation for the ephemeral stack.
func addNetworkIsolation(composeContent, networkName string) string {
	// Check if a top-level networks section already exists
	if strings.Contains(composeContent, "\nnetworks:") {
		// Append the ephemeral network to the existing section
		composeContent = strings.Replace(composeContent, "\nnetworks:", fmt.Sprintf("\nnetworks:\n  %s:\n    driver: bridge", networkName), 1)
	} else {
		// Add a new top-level networks section at the end
		composeContent += fmt.Sprintf("\n\nnetworks:\n  %s:\n    driver: bridge\n", networkName)
	}
	return composeContent
}

// addLog creates a lifecycle log entry for an ephemeral environment.
func addLog(ctx context.Context, repo Repository, envID uuid.UUID, phase, message, level string) {
	logEntry := &models.EphemeralEnvironmentLog{
		ID:            uuid.New(),
		EnvironmentID: envID,
		Phase:         phase,
		Message:       message,
		Level:         level,
		CreatedAt:     time.Now(),
	}
	// Best-effort: log entries are informational; do not fail the operation
	_ = repo.CreateLog(ctx, logEntry)
}

// setFailed updates the environment status to "failed" and logs the error.
func (s *Service) setFailed(ctx context.Context, id uuid.UUID, errorMsg string) {
	if updateErr := s.repo.UpdateStatus(ctx, id, models.EphemeralStatusFailed, errorMsg); updateErr != nil {
		s.logger.Error("failed to set environment status to failed",
			"error", updateErr, "id", id.String(), "original_error", errorMsg)
	}
	addLog(ctx, s.repo, id, "error", errorMsg, "error")
}

// calculatePortOffset derives a deterministic port offset from the stack name
// within the configured port range.
func (s *Service) calculatePortOffset(stackName string) int {
	rangeSize := s.config.PortRangeEnd - s.config.PortRangeStart
	if rangeSize <= 0 {
		return 0
	}

	// Simple hash-based offset from the stack name
	hash := 0
	for _, c := range stackName {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}

	return s.config.PortRangeStart + (hash % rangeSize)
}

// generateAccessURL builds the access URL from the base URL and the first
// mapped port.
func (s *Service) generateAccessURL(portMappings map[string]string) string {
	if len(portMappings) == 0 {
		return ""
	}

	// Find the lowest mapped port to use as the primary access port
	lowestPort := 0
	for _, newPort := range portMappings {
		port, err := strconv.Atoi(newPort)
		if err != nil {
			continue
		}
		if lowestPort == 0 || port < lowestPort {
			lowestPort = port
		}
	}

	if lowestPort == 0 {
		return ""
	}

	baseURL := strings.TrimRight(s.config.BaseURL, "/")
	return fmt.Sprintf("%s:%d", baseURL, lowestPort)
}

// marshalOrNull marshals a value to JSON, returning json.RawMessage("null") if
// the value is nil.
func marshalOrNull(v interface{}) (json.RawMessage, error) {
	if v == nil {
		return json.RawMessage("null"), nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return data, nil
}
