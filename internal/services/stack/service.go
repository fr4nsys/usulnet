// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package stack provides Docker Compose stack management services.
package stack

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	containerservice "github.com/fr4nsys/usulnet/internal/services/container"
	hostservice "github.com/fr4nsys/usulnet/internal/services/host"
)

// ServiceConfig contains stack service configuration.
type ServiceConfig struct {
	// StacksDir is the directory where stack files are stored
	StacksDir string

	// ComposeCommand is the docker compose command (docker compose or docker-compose)
	ComposeCommand string

	// DefaultTimeout for stack operations
	DefaultTimeout time.Duration

	// PullBeforeDeploy pulls images before deploying
	PullBeforeDeploy bool
}

// DefaultConfig returns default service configuration.
func DefaultConfig() ServiceConfig {
	return ServiceConfig{
		StacksDir:        "/data/stacks",
		ComposeCommand:   "docker compose",
		DefaultTimeout:   5 * time.Minute,
		PullBeforeDeploy: true,
	}
}

// Service provides Docker Compose stack management operations.
type Service struct {
	repo             *postgres.StackRepository
	hostService      *hostservice.Service
	containerService *containerservice.Service
	config           ServiceConfig
	logger           *logger.Logger

	// deployMu prevents concurrent deploys of the same stack
	deployMu sync.Map
}

// NewService creates a new stack service.
func NewService(
	repo *postgres.StackRepository,
	hostService *hostservice.Service,
	containerService *containerservice.Service,
	config ServiceConfig,
	log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.Nop()
	}

	// Ensure stacks directory exists
	os.MkdirAll(config.StacksDir, 0755)

	return &Service{
		repo:             repo,
		hostService:      hostService,
		containerService: containerService,
		config:           config,
		logger:           log.Named("stack"),
	}
}

// ============================================================================
// CRUD Operations
// ============================================================================

// Create creates a new stack.
func (s *Service) Create(ctx context.Context, hostID uuid.UUID, input *models.CreateStackInput) (*models.Stack, error) {
	// Validate input
	if input.Name == "" {
		return nil, apperrors.InvalidInput("name is required")
	}
	if input.ComposeFile == "" {
		return nil, apperrors.InvalidInput("compose content is required")
	}

	// Check for duplicate name
	exists, err := s.repo.ExistsByName(ctx, hostID, input.Name)
	if err != nil {
		return nil, fmt.Errorf("check name exists: %w", err)
	}
	if exists {
		return nil, apperrors.AlreadyExists("stack with this name")
	}

	// Validate compose content
	if err := s.validateComposeContent(input.ComposeFile); err != nil {
		return nil, apperrors.InvalidInput(fmt.Sprintf("invalid compose content: %v", err))
	}

	// Create stack model
	stack := &models.Stack{
		ID:          uuid.New(),
		HostID:      hostID,
		Name:        input.Name,
		ComposeFile: input.ComposeFile,
		EnvFile:     input.EnvFile,
		Status:      models.StackStatusInactive,
	}

	// Parse service count from compose file
	if services, err := s.parseServices(input.ComposeFile); err == nil {
		stack.ServiceCount = len(services)
	}

	// Create stack directory
	stackDir := s.stackDir(stack.ID)
	if err := os.MkdirAll(stackDir, 0755); err != nil {
		return nil, fmt.Errorf("create stack directory: %w", err)
	}

	// Write compose file
	composePath := filepath.Join(stackDir, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(input.ComposeFile), 0644); err != nil {
		os.RemoveAll(stackDir)
		return nil, fmt.Errorf("write compose file: %w", err)
	}

	// Write env file if provided
	if input.EnvFile != nil && *input.EnvFile != "" {
		envPath := filepath.Join(stackDir, ".env")
		if err := os.WriteFile(envPath, []byte(*input.EnvFile), 0644); err != nil {
			os.RemoveAll(stackDir)
			return nil, fmt.Errorf("write env file: %w", err)
		}
	}

	// Save to database
	if err := s.repo.Create(ctx, stack); err != nil {
		os.RemoveAll(stackDir)
		return nil, fmt.Errorf("save stack: %w", err)
	}

	s.logger.Info("stack created",
		"id", stack.ID,
		"name", stack.Name,
		"host_id", stack.HostID,
	)

	return stack, nil
}

// Get retrieves a stack by ID.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Stack, error) {
	return s.repo.GetByID(ctx, id)
}

// GetByName retrieves a stack by name.
func (s *Service) GetByName(ctx context.Context, hostID uuid.UUID, name string) (*models.Stack, error) {
	return s.repo.GetByName(ctx, hostID, name)
}

// Update updates a stack.
func (s *Service) Update(ctx context.Context, id uuid.UUID, input *models.UpdateStackInput) (*models.Stack, error) {
	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if input.ComposeFile != nil {
		// Validate new compose content
		if err := s.validateComposeContent(*input.ComposeFile); err != nil {
			return nil, apperrors.InvalidInput(fmt.Sprintf("invalid compose content: %v", err))
		}
		stack.ComposeFile = *input.ComposeFile

		// Write new compose file
		composePath := filepath.Join(s.stackDir(stack.ID), "docker-compose.yml")
		if err := os.WriteFile(composePath, []byte(*input.ComposeFile), 0644); err != nil {
			return nil, fmt.Errorf("write compose file: %w", err)
		}
	}

	if input.EnvFile != nil {
		stack.EnvFile = input.EnvFile

		// Write env file
		envPath := filepath.Join(s.stackDir(stack.ID), ".env")
		if *input.EnvFile != "" {
			if err := os.WriteFile(envPath, []byte(*input.EnvFile), 0644); err != nil {
				return nil, fmt.Errorf("write env file: %w", err)
			}
		} else {
			os.Remove(envPath) // Remove if empty
		}
	}

	// Save to database
	if err := s.repo.Update(ctx, stack); err != nil {
		return nil, fmt.Errorf("update stack: %w", err)
	}

	s.logger.Info("stack updated",
		"id", stack.ID,
		"name", stack.Name,
	)

	return stack, nil
}

// Delete removes a stack.
func (s *Service) Delete(ctx context.Context, id uuid.UUID, removeVolumes bool) error {
	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Stop stack first if running
	if stack.Status == models.StackStatusActive {
		if err := s.Stop(ctx, id, removeVolumes); err != nil {
			s.logger.Warn("failed to stop stack before delete",
				"id", id,
				"error", err,
			)
		}
	}

	// Remove stack directory
	stackDir := s.stackDir(id)
	if err := os.RemoveAll(stackDir); err != nil {
		s.logger.Warn("failed to remove stack directory",
			"dir", stackDir,
			"error", err,
		)
	}

	// Delete from database
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete stack: %w", err)
	}

	s.logger.Info("stack deleted",
		"id", id,
		"name", stack.Name,
	)

	return nil
}

// List retrieves stacks with pagination.
func (s *Service) List(ctx context.Context, opts postgres.StackListOptions) ([]*models.Stack, int64, error) {
	return s.repo.List(ctx, opts)
}

// ListByHost retrieves all stacks for a host.
func (s *Service) ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.Stack, error) {
	return s.repo.ListByHost(ctx, hostID)
}

// ============================================================================
// Lifecycle Operations
// ============================================================================

// Deploy deploys a stack.
func (s *Service) Deploy(ctx context.Context, id uuid.UUID) (*DeployResult, error) {
	// Acquire deploy lock
	if _, loaded := s.deployMu.LoadOrStore(id.String(), true); loaded {
		return nil, apperrors.AlreadyExists("stack deployment already in progress")
	}
	defer s.deployMu.Delete(id.String())

	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Update status
	s.repo.UpdateStatus(ctx, id, models.StackStatusUnknown)

	result := &DeployResult{
		StackID:   id,
		StartedAt: time.Now().UTC(),
	}

	// Build command
	args := s.buildComposeArgs(stack, "up", "-d")
	if s.config.PullBeforeDeploy {
		args = append(args, "--pull", "always")
	}

	// Execute
	output, err := s.execCompose(ctx, stack, args...)
	result.Output = output
	result.FinishedAt = time.Now().UTC()

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		// FIX: Removed unused msg variable - error is already captured in result.Error
		s.repo.UpdateStatus(ctx, id, models.StackStatusError)
		s.logger.Error("stack deploy failed",
			"id", id,
			"name", stack.Name,
			"error", err,
		)
		return result, nil // Return result, not error
	}

	result.Success = true
	s.repo.UpdateStatus(ctx, id, models.StackStatusActive)

	// Sync containers
	go s.syncStackContainers(context.Background(), stack)

	s.logger.Info("stack deployed",
		"id", id,
		"name", stack.Name,
	)

	return result, nil
}

// Stop stops a stack.
func (s *Service) Stop(ctx context.Context, id uuid.UUID, removeVolumes bool) error {
	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	args := s.buildComposeArgs(stack, "down")
	if removeVolumes {
		args = append(args, "-v")
	}

	output, err := s.execCompose(ctx, stack, args...)
	if err != nil {
		s.logger.Error("stack stop failed",
			"id", id,
			"output", output,
			"error", err,
		)
		return fmt.Errorf("stop stack: %w", err)
	}

	s.repo.UpdateStatus(ctx, id, models.StackStatusInactive)

	s.logger.Info("stack stopped",
		"id", id,
		"name", stack.Name,
	)

	return nil
}

// Start starts a stopped stack.
func (s *Service) Start(ctx context.Context, id uuid.UUID) error {
	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	args := s.buildComposeArgs(stack, "start")

	output, err := s.execCompose(ctx, stack, args...)
	if err != nil {
		s.logger.Error("stack start failed",
			"id", id,
			"output", output,
			"error", err,
		)
		return fmt.Errorf("start stack: %w", err)
	}

	s.repo.UpdateStatus(ctx, id, models.StackStatusActive)

	s.logger.Info("stack started",
		"id", id,
		"name", stack.Name,
	)

	return nil
}

// Restart restarts a stack.
func (s *Service) Restart(ctx context.Context, id uuid.UUID) error {
	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	args := s.buildComposeArgs(stack, "restart")

	output, err := s.execCompose(ctx, stack, args...)
	if err != nil {
		s.logger.Error("stack restart failed",
			"id", id,
			"output", output,
			"error", err,
		)
		return fmt.Errorf("restart stack: %w", err)
	}

	s.logger.Info("stack restarted",
		"id", id,
		"name", stack.Name,
	)

	return nil
}

// Pull pulls images for a stack.
func (s *Service) Pull(ctx context.Context, id uuid.UUID) (string, error) {
	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return "", err
	}

	args := s.buildComposeArgs(stack, "pull")

	output, err := s.execCompose(ctx, stack, args...)
	if err != nil {
		return output, fmt.Errorf("pull stack: %w", err)
	}

	s.logger.Info("stack images pulled",
		"id", id,
		"name", stack.Name,
	)

	return output, nil
}

// ============================================================================
// Service Operations
// ============================================================================

// ScaleService scales a service within a stack.
func (s *Service) ScaleService(ctx context.Context, id uuid.UUID, service string, replicas int) error {
	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	args := s.buildComposeArgs(stack, "up", "-d", "--scale", fmt.Sprintf("%s=%d", service, replicas))

	output, err := s.execCompose(ctx, stack, args...)
	if err != nil {
		s.logger.Error("scale service failed",
			"id", id,
			"service", service,
			"output", output,
			"error", err,
		)
		return fmt.Errorf("scale service: %w", err)
	}

	s.logger.Info("service scaled",
		"stack_id", id,
		"service", service,
		"replicas", replicas,
	)

	return nil
}

// RestartService restarts a specific service.
func (s *Service) RestartService(ctx context.Context, id uuid.UUID, service string) error {
	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	args := s.buildComposeArgs(stack, "restart", service)

	output, err := s.execCompose(ctx, stack, args...)
	if err != nil {
		s.logger.Error("restart service failed",
			"id", id,
			"service", service,
			"output", output,
			"error", err,
		)
		return fmt.Errorf("restart service: %w", err)
	}

	s.logger.Info("service restarted",
		"stack_id", id,
		"service", service,
	)

	return nil
}

// GetServiceLogs retrieves logs for a service.
func (s *Service) GetServiceLogs(ctx context.Context, id uuid.UUID, service string, tail int) (string, error) {
	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return "", err
	}

	args := s.buildComposeArgs(stack, "logs", "--no-color")
	if tail > 0 {
		args = append(args, "--tail", fmt.Sprintf("%d", tail))
	}
	args = append(args, service)

	output, err := s.execCompose(ctx, stack, args...)
	if err != nil {
		return output, fmt.Errorf("get service logs: %w", err)
	}

	return output, nil
}

// ============================================================================
// Status Operations
// ============================================================================

// GetStatus retrieves detailed status of a stack.
// FIX: Return type changed from *models.StackStatus to *models.StackStatusResponse
func (s *Service) GetStatus(ctx context.Context, id uuid.UUID) (*models.StackStatusResponse, error) {
	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// FIX: Use StackStatusResponse instead of StackStatus (which is a string type)
	status := &models.StackStatusResponse{
		StackID:      id,
		Status:       stack.Status,
		Services:     make([]*models.StackServiceStatus, 0),
		ServiceCount: stack.ServiceCount,
		RunningCount: stack.RunningCount,
	}

	// Get ps output
	args := s.buildComposeArgs(stack, "ps", "--format", "json")
	output, err := s.execCompose(ctx, stack, args...)
	if err != nil {
		return status, nil // Return basic status
	}

	// Parse services from compose file
	services, err := s.parseServices(stack.ComposeFile)
	if err != nil {
		return status, nil
	}

	// Get container status for each service
	for _, svcName := range services {
		// FIX: Use models.StackServiceStatus (now defined in stack_status.go)
		svcStatus := &models.StackServiceStatus{
			Name:    svcName,
			Running: 0,
			Desired: 1, // Default
		}

		// Count running containers for this service
		// This is simplified - in production, parse the JSON output
		if strings.Contains(output, svcName) {
			svcStatus.Running = 1
			svcStatus.Status = "running"
		} else {
			svcStatus.Status = "stopped"
		}

		status.Services = append(status.Services, svcStatus)
	}

	return status, nil
}

// GetContainers retrieves containers belonging to a stack.
func (s *Service) GetContainers(ctx context.Context, id uuid.UUID) ([]*models.Container, error) {
	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Get containers with the stack label
	return s.containerService.ListByLabel(ctx, stack.HostID,
		"com.docker.compose.project", stack.Name)
}

// ============================================================================
// Config Operations
// ============================================================================

// ValidateCompose validates compose content without deploying.
func (s *Service) ValidateCompose(ctx context.Context, hostID uuid.UUID, content string) (*ValidateResult, error) {
	result := &ValidateResult{
		Valid: true,
	}

	// Basic YAML validation
	var compose map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &compose); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("YAML parse error: %v", err))
		return result, nil
	}

	// Check for services
	services, ok := compose["services"]
	if !ok {
		result.Valid = false
		result.Errors = append(result.Errors, "missing 'services' key")
		return result, nil
	}

	servicesMap, ok := services.(map[string]interface{})
	if !ok {
		result.Valid = false
		result.Errors = append(result.Errors, "'services' must be a map")
		return result, nil
	}

	// Validate each service
	for name, svc := range servicesMap {
		svcMap, ok := svc.(map[string]interface{})
		if !ok {
			result.Warnings = append(result.Warnings, fmt.Sprintf("service '%s' has invalid format", name))
			continue
		}

		// Check for image or build
		_, hasImage := svcMap["image"]
		_, hasBuild := svcMap["build"]
		if !hasImage && !hasBuild {
			result.Warnings = append(result.Warnings, fmt.Sprintf("service '%s' has no image or build", name))
		}
	}

	// Extract service names
	for name := range servicesMap {
		result.Services = append(result.Services, name)
	}

	return result, nil
}

// GetComposeConfig retrieves the processed compose config.
func (s *Service) GetComposeConfig(ctx context.Context, id uuid.UUID) (string, error) {
	stack, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return "", err
	}

	args := s.buildComposeArgs(stack, "config")

	output, err := s.execCompose(ctx, stack, args...)
	if err != nil {
		return "", fmt.Errorf("get compose config: %w", err)
	}

	return output, nil
}

// ============================================================================
// Redeploy (Update & Deploy)
// ============================================================================

// Redeploy updates and redeploys a stack.
func (s *Service) Redeploy(ctx context.Context, id uuid.UUID, input *models.UpdateStackInput) (*DeployResult, error) {
	// Update first
	if input != nil && (input.ComposeFile != nil || input.EnvFile != nil) {
		if _, err := s.Update(ctx, id, input); err != nil {
			return nil, err
		}
	}

	// Then deploy
	return s.Deploy(ctx, id)
}

// ============================================================================
// Internal Methods
// ============================================================================

// DeployResult contains the result of a deploy operation.
type DeployResult struct {
	StackID    uuid.UUID
	Success    bool
	Output     string
	Error      string
	StartedAt  time.Time
	FinishedAt time.Time
}

// ValidateResult contains the result of compose validation.
type ValidateResult struct {
	Valid    bool
	Errors   []string
	Warnings []string
	Services []string
}

func (s *Service) stackDir(id uuid.UUID) string {
	return filepath.Join(s.config.StacksDir, id.String())
}

func (s *Service) buildComposeArgs(stack *models.Stack, subcommand string, extraArgs ...string) []string {
	stackDir := s.stackDir(stack.ID)

	args := []string{
		"-f", filepath.Join(stackDir, "docker-compose.yml"),
		"-p", stack.Name,
	}

	// Add env file if exists
	envPath := filepath.Join(stackDir, ".env")
	if _, err := os.Stat(envPath); err == nil {
		args = append(args, "--env-file", envPath)
	}

	args = append(args, subcommand)
	args = append(args, extraArgs...)

	return args
}

func (s *Service) execCompose(ctx context.Context, stack *models.Stack, args ...string) (string, error) {
	// Set timeout
	ctx, cancel := context.WithTimeout(ctx, s.config.DefaultTimeout)
	defer cancel()

	// Build command
	cmdParts := strings.Fields(s.config.ComposeCommand)
	cmdName := cmdParts[0]
	cmdArgs := append(cmdParts[1:], args...)

	cmd := exec.CommandContext(ctx, cmdName, cmdArgs...)
	cmd.Dir = s.stackDir(stack.ID)

	// Set environment
	cmd.Env = os.Environ()

	// For remote hosts, we need to set DOCKER_HOST
	host, err := s.hostService.Get(ctx, stack.HostID)
	if err == nil && host.EndpointURL != nil {
		cmd.Env = append(cmd.Env, fmt.Sprintf("DOCKER_HOST=%s", *host.EndpointURL))
	}

	// Execute
	output, err := cmd.CombinedOutput()

	return string(output), err
}

func (s *Service) validateComposeContent(content string) error {
	var compose map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &compose); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}

	// Must have services
	if _, ok := compose["services"]; !ok {
		return fmt.Errorf("missing 'services' key")
	}

	return nil
}

func (s *Service) parseServices(content string) ([]string, error) {
	var compose struct {
		Services map[string]interface{} `yaml:"services"`
	}

	if err := yaml.Unmarshal([]byte(content), &compose); err != nil {
		return nil, err
	}

	services := make([]string, 0, len(compose.Services))
	for name := range compose.Services {
		services = append(services, name)
	}

	return services, nil
}

func (s *Service) syncStackContainers(ctx context.Context, stack *models.Stack) {
	// Wait a bit for containers to start
	time.Sleep(5 * time.Second)

	// Parse compose file to get total service count
	services, err := s.parseServices(stack.ComposeFile)
	if err != nil {
		s.logger.Warn("failed to parse services for sync",
			"stack_id", stack.ID,
			"error", err,
		)
		return
	}
	serviceCount := len(services)

	// Get running containers
	containers, err := s.GetContainers(ctx, stack.ID)
	if err != nil {
		s.logger.Warn("failed to sync stack containers",
			"stack_id", stack.ID,
			"error", err,
		)
		// Still update service count even if we can't get containers
		s.repo.UpdateCounts(ctx, stack.ID, serviceCount, 0)
		return
	}

	// Count running containers
	runningCount := 0
	for _, c := range containers {
		if c.State == models.ContainerStateRunning {
			runningCount++
		}
	}

	// Update counts in database
	if err := s.repo.UpdateCounts(ctx, stack.ID, serviceCount, runningCount); err != nil {
		s.logger.Warn("failed to update stack counts",
			"stack_id", stack.ID,
			"error", err,
		)
		return
	}

	s.logger.Info("stack containers synced",
		"stack_id", stack.ID,
		"service_count", serviceCount,
		"running_count", runningCount,
	)
}

// ============================================================================
// Discovery Operations
// ============================================================================

// DiscoveredStack represents a Docker Compose project discovered from running containers
type DiscoveredStack struct {
	Name          string
	ServiceCount  int
	RunningCount  int
	StoppedCount  int
	Services      []DiscoveredService
	WorkingDir    string
	ConfigFiles   string
	IsManaged     bool // true if managed by usulnet
	ManagedStackID *uuid.UUID // if managed, the usulnet stack ID
}

// DiscoveredService represents a service discovered from a container
type DiscoveredService struct {
	Name        string
	ContainerID string
	Image       string
	State       string
	Status      string
}

// DiscoverComposeProjects discovers Docker Compose projects from running containers
// This allows usulnet to show stacks created externally via docker compose CLI
func (s *Service) DiscoverComposeProjects(ctx context.Context, hostID uuid.UUID) ([]*DiscoveredStack, error) {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("get docker client: %w", err)
	}

	// List all containers with compose project label
	containers, err := client.ContainerList(ctx, docker.ContainerListOptions{
		All: true,
		Filters: map[string][]string{
			"label": {"com.docker.compose.project"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	// Group containers by project name
	projectMap := make(map[string]*DiscoveredStack)

	for _, c := range containers {
		projectName := c.Labels["com.docker.compose.project"]
		if projectName == "" {
			continue
		}

		// Get or create project
		project, ok := projectMap[projectName]
		if !ok {
			project = &DiscoveredStack{
				Name:         projectName,
				WorkingDir:   c.Labels["com.docker.compose.project.working_dir"],
				ConfigFiles:  c.Labels["com.docker.compose.project.config_files"],
				Services:     []DiscoveredService{},
			}
			projectMap[projectName] = project
		}

		// Add service
		serviceName := c.Labels["com.docker.compose.service"]
		if serviceName == "" {
			serviceName = "unknown"
		}

		state := c.State
		if state == "running" {
			project.RunningCount++
		} else {
			project.StoppedCount++
		}
		project.ServiceCount++

		// Get container name (remove leading /)
		containerName := ""
		if c.Name != "" {
			containerName = strings.TrimPrefix(c.Name, "/")
		}

		// Get primary image name
		image := c.Image
		if len(c.Image) > 20 && strings.Contains(c.Image, "@sha256:") {
			// Truncate sha256 digest
			parts := strings.Split(c.Image, "@")
			if len(parts) > 0 {
				image = parts[0]
			}
		}

		project.Services = append(project.Services, DiscoveredService{
			Name:        serviceName,
			ContainerID: c.ID,
			Image:       image,
			State:       c.State,
			Status:      c.Status,
		})

		// Add container name if different from service name
		if containerName != "" && containerName != serviceName {
			project.Services[len(project.Services)-1].Name = fmt.Sprintf("%s (%s)", serviceName, containerName)
		}
	}

	// Check which projects are managed by usulnet
	if s.repo != nil {
		managedStacks, _, err := s.repo.List(ctx, postgres.StackListOptions{})
		if err == nil {
			managedNames := make(map[string]uuid.UUID)
			for _, st := range managedStacks {
				managedNames[st.Name] = st.ID
			}

			for name, project := range projectMap {
				if stackID, ok := managedNames[name]; ok {
					project.IsManaged = true
					project.ManagedStackID = &stackID
				}
			}
		}
	}

	// Convert map to slice
	result := make([]*DiscoveredStack, 0, len(projectMap))
	for _, project := range projectMap {
		result = append(result, project)
	}

	return result, nil
}

// ListAll retrieves all stacks including discovered Docker Compose projects
func (s *Service) ListAll(ctx context.Context, hostID uuid.UUID) ([]*DiscoveredStack, error) {
	// Get discovered compose projects
	discovered, err := s.DiscoverComposeProjects(ctx, hostID)
	if err != nil {
		s.logger.Warn("failed to discover compose projects", "error", err)
		discovered = []*DiscoveredStack{}
	}

	// Get managed stacks that might not have running containers
	if s.repo != nil {
		managedStacks, _, err := s.repo.List(ctx, postgres.StackListOptions{HostID: &hostID})
		if err == nil {
			// Create a set of discovered project names
			discoveredNames := make(map[string]bool)
			for _, d := range discovered {
				discoveredNames[d.Name] = true
			}

			// Add managed stacks that aren't running
			for _, st := range managedStacks {
				if !discoveredNames[st.Name] {
					discovered = append(discovered, &DiscoveredStack{
						Name:           st.Name,
						ServiceCount:   st.ServiceCount,
						RunningCount:   0,
						StoppedCount:   st.ServiceCount,
						IsManaged:      true,
						ManagedStackID: &st.ID,
					})
				}
			}
		}
	}

	return discovered, nil
}

// ============================================================================
// Version Management
// ============================================================================

// versionStore provides in-memory version storage (should be replaced with database)
var versionStore = struct {
	sync.RWMutex
	versions map[string][]*models.StackVersion
}{
	versions: make(map[string][]*models.StackVersion),
}

// CreateVersion creates a new version of the stack's compose file.
func (s *Service) CreateVersion(ctx context.Context, stackID uuid.UUID, comment string, userID *uuid.UUID) (*models.StackVersion, error) {
	stack, err := s.repo.GetByID(ctx, stackID)
	if err != nil {
		return nil, err
	}

	versionStore.Lock()
	defer versionStore.Unlock()

	versions := versionStore.versions[stackID.String()]
	nextVersion := 1
	if len(versions) > 0 {
		nextVersion = versions[len(versions)-1].Version + 1
	}

	version := &models.StackVersion{
		ID:          uuid.New(),
		StackID:     stackID,
		Version:     nextVersion,
		ComposeFile: stack.ComposeFile,
		EnvFile:     stack.EnvFile,
		Comment:     comment,
		CreatedBy:   userID,
		CreatedAt:   time.Now().UTC(),
	}

	versionStore.versions[stackID.String()] = append(versions, version)

	s.logger.Info("stack version created",
		"stack_id", stackID,
		"version", nextVersion,
		"comment", comment,
	)

	return version, nil
}

// ListVersions returns all versions of a stack.
func (s *Service) ListVersions(ctx context.Context, stackID uuid.UUID) ([]*models.StackVersion, error) {
	versionStore.RLock()
	defer versionStore.RUnlock()

	versions := versionStore.versions[stackID.String()]
	if versions == nil {
		return []*models.StackVersion{}, nil
	}

	// Return copies in reverse order (newest first)
	result := make([]*models.StackVersion, len(versions))
	for i, v := range versions {
		result[len(versions)-1-i] = v
	}
	return result, nil
}

// GetVersion returns a specific version of a stack.
func (s *Service) GetVersion(ctx context.Context, stackID uuid.UUID, version int) (*models.StackVersion, error) {
	versionStore.RLock()
	defer versionStore.RUnlock()

	versions := versionStore.versions[stackID.String()]
	for _, v := range versions {
		if v.Version == version {
			return v, nil
		}
	}
	return nil, apperrors.NotFound("version")
}

// DiffVersions compares two versions and returns the differences.
func (s *Service) DiffVersions(ctx context.Context, stackID uuid.UUID, fromVersion, toVersion int) (*models.StackVersionDiff, error) {
	var fromCompose, toCompose string
	var fromEnv, toEnv *string

	if fromVersion == 0 {
		// Compare with current
		stack, err := s.repo.GetByID(ctx, stackID)
		if err != nil {
			return nil, err
		}
		fromCompose = stack.ComposeFile
		fromEnv = stack.EnvFile
	} else {
		v, err := s.GetVersion(ctx, stackID, fromVersion)
		if err != nil {
			return nil, fmt.Errorf("from version: %w", err)
		}
		fromCompose = v.ComposeFile
		fromEnv = v.EnvFile
	}

	if toVersion == 0 {
		// Compare with current
		stack, err := s.repo.GetByID(ctx, stackID)
		if err != nil {
			return nil, err
		}
		toCompose = stack.ComposeFile
		toEnv = stack.EnvFile
	} else {
		v, err := s.GetVersion(ctx, stackID, toVersion)
		if err != nil {
			return nil, fmt.Errorf("to version: %w", err)
		}
		toCompose = v.ComposeFile
		toEnv = v.EnvFile
	}

	diff := &models.StackVersionDiff{
		FromVersion:    fromVersion,
		ToVersion:      toVersion,
		ComposeChanges: computeLineDiff(fromCompose, toCompose),
	}

	// Compute env diff if applicable
	fromEnvStr := ""
	toEnvStr := ""
	if fromEnv != nil {
		fromEnvStr = *fromEnv
	}
	if toEnv != nil {
		toEnvStr = *toEnv
	}
	if fromEnvStr != "" || toEnvStr != "" {
		diff.EnvChanges = computeLineDiff(fromEnvStr, toEnvStr)
	}

	// Compute summary
	diff.Summary = computeDiffSummary(fromCompose, toCompose, diff.ComposeChanges)

	return diff, nil
}

// RestoreVersion restores a stack to a previous version.
func (s *Service) RestoreVersion(ctx context.Context, stackID uuid.UUID, version int, comment string, userID *uuid.UUID) (*models.Stack, error) {
	v, err := s.GetVersion(ctx, stackID, version)
	if err != nil {
		return nil, err
	}

	// Create a new version with current state before restoring
	_, err = s.CreateVersion(ctx, stackID, fmt.Sprintf("Auto-backup before restore to v%d", version), userID)
	if err != nil {
		s.logger.Warn("failed to create backup version before restore", "error", err)
	}

	// Update the stack
	input := &models.UpdateStackInput{
		ComposeFile: &v.ComposeFile,
		EnvFile:     v.EnvFile,
	}

	stack, err := s.Update(ctx, stackID, input)
	if err != nil {
		return nil, fmt.Errorf("restore version: %w", err)
	}

	s.logger.Info("stack restored to version",
		"stack_id", stackID,
		"version", version,
	)

	return stack, nil
}

// computeLineDiff computes line-by-line diff between two strings.
func computeLineDiff(from, to string) []models.DiffLine {
	fromLines := strings.Split(from, "\n")
	toLines := strings.Split(to, "\n")

	// Simple LCS-based diff
	lcs := longestCommonSubsequence(fromLines, toLines)

	var result []models.DiffLine
	fi, ti, li := 0, 0, 0

	for fi < len(fromLines) || ti < len(toLines) {
		if li < len(lcs) && fi < len(fromLines) && ti < len(toLines) && fromLines[fi] == lcs[li] && toLines[ti] == lcs[li] {
			result = append(result, models.DiffLine{
				Type:    models.DiffLineContext,
				Content: fromLines[fi],
				OldLine: fi + 1,
				NewLine: ti + 1,
			})
			fi++
			ti++
			li++
		} else if fi < len(fromLines) && (li >= len(lcs) || fromLines[fi] != lcs[li]) {
			result = append(result, models.DiffLine{
				Type:    models.DiffLineRemove,
				Content: fromLines[fi],
				OldLine: fi + 1,
			})
			fi++
		} else if ti < len(toLines) {
			result = append(result, models.DiffLine{
				Type:    models.DiffLineAdd,
				Content: toLines[ti],
				NewLine: ti + 1,
			})
			ti++
		}
	}

	return result
}

// longestCommonSubsequence finds the LCS of two string slices.
func longestCommonSubsequence(a, b []string) []string {
	m, n := len(a), len(b)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				if dp[i-1][j] > dp[i][j-1] {
					dp[i][j] = dp[i-1][j]
				} else {
					dp[i][j] = dp[i][j-1]
				}
			}
		}
	}

	// Reconstruct LCS
	lcs := make([]string, 0, dp[m][n])
	i, j := m, n
	for i > 0 && j > 0 {
		if a[i-1] == b[j-1] {
			lcs = append([]string{a[i-1]}, lcs...)
			i--
			j--
		} else if dp[i-1][j] > dp[i][j-1] {
			i--
		} else {
			j--
		}
	}

	return lcs
}

// computeDiffSummary computes a summary of changes.
func computeDiffSummary(fromCompose, toCompose string, changes []models.DiffLine) models.DiffSummary {
	summary := models.DiffSummary{}

	for _, c := range changes {
		switch c.Type {
		case models.DiffLineAdd:
			summary.LinesAdded++
		case models.DiffLineRemove:
			summary.LinesRemoved++
		}
	}

	// Parse services from both versions
	fromServices := extractServiceNames(fromCompose)
	toServices := extractServiceNames(toCompose)

	// Find added, removed, modified services
	fromSet := make(map[string]bool)
	toSet := make(map[string]bool)
	for _, s := range fromServices {
		fromSet[s] = true
	}
	for _, s := range toServices {
		toSet[s] = true
	}

	for s := range toSet {
		if !fromSet[s] {
			summary.ServicesAdded = append(summary.ServicesAdded, s)
		} else {
			// Service exists in both - check if modified
			summary.ServicesModified = append(summary.ServicesModified, s)
		}
	}

	for s := range fromSet {
		if !toSet[s] {
			summary.ServicesRemoved = append(summary.ServicesRemoved, s)
		}
	}

	// Remove services from modified if they weren't actually changed
	// (simplified - just keep all that exist in both)

	return summary
}

// extractServiceNames extracts service names from compose YAML.
func extractServiceNames(composeContent string) []string {
	var config struct {
		Services map[string]interface{} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(composeContent), &config); err != nil {
		return nil
	}

	names := make([]string, 0, len(config.Services))
	for name := range config.Services {
		names = append(names, name)
	}
	return names
}

// ============================================================================
// Dry Run
// ============================================================================

// DryRunResult contains the result of a dry run.
type DryRunResult struct {
	Valid           bool     `json:"valid"`
	Errors          []string `json:"errors,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	ServicesCreated []string `json:"services_created,omitempty"`
	ServicesUpdated []string `json:"services_updated,omitempty"`
	ServicesRemoved []string `json:"services_removed,omitempty"`
	NetworksCreated []string `json:"networks_created,omitempty"`
	VolumesCreated  []string `json:"volumes_created,omitempty"`
	ImagesToPull    []string `json:"images_to_pull,omitempty"`
}

// DryRun validates a stack configuration without deploying.
func (s *Service) DryRun(ctx context.Context, stackID uuid.UUID) (*DryRunResult, error) {
	stack, err := s.repo.GetByID(ctx, stackID)
	if err != nil {
		return nil, err
	}

	result := &DryRunResult{Valid: true}

	// Validate compose content
	if err := s.validateComposeContent(stack.ComposeFile); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid compose file: %v", err))
		return result, nil
	}

	// Parse compose file
	var config models.ComposeConfig
	if err := yaml.Unmarshal([]byte(stack.ComposeFile), &config); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse compose: %v", err))
		return result, nil
	}

	// Analyze services
	for name, svc := range config.Services {
		result.ServicesCreated = append(result.ServicesCreated, name)

		// Check images
		if svc.Image != "" {
			result.ImagesToPull = append(result.ImagesToPull, svc.Image)
		} else if svc.Build == nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Service '%s' has no image or build context", name))
		}
	}

	// Analyze networks
	for name := range config.Networks {
		result.NetworksCreated = append(result.NetworksCreated, name)
	}

	// Analyze volumes
	for name := range config.Volumes {
		result.VolumesCreated = append(result.VolumesCreated, name)
	}

	// Run docker compose config to validate
	stackDir := s.stackDir(stackID)
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", filepath.Join(stackDir, "docker-compose.yml"), "config", "--quiet")
	if output, err := cmd.CombinedOutput(); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Docker compose validation failed: %s", strings.TrimSpace(string(output))))
	}

	return result, nil
}

// DryRunContent validates compose content without creating a stack.
func (s *Service) DryRunContent(ctx context.Context, composeContent string, envContent string) (*DryRunResult, error) {
	result := &DryRunResult{Valid: true}

	// Validate compose content
	if err := s.validateComposeContent(composeContent); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid compose file: %v", err))
		return result, nil
	}

	// Parse compose file
	var config models.ComposeConfig
	if err := yaml.Unmarshal([]byte(composeContent), &config); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse compose: %v", err))
		return result, nil
	}

	// Analyze services
	for name, svc := range config.Services {
		result.ServicesCreated = append(result.ServicesCreated, name)

		if svc.Image != "" {
			result.ImagesToPull = append(result.ImagesToPull, svc.Image)
		} else if svc.Build == nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Service '%s' has no image or build context", name))
		}
	}

	// Analyze networks
	for name := range config.Networks {
		result.NetworksCreated = append(result.NetworksCreated, name)
	}

	// Analyze volumes
	for name := range config.Volumes {
		result.VolumesCreated = append(result.VolumesCreated, name)
	}

	// Create temp directory for validation
	tmpDir, err := os.MkdirTemp("", "usulnet-dryrun-")
	if err != nil {
		result.Warnings = append(result.Warnings, "Could not perform full validation")
		return result, nil
	}
	defer os.RemoveAll(tmpDir)

	// Write files
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	os.WriteFile(composePath, []byte(composeContent), 0644)
	if envContent != "" {
		os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644)
	}

	// Run docker compose config
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composePath, "config", "--quiet")
	if output, err := cmd.CombinedOutput(); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Docker compose validation failed: %s", strings.TrimSpace(string(output))))
	}

	return result, nil
}

// ============================================================================
// Stack Dependencies
// ============================================================================

// dependencyStore provides in-memory dependency storage.
var dependencyStore = struct {
	sync.RWMutex
	deps map[string][]*models.StackDependency
}{
	deps: make(map[string][]*models.StackDependency),
}

// AddDependency adds a dependency from one stack to another.
func (s *Service) AddDependency(ctx context.Context, stackID, dependsOnID uuid.UUID, condition string, optional bool) (*models.StackDependency, error) {
	// Verify both stacks exist
	stack, err := s.repo.GetByID(ctx, stackID)
	if err != nil {
		return nil, fmt.Errorf("stack not found: %w", err)
	}

	dependsOn, err := s.repo.GetByID(ctx, dependsOnID)
	if err != nil {
		return nil, fmt.Errorf("dependency stack not found: %w", err)
	}

	// Check for circular dependency
	if hasCycle := s.checkCircularDependency(stackID, dependsOnID); hasCycle {
		return nil, apperrors.InvalidInput("circular dependency detected")
	}

	// Validate condition
	if condition == "" {
		condition = string(models.DependencyConditionStarted)
	}

	dep := &models.StackDependency{
		ID:            uuid.New(),
		StackID:       stackID,
		DependsOnID:   dependsOnID,
		DependsOnName: dependsOn.Name,
		Condition:     condition,
		Optional:      optional,
		CreatedAt:     time.Now().UTC(),
	}

	dependencyStore.Lock()
	dependencyStore.deps[stackID.String()] = append(dependencyStore.deps[stackID.String()], dep)
	dependencyStore.Unlock()

	s.logger.Info("stack dependency added",
		"stack_id", stackID,
		"stack_name", stack.Name,
		"depends_on_id", dependsOnID,
		"depends_on_name", dependsOn.Name,
		"condition", condition,
	)

	return dep, nil
}

// RemoveDependency removes a dependency.
func (s *Service) RemoveDependency(ctx context.Context, stackID, dependsOnID uuid.UUID) error {
	dependencyStore.Lock()
	defer dependencyStore.Unlock()

	deps := dependencyStore.deps[stackID.String()]
	for i, d := range deps {
		if d.DependsOnID == dependsOnID {
			dependencyStore.deps[stackID.String()] = append(deps[:i], deps[i+1:]...)
			s.logger.Info("stack dependency removed",
				"stack_id", stackID,
				"depends_on_id", dependsOnID,
			)
			return nil
		}
	}

	return apperrors.NotFound("dependency")
}

// ListDependencies returns all dependencies for a stack.
func (s *Service) ListDependencies(ctx context.Context, stackID uuid.UUID) ([]*models.StackDependency, error) {
	dependencyStore.RLock()
	defer dependencyStore.RUnlock()

	deps := dependencyStore.deps[stackID.String()]
	if deps == nil {
		return []*models.StackDependency{}, nil
	}

	// Return copies
	result := make([]*models.StackDependency, len(deps))
	copy(result, deps)
	return result, nil
}

// GetDependents returns stacks that depend on the given stack.
func (s *Service) GetDependents(ctx context.Context, stackID uuid.UUID) ([]*models.StackDependency, error) {
	dependencyStore.RLock()
	defer dependencyStore.RUnlock()

	var dependents []*models.StackDependency
	for _, deps := range dependencyStore.deps {
		for _, d := range deps {
			if d.DependsOnID == stackID {
				dependents = append(dependents, d)
			}
		}
	}

	return dependents, nil
}

// checkCircularDependency checks if adding a dependency would create a cycle.
func (s *Service) checkCircularDependency(stackID, dependsOnID uuid.UUID) bool {
	visited := make(map[string]bool)
	return s.hasCycleDFS(dependsOnID.String(), stackID.String(), visited)
}

func (s *Service) hasCycleDFS(current, target string, visited map[string]bool) bool {
	if current == target {
		return true
	}

	if visited[current] {
		return false
	}
	visited[current] = true

	dependencyStore.RLock()
	deps := dependencyStore.deps[current]
	dependencyStore.RUnlock()

	for _, d := range deps {
		if s.hasCycleDFS(d.DependsOnID.String(), target, visited) {
			return true
		}
	}

	return false
}

// GetDeployOrder returns stacks in the order they should be deployed (respecting dependencies).
func (s *Service) GetDeployOrder(ctx context.Context, stackIDs []uuid.UUID) ([]uuid.UUID, error) {
	// Build adjacency list
	graph := make(map[string][]string)
	inDegree := make(map[string]int)

	for _, id := range stackIDs {
		idStr := id.String()
		if _, ok := graph[idStr]; !ok {
			graph[idStr] = []string{}
			inDegree[idStr] = 0
		}
	}

	dependencyStore.RLock()
	for _, id := range stackIDs {
		idStr := id.String()
		for _, dep := range dependencyStore.deps[idStr] {
			depStr := dep.DependsOnID.String()
			if _, ok := graph[depStr]; ok {
				graph[depStr] = append(graph[depStr], idStr)
				inDegree[idStr]++
			}
		}
	}
	dependencyStore.RUnlock()

	// Topological sort using Kahn's algorithm
	var queue []string
	for id, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, id)
		}
	}

	var result []uuid.UUID
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		id, _ := uuid.Parse(current)
		result = append(result, id)

		for _, neighbor := range graph[current] {
			inDegree[neighbor]--
			if inDegree[neighbor] == 0 {
				queue = append(queue, neighbor)
			}
		}
	}

	if len(result) != len(stackIDs) {
		return nil, apperrors.InvalidInput("circular dependency detected in stack deployment order")
	}

	return result, nil
}
