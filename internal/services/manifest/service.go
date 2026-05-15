// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Repository Interface
// ============================================================================

// Repository defines data access for manifest builder.
type Repository interface {
	CreateTemplate(ctx context.Context, t *models.ManifestTemplate) error
	GetTemplate(ctx context.Context, id uuid.UUID) (*models.ManifestTemplate, error)
	ListTemplates(ctx context.Context, format string, category string) ([]*models.ManifestTemplate, error)
	UpdateTemplate(ctx context.Context, t *models.ManifestTemplate) error
	DeleteTemplate(ctx context.Context, id uuid.UUID) error
	IncrementTemplateUsage(ctx context.Context, id uuid.UUID) error
	ListTemplateCategories(ctx context.Context) ([]string, error)

	CreateSession(ctx context.Context, s *models.ManifestBuilderSession) error
	GetSession(ctx context.Context, id uuid.UUID) (*models.ManifestBuilderSession, error)
	ListSessions(ctx context.Context, userID uuid.UUID) ([]*models.ManifestBuilderSession, error)
	UpdateSession(ctx context.Context, s *models.ManifestBuilderSession) error
	DeleteSession(ctx context.Context, id uuid.UUID) error

	CreateComponent(ctx context.Context, c *models.ManifestBuilderComponent) error
	GetComponent(ctx context.Context, id uuid.UUID) (*models.ManifestBuilderComponent, error)
	ListComponents(ctx context.Context, category string) ([]*models.ManifestBuilderComponent, error)
	DeleteComponent(ctx context.Context, id uuid.UUID) error
	SeedBuiltinComponents(ctx context.Context) error
}

// ============================================================================
// Configuration
// ============================================================================

// Config holds service configuration.
type Config struct {
	MaxServicesPerManifest int
	MaxSessionsPerUser     int
	DefaultComposeVersion  string
}

// DefaultConfig returns the default configuration for the manifest service.
func DefaultConfig() Config {
	return Config{
		MaxServicesPerManifest: 50,
		MaxSessionsPerUser:     25,
		DefaultComposeVersion:  "3.8",
	}
}

// ============================================================================
// Service
// ============================================================================

// Service provides manifest builder operations including template management,
// visual builder sessions, and Docker Compose generation.
type Service struct {
	repo   Repository
	config Config
	logger *logger.Logger
}

// NewService creates a new manifest builder service.
func NewService(repo Repository, cfg Config, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}

	return &Service{
		repo:   repo,
		config: cfg,
		logger: log.Named("manifest"),
	}
}

// ============================================================================
// Input DTOs
// ============================================================================

// CreateTemplateInput holds input for creating a manifest template.
type CreateTemplateInput struct {
	Name        string
	Description string
	Format      models.ManifestFormat
	Category    string
	Icon        string
	Version     string
	Content     string
	Variables   []models.ManifestTemplateVariable
	IsPublic    bool
	Tags        []string
	CreatedBy   *uuid.UUID
}

// CreateComponentInput holds input for creating a builder component.
type CreateComponentInput struct {
	Name          string
	Description   string
	Category      string
	Icon          string
	DefaultConfig json.RawMessage
	Ports         json.RawMessage
	Volumes       json.RawMessage
	Environment   json.RawMessage
	HealthCheck   json.RawMessage
	DependsOn     json.RawMessage
	CreatedBy     *uuid.UUID
}

// ============================================================================
// Compose YAML Types
// ============================================================================

// ComposeFile represents a docker-compose.yml structure.
type ComposeFile struct {
	Version  string                    `yaml:"version"`
	Services map[string]ComposeService `yaml:"services"`
	Networks map[string]ComposeNetwork `yaml:"networks,omitempty"`
	Volumes  map[string]ComposeVolume  `yaml:"volumes,omitempty"`
}

// ComposeService represents a single service in docker-compose.
type ComposeService struct {
	Image       string              `yaml:"image"`
	Ports       []string            `yaml:"ports,omitempty"`
	Volumes     []string            `yaml:"volumes,omitempty"`
	Environment map[string]string   `yaml:"environment,omitempty"`
	Command     string              `yaml:"command,omitempty"`
	Restart     string              `yaml:"restart,omitempty"`
	DependsOn   []string            `yaml:"depends_on,omitempty"`
	Networks    []string            `yaml:"networks,omitempty"`
	Labels      map[string]string   `yaml:"labels,omitempty"`
	HealthCheck *ComposeHealthCheck `yaml:"healthcheck,omitempty"`
	Deploy      *ComposeDeploy      `yaml:"deploy,omitempty"`
}

// ComposeHealthCheck represents a docker-compose healthcheck.
type ComposeHealthCheck struct {
	Test        []string `yaml:"test"`
	Interval    string   `yaml:"interval,omitempty"`
	Timeout     string   `yaml:"timeout,omitempty"`
	Retries     int      `yaml:"retries,omitempty"`
	StartPeriod string   `yaml:"start_period,omitempty"`
}

// ComposeDeploy represents docker-compose deploy configuration.
type ComposeDeploy struct {
	Replicas  int               `yaml:"replicas,omitempty"`
	Resources *ComposeResources `yaml:"resources,omitempty"`
}

// ComposeResources represents docker-compose resource limits and reservations.
type ComposeResources struct {
	Limits       *ComposeResourceSpec `yaml:"limits,omitempty"`
	Reservations *ComposeResourceSpec `yaml:"reservations,omitempty"`
}

// ComposeResourceSpec represents CPU/memory resource specifications.
type ComposeResourceSpec struct {
	CPUs   string `yaml:"cpus,omitempty"`
	Memory string `yaml:"memory,omitempty"`
}

// ComposeNetwork represents a docker-compose network definition.
type ComposeNetwork struct {
	Driver string `yaml:"driver,omitempty" json:"driver,omitempty"`
}

// ComposeVolume represents a docker-compose volume definition.
type ComposeVolume struct {
	Driver string `yaml:"driver,omitempty" json:"driver,omitempty"`
}

// ============================================================================
// Template Management
// ============================================================================

// CreateTemplate creates a new manifest template.
func (s *Service) CreateTemplate(ctx context.Context, input CreateTemplateInput) (*models.ManifestTemplate, error) {
	if strings.TrimSpace(input.Name) == "" {
		return nil, apperrors.InvalidInput("template name is required")
	}
	if strings.TrimSpace(input.Content) == "" {
		return nil, apperrors.InvalidInput("template content is required")
	}

	variablesJSON, err := json.Marshal(input.Variables)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeInternal, "failed to marshal template variables")
	}

	tagsJSON, err := json.Marshal(input.Tags)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.CodeInternal, "failed to marshal template tags")
	}

	now := time.Now().UTC()
	t := &models.ManifestTemplate{
		ID:          uuid.New(),
		Name:        strings.TrimSpace(input.Name),
		Description: strings.TrimSpace(input.Description),
		Format:      input.Format,
		Category:    strings.TrimSpace(input.Category),
		Icon:        input.Icon,
		Version:     input.Version,
		Content:     input.Content,
		Variables:   variablesJSON,
		IsPublic:    input.IsPublic,
		IsBuiltin:   false,
		UsageCount:  0,
		Tags:        tagsJSON,
		CreatedBy:   input.CreatedBy,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.repo.CreateTemplate(ctx, t); err != nil {
		s.logger.Error("failed to create template", "name", input.Name, "error", err)
		return nil, fmt.Errorf("create template: %w", err)
	}

	s.logger.Info("template created", "id", t.ID, "name", t.Name)
	return t, nil
}

// GetTemplate retrieves a manifest template by ID.
func (s *Service) GetTemplate(ctx context.Context, id uuid.UUID) (*models.ManifestTemplate, error) {
	t, err := s.repo.GetTemplate(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get template: %w", err)
	}
	return t, nil
}

// ListTemplates returns templates optionally filtered by format and category.
func (s *Service) ListTemplates(ctx context.Context, format string, category string) ([]*models.ManifestTemplate, error) {
	templates, err := s.repo.ListTemplates(ctx, format, category)
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	return templates, nil
}

// UpdateTemplate updates an existing manifest template.
func (s *Service) UpdateTemplate(ctx context.Context, id uuid.UUID, input CreateTemplateInput) error {
	t, err := s.repo.GetTemplate(ctx, id)
	if err != nil {
		return fmt.Errorf("get template for update: %w", err)
	}

	if strings.TrimSpace(input.Name) != "" {
		t.Name = strings.TrimSpace(input.Name)
	}
	if input.Description != "" {
		t.Description = strings.TrimSpace(input.Description)
	}
	if input.Format != "" {
		t.Format = input.Format
	}
	if input.Category != "" {
		t.Category = strings.TrimSpace(input.Category)
	}
	if input.Icon != "" {
		t.Icon = input.Icon
	}
	if input.Version != "" {
		t.Version = input.Version
	}
	if input.Content != "" {
		t.Content = input.Content
	}
	if input.Variables != nil {
		variablesJSON, err := json.Marshal(input.Variables)
		if err != nil {
			return apperrors.Wrap(err, apperrors.CodeInternal, "failed to marshal template variables")
		}
		t.Variables = variablesJSON
	}
	if input.Tags != nil {
		tagsJSON, err := json.Marshal(input.Tags)
		if err != nil {
			return apperrors.Wrap(err, apperrors.CodeInternal, "failed to marshal template tags")
		}
		t.Tags = tagsJSON
	}

	t.IsPublic = input.IsPublic
	t.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateTemplate(ctx, t); err != nil {
		s.logger.Error("failed to update template", "id", id, "error", err)
		return fmt.Errorf("update template: %w", err)
	}

	s.logger.Info("template updated", "id", id, "name", t.Name)
	return nil
}

// DeleteTemplate deletes a manifest template by ID.
func (s *Service) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.DeleteTemplate(ctx, id); err != nil {
		return fmt.Errorf("delete template: %w", err)
	}
	s.logger.Info("template deleted", "id", id)
	return nil
}

// ListCategories returns all available template categories.
func (s *Service) ListCategories(ctx context.Context) ([]string, error) {
	categories, err := s.repo.ListTemplateCategories(ctx)
	if err != nil {
		return nil, fmt.Errorf("list categories: %w", err)
	}
	return categories, nil
}

// ============================================================================
// Session Management (Visual Builder)
// ============================================================================

// CreateSession creates a new visual builder session for a user.
func (s *Service) CreateSession(ctx context.Context, userID uuid.UUID, name string, format models.ManifestFormat) (*models.ManifestBuilderSession, error) {
	if strings.TrimSpace(name) == "" {
		return nil, apperrors.InvalidInput("session name is required")
	}

	// Check session limit per user.
	existing, err := s.repo.ListSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions for limit check: %w", err)
	}
	if len(existing) >= s.config.MaxSessionsPerUser {
		return nil, apperrors.InvalidInput(fmt.Sprintf(
			"maximum sessions per user reached (%d/%d)",
			len(existing), s.config.MaxSessionsPerUser,
		))
	}

	if format == "" {
		format = models.ManifestFormatCompose
	}

	now := time.Now().UTC()
	session := &models.ManifestBuilderSession{
		ID:                uuid.New(),
		Name:              strings.TrimSpace(name),
		UserID:            userID,
		Format:            format,
		CanvasState:       json.RawMessage(`{}`),
		Services:          json.RawMessage(`[]`),
		Networks:          json.RawMessage(`{}`),
		Volumes:           json.RawMessage(`{}`),
		GeneratedManifest: "",
		ValidationErrors:  json.RawMessage(`[]`),
		IsSaved:           false,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := s.repo.CreateSession(ctx, session); err != nil {
		s.logger.Error("failed to create builder session", "user_id", userID, "error", err)
		return nil, fmt.Errorf("create session: %w", err)
	}

	s.logger.Info("builder session created", "id", session.ID, "user_id", userID, "name", name)
	return session, nil
}

// GetSession retrieves a builder session by ID.
func (s *Service) GetSession(ctx context.Context, id uuid.UUID) (*models.ManifestBuilderSession, error) {
	session, err := s.repo.GetSession(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	return session, nil
}

// ListSessions returns all builder sessions for a user.
func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]*models.ManifestBuilderSession, error) {
	sessions, err := s.repo.ListSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return sessions, nil
}

// UpdateSessionCanvas updates the canvas state and regenerates the manifest.
func (s *Service) UpdateSessionCanvas(
	ctx context.Context,
	sessionID uuid.UUID,
	canvasState json.RawMessage,
	services []models.ManifestServiceBlock,
	networks json.RawMessage,
	volumes json.RawMessage,
) error {
	session, err := s.repo.GetSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("get session for canvas update: %w", err)
	}

	// Enforce max services limit.
	if len(services) > s.config.MaxServicesPerManifest {
		return apperrors.InvalidInput(fmt.Sprintf(
			"maximum services per manifest exceeded (%d/%d)",
			len(services), s.config.MaxServicesPerManifest,
		))
	}

	// Generate the compose manifest from service blocks.
	version := s.config.DefaultComposeVersion
	generatedYAML, validationErrors := s.GenerateCompose(services, networks, volumes, version)

	// Marshal services for storage.
	servicesJSON, err := json.Marshal(services)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeInternal, "failed to marshal services")
	}

	// Marshal validation errors.
	validationJSON, err := json.Marshal(validationErrors)
	if err != nil {
		return apperrors.Wrap(err, apperrors.CodeInternal, "failed to marshal validation errors")
	}

	// Update session state.
	session.CanvasState = canvasState
	session.Services = servicesJSON
	session.Networks = networks
	session.Volumes = volumes
	session.GeneratedManifest = generatedYAML
	session.ValidationErrors = validationJSON
	session.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateSession(ctx, session); err != nil {
		s.logger.Error("failed to update session canvas", "session_id", sessionID, "error", err)
		return fmt.Errorf("update session canvas: %w", err)
	}

	s.logger.Debug("session canvas updated", "session_id", sessionID, "services", len(services))
	return nil
}

// DeleteSession deletes a builder session by ID.
func (s *Service) DeleteSession(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.DeleteSession(ctx, id); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	s.logger.Info("builder session deleted", "id", id)
	return nil
}

// SaveSession marks a builder session as saved.
func (s *Service) SaveSession(ctx context.Context, id uuid.UUID) error {
	session, err := s.repo.GetSession(ctx, id)
	if err != nil {
		return fmt.Errorf("get session for save: %w", err)
	}

	session.IsSaved = true
	session.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateSession(ctx, session); err != nil {
		s.logger.Error("failed to save session", "id", id, "error", err)
		return fmt.Errorf("save session: %w", err)
	}

	s.logger.Info("builder session saved", "id", id)
	return nil
}

// ============================================================================
// Manifest Generation
// ============================================================================

// GenerateCompose builds a Docker Compose YAML string from service blocks.
// It returns the generated YAML and any validation errors found.
func (s *Service) GenerateCompose(
	services []models.ManifestServiceBlock,
	networks json.RawMessage,
	volumes json.RawMessage,
	version string,
) (string, []models.ManifestValidationError) {
	var validationErrors []models.ManifestValidationError

	if version == "" {
		version = s.config.DefaultComposeVersion
	}

	// --- Validation ---

	// Check for duplicate service names.
	nameCount := make(map[string]int)
	for _, svc := range services {
		nameCount[svc.Name]++
	}
	for name, count := range nameCount {
		if count > 1 {
			validationErrors = append(validationErrors, models.ManifestValidationError{
				Service:  name,
				Field:    "name",
				Message:  fmt.Sprintf("duplicate service name '%s' (appears %d times)", name, count),
				Severity: "error",
			})
		}
	}

	// Check for missing images.
	for _, svc := range services {
		if strings.TrimSpace(svc.Name) == "" {
			validationErrors = append(validationErrors, models.ManifestValidationError{
				Field:    "name",
				Message:  "service name is required",
				Severity: "error",
			})
		}
		if strings.TrimSpace(svc.Image) == "" {
			validationErrors = append(validationErrors, models.ManifestValidationError{
				Service:  svc.Name,
				Field:    "image",
				Message:  fmt.Sprintf("service '%s' is missing an image", svc.Name),
				Severity: "error",
			})
		}
	}

	// Check for port conflicts.
	portErrors := checkPortConflicts(services)
	validationErrors = append(validationErrors, portErrors...)

	// Check for circular dependencies.
	cycles := detectCircularDeps(services)
	for _, cycle := range cycles {
		validationErrors = append(validationErrors, models.ManifestValidationError{
			Field:    "depends_on",
			Message:  cycle,
			Severity: "error",
		})
	}

	// --- Build YAML ---

	var b strings.Builder

	b.WriteString(fmt.Sprintf("version: \"%s\"\n", version))
	b.WriteString("\n")

	// Services section.
	if len(services) > 0 {
		b.WriteString("services:\n")
		for _, svc := range services {
			writeComposeService(&b, svc)
		}
	}

	// Networks section.
	networkDefs := parseNetworkDefs(networks)
	if len(networkDefs) > 0 {
		b.WriteString("\nnetworks:\n")
		for name, net := range networkDefs {
			if net.Driver != "" {
				b.WriteString(fmt.Sprintf("  %s:\n", name))
				b.WriteString(fmt.Sprintf("    driver: %s\n", net.Driver))
			} else {
				b.WriteString(fmt.Sprintf("  %s: {}\n", name))
			}
		}
	}

	// Volumes section.
	volumeDefs := parseVolumeDefs(volumes)
	if len(volumeDefs) > 0 {
		b.WriteString("\nvolumes:\n")
		for name, vol := range volumeDefs {
			if vol.Driver != "" {
				b.WriteString(fmt.Sprintf("  %s:\n", name))
				b.WriteString(fmt.Sprintf("    driver: %s\n", vol.Driver))
			} else {
				b.WriteString(fmt.Sprintf("  %s: {}\n", name))
			}
		}
	}

	return b.String(), validationErrors
}

// writeComposeService writes a single service definition in YAML format.
func writeComposeService(b *strings.Builder, svc models.ManifestServiceBlock) {
	fmt.Fprintf(b, "  %s:\n", svc.Name)

	// Image with optional tag.
	image := strings.TrimSpace(svc.Image)
	if tag := strings.TrimSpace(svc.Tag); tag != "" {
		image = image + ":" + tag
	}
	fmt.Fprintf(b, "    image: %s\n", image)

	// Command.
	if cmd := strings.TrimSpace(svc.Command); cmd != "" {
		fmt.Fprintf(b, "    command: %s\n", cmd)
	}

	// Restart policy.
	if restart := strings.TrimSpace(svc.Restart); restart != "" {
		fmt.Fprintf(b, "    restart: %s\n", restart)
	}

	// Ports.
	if len(svc.Ports) > 0 {
		b.WriteString("    ports:\n")
		for _, p := range svc.Ports {
			proto := strings.TrimSpace(p.Protocol)
			if proto != "" && proto != "tcp" {
				fmt.Fprintf(b, "      - \"%d:%d/%s\"\n", p.Host, p.Container, proto)
			} else {
				fmt.Fprintf(b, "      - \"%d:%d\"\n", p.Host, p.Container)
			}
		}
	}

	// Volumes.
	if len(svc.Volumes) > 0 {
		b.WriteString("    volumes:\n")
		for _, v := range svc.Volumes {
			mount := fmt.Sprintf("%s:%s", v.Source, v.Target)
			if v.ReadOnly {
				mount += ":ro"
			}
			fmt.Fprintf(b, "      - %s\n", mount)
		}
	}

	// Environment.
	if len(svc.Environment) > 0 {
		b.WriteString("    environment:\n")
		for key, val := range svc.Environment {
			fmt.Fprintf(b, "      %s: \"%s\"\n", key, escapeYAMLString(val))
		}
	}

	// Depends on.
	if len(svc.DependsOn) > 0 {
		b.WriteString("    depends_on:\n")
		for _, dep := range svc.DependsOn {
			fmt.Fprintf(b, "      - %s\n", dep)
		}
	}

	// Networks.
	if len(svc.Networks) > 0 {
		b.WriteString("    networks:\n")
		for _, net := range svc.Networks {
			fmt.Fprintf(b, "      - %s\n", net)
		}
	}

	// Labels.
	if len(svc.Labels) > 0 {
		b.WriteString("    labels:\n")
		for key, val := range svc.Labels {
			fmt.Fprintf(b, "      %s: \"%s\"\n", key, escapeYAMLString(val))
		}
	}

	// Health check.
	if svc.HealthCheck != nil {
		b.WriteString("    healthcheck:\n")
		if svc.HealthCheck.Test != "" {
			fmt.Fprintf(b, "      test: [\"CMD-SHELL\", \"%s\"]\n", escapeYAMLString(svc.HealthCheck.Test))
		}
		if svc.HealthCheck.Interval != "" {
			fmt.Fprintf(b, "      interval: %s\n", svc.HealthCheck.Interval)
		}
		if svc.HealthCheck.Timeout != "" {
			fmt.Fprintf(b, "      timeout: %s\n", svc.HealthCheck.Timeout)
		}
		if svc.HealthCheck.Retries > 0 {
			fmt.Fprintf(b, "      retries: %d\n", svc.HealthCheck.Retries)
		}
		if svc.HealthCheck.StartPeriod != "" {
			fmt.Fprintf(b, "      start_period: %s\n", svc.HealthCheck.StartPeriod)
		}
	}

	// Deploy.
	if svc.Deploy != nil {
		hasDeploy := svc.Deploy.Replicas > 0 ||
			svc.Deploy.CPULimit != "" || svc.Deploy.MemLimit != "" ||
			svc.Deploy.CPUReservation != "" || svc.Deploy.MemReservation != ""

		if hasDeploy {
			b.WriteString("    deploy:\n")
			if svc.Deploy.Replicas > 0 {
				fmt.Fprintf(b, "      replicas: %d\n", svc.Deploy.Replicas)
			}

			hasLimits := svc.Deploy.CPULimit != "" || svc.Deploy.MemLimit != ""
			hasReservations := svc.Deploy.CPUReservation != "" || svc.Deploy.MemReservation != ""

			if hasLimits || hasReservations {
				b.WriteString("      resources:\n")

				if hasLimits {
					b.WriteString("        limits:\n")
					if svc.Deploy.CPULimit != "" {
						fmt.Fprintf(b, "          cpus: \"%s\"\n", svc.Deploy.CPULimit)
					}
					if svc.Deploy.MemLimit != "" {
						fmt.Fprintf(b, "          memory: %s\n", svc.Deploy.MemLimit)
					}
				}

				if hasReservations {
					b.WriteString("        reservations:\n")
					if svc.Deploy.CPUReservation != "" {
						fmt.Fprintf(b, "          cpus: \"%s\"\n", svc.Deploy.CPUReservation)
					}
					if svc.Deploy.MemReservation != "" {
						fmt.Fprintf(b, "          memory: %s\n", svc.Deploy.MemReservation)
					}
				}
			}
		}
	}
}

// ============================================================================
// Manifest Validation
// ============================================================================

// ValidateManifest performs basic validation on a manifest string.
func (s *Service) ValidateManifest(content string, format models.ManifestFormat) []models.ManifestValidationError {
	var errors []models.ManifestValidationError

	content = strings.TrimSpace(content)
	if content == "" {
		errors = append(errors, models.ManifestValidationError{
			Field:    "content",
			Message:  "manifest content is empty",
			Severity: "error",
		})
		return errors
	}

	if format == models.ManifestFormatCompose || format == "" {
		errors = append(errors, validateComposeContent(content)...)
	}

	return errors
}

// validateComposeContent checks a docker-compose YAML string for common issues.
func validateComposeContent(content string) []models.ManifestValidationError {
	var errors []models.ManifestValidationError

	lines := strings.Split(content, "\n")

	hasVersion := false
	hasServices := false
	inServices := false
	currentService := ""
	serviceHasImage := make(map[string]bool)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check for version.
		if strings.HasPrefix(trimmed, "version:") {
			hasVersion = true
		}

		// Check for services section.
		if trimmed == "services:" {
			hasServices = true
			inServices = true
			continue
		}

		// Detect top-level sections that end services block.
		if inServices && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && trimmed != "" {
			if trimmed == "networks:" || trimmed == "volumes:" || trimmed == "configs:" || trimmed == "secrets:" {
				inServices = false
				continue
			}
		}

		// Inside services, detect service names (2-space indent, ends with ':').
		if inServices && len(line) > 2 {
			// Service name: exactly 2 spaces of indent.
			if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
				name := strings.TrimSpace(strings.TrimSuffix(trimmed, ":"))
				if strings.HasSuffix(trimmed, ":") && name != "" {
					currentService = name
				}
			}

			// Check for image field inside a service.
			if currentService != "" && strings.HasPrefix(trimmed, "image:") {
				imgVal := strings.TrimSpace(strings.TrimPrefix(trimmed, "image:"))
				if imgVal != "" {
					serviceHasImage[currentService] = true
				}
			}
		}

		// Check for invalid port formats.
		if strings.HasPrefix(trimmed, "- \"") && strings.Contains(trimmed, ":") {
			portStr := strings.Trim(trimmed, "- \"")
			if isLikelyPortMapping(portStr) {
				if err := validatePortFormat(portStr); err != "" {
					errors = append(errors, models.ManifestValidationError{
						Service:  currentService,
						Field:    "ports",
						Message:  err,
						Severity: "warning",
					})
				}
			}
		}
	}

	if !hasVersion {
		errors = append(errors, models.ManifestValidationError{
			Field:    "version",
			Message:  "missing 'version' field",
			Severity: "warning",
		})
	}

	if !hasServices {
		errors = append(errors, models.ManifestValidationError{
			Field:    "services",
			Message:  "missing 'services' section",
			Severity: "error",
		})
	}

	// Check for services without images.
	for svc, hasImg := range serviceHasImage {
		if !hasImg {
			errors = append(errors, models.ManifestValidationError{
				Service:  svc,
				Field:    "image",
				Message:  fmt.Sprintf("service '%s' has no image defined", svc),
				Severity: "error",
			})
		}
	}

	return errors
}

// isLikelyPortMapping determines if a string looks like a port mapping (e.g. "8080:80").
func isLikelyPortMapping(s string) bool {
	// Remove protocol suffix.
	s = strings.TrimSuffix(s, "/tcp")
	s = strings.TrimSuffix(s, "/udp")
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

// validatePortFormat validates a port mapping string.
func validatePortFormat(port string) string {
	// Strip protocol.
	port = strings.TrimSuffix(port, "/tcp")
	port = strings.TrimSuffix(port, "/udp")

	parts := strings.Split(port, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return fmt.Sprintf("invalid port format '%s': expected 'host:container' or 'host:container/protocol'", port)
	}

	for _, p := range parts {
		if p == "" {
			return fmt.Sprintf("invalid port format '%s': empty port number", port)
		}
		var num int
		if _, err := fmt.Sscanf(p, "%d", &num); err != nil {
			return fmt.Sprintf("invalid port format '%s': non-numeric port", port)
		}
		if num < 1 || num > 65535 {
			return fmt.Sprintf("invalid port format '%s': port %d out of range (1-65535)", port, num)
		}
	}

	return ""
}

// ============================================================================
// Template Rendering
// ============================================================================

// RenderTemplate loads a template, replaces variable placeholders, and returns the rendered content.
func (s *Service) RenderTemplate(ctx context.Context, templateID uuid.UUID, variables map[string]string) (string, error) {
	t, err := s.repo.GetTemplate(ctx, templateID)
	if err != nil {
		return "", fmt.Errorf("get template for rendering: %w", err)
	}

	rendered := t.Content

	// Parse template variables to get defaults.
	var templateVars []models.ManifestTemplateVariable
	if len(t.Variables) > 0 {
		if err := json.Unmarshal(t.Variables, &templateVars); err != nil {
			s.logger.Warn("failed to parse template variables", "template_id", templateID, "error", err)
		}
	}

	// Build a merged map: defaults first, then user-provided values override.
	merged := make(map[string]string)
	for _, v := range templateVars {
		if v.Default != "" {
			merged[v.Name] = v.Default
		}
	}
	for k, v := range variables {
		merged[k] = v
	}

	// Replace {{.VarName}} placeholders.
	for name, value := range merged {
		placeholder := fmt.Sprintf("{{.%s}}", name)
		rendered = strings.ReplaceAll(rendered, placeholder, value)
	}

	// Increment usage count.
	if err := s.repo.IncrementTemplateUsage(ctx, templateID); err != nil {
		s.logger.Warn("failed to increment template usage count", "template_id", templateID, "error", err)
	}

	return rendered, nil
}

// ============================================================================
// Component Library
// ============================================================================

// ListComponents returns builder components optionally filtered by category.
func (s *Service) ListComponents(ctx context.Context, category string) ([]*models.ManifestBuilderComponent, error) {
	components, err := s.repo.ListComponents(ctx, category)
	if err != nil {
		return nil, fmt.Errorf("list components: %w", err)
	}
	return components, nil
}

// GetComponent retrieves a builder component by ID.
func (s *Service) GetComponent(ctx context.Context, id uuid.UUID) (*models.ManifestBuilderComponent, error) {
	c, err := s.repo.GetComponent(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get component: %w", err)
	}
	return c, nil
}

// CreateComponent creates a new builder component.
func (s *Service) CreateComponent(ctx context.Context, input CreateComponentInput) (*models.ManifestBuilderComponent, error) {
	if strings.TrimSpace(input.Name) == "" {
		return nil, apperrors.InvalidInput("component name is required")
	}

	now := time.Now().UTC()
	c := &models.ManifestBuilderComponent{
		ID:            uuid.New(),
		Name:          strings.TrimSpace(input.Name),
		Description:   strings.TrimSpace(input.Description),
		Category:      strings.TrimSpace(input.Category),
		Icon:          input.Icon,
		DefaultConfig: input.DefaultConfig,
		Ports:         input.Ports,
		Volumes:       input.Volumes,
		Environment:   input.Environment,
		HealthCheck:   input.HealthCheck,
		DependsOn:     input.DependsOn,
		IsBuiltin:     false,
		CreatedBy:     input.CreatedBy,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// Ensure non-nil JSON fields.
	if c.DefaultConfig == nil {
		c.DefaultConfig = json.RawMessage(`{}`)
	}
	if c.Ports == nil {
		c.Ports = json.RawMessage(`[]`)
	}
	if c.Volumes == nil {
		c.Volumes = json.RawMessage(`[]`)
	}
	if c.Environment == nil {
		c.Environment = json.RawMessage(`{}`)
	}
	if c.HealthCheck == nil {
		c.HealthCheck = json.RawMessage(`null`)
	}
	if c.DependsOn == nil {
		c.DependsOn = json.RawMessage(`[]`)
	}

	if err := s.repo.CreateComponent(ctx, c); err != nil {
		s.logger.Error("failed to create component", "name", input.Name, "error", err)
		return nil, fmt.Errorf("create component: %w", err)
	}

	s.logger.Info("component created", "id", c.ID, "name", c.Name)
	return c, nil
}

// SeedBuiltinComponents delegates to the repository to seed built-in components.
func (s *Service) SeedBuiltinComponents(ctx context.Context) error {
	if err := s.repo.SeedBuiltinComponents(ctx); err != nil {
		s.logger.Error("failed to seed builtin components", "error", err)
		return fmt.Errorf("seed builtin components: %w", err)
	}
	s.logger.Info("builtin components seeded")
	return nil
}

// ============================================================================
// Seed Builtin Templates
// ============================================================================

// SeedBuiltinTemplates creates the default set of built-in manifest templates.
func (s *Service) SeedBuiltinTemplates(ctx context.Context) error {
	templates := []models.ManifestTemplate{
		{
			ID:          uuid.New(),
			Name:        "Basic Web App",
			Description: "A basic web application stack with Nginx reverse proxy, application server, and PostgreSQL database.",
			Format:      models.ManifestFormatCompose,
			Category:    "web",
			Icon:        "globe",
			Version:     "1.0.0",
			Content: `version: "3.8"

services:
  nginx:
    image: nginx:{{.NginxVersion}}
    restart: unless-stopped
    ports:
      - "{{.HTTPPort}}:80"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - app
    networks:
      - frontend

  app:
    image: {{.AppImage}}
    restart: unless-stopped
    environment:
      DATABASE_URL: "postgres://{{.DBUser}}:{{.DBPassword}}@db:5432/{{.DBName}}"
    depends_on:
      - db
    networks:
      - frontend
      - backend

  db:
    image: postgres:{{.PostgresVersion}}
    restart: unless-stopped
    environment:
      POSTGRES_USER: "{{.DBUser}}"
      POSTGRES_PASSWORD: "{{.DBPassword}}"
      POSTGRES_DB: "{{.DBName}}"
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks:
      - backend
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U {{.DBUser}}"]
      interval: 10s
      timeout: 5s
      retries: 5

networks:
  frontend: {}
  backend: {}

volumes:
  pgdata: {}`,
			Variables: mustMarshalJSON([]models.ManifestTemplateVariable{
				{Name: "NginxVersion", Type: "string", Default: "alpine", Description: "Nginx image tag", Required: false},
				{Name: "AppImage", Type: "string", Default: "myapp:latest", Description: "Application Docker image", Required: true},
				{Name: "HTTPPort", Type: "number", Default: "80", Description: "Host HTTP port", Required: false},
				{Name: "PostgresVersion", Type: "string", Default: "16-alpine", Description: "PostgreSQL image tag", Required: false},
				{Name: "DBUser", Type: "string", Default: "app", Description: "Database user", Required: true},
				{Name: "DBPassword", Type: "string", Default: "changeme", Description: "Database password", Required: true},
				{Name: "DBName", Type: "string", Default: "appdb", Description: "Database name", Required: true},
			}),
			IsPublic:  true,
			IsBuiltin: true,
			Tags:      mustMarshalJSON([]string{"web", "nginx", "postgres", "starter"}),
		},
		{
			ID:          uuid.New(),
			Name:        "WordPress Stack",
			Description: "Complete WordPress deployment with MySQL database and phpMyAdmin for database management.",
			Format:      models.ManifestFormatCompose,
			Category:    "cms",
			Icon:        "edit",
			Version:     "1.0.0",
			Content: `version: "3.8"

services:
  wordpress:
    image: wordpress:{{.WordPressVersion}}
    restart: unless-stopped
    ports:
      - "{{.HTTPPort}}:80"
    environment:
      WORDPRESS_DB_HOST: "mysql:3306"
      WORDPRESS_DB_USER: "{{.DBUser}}"
      WORDPRESS_DB_PASSWORD: "{{.DBPassword}}"
      WORDPRESS_DB_NAME: "{{.DBName}}"
    volumes:
      - wp_data:/var/www/html
    depends_on:
      - mysql
    networks:
      - wp-network

  mysql:
    image: mysql:{{.MySQLVersion}}
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: "{{.DBRootPassword}}"
      MYSQL_DATABASE: "{{.DBName}}"
      MYSQL_USER: "{{.DBUser}}"
      MYSQL_PASSWORD: "{{.DBPassword}}"
    volumes:
      - mysql_data:/var/lib/mysql
    networks:
      - wp-network
    healthcheck:
      test: ["CMD-SHELL", "mysqladmin ping -h localhost"]
      interval: 10s
      timeout: 5s
      retries: 5

  phpmyadmin:
    image: phpmyadmin:{{.PHPMyAdminVersion}}
    restart: unless-stopped
    ports:
      - "{{.PHPMyAdminPort}}:80"
    environment:
      PMA_HOST: mysql
      PMA_PORT: "3306"
      MYSQL_ROOT_PASSWORD: "{{.DBRootPassword}}"
    depends_on:
      - mysql
    networks:
      - wp-network

networks:
  wp-network: {}

volumes:
  wp_data: {}
  mysql_data: {}`,
			Variables: mustMarshalJSON([]models.ManifestTemplateVariable{
				{Name: "WordPressVersion", Type: "string", Default: "latest", Description: "WordPress image tag", Required: false},
				{Name: "MySQLVersion", Type: "string", Default: "8.0", Description: "MySQL image tag", Required: false},
				{Name: "PHPMyAdminVersion", Type: "string", Default: "latest", Description: "phpMyAdmin image tag", Required: false},
				{Name: "HTTPPort", Type: "number", Default: "8080", Description: "WordPress HTTP port", Required: false},
				{Name: "PHPMyAdminPort", Type: "number", Default: "8081", Description: "phpMyAdmin HTTP port", Required: false},
				{Name: "DBUser", Type: "string", Default: "wordpress", Description: "Database user", Required: true},
				{Name: "DBPassword", Type: "string", Default: "changeme", Description: "Database password", Required: true},
				{Name: "DBRootPassword", Type: "string", Default: "rootchangeme", Description: "MySQL root password", Required: true},
				{Name: "DBName", Type: "string", Default: "wordpress", Description: "Database name", Required: true},
			}),
			IsPublic:  true,
			IsBuiltin: true,
			Tags:      mustMarshalJSON([]string{"wordpress", "cms", "mysql", "phpmyadmin"}),
		},
		{
			ID:          uuid.New(),
			Name:        "Monitoring Stack",
			Description: "Production-ready monitoring with Prometheus for metrics collection, Grafana for visualization, and Node Exporter for host metrics.",
			Format:      models.ManifestFormatCompose,
			Category:    "monitoring",
			Icon:        "activity",
			Version:     "1.0.0",
			Content: `version: "3.8"

services:
  prometheus:
    image: prom/prometheus:{{.PrometheusVersion}}
    restart: unless-stopped
    ports:
      - "{{.PrometheusPort}}:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command: --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.retention.time={{.RetentionDays}}d
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:{{.GrafanaVersion}}
    restart: unless-stopped
    ports:
      - "{{.GrafanaPort}}:3000"
    environment:
      GF_SECURITY_ADMIN_USER: "{{.GrafanaUser}}"
      GF_SECURITY_ADMIN_PASSWORD: "{{.GrafanaPassword}}"
      GF_USERS_ALLOW_SIGN_UP: "false"
    volumes:
      - grafana_data:/var/lib/grafana
    depends_on:
      - prometheus
    networks:
      - monitoring

  node-exporter:
    image: prom/node-exporter:{{.NodeExporterVersion}}
    restart: unless-stopped
    ports:
      - "{{.NodeExporterPort}}:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command: --path.procfs=/host/proc --path.sysfs=/host/sys --path.rootfs=/rootfs
    networks:
      - monitoring

networks:
  monitoring: {}

volumes:
  prometheus_data: {}
  grafana_data: {}`,
			Variables: mustMarshalJSON([]models.ManifestTemplateVariable{
				{Name: "PrometheusVersion", Type: "string", Default: "latest", Description: "Prometheus image tag", Required: false},
				{Name: "GrafanaVersion", Type: "string", Default: "latest", Description: "Grafana image tag", Required: false},
				{Name: "NodeExporterVersion", Type: "string", Default: "latest", Description: "Node Exporter image tag", Required: false},
				{Name: "PrometheusPort", Type: "number", Default: "9090", Description: "Prometheus port", Required: false},
				{Name: "GrafanaPort", Type: "number", Default: "3000", Description: "Grafana port", Required: false},
				{Name: "NodeExporterPort", Type: "number", Default: "9100", Description: "Node Exporter port", Required: false},
				{Name: "GrafanaUser", Type: "string", Default: "admin", Description: "Grafana admin username", Required: true},
				{Name: "GrafanaPassword", Type: "string", Default: "changeme", Description: "Grafana admin password", Required: true},
				{Name: "RetentionDays", Type: "number", Default: "30", Description: "Prometheus data retention in days", Required: false},
			}),
			IsPublic:  true,
			IsBuiltin: true,
			Tags:      mustMarshalJSON([]string{"monitoring", "prometheus", "grafana", "metrics"}),
		},
		{
			ID:          uuid.New(),
			Name:        "Redis Cluster",
			Description: "Redis instance with Redis Commander web UI for management and visualization.",
			Format:      models.ManifestFormatCompose,
			Category:    "database",
			Icon:        "database",
			Version:     "1.0.0",
			Content: `version: "3.8"

services:
  redis:
    image: redis:{{.RedisVersion}}
    restart: unless-stopped
    ports:
      - "{{.RedisPort}}:6379"
    command: redis-server --requirepass {{.RedisPassword}} --maxmemory {{.MaxMemory}} --maxmemory-policy {{.EvictionPolicy}}
    volumes:
      - redis_data:/data
    networks:
      - redis-network
    healthcheck:
      test: ["CMD-SHELL", "redis-cli -a {{.RedisPassword}} ping | grep PONG"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis-commander:
    image: rediscommander/redis-commander:{{.CommanderVersion}}
    restart: unless-stopped
    ports:
      - "{{.CommanderPort}}:8081"
    environment:
      REDIS_HOSTS: "local:redis:6379:0:{{.RedisPassword}}"
      HTTP_USER: "{{.CommanderUser}}"
      HTTP_PASSWORD: "{{.CommanderPassword}}"
    depends_on:
      - redis
    networks:
      - redis-network

networks:
  redis-network: {}

volumes:
  redis_data: {}`,
			Variables: mustMarshalJSON([]models.ManifestTemplateVariable{
				{Name: "RedisVersion", Type: "string", Default: "7-alpine", Description: "Redis image tag", Required: false},
				{Name: "CommanderVersion", Type: "string", Default: "latest", Description: "Redis Commander image tag", Required: false},
				{Name: "RedisPort", Type: "number", Default: "6379", Description: "Redis port", Required: false},
				{Name: "CommanderPort", Type: "number", Default: "8082", Description: "Redis Commander port", Required: false},
				{Name: "RedisPassword", Type: "string", Default: "changeme", Description: "Redis password", Required: true},
				{Name: "MaxMemory", Type: "string", Default: "256mb", Description: "Redis max memory limit", Required: false},
				{Name: "EvictionPolicy", Type: "select", Default: "allkeys-lru", Description: "Redis eviction policy", Required: false, Options: []string{"noeviction", "allkeys-lru", "volatile-lru", "allkeys-random", "volatile-random", "volatile-ttl"}},
				{Name: "CommanderUser", Type: "string", Default: "admin", Description: "Redis Commander username", Required: true},
				{Name: "CommanderPassword", Type: "string", Default: "changeme", Description: "Redis Commander password", Required: true},
			}),
			IsPublic:  true,
			IsBuiltin: true,
			Tags:      mustMarshalJSON([]string{"redis", "cache", "database", "commander"}),
		},
	}

	now := time.Now().UTC()
	for i := range templates {
		templates[i].CreatedAt = now
		templates[i].UpdatedAt = now

		if err := s.repo.CreateTemplate(ctx, &templates[i]); err != nil {
			// Skip if template already exists (idempotent seeding).
			if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "duplicate") {
				s.logger.Debug("builtin template already exists, skipping", "name", templates[i].Name)
				continue
			}
			s.logger.Error("failed to seed builtin template", "name", templates[i].Name, "error", err)
			return fmt.Errorf("seed builtin template %q: %w", templates[i].Name, err)
		}
		s.logger.Info("builtin template seeded", "name", templates[i].Name, "id", templates[i].ID)
	}

	s.logger.Info("builtin templates seeded", "count", len(templates))
	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// detectCircularDeps detects circular dependencies in the depends_on chains
// of service blocks. Returns a list of human-readable cycle descriptions.
func detectCircularDeps(services []models.ManifestServiceBlock) []string {
	// Build adjacency list.
	graph := make(map[string][]string)
	serviceNames := make(map[string]bool)
	for _, svc := range services {
		serviceNames[svc.Name] = true
		graph[svc.Name] = svc.DependsOn
	}

	var cycles []string

	// Track visited state: 0 = unvisited, 1 = in current path, 2 = fully visited.
	state := make(map[string]int)
	path := make([]string, 0)

	var dfs func(node string) bool
	dfs = func(node string) bool {
		state[node] = 1 // Mark as in current path.
		path = append(path, node)

		for _, dep := range graph[node] {
			if state[dep] == 1 {
				// Found a cycle. Build the cycle path.
				cycleStart := -1
				for i, n := range path {
					if n == dep {
						cycleStart = i
						break
					}
				}
				if cycleStart >= 0 {
					cyclePath := append(path[cycleStart:], dep)
					cycles = append(cycles, fmt.Sprintf(
						"circular dependency detected: %s",
						strings.Join(cyclePath, " -> "),
					))
				}
				return true
			}
			if state[dep] == 0 {
				// dfs(dep) may detect additional cycles; we still want to
				// finish visiting every unvisited dependency from this node,
				// so the return value is intentionally ignored here.
				_ = dfs(dep)
			}
		}

		path = path[:len(path)-1]
		state[node] = 2 // Mark as fully visited.
		return false
	}

	for name := range serviceNames {
		if state[name] == 0 {
			dfs(name)
		}
	}

	return cycles
}

// checkPortConflicts finds duplicate host port usage across services.
func checkPortConflicts(services []models.ManifestServiceBlock) []models.ManifestValidationError {
	var errors []models.ManifestValidationError

	// Map host port + protocol to the service that uses it.
	type portKey struct {
		port     int
		protocol string
	}

	portUsers := make(map[portKey][]string)

	for _, svc := range services {
		for _, p := range svc.Ports {
			proto := p.Protocol
			if proto == "" {
				proto = "tcp"
			}
			key := portKey{port: p.Host, protocol: proto}
			portUsers[key] = append(portUsers[key], svc.Name)
		}
	}

	for key, users := range portUsers {
		if len(users) > 1 {
			errors = append(errors, models.ManifestValidationError{
				Field:    "ports",
				Message:  fmt.Sprintf("host port %d/%s is used by multiple services: %s", key.port, key.protocol, strings.Join(users, ", ")),
				Severity: "error",
			})
		}
	}

	return errors
}

// parseNetworkDefs parses network definitions from JSON.
func parseNetworkDefs(data json.RawMessage) map[string]ComposeNetwork {
	result := make(map[string]ComposeNetwork)
	if len(data) == 0 {
		return result
	}

	// Try parsing as map of network objects.
	var networkMap map[string]ComposeNetwork
	if err := json.Unmarshal(data, &networkMap); err == nil {
		return networkMap
	}

	// Try parsing as map of strings (simple network names).
	var simpleMap map[string]interface{}
	if err := json.Unmarshal(data, &simpleMap); err == nil {
		for name, val := range simpleMap {
			net := ComposeNetwork{}
			if m, ok := val.(map[string]interface{}); ok {
				if d, ok := m["driver"].(string); ok {
					net.Driver = d
				}
			}
			result[name] = net
		}
	}

	return result
}

// parseVolumeDefs parses volume definitions from JSON.
func parseVolumeDefs(data json.RawMessage) map[string]ComposeVolume {
	result := make(map[string]ComposeVolume)
	if len(data) == 0 {
		return result
	}

	// Try parsing as map of volume objects.
	var volumeMap map[string]ComposeVolume
	if err := json.Unmarshal(data, &volumeMap); err == nil {
		return volumeMap
	}

	// Try parsing as map of generic objects.
	var simpleMap map[string]interface{}
	if err := json.Unmarshal(data, &simpleMap); err == nil {
		for name, val := range simpleMap {
			vol := ComposeVolume{}
			if m, ok := val.(map[string]interface{}); ok {
				if d, ok := m["driver"].(string); ok {
					vol.Driver = d
				}
			}
			result[name] = vol
		}
	}

	return result
}

// escapeYAMLString escapes special characters in a YAML string value.
func escapeYAMLString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

// mustMarshalJSON marshals a value to JSON, panicking on error.
// Used only for compile-time constant template data.
func mustMarshalJSON(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("manifest: failed to marshal JSON: %v", err))
	}
	return data
}
