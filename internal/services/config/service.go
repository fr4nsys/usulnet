// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package config

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// Service provides configuration management operations
type Service struct {
	variableRepo *postgres.ConfigVariableRepository
	templateRepo *postgres.ConfigTemplateRepository
	auditRepo    *postgres.ConfigAuditRepository
	syncRepo     *postgres.ConfigSyncRepository
	encryptor    *crypto.AESEncryptor
	logger       *logger.Logger
}

// NewService creates a new config service
func NewService(
	variableRepo *postgres.ConfigVariableRepository,
	templateRepo *postgres.ConfigTemplateRepository,
	auditRepo *postgres.ConfigAuditRepository,
	syncRepo *postgres.ConfigSyncRepository,
	encryptor *crypto.AESEncryptor,
	log *logger.Logger,
) *Service {
	return &Service{
		variableRepo: variableRepo,
		templateRepo: templateRepo,
		auditRepo:    auditRepo,
		syncRepo:     syncRepo,
		encryptor:    encryptor,
		logger:       log.Named("config_service"),
	}
}

// ============================================================================
// Variable Operations
// ============================================================================

// CreateVariable creates a new configuration variable
func (s *Service) CreateVariable(ctx context.Context, input models.CreateVariableInput, userID *uuid.UUID) (*models.ConfigVariable, error) {
	log := logger.FromContext(ctx)

	// Validate variable name format
	if !isValidVariableName(input.Name) {
		return nil, errors.InvalidInput("variable name must be uppercase with underscores (e.g., MY_VAR_NAME)")
	}

	// Create variable
	v := &models.ConfigVariable{
		ID:           uuid.New(),
		Name:         input.Name,
		Value:        input.Value,
		Type:         input.Type,
		Scope:        input.Scope,
		ScopeID:      input.ScopeID,
		Description:  input.Description,
		IsRequired:   input.IsRequired,
		DefaultValue: input.DefaultValue,
		Version:      1,
		CreatedBy:    userID,
		UpdatedBy:    userID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Encrypt value if secret
	if v.Type == models.VariableTypeSecret {
		encrypted, err := s.encryptor.EncryptString(v.Value)
		if err != nil {
			log.Error("Failed to encrypt secret", "name", v.Name, "error", err)
			return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt secret")
		}
		v.Value = encrypted
	}

	// Handle computed values
	if v.Type == models.VariableTypeComputed {
		computed, err := s.computeValue(v.Value)
		if err != nil {
			return nil, err
		}
		v.Value = computed
	}

	// Validate template exists if template scope
	if v.Scope == models.VariableScopeTemplate && v.ScopeID != nil {
		exists, err := s.templateRepo.Exists(ctx, *v.ScopeID)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, errors.NotFound("template")
		}
	}

	// Create in database
	if err := s.variableRepo.Create(ctx, v); err != nil {
		return nil, err
	}

	// Audit log
	s.logAudit(ctx, "create", "variable", v.ID.String(), v.Name, nil, maskIfSecret(v.Value, v.Type), userID)

	log.Info("Config variable created",
		"variable_id", v.ID,
		"name", v.Name,
		"scope", v.Scope)

	return v, nil
}

// GetVariable retrieves a variable by ID
func (s *Service) GetVariable(ctx context.Context, id uuid.UUID) (*models.ConfigVariable, error) {
	v, err := s.variableRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Decrypt if secret (only for display, mark as masked)
	if v.Type == models.VariableTypeSecret {
		// Don't decrypt in the response, just indicate it's encrypted
		v.Value = "********"
	}

	return v, nil
}

// GetVariableDecrypted retrieves a variable with decrypted value (for internal use)
func (s *Service) GetVariableDecrypted(ctx context.Context, id uuid.UUID) (*models.ConfigVariable, error) {
	v, err := s.variableRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Decrypt if secret
	if v.Type == models.VariableTypeSecret {
		decrypted, err := s.encryptor.DecryptString(v.Value)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDecryptionFailed, "failed to decrypt secret")
		}
		v.Value = decrypted
	}

	return v, nil
}

// UpdateVariable updates an existing variable
func (s *Service) UpdateVariable(ctx context.Context, id uuid.UUID, input models.UpdateVariableInput, userID *uuid.UUID) (*models.ConfigVariable, error) {
	log := logger.FromContext(ctx)

	// Get existing variable
	existing, err := s.variableRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	oldValue := maskIfSecret(existing.Value, existing.Type)

	// Update fields
	if input.Value != nil {
		newValue := *input.Value
		if existing.Type == models.VariableTypeSecret {
			encrypted, err := s.encryptor.EncryptString(newValue)
			if err != nil {
				return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt secret")
			}
			newValue = encrypted
		} else if existing.Type == models.VariableTypeComputed {
			computed, err := s.computeValue(newValue)
			if err != nil {
				return nil, err
			}
			newValue = computed
		}
		existing.Value = newValue
	}

	if input.Description != nil {
		existing.Description = input.Description
	}

	if input.IsRequired != nil {
		existing.IsRequired = *input.IsRequired
	}

	if input.DefaultValue != nil {
		existing.DefaultValue = input.DefaultValue
	}

	existing.UpdatedBy = userID
	existing.UpdatedAt = time.Now()

	// Update in database
	if err := s.variableRepo.Update(ctx, existing); err != nil {
		return nil, err
	}

	// Audit log
	newValue := maskIfSecret(existing.Value, existing.Type)
	s.logAudit(ctx, "update", "variable", id.String(), existing.Name, oldValue, newValue, userID)

	log.Info("Config variable updated",
		"variable_id", id,
		"name", existing.Name)

	return existing, nil
}

// DeleteVariable removes a variable
func (s *Service) DeleteVariable(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	log := logger.FromContext(ctx)

	// Get variable for audit
	v, err := s.variableRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Delete
	if err := s.variableRepo.Delete(ctx, id); err != nil {
		return err
	}

	// Audit log
	oldValue := maskIfSecret(v.Value, v.Type)
	s.logAudit(ctx, "delete", "variable", id.String(), v.Name, oldValue, nil, userID)

	log.Info("Config variable deleted",
		"variable_id", id,
		"name", v.Name)

	return nil
}

// ListVariables retrieves variables with filtering
func (s *Service) ListVariables(ctx context.Context, opts models.VariableListOptions) ([]*models.ConfigVariable, int, error) {
	variables, total, err := s.variableRepo.List(ctx, opts)
	if err != nil {
		return nil, 0, err
	}

	// Mask secrets
	for _, v := range variables {
		if v.Type == models.VariableTypeSecret {
			v.Value = "********"
		}
	}

	return variables, total, nil
}

// GetVariableUsage returns where a variable is used
func (s *Service) GetVariableUsage(ctx context.Context, id uuid.UUID) (*models.VariableUsage, error) {
	v, err := s.variableRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	usage := &models.VariableUsage{
		VariableID:   v.ID,
		VariableName: v.Name,
		UsedIn:       []models.UsageEntry{},
	}

	// Get syncs that use this variable
	syncs, _, err := s.syncRepo.List(ctx, postgres.SyncListOptions{Limit: 1000})
	if err != nil {
		return nil, err
	}

	for _, sync := range syncs {
		// Check if variable applies to this sync based on scope
		applies := false
		switch v.Scope {
		case models.VariableScopeGlobal:
			applies = true
		case models.VariableScopeTemplate:
			applies = sync.TemplateName != nil && v.ScopeID != nil && *sync.TemplateName == *v.ScopeID
		case models.VariableScopeContainer:
			applies = v.ScopeID != nil && sync.ContainerID == *v.ScopeID
		}

		if applies {
			usage.UsedIn = append(usage.UsedIn, models.UsageEntry{
				Type: "container",
				ID:   sync.ContainerID,
				Name: sync.ContainerName,
			})
		}
	}

	return usage, nil
}

// GetVariableHistory retrieves version history
func (s *Service) GetVariableHistory(ctx context.Context, id uuid.UUID, limit int) ([]*models.VariableHistory, error) {
	history, err := s.variableRepo.GetHistory(ctx, id, limit)
	if err != nil {
		return nil, err
	}

	// Get current variable to check if it's a secret
	v, err := s.variableRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Mask values if secret
	if v.Type == models.VariableTypeSecret {
		for _, h := range history {
			h.Value = "********"
		}
	}

	return history, nil
}

// RollbackVariable reverts to a previous version
func (s *Service) RollbackVariable(ctx context.Context, id uuid.UUID, version int, userID *uuid.UUID) (*models.ConfigVariable, error) {
	log := logger.FromContext(ctx)

	// Get history version
	h, err := s.variableRepo.GetHistoryVersion(ctx, id, version)
	if err != nil {
		return nil, err
	}

	// Update variable with historical value
	result, err := s.UpdateVariable(ctx, id, models.UpdateVariableInput{
		Value: &h.Value,
	}, userID)
	if err != nil {
		return nil, err
	}

	log.Info("Config variable rolled back",
		"variable_id", id,
		"to_version", version)

	return result, nil
}

// ============================================================================
// Template Operations
// ============================================================================

// CreateTemplate creates a new configuration template
func (s *Service) CreateTemplate(ctx context.Context, input models.CreateTemplateInput, userID *uuid.UUID) (*models.ConfigTemplate, error) {
	log := logger.FromContext(ctx)

	t := &models.ConfigTemplate{
		ID:          uuid.New(),
		Name:        input.Name,
		Description: input.Description,
		IsDefault:   input.IsDefault,
		CreatedBy:   userID,
		UpdatedBy:   userID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// If copying from another template
	if input.CopyFrom != nil && *input.CopyFrom != "" {
		source, err := s.templateRepo.GetByName(ctx, *input.CopyFrom)
		if err != nil {
			return nil, err
		}
		return s.templateRepo.CopyTemplate(ctx, source.ID, input.Name, userID)
	}

	// Create new template
	if err := s.templateRepo.Create(ctx, t); err != nil {
		return nil, err
	}

	// Audit log
	s.logAudit(ctx, "create", "template", t.ID.String(), t.Name, nil, nil, userID)

	log.Info("Config template created",
		"template_id", t.ID,
		"name", t.Name)

	return t, nil
}

// GetTemplate retrieves a template by ID
func (s *Service) GetTemplate(ctx context.Context, id uuid.UUID) (*models.ConfigTemplate, error) {
	t, err := s.templateRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Load variables
	variables, err := s.variableRepo.ListByScope(ctx, models.VariableScopeTemplate, &t.Name)
	if err != nil {
		return nil, err
	}

	// Mask secrets
	for _, v := range variables {
		if v.Type == models.VariableTypeSecret {
			v.Value = "********"
		}
	}

	t.Variables = make([]models.ConfigVariable, len(variables))
	for i, v := range variables {
		t.Variables[i] = *v
	}

	return t, nil
}

// GetTemplateByName retrieves a template by name
func (s *Service) GetTemplateByName(ctx context.Context, name string) (*models.ConfigTemplate, error) {
	return s.templateRepo.GetByName(ctx, name)
}

// UpdateTemplate updates an existing template
func (s *Service) UpdateTemplate(ctx context.Context, id uuid.UUID, input models.UpdateTemplateInput, userID *uuid.UUID) (*models.ConfigTemplate, error) {
	log := logger.FromContext(ctx)

	t, err := s.templateRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		t.Name = *input.Name
	}
	if input.Description != nil {
		t.Description = input.Description
	}
	if input.IsDefault != nil {
		t.IsDefault = *input.IsDefault
	}

	t.UpdatedBy = userID
	t.UpdatedAt = time.Now()

	if err := s.templateRepo.Update(ctx, t); err != nil {
		return nil, err
	}

	// Audit log
	s.logAudit(ctx, "update", "template", id.String(), t.Name, nil, nil, userID)

	log.Info("Config template updated",
		"template_id", id,
		"name", t.Name)

	return t, nil
}

// DeleteTemplate removes a template
func (s *Service) DeleteTemplate(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	log := logger.FromContext(ctx)

	t, err := s.templateRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if err := s.templateRepo.Delete(ctx, id); err != nil {
		return err
	}

	// Audit log
	s.logAudit(ctx, "delete", "template", id.String(), t.Name, nil, nil, userID)

	log.Info("Config template deleted",
		"template_id", id,
		"name", t.Name)

	return nil
}

// ListTemplates retrieves all templates
func (s *Service) ListTemplates(ctx context.Context, search *string, limit, offset int) ([]*models.ConfigTemplate, int, error) {
	return s.templateRepo.List(ctx, search, limit, offset)
}

// SetDefaultTemplate sets a template as default
func (s *Service) SetDefaultTemplate(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	log := logger.FromContext(ctx)

	if err := s.templateRepo.SetDefault(ctx, id); err != nil {
		return err
	}

	t, _ := s.templateRepo.GetByID(ctx, id)
	s.logAudit(ctx, "update", "template", id.String(), t.Name, nil, nil, userID)

	log.Info("Config template set as default", "template_id", id)
	return nil
}

// ============================================================================
// Export/Import Operations
// ============================================================================

// ExportConfig exports configuration to JSON
func (s *Service) ExportConfig(ctx context.Context, password *string) (*models.ConfigExport, error) {
	log := logger.FromContext(ctx)

	// Get all variables (decrypted)
	variables, _, err := s.variableRepo.List(ctx, models.VariableListOptions{Limit: 10000})
	if err != nil {
		return nil, err
	}

	// Decrypt secrets for export
	for _, v := range variables {
		if v.Type == models.VariableTypeSecret {
			decrypted, err := s.encryptor.DecryptString(v.Value)
			if err != nil {
				log.Warn("Failed to decrypt variable for export", "name", v.Name)
				continue
			}
			v.Value = decrypted
		}
	}

	// Get all templates
	templates, err := s.templateRepo.ListAll(ctx)
	if err != nil {
		return nil, err
	}

	export := &models.ConfigExport{
		Version:    "1.0",
		ExportedAt: time.Now(),
		Variables:  make([]models.ConfigVariable, len(variables)),
		Templates:  make([]models.ConfigTemplate, len(templates)),
		Encrypted:  password != nil && *password != "",
	}

	for i, v := range variables {
		export.Variables[i] = *v
	}
	for i, t := range templates {
		export.Templates[i] = *t
	}

	log.Info("Config exported",
		"variables", len(export.Variables),
		"templates", len(export.Templates),
		"encrypted", export.Encrypted)

	return export, nil
}

// ImportConfig imports configuration from JSON
func (s *Service) ImportConfig(ctx context.Context, input models.ConfigImportInput, userID *uuid.UUID) error {
	log := logger.FromContext(ctx)

	// Parse data
	var export models.ConfigExport
	if err := json.Unmarshal([]byte(input.Data), &export); err != nil {
		return errors.InvalidInput("invalid config data format")
	}

	// Import templates first
	for _, t := range export.Templates {
		existing, _ := s.templateRepo.GetByName(ctx, t.Name)
		if existing != nil {
			if !input.Overwrite {
				continue
			}
			// Update existing
			t.ID = existing.ID
			t.UpdatedBy = userID
			if err := s.templateRepo.Update(ctx, &t); err != nil {
				log.Warn("Failed to update template during import", "name", t.Name, "error", err)
			}
		} else {
			// Create new
			t.ID = uuid.New()
			t.CreatedBy = userID
			t.UpdatedBy = userID
			if err := s.templateRepo.Create(ctx, &t); err != nil {
				log.Warn("Failed to create template during import", "name", t.Name, "error", err)
			}
		}
	}

	// Import variables
	for _, v := range export.Variables {
		if input.SkipSecrets && v.Type == models.VariableTypeSecret {
			continue
		}

		existing, _ := s.variableRepo.GetByName(ctx, v.Name, v.Scope, v.ScopeID)
		if existing != nil {
			if !input.Overwrite {
				continue
			}
			// Update existing
			v.ID = existing.ID
			v.Version = existing.Version
			v.UpdatedBy = userID

			// Re-encrypt if secret
			if v.Type == models.VariableTypeSecret {
				encrypted, _ := s.encryptor.EncryptString(v.Value)
				v.Value = encrypted
			}

			if err := s.variableRepo.Update(ctx, &v); err != nil {
				log.Warn("Failed to update variable during import", "name", v.Name, "error", err)
			}
		} else {
			// Create new
			v.ID = uuid.New()
			v.Version = 1
			v.CreatedBy = userID
			v.UpdatedBy = userID

			// Encrypt if secret
			if v.Type == models.VariableTypeSecret {
				encrypted, _ := s.encryptor.EncryptString(v.Value)
				v.Value = encrypted
			}

			if err := s.variableRepo.Create(ctx, &v); err != nil {
				log.Warn("Failed to create variable during import", "name", v.Name, "error", err)
			}
		}
	}

	// Audit log
	s.logAudit(ctx, "import", "config", "", "config_import", nil, nil, userID)

	log.Info("Config imported",
		"variables", len(export.Variables),
		"templates", len(export.Templates))

	return nil
}

// ============================================================================
// Audit Operations
// ============================================================================

// GetAuditLog retrieves audit logs
func (s *Service) GetAuditLog(ctx context.Context, opts postgres.AuditListOptions) ([]*models.ConfigAuditLog, int, error) {
	return s.auditRepo.List(ctx, opts)
}

// ============================================================================
// Helper Functions
// ============================================================================

// logAudit creates an audit log entry
func (s *Service) logAudit(ctx context.Context, action, entityType, entityID, entityName string, oldValue, newValue *string, userID *uuid.UUID) {
	entry := &postgres.AuditLogEntry{
		Action:     action,
		EntityType: entityType,
		EntityID:   entityID,
		EntityName: entityName,
		OldValue:   oldValue,
		NewValue:   newValue,
		UserID:     userID,
	}

	// Try to get additional context from request
	// This would normally come from middleware
	// entry.IPAddress, entry.UserAgent, entry.Username...

	if err := s.auditRepo.Create(ctx, entry); err != nil {
		s.logger.Warn("Failed to create audit log", "error", err)
	}
}

// isValidVariableName validates variable name format
func isValidVariableName(name string) bool {
	// Must be uppercase with underscores, start with letter
	matched, _ := regexp.MatchString(`^[A-Z][A-Z0-9_]*$`, name)
	return matched
}

// maskIfSecret returns masked value if variable is secret
func maskIfSecret(value string, varType models.VariableType) *string {
	if varType == models.VariableTypeSecret {
		m := "********"
		return &m
	}
	return &value
}

// computeValue handles computed variable types
func (s *Service) computeValue(expression string) (string, error) {
	expr := strings.ToLower(strings.TrimSpace(expression))

	switch {
	case expr == "uuid":
		return uuid.New().String(), nil
	case expr == "timestamp":
		return time.Now().Format(time.RFC3339), nil
	case expr == "unix":
		return fmt.Sprintf("%d", time.Now().Unix()), nil
	case strings.HasPrefix(expr, "random:"):
		// random:32 generates 32 char random string
		length := 32
		fmt.Sscanf(expr, "random:%d", &length)
		return generateRandomString(length), nil
	default:
		return expression, nil
	}
}

// generateRandomString generates a random alphanumeric string
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		time.Sleep(1) // Ensure different values
	}
	return string(b)
}
