// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// RegistryRepo defines the interface for registry persistence.
type RegistryRepo interface {
	Create(ctx context.Context, input models.CreateRegistryInput) (*models.Registry, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Registry, error)
	List(ctx context.Context) ([]*models.Registry, error)
	Update(ctx context.Context, id uuid.UUID, input models.CreateRegistryInput) (*models.Registry, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// WebhookRepo defines the interface for outgoing webhook persistence.
type WebhookRepo interface {
	Create(ctx context.Context, wh *models.OutgoingWebhook) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.OutgoingWebhook, error)
	List(ctx context.Context) ([]*models.OutgoingWebhook, error)
	ListEnabled(ctx context.Context, event string) ([]*models.OutgoingWebhook, error)
	Update(ctx context.Context, wh *models.OutgoingWebhook) error
	Delete(ctx context.Context, id uuid.UUID) error
	CreateDelivery(ctx context.Context, d *models.WebhookDelivery) error
	UpdateDelivery(ctx context.Context, d *models.WebhookDelivery) error
	GetDelivery(ctx context.Context, id uuid.UUID) (*models.WebhookDelivery, error)
	ListDeliveries(ctx context.Context, opts models.WebhookDeliveryListOptions) ([]*models.WebhookDelivery, int64, error)
	ListPendingDeliveries(ctx context.Context, limit int) ([]*models.WebhookDelivery, error)
}

// RunbookRepo defines the interface for runbook persistence.
type RunbookRepo interface {
	Create(ctx context.Context, rb *models.Runbook) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Runbook, error)
	List(ctx context.Context, opts models.RunbookListOptions) ([]*models.Runbook, int64, error)
	Update(ctx context.Context, rb *models.Runbook) error
	Delete(ctx context.Context, id uuid.UUID) error
	CreateExecution(ctx context.Context, exec *models.RunbookExecution) error
	UpdateExecution(ctx context.Context, exec *models.RunbookExecution) error
	GetExecution(ctx context.Context, id uuid.UUID) (*models.RunbookExecution, error)
	ListExecutions(ctx context.Context, runbookID uuid.UUID, limit int) ([]*models.RunbookExecution, error)
	ListRecentExecutions(ctx context.Context, limit int) ([]*models.RunbookExecution, error)
	GetCategories(ctx context.Context) ([]string, error)
}

// AutoDeployRepo defines the interface for auto-deploy rule persistence.
type AutoDeployRepo interface {
	Create(ctx context.Context, rule *models.AutoDeployRule) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.AutoDeployRule, error)
	List(ctx context.Context) ([]*models.AutoDeployRule, error)
	Delete(ctx context.Context, id uuid.UUID) error
	MatchRules(ctx context.Context, sourceType, sourceRepo string, branch *string) ([]*models.AutoDeployRule, error)
}

// ComplianceRepo defines the interface for compliance policy persistence.
type ComplianceRepo interface {
	CreatePolicy(ctx context.Context, p *CompliancePolicyRecord) error
	GetPolicy(ctx context.Context, id uuid.UUID) (*CompliancePolicyRecord, error)
	ListPolicies(ctx context.Context) ([]*CompliancePolicyRecord, error)
	DeletePolicy(ctx context.Context, id uuid.UUID) error
	TogglePolicy(ctx context.Context, id uuid.UUID) (bool, error)
	UpdateLastCheck(ctx context.Context, id uuid.UUID, t time.Time) error
	CreateViolation(ctx context.Context, v *ComplianceViolationRecord) error
	ListViolations(ctx context.Context, status *string) ([]*ComplianceViolationRecord, error)
	UpdateViolationStatus(ctx context.Context, id uuid.UUID, status string, resolvedBy *uuid.UUID) error
	ViolationExistsForPolicy(ctx context.Context, policyID uuid.UUID, containerID string) (bool, error)
	CountViolationsByPolicy(ctx context.Context, policyID uuid.UUID) (int, error)
}

// Type aliases pointing to shared models for DB record types.
type CompliancePolicyRecord = models.CompliancePolicyRecord
type ComplianceViolationRecord = models.ComplianceViolationRecord

// ManagedSecretRepo defines the interface for managed secret persistence.
type ManagedSecretRepo interface {
	Create(ctx context.Context, s *ManagedSecretRecord) error
	GetByID(ctx context.Context, id uuid.UUID) (*ManagedSecretRecord, error)
	List(ctx context.Context) ([]*ManagedSecretRecord, error)
	Update(ctx context.Context, s *ManagedSecretRecord) error
	Delete(ctx context.Context, id uuid.UUID) error
}

type ManagedSecretRecord = models.ManagedSecretRecord

// LifecycleRepo defines the interface for lifecycle policy persistence.
type LifecycleRepo interface {
	CreatePolicy(ctx context.Context, p *LifecyclePolicyRecord) error
	GetPolicy(ctx context.Context, id uuid.UUID) (*LifecyclePolicyRecord, error)
	ListPolicies(ctx context.Context) ([]*LifecyclePolicyRecord, error)
	DeletePolicy(ctx context.Context, id uuid.UUID) error
	TogglePolicy(ctx context.Context, id uuid.UUID) (bool, error)
	UpdateLastExecution(ctx context.Context, id uuid.UUID, executedAt time.Time, result string) error
	CreateHistoryEntry(ctx context.Context, h *LifecycleHistoryRecord) error
	ListHistory(ctx context.Context, limit int) ([]*LifecycleHistoryRecord, error)
	TotalSpaceReclaimed(ctx context.Context) (int64, error)
}

type LifecyclePolicyRecord = models.LifecyclePolicyRecord
type LifecycleHistoryRecord = models.LifecycleHistoryRecord

// MaintenanceRepo defines the interface for maintenance window persistence.
type MaintenanceRepo interface {
	Create(ctx context.Context, mw *MaintenanceWindowRecord) error
	GetByID(ctx context.Context, id uuid.UUID) (*MaintenanceWindowRecord, error)
	List(ctx context.Context) ([]*MaintenanceWindowRecord, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Toggle(ctx context.Context, id uuid.UUID) (bool, error)
	SetActive(ctx context.Context, id uuid.UUID, active bool) error
	UpdateLastRun(ctx context.Context, id uuid.UUID, runAt time.Time, status string) error
}

type MaintenanceWindowRecord = models.MaintenanceWindowRecord

// GitOpsRepo defines the interface for GitOps pipeline persistence.
type GitOpsRepo interface {
	CreatePipeline(ctx context.Context, p *GitOpsPipelineRecord) error
	GetPipeline(ctx context.Context, id uuid.UUID) (*GitOpsPipelineRecord, error)
	ListPipelines(ctx context.Context) ([]*GitOpsPipelineRecord, error)
	DeletePipeline(ctx context.Context, id uuid.UUID) error
	TogglePipeline(ctx context.Context, id uuid.UUID) (bool, error)
	IncrementDeployCount(ctx context.Context, id uuid.UUID, deployAt time.Time, status string) error
	CreateDeployment(ctx context.Context, d *GitOpsDeploymentRecord) error
	ListDeployments(ctx context.Context, limit int) ([]*GitOpsDeploymentRecord, error)
}

type GitOpsPipelineRecord = models.GitOpsPipelineRecord
type GitOpsDeploymentRecord = models.GitOpsDeploymentRecord

// ResourceQuotaRepo defines the interface for resource quota persistence.
type ResourceQuotaRepo interface {
	Create(ctx context.Context, q *ResourceQuotaRecord) error
	List(ctx context.Context) ([]*ResourceQuotaRecord, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Toggle(ctx context.Context, id uuid.UUID) (bool, error)
}

type ResourceQuotaRecord = models.ResourceQuotaRecord

// ContainerTemplateRepo defines the interface for container template persistence.
type ContainerTemplateRepo interface {
	Create(ctx context.Context, t *ContainerTemplateRecord) error
	GetByID(ctx context.Context, id uuid.UUID) (*ContainerTemplateRecord, error)
	List(ctx context.Context) ([]*ContainerTemplateRecord, error)
	Delete(ctx context.Context, id uuid.UUID) error
	IncrementUsage(ctx context.Context, id uuid.UUID) error
	GetCategories(ctx context.Context) ([]string, error)
}

type ContainerTemplateRecord = models.ContainerTemplateRecord

// TrackedVulnRepo defines the interface for tracked vulnerability persistence.
type TrackedVulnRepo interface {
	Create(ctx context.Context, v *TrackedVulnRecord) error
	Upsert(ctx context.Context, v *TrackedVulnRecord) error
	GetByID(ctx context.Context, id uuid.UUID) (*TrackedVulnRecord, error)
	List(ctx context.Context) ([]*TrackedVulnRecord, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error
	Resolve(ctx context.Context, id uuid.UUID, notes string, scanID *uuid.UUID) error
	Assign(ctx context.Context, id uuid.UUID, assigneeID *uuid.UUID, assigneeName string) error
	ListSLABreached(ctx context.Context) ([]*TrackedVulnRecord, error)
	WeeklyTrend(ctx context.Context) ([]models.VulnWeeklyTrend, error)
	TopAffectedImages(ctx context.Context, limit int) ([]models.ImageVulnCount, error)
	MTTRBySeverity(ctx context.Context) (map[string]float64, error)
	SLACompliancePercent(ctx context.Context) (float64, error)
	ExistsByCVE(ctx context.Context, cveID string) (bool, error)
	CountSLABreached(ctx context.Context) (int, error)
	CountResolvedSince(ctx context.Context, since time.Time) (int, error)
	CountBySeverity(ctx context.Context) (map[string]int, error)
	CountByStatus(ctx context.Context) (map[string]int, error)
}

type TrackedVulnRecord = models.TrackedVulnRecord
