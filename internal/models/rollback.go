// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// RollbackScope controls which stacks a policy applies to.
type RollbackScope string

const (
	// RollbackScopeAll matches every stack on the host.
	RollbackScopeAll RollbackScope = "all"
	// RollbackScopeStack matches a single stack by ID (ScopeStackID).
	RollbackScopeStack RollbackScope = "stack"
	// RollbackScopeTag matches stacks whose name contains ScopeValue.
	// (v26.2.7 called this "label" — the column is renamed for clarity
	// since stacks have a name + free-form description, not labels.)
	RollbackScopeTag RollbackScope = "tag"
)

// RollbackTriggerKind enumerates the failure signals a policy reacts to.
type RollbackTriggerKind string

const (
	// RollbackTriggerDeployFailed fires when a stack_deploy job completes
	// with a non-zero exit. The change_event action is "deploy" with a
	// metadata.error field set.
	RollbackTriggerDeployFailed RollbackTriggerKind = "deploy_failed"
	// RollbackTriggerHealthcheckFailed fires when a post-deploy
	// healthcheck never went green inside WindowSeconds. The deploy
	// itself returned 0 but the container is unhealthy.
	RollbackTriggerHealthcheckFailed RollbackTriggerKind = "healthcheck_failed"
	// RollbackTriggerContainerCrash fires when a stack's containers
	// restart more than FailureThreshold times inside WindowSeconds.
	RollbackTriggerContainerCrash RollbackTriggerKind = "container_crash"
)

// RollbackStrategy picks which historical version to roll back to.
type RollbackStrategy string

const (
	// RollbackStrategyPrevious uses the version immediately before the
	// failing one. Naive but fast.
	RollbackStrategyPrevious RollbackStrategy = "previous"
	// RollbackStrategyLastHealthy walks the version history backward
	// until it finds one whose deploy succeeded and whose healthcheck
	// went green. This is the default — v26.2.7 used "previous" which
	// is unsafe when the previous deploy itself failed.
	RollbackStrategyLastHealthy RollbackStrategy = "last_healthy"
)

// RollbackExecutionStatus is the lifecycle status of an execution.
type RollbackExecutionStatus string

const (
	RollbackExecutionPending   RollbackExecutionStatus = "pending"
	RollbackExecutionRunning   RollbackExecutionStatus = "running"
	RollbackExecutionSucceeded RollbackExecutionStatus = "succeeded"
	RollbackExecutionFailed    RollbackExecutionStatus = "failed"
	RollbackExecutionSkipped   RollbackExecutionStatus = "skipped"
	RollbackExecutionDryRun    RollbackExecutionStatus = "dry_run"
)

// RollbackAuditAction enumerates the actions recorded in the append-only
// audit log. These are also the values written to rollback_audit_log.action.
const (
	RollbackAuditActionPolicyCreated  = "policy_created"
	RollbackAuditActionPolicyUpdated  = "policy_updated"
	RollbackAuditActionPolicyDeleted  = "policy_deleted"
	RollbackAuditActionPolicyEnabled  = "policy_enabled"
	RollbackAuditActionPolicyDisabled = "policy_disabled"
	RollbackAuditActionExecutionFired = "execution_fired"
	RollbackAuditActionExecutionDone  = "execution_done"
	RollbackAuditActionExecutionFail  = "execution_failed"
	RollbackAuditActionExecutionSkip  = "execution_skipped"
	RollbackAuditActionDryRun         = "dry_run"
)

// RollbackPolicy is an operator-defined detection + remediation rule.
// When the scheduler worker observes a change_event that matches the
// policy's scope and trigger, the rollback service executes the
// configured strategy against the target stack.
type RollbackPolicy struct {
	ID               uuid.UUID           `json:"id" db:"id"`
	Name             string              `json:"name" db:"name"`
	Description      string              `json:"description" db:"description"`
	Enabled          bool                `json:"enabled" db:"enabled"`
	Scope            RollbackScope       `json:"scope" db:"scope"`
	ScopeStackID     *uuid.UUID          `json:"scope_stack_id,omitempty" db:"scope_stack_id"`
	ScopeValue       string              `json:"scope_value,omitempty" db:"scope_value"`
	TriggerKind      RollbackTriggerKind `json:"trigger_kind" db:"trigger_kind"`
	FailureThreshold *int                `json:"failure_threshold,omitempty" db:"failure_threshold"`
	WindowSeconds    *int                `json:"window_seconds,omitempty" db:"window_seconds"`
	LastGoodStrategy RollbackStrategy    `json:"last_good_strategy" db:"last_good_strategy"`
	CooldownSeconds  int                 `json:"cooldown_seconds" db:"cooldown_seconds"`
	DryRun           bool                `json:"dry_run" db:"dry_run"`
	CreatedBy        *uuid.UUID          `json:"created_by,omitempty" db:"created_by"`
	CreatedAt        time.Time           `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time           `json:"updated_at" db:"updated_at"`
}

// CreateRollbackPolicyInput is the create-policy payload. The service
// validates Scope/TriggerKind/LastGoodStrategy against the closed enums
// before persisting.
type CreateRollbackPolicyInput struct {
	Name             string              `json:"name"`
	Description      string              `json:"description"`
	Enabled          bool                `json:"enabled"`
	Scope            RollbackScope       `json:"scope"`
	ScopeStackID     *uuid.UUID          `json:"scope_stack_id,omitempty"`
	ScopeValue       string              `json:"scope_value,omitempty"`
	TriggerKind      RollbackTriggerKind `json:"trigger_kind"`
	FailureThreshold *int                `json:"failure_threshold,omitempty"`
	WindowSeconds    *int                `json:"window_seconds,omitempty"`
	LastGoodStrategy RollbackStrategy    `json:"last_good_strategy"`
	CooldownSeconds  int                 `json:"cooldown_seconds"`
	DryRun           bool                `json:"dry_run"`
}

// UpdateRollbackPolicyInput is the patch payload. Only non-nil fields
// are applied.
type UpdateRollbackPolicyInput struct {
	Name             *string              `json:"name,omitempty"`
	Description      *string              `json:"description,omitempty"`
	Enabled          *bool                `json:"enabled,omitempty"`
	Scope            *RollbackScope       `json:"scope,omitempty"`
	ScopeStackID     *uuid.UUID           `json:"scope_stack_id,omitempty"`
	ScopeValue       *string              `json:"scope_value,omitempty"`
	TriggerKind      *RollbackTriggerKind `json:"trigger_kind,omitempty"`
	FailureThreshold *int                 `json:"failure_threshold,omitempty"`
	WindowSeconds    *int                 `json:"window_seconds,omitempty"`
	LastGoodStrategy *RollbackStrategy    `json:"last_good_strategy,omitempty"`
	CooldownSeconds  *int                 `json:"cooldown_seconds,omitempty"`
	DryRun           *bool                `json:"dry_run,omitempty"`
}

// RollbackExecution is a fired-and-resolved (or in-flight) rollback run.
// Rows are inserted at "pending", advanced through "running", and end at
// one of "succeeded" / "failed" / "skipped" / "dry_run".
type RollbackExecution struct {
	ID            uuid.UUID               `json:"id" db:"id"`
	PolicyID      uuid.UUID               `json:"policy_id" db:"policy_id"`
	StackID       uuid.UUID               `json:"stack_id" db:"stack_id"`
	ChangeEventID *uuid.UUID              `json:"change_event_id,omitempty" db:"change_event_id"`
	TriggerKind   RollbackTriggerKind     `json:"trigger_kind" db:"trigger_kind"`
	FromVersion   *int                    `json:"from_version,omitempty" db:"from_version"`
	ToVersion     *int                    `json:"to_version,omitempty" db:"to_version"`
	Status        RollbackExecutionStatus `json:"status" db:"status"`
	Reason        string                  `json:"reason" db:"reason"`
	Error         string                  `json:"error,omitempty" db:"error"`
	StartedAt     *time.Time              `json:"started_at,omitempty" db:"started_at"`
	FinishedAt    *time.Time              `json:"finished_at,omitempty" db:"finished_at"`
	CreatedAt     time.Time               `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time               `json:"updated_at" db:"updated_at"`
}

// RollbackExecutionListOptions filters /executions queries.
type RollbackExecutionListOptions struct {
	PolicyID *uuid.UUID
	StackID  *uuid.UUID
	Status   RollbackExecutionStatus
	Limit    int
	Offset   int
}

// RollbackAuditEntry is a row in rollback_audit_log. Append-only —
// every UPDATE/DELETE is blocked at the SQL layer by
// rollback_audit_log_append_only_trigger.
type RollbackAuditEntry struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	PolicyID    *uuid.UUID `json:"policy_id,omitempty" db:"policy_id"`
	ExecutionID *uuid.UUID `json:"execution_id,omitempty" db:"execution_id"`
	StackID     *uuid.UUID `json:"stack_id,omitempty" db:"stack_id"`
	ActorID     *uuid.UUID `json:"actor_id,omitempty" db:"actor_id"`
	Action      string     `json:"action" db:"action"`
	Details     string     `json:"details,omitempty" db:"details"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
}

// RollbackDryRunResult is the preview returned by the dry-run endpoint.
// It tells the operator "if this policy fired right now against this
// stack, here's what the service would do." No write is performed.
type RollbackDryRunResult struct {
	Matched       bool                    `json:"matched"`
	PolicyID      uuid.UUID               `json:"policy_id"`
	StackID       *uuid.UUID              `json:"stack_id,omitempty"`
	StackName     string                  `json:"stack_name,omitempty"`
	FromVersion   *int                    `json:"from_version,omitempty"`
	ToVersion     *int                    `json:"to_version,omitempty"`
	Strategy      RollbackStrategy        `json:"strategy"`
	WouldExecute  bool                    `json:"would_execute"`
	SkipReason    string                  `json:"skip_reason,omitempty"`
	PolicyEnabled bool                    `json:"policy_enabled"`
	PolicyDryRun  bool                    `json:"policy_dry_run"`
	Reason        string                  `json:"reason,omitempty"`
	NextStatus    RollbackExecutionStatus `json:"next_status"`
}
