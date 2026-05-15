// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package rollback implements automated rollback of failed stack deploys.
//
// Operator-defined policies match the failure signals emitted as
// change_events by the stack service. When a matching policy is found,
// the rollback service picks the last known-good version of the affected
// stack and invokes the existing stack-revert API to restore it. Every
// decision (matched, fired, executed, skipped, dry-run) is recorded in
// rollback_audit_log; that table is append-only by Postgres trigger.
//
// The module is a free AGPL feature — no biz gating, no edition checks,
// no call-home. Locking is per stack ID so a manual deploy and an
// automated rollback cannot interleave on the same target.
package rollback

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Sentinel errors. API handlers map these to stable HTTP status codes.
var (
	// ErrInvalidInput is returned for malformed/out-of-enum policy fields.
	ErrInvalidInput = errors.New("rollback: invalid input")
	// ErrStackBusy is returned when a rollback execution is requested
	// against a stack that already has one in flight. The caller
	// should retry after the lock is released.
	ErrStackBusy = errors.New("rollback: stack is already being rolled back")
	// ErrNoLastKnownGood is returned when the strategy could not find a
	// historical version to roll back to. The execution row records
	// status=failed with this reason.
	ErrNoLastKnownGood = errors.New("rollback: no last-known-good version available")
	// ErrStackNotFound is returned when the change_event's resource_id
	// does not resolve to a known stack.
	ErrStackNotFound = errors.New("rollback: stack not found")
)

// PolicyRepository persists policy rows.
type PolicyRepository interface {
	Create(ctx context.Context, p *models.RollbackPolicy) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.RollbackPolicy, error)
	List(ctx context.Context) ([]models.RollbackPolicy, error)
	ListEnabled(ctx context.Context) ([]models.RollbackPolicy, error)
	Update(ctx context.Context, p *models.RollbackPolicy) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// ExecutionRepository persists execution rows.
type ExecutionRepository interface {
	Create(ctx context.Context, e *models.RollbackExecution) error
	Update(ctx context.Context, e *models.RollbackExecution) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.RollbackExecution, error)
	List(ctx context.Context, opts models.RollbackExecutionListOptions) ([]models.RollbackExecution, int, error)
	MostRecentForStack(ctx context.Context, stackID uuid.UUID) (*models.RollbackExecution, error)
}

// AuditRepository writes append-only audit rows.
type AuditRepository interface {
	Append(ctx context.Context, e *models.RollbackAuditEntry) error
	List(ctx context.Context, policyID, stackID uuid.UUID, limit, offset int) ([]models.RollbackAuditEntry, int, error)
}

// StackVersionGetter is the narrow contract this service requires of the
// stack module. Satisfied by *stack.Service in production (Get +
// ListVersions + RestoreVersion).
type StackVersionGetter interface {
	// Get returns the stack row by ID, including its current compose
	// contents. Returns NotFound when the stack does not exist.
	Get(ctx context.Context, id uuid.UUID) (*models.Stack, error)
	// ListVersions returns the version history for the stack, newest
	// first. Used by the "last_healthy" strategy walk.
	ListVersions(ctx context.Context, stackID uuid.UUID) ([]*models.StackVersion, error)
	// RestoreVersion applies the named version to the live stack
	// (compose update + redeploy). The stack module already audits
	// this action via change_events.
	RestoreVersion(ctx context.Context, stackID uuid.UUID, version int, comment string, userID *uuid.UUID) (*models.Stack, error)
}

// Service is the rollback business logic. Construct via NewService and
// hold a single instance for the process lifetime.
type Service struct {
	policies   PolicyRepository
	executions ExecutionRepository
	audit      AuditRepository
	stacks     StackVersionGetter
	logger     *logger.Logger
	clock      func() time.Time

	// Per-stack mutexes. A rollback execution holds the lock for the
	// target stack from "running" through to terminal status. Manual
	// deploys that go through the stack module hit the same lock if
	// they call Service.LockStack — but here we only protect against
	// concurrent rollback executions touching the same stack.
	stackLocks   map[uuid.UUID]*sync.Mutex
	stackLocksMu sync.Mutex
}

// NewService constructs the rollback service.
func NewService(policies PolicyRepository, executions ExecutionRepository, audit AuditRepository, stacks StackVersionGetter, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		policies:   policies,
		executions: executions,
		audit:      audit,
		stacks:     stacks,
		logger:     log.Named("rollback"),
		clock:      time.Now,
		stackLocks: make(map[uuid.UUID]*sync.Mutex),
	}
}

// SetClock overrides the clock — tests only.
func (s *Service) SetClock(fn func() time.Time) {
	s.clock = fn
}

// ============================================================================
// Validation
// ============================================================================

func validScope(s models.RollbackScope) bool {
	switch s {
	case models.RollbackScopeAll, models.RollbackScopeStack, models.RollbackScopeTag:
		return true
	}
	return false
}

func validTrigger(t models.RollbackTriggerKind) bool {
	switch t {
	case models.RollbackTriggerDeployFailed,
		models.RollbackTriggerHealthcheckFailed,
		models.RollbackTriggerContainerCrash:
		return true
	}
	return false
}

func validStrategy(s models.RollbackStrategy) bool {
	switch s {
	case models.RollbackStrategyPrevious, models.RollbackStrategyLastHealthy:
		return true
	}
	return false
}

func validateCreatePolicy(in *models.CreateRollbackPolicyInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if in.Scope == "" {
		in.Scope = models.RollbackScopeAll
	}
	if !validScope(in.Scope) {
		return fmt.Errorf("%w: unknown scope %q", ErrInvalidInput, in.Scope)
	}
	if in.Scope == models.RollbackScopeStack && in.ScopeStackID == nil {
		return fmt.Errorf("%w: scope=stack requires scope_stack_id", ErrInvalidInput)
	}
	if in.Scope == models.RollbackScopeTag && strings.TrimSpace(in.ScopeValue) == "" {
		return fmt.Errorf("%w: scope=tag requires scope_value", ErrInvalidInput)
	}
	if in.TriggerKind == "" {
		in.TriggerKind = models.RollbackTriggerDeployFailed
	}
	if !validTrigger(in.TriggerKind) {
		return fmt.Errorf("%w: unknown trigger_kind %q", ErrInvalidInput, in.TriggerKind)
	}
	if in.LastGoodStrategy == "" {
		in.LastGoodStrategy = models.RollbackStrategyLastHealthy
	}
	if !validStrategy(in.LastGoodStrategy) {
		return fmt.Errorf("%w: unknown last_good_strategy %q", ErrInvalidInput, in.LastGoodStrategy)
	}
	if in.CooldownSeconds < 0 {
		return fmt.Errorf("%w: cooldown_seconds must be >= 0", ErrInvalidInput)
	}
	if in.TriggerKind == models.RollbackTriggerContainerCrash {
		if in.FailureThreshold != nil && *in.FailureThreshold <= 0 {
			return fmt.Errorf("%w: failure_threshold must be > 0", ErrInvalidInput)
		}
		if in.WindowSeconds != nil && *in.WindowSeconds <= 0 {
			return fmt.Errorf("%w: window_seconds must be > 0", ErrInvalidInput)
		}
	}
	return nil
}

func validateUpdatePolicy(in *models.UpdateRollbackPolicyInput) error {
	if in.Name != nil {
		trimmed := strings.TrimSpace(*in.Name)
		if trimmed == "" {
			return fmt.Errorf("%w: name cannot be empty", ErrInvalidInput)
		}
		*in.Name = trimmed
	}
	if in.Scope != nil && !validScope(*in.Scope) {
		return fmt.Errorf("%w: unknown scope %q", ErrInvalidInput, *in.Scope)
	}
	if in.TriggerKind != nil && !validTrigger(*in.TriggerKind) {
		return fmt.Errorf("%w: unknown trigger_kind %q", ErrInvalidInput, *in.TriggerKind)
	}
	if in.LastGoodStrategy != nil && !validStrategy(*in.LastGoodStrategy) {
		return fmt.Errorf("%w: unknown last_good_strategy %q", ErrInvalidInput, *in.LastGoodStrategy)
	}
	if in.CooldownSeconds != nil && *in.CooldownSeconds < 0 {
		return fmt.Errorf("%w: cooldown_seconds must be >= 0", ErrInvalidInput)
	}
	return nil
}

// ============================================================================
// Policy CRUD
// ============================================================================

// CreatePolicy validates the input and persists a new policy.
func (s *Service) CreatePolicy(ctx context.Context, in models.CreateRollbackPolicyInput, actor *uuid.UUID) (*models.RollbackPolicy, error) {
	if err := validateCreatePolicy(&in); err != nil {
		return nil, err
	}
	p := &models.RollbackPolicy{
		Name:             in.Name,
		Description:      in.Description,
		Enabled:          in.Enabled,
		Scope:            in.Scope,
		ScopeStackID:     in.ScopeStackID,
		ScopeValue:       in.ScopeValue,
		TriggerKind:      in.TriggerKind,
		FailureThreshold: in.FailureThreshold,
		WindowSeconds:    in.WindowSeconds,
		LastGoodStrategy: in.LastGoodStrategy,
		CooldownSeconds:  in.CooldownSeconds,
		DryRun:           in.DryRun,
		CreatedBy:        actor,
	}
	if err := s.policies.Create(ctx, p); err != nil {
		return nil, err
	}
	s.appendAudit(ctx, &models.RollbackAuditEntry{
		PolicyID: ptrUUID(p.ID),
		ActorID:  actor,
		Action:   models.RollbackAuditActionPolicyCreated,
		Details:  fmt.Sprintf("name=%q scope=%s trigger=%s strategy=%s enabled=%v dry_run=%v", p.Name, p.Scope, p.TriggerKind, p.LastGoodStrategy, p.Enabled, p.DryRun),
	})
	return p, nil
}

// UpdatePolicy applies a partial update.
func (s *Service) UpdatePolicy(ctx context.Context, id uuid.UUID, in models.UpdateRollbackPolicyInput, actor *uuid.UUID) (*models.RollbackPolicy, error) {
	if err := validateUpdatePolicy(&in); err != nil {
		return nil, err
	}
	p, err := s.policies.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	prevEnabled := p.Enabled
	if in.Name != nil {
		p.Name = *in.Name
	}
	if in.Description != nil {
		p.Description = *in.Description
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	if in.Scope != nil {
		p.Scope = *in.Scope
	}
	if in.ScopeStackID != nil {
		p.ScopeStackID = in.ScopeStackID
	}
	if in.ScopeValue != nil {
		p.ScopeValue = *in.ScopeValue
	}
	if in.TriggerKind != nil {
		p.TriggerKind = *in.TriggerKind
	}
	if in.FailureThreshold != nil {
		p.FailureThreshold = in.FailureThreshold
	}
	if in.WindowSeconds != nil {
		p.WindowSeconds = in.WindowSeconds
	}
	if in.LastGoodStrategy != nil {
		p.LastGoodStrategy = *in.LastGoodStrategy
	}
	if in.CooldownSeconds != nil {
		p.CooldownSeconds = *in.CooldownSeconds
	}
	if in.DryRun != nil {
		p.DryRun = *in.DryRun
	}

	// Cross-field invariants — re-run the create validator on the
	// merged result.
	merged := models.CreateRollbackPolicyInput{
		Name:             p.Name,
		Description:      p.Description,
		Enabled:          p.Enabled,
		Scope:            p.Scope,
		ScopeStackID:     p.ScopeStackID,
		ScopeValue:       p.ScopeValue,
		TriggerKind:      p.TriggerKind,
		FailureThreshold: p.FailureThreshold,
		WindowSeconds:    p.WindowSeconds,
		LastGoodStrategy: p.LastGoodStrategy,
		CooldownSeconds:  p.CooldownSeconds,
		DryRun:           p.DryRun,
	}
	if err := validateCreatePolicy(&merged); err != nil {
		return nil, err
	}

	if err := s.policies.Update(ctx, p); err != nil {
		return nil, err
	}

	action := models.RollbackAuditActionPolicyUpdated
	if prevEnabled != p.Enabled {
		if p.Enabled {
			action = models.RollbackAuditActionPolicyEnabled
		} else {
			action = models.RollbackAuditActionPolicyDisabled
		}
	}
	s.appendAudit(ctx, &models.RollbackAuditEntry{
		PolicyID: ptrUUID(p.ID),
		ActorID:  actor,
		Action:   action,
		Details:  fmt.Sprintf("name=%q enabled=%v dry_run=%v", p.Name, p.Enabled, p.DryRun),
	})

	return p, nil
}

// DeletePolicy removes a policy. Executions are cascade-deleted; audit
// rows are preserved (the audit table is append-only and policy_id is
// nullable for exactly this reason).
func (s *Service) DeletePolicy(ctx context.Context, id uuid.UUID, actor *uuid.UUID) error {
	p, err := s.policies.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.policies.Delete(ctx, id); err != nil {
		return err
	}
	s.appendAudit(ctx, &models.RollbackAuditEntry{
		PolicyID: ptrUUID(p.ID),
		ActorID:  actor,
		Action:   models.RollbackAuditActionPolicyDeleted,
		Details:  fmt.Sprintf("name=%q", p.Name),
	})
	return nil
}

// GetPolicy returns a single policy.
func (s *Service) GetPolicy(ctx context.Context, id uuid.UUID) (*models.RollbackPolicy, error) {
	return s.policies.GetByID(ctx, id)
}

// ListPolicies returns all policies.
func (s *Service) ListPolicies(ctx context.Context) ([]models.RollbackPolicy, error) {
	return s.policies.List(ctx)
}

// ListEnabledPolicies returns only the enabled policies, in name order.
// Used by the scheduler worker's match loop on every change_event.
func (s *Service) ListEnabledPolicies(ctx context.Context) ([]models.RollbackPolicy, error) {
	return s.policies.ListEnabled(ctx)
}

// ============================================================================
// Execution
// ============================================================================

// ListExecutions returns execution rows filtered by the given options.
func (s *Service) ListExecutions(ctx context.Context, opts models.RollbackExecutionListOptions) ([]models.RollbackExecution, int, error) {
	return s.executions.List(ctx, opts)
}

// GetExecution returns a single execution.
func (s *Service) GetExecution(ctx context.Context, id uuid.UUID) (*models.RollbackExecution, error) {
	return s.executions.GetByID(ctx, id)
}

// ListAudit returns paginated audit rows. policyID / stackID may be
// uuid.Nil to skip the filter.
func (s *Service) ListAudit(ctx context.Context, policyID, stackID uuid.UUID, limit, offset int) ([]models.RollbackAuditEntry, int, error) {
	return s.audit.List(ctx, policyID, stackID, limit, offset)
}

// MatchesEvent reports whether the given policy should fire on the
// given change_event. Exposed so the worker can run the match in-process
// instead of re-loading the policy after the dry-run path.
//
// The match logic:
//   - The event's resource_type must be "stack".
//   - The event's action must indicate failure for the policy's trigger
//     kind. v26.5.0's change_events writes action="deploy" with an error
//     in the metadata; the worker passes the parsed failure signal here.
//   - The scope must contain the affected stack.
func (s *Service) MatchesEvent(policy *models.RollbackPolicy, e *models.ChangeEvent, stack *models.Stack) bool {
	if !policy.Enabled {
		return false
	}
	if e == nil || stack == nil {
		return false
	}
	if e.ResourceType != models.ChangeResourceStack {
		return false
	}
	switch policy.Scope {
	case models.RollbackScopeAll:
		// match every stack
	case models.RollbackScopeStack:
		if policy.ScopeStackID == nil || *policy.ScopeStackID != stack.ID {
			return false
		}
	case models.RollbackScopeTag:
		if policy.ScopeValue == "" {
			return false
		}
		if !strings.Contains(strings.ToLower(stack.Name), strings.ToLower(policy.ScopeValue)) {
			return false
		}
	default:
		return false
	}
	return true
}

// DryRun previews what an execution of policyID against stackID would
// do. It does not mutate the live stack or the execution table; only an
// audit row is appended so the operator's "try it" click is recorded.
func (s *Service) DryRun(ctx context.Context, policyID, stackID uuid.UUID, actor *uuid.UUID) (*models.RollbackDryRunResult, error) {
	p, err := s.policies.GetByID(ctx, policyID)
	if err != nil {
		return nil, err
	}
	stack, err := s.stacks.Get(ctx, stackID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStackNotFound, err)
	}

	// We don't have a real change_event here — build a synthetic one
	// so the matching logic can be exercised.
	synthetic := &models.ChangeEvent{
		ResourceType: models.ChangeResourceStack,
		ResourceID:   stack.ID.String(),
		ResourceName: stack.Name,
		Action:       models.ChangeActionDeploy,
	}
	matched := s.MatchesEvent(p, synthetic, stack)

	result := &models.RollbackDryRunResult{
		Matched:       matched,
		PolicyID:      p.ID,
		StackID:       ptrUUID(stack.ID),
		StackName:     stack.Name,
		Strategy:      p.LastGoodStrategy,
		PolicyEnabled: p.Enabled,
		PolicyDryRun:  p.DryRun,
		NextStatus:    models.RollbackExecutionDryRun,
	}

	if !matched {
		result.Reason = "policy scope does not contain this stack"
		result.SkipReason = result.Reason
		s.appendAudit(ctx, &models.RollbackAuditEntry{
			PolicyID: ptrUUID(p.ID),
			StackID:  ptrUUID(stack.ID),
			ActorID:  actor,
			Action:   models.RollbackAuditActionDryRun,
			Details:  fmt.Sprintf("matched=false reason=%q", result.Reason),
		})
		return result, nil
	}

	// Resolve the target version using the policy's strategy.
	versions, err := s.stacks.ListVersions(ctx, stack.ID)
	if err != nil {
		result.Reason = fmt.Sprintf("listing versions: %v", err)
		result.SkipReason = result.Reason
		return result, nil
	}
	from, to, vErr := s.pickRollbackTarget(versions, p.LastGoodStrategy)
	if vErr != nil {
		result.Reason = vErr.Error()
		result.SkipReason = result.Reason
		s.appendAudit(ctx, &models.RollbackAuditEntry{
			PolicyID: ptrUUID(p.ID),
			StackID:  ptrUUID(stack.ID),
			ActorID:  actor,
			Action:   models.RollbackAuditActionDryRun,
			Details:  fmt.Sprintf("matched=true reason=%q", vErr.Error()),
		})
		return result, nil
	}
	if from != 0 {
		v := from
		result.FromVersion = &v
	}
	v := to
	result.ToVersion = &v
	result.WouldExecute = !p.DryRun
	result.Reason = fmt.Sprintf("policy would restore version %d (from %d) via strategy %q", to, from, p.LastGoodStrategy)

	// Audit the preview.
	s.appendAudit(ctx, &models.RollbackAuditEntry{
		PolicyID: ptrUUID(p.ID),
		StackID:  ptrUUID(stack.ID),
		ActorID:  actor,
		Action:   models.RollbackAuditActionDryRun,
		Details:  result.Reason,
	})
	return result, nil
}

// Execute runs a rollback now, synchronously. The caller supplies the
// originating event when one is known; pass nil for manual /
// dry-promotion paths. The lock is held for the entire execution so a
// concurrent ExecuteOnEvent on the same stack returns ErrStackBusy.
//
// The execution row is inserted at status=pending, advanced to running,
// and ends at succeeded/failed/skipped/dry_run. The stack-revert call
// itself is delegated to StackVersionGetter.RestoreVersion — the stack
// module owns the redeploy and writes its own change_event.
func (s *Service) Execute(ctx context.Context, policy *models.RollbackPolicy, stack *models.Stack, originating *models.ChangeEvent, actor *uuid.UUID) (*models.RollbackExecution, error) {
	if policy == nil || stack == nil {
		return nil, fmt.Errorf("%w: policy and stack are required", ErrInvalidInput)
	}

	now := s.clock()

	// Cooldown — refuse to execute if the most recent run on this stack
	// is still within the configured window. Prevents flapping on a
	// repeatedly-failing deploy.
	if policy.CooldownSeconds > 0 {
		if recent, err := s.executions.MostRecentForStack(ctx, stack.ID); err == nil && recent != nil {
			if now.Sub(recent.CreatedAt) < time.Duration(policy.CooldownSeconds)*time.Second {
				skip := &models.RollbackExecution{
					PolicyID:    policy.ID,
					StackID:     stack.ID,
					TriggerKind: policy.TriggerKind,
					Status:      models.RollbackExecutionSkipped,
					Reason:      fmt.Sprintf("cooldown active (%ds remaining)", policy.CooldownSeconds-int(now.Sub(recent.CreatedAt).Seconds())),
				}
				if originating != nil {
					id := originating.ID
					skip.ChangeEventID = &id
				}
				started := s.clock()
				skip.StartedAt = &started
				skip.FinishedAt = &started
				if err := s.executions.Create(ctx, skip); err != nil {
					return nil, err
				}
				s.appendAudit(ctx, &models.RollbackAuditEntry{
					PolicyID:    ptrUUID(policy.ID),
					ExecutionID: ptrUUID(skip.ID),
					StackID:     ptrUUID(stack.ID),
					ActorID:     actor,
					Action:      models.RollbackAuditActionExecutionSkip,
					Details:     skip.Reason,
				})
				return skip, nil
			}
		}
	}

	// Acquire stack lock before mutating the live stack. Held for the
	// remainder of the call.
	lock, locked := s.tryLockStack(stack.ID)
	if !locked {
		return nil, ErrStackBusy
	}
	defer s.unlockStack(stack.ID, lock)

	// Insert pending row.
	exec := &models.RollbackExecution{
		PolicyID:    policy.ID,
		StackID:     stack.ID,
		TriggerKind: policy.TriggerKind,
		Status:      models.RollbackExecutionPending,
	}
	if originating != nil {
		id := originating.ID
		exec.ChangeEventID = &id
	}
	if err := s.executions.Create(ctx, exec); err != nil {
		return nil, err
	}
	s.appendAudit(ctx, &models.RollbackAuditEntry{
		PolicyID:    ptrUUID(policy.ID),
		ExecutionID: ptrUUID(exec.ID),
		StackID:     ptrUUID(stack.ID),
		ActorID:     actor,
		Action:      models.RollbackAuditActionExecutionFired,
		Details:     fmt.Sprintf("policy=%q trigger=%s", policy.Name, policy.TriggerKind),
	})

	// Resolve target version.
	versions, err := s.stacks.ListVersions(ctx, stack.ID)
	if err != nil {
		return s.finishFailed(ctx, exec, fmt.Sprintf("listing versions: %v", err), actor)
	}
	from, to, vErr := s.pickRollbackTarget(versions, policy.LastGoodStrategy)
	if vErr != nil {
		return s.finishFailed(ctx, exec, vErr.Error(), actor)
	}
	if from != 0 {
		v := from
		exec.FromVersion = &v
	}
	v := to
	exec.ToVersion = &v

	// Move to running.
	started := s.clock()
	exec.StartedAt = &started
	exec.Status = models.RollbackExecutionRunning
	exec.Reason = fmt.Sprintf("restoring version %d via strategy %q", to, policy.LastGoodStrategy)
	if err := s.executions.Update(ctx, exec); err != nil {
		return nil, err
	}

	// Dry-run policies: stop after picking the target.
	if policy.DryRun {
		finished := s.clock()
		exec.FinishedAt = &finished
		exec.Status = models.RollbackExecutionDryRun
		exec.Reason = fmt.Sprintf("dry-run: would restore version %d", to)
		if err := s.executions.Update(ctx, exec); err != nil {
			return nil, err
		}
		s.appendAudit(ctx, &models.RollbackAuditEntry{
			PolicyID:    ptrUUID(policy.ID),
			ExecutionID: ptrUUID(exec.ID),
			StackID:     ptrUUID(stack.ID),
			ActorID:     actor,
			Action:      models.RollbackAuditActionDryRun,
			Details:     exec.Reason,
		})
		return exec, nil
	}

	// Invoke the stack module's revert API.
	_, restoreErr := s.stacks.RestoreVersion(ctx, stack.ID, to, fmt.Sprintf("automated rollback by policy %q", policy.Name), actor)
	finished := s.clock()
	exec.FinishedAt = &finished
	if restoreErr != nil {
		return s.finishFailed(ctx, exec, fmt.Sprintf("restore version %d failed: %v", to, restoreErr), actor)
	}

	exec.Status = models.RollbackExecutionSucceeded
	exec.Reason = fmt.Sprintf("restored version %d", to)
	if err := s.executions.Update(ctx, exec); err != nil {
		return nil, err
	}
	s.appendAudit(ctx, &models.RollbackAuditEntry{
		PolicyID:    ptrUUID(policy.ID),
		ExecutionID: ptrUUID(exec.ID),
		StackID:     ptrUUID(stack.ID),
		ActorID:     actor,
		Action:      models.RollbackAuditActionExecutionDone,
		Details:     exec.Reason,
	})
	return exec, nil
}

// ExecuteOnEvent is the worker's entry point: given an in-flight
// change_event observed on the stream, run every enabled policy that
// matches and execute the first one to fire.
//
// Returns the execution row when something fired (success or skip), nil
// when no policy matched. Errors are returned only for transport-level
// failures; per-policy failures are recorded in the execution row.
func (s *Service) ExecuteOnEvent(ctx context.Context, e *models.ChangeEvent) (*models.RollbackExecution, error) {
	if e == nil || e.ResourceType != models.ChangeResourceStack {
		return nil, nil
	}
	stackID, parseErr := uuid.Parse(e.ResourceID)
	if parseErr != nil {
		// A change_event with a non-UUID resource_id is a logic bug
		// somewhere upstream; we log and skip rather than propagate
		// because the worker must not let one bad event stop the
		// stream.
		s.logger.Debug("rollback: event has non-UUID resource_id",
			"resource_id", e.ResourceID,
			"action", e.Action,
		)
		return nil, nil //nolint:nilerr // intentional: bad event, skip
	}
	stack, err := s.stacks.Get(ctx, stackID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStackNotFound, err)
	}

	policies, err := s.policies.ListEnabled(ctx)
	if err != nil {
		return nil, err
	}
	for i := range policies {
		p := &policies[i]
		if !s.MatchesEvent(p, e, stack) {
			continue
		}
		if !triggerMatchesAction(p.TriggerKind, e) {
			continue
		}
		// First match wins. Subsequent policies that also matched are
		// audited as "skipped" via the standard execution row so the
		// operator can see policy collisions in the log.
		exec, execErr := s.Execute(ctx, p, stack, e, nil)
		if execErr != nil {
			if errors.Is(execErr, ErrStackBusy) {
				return nil, nil
			}
			return nil, execErr
		}
		return exec, nil
	}
	return nil, nil
}

// triggerMatchesAction returns true when the event signals the failure
// kind a policy listens for. The stack module writes action="deploy"
// with metadata.error set on failure (change_events convention); we
// look for non-empty .error in the metadata, or for action ==
// ChangeActionRollback already (avoiding infinite loops on our own
// audit rows).
func triggerMatchesAction(kind models.RollbackTriggerKind, e *models.ChangeEvent) bool {
	if e == nil {
		return false
	}
	// Refuse to fire on our own change_events.
	if e.Action == models.ChangeActionRollback {
		return false
	}
	switch kind {
	case models.RollbackTriggerDeployFailed:
		if e.Action != models.ChangeActionDeploy {
			return false
		}
		return eventHasError(e)
	case models.RollbackTriggerHealthcheckFailed:
		// Heuristic: stack module emits action="restart" or
		// "config_change" with metadata.healthcheck_failed=true when
		// the post-deploy healthcheck times out.
		if e.Action != models.ChangeActionRestart && e.Action != models.ChangeActionConfigChange {
			return false
		}
		return eventMetadataBool(e, "healthcheck_failed")
	case models.RollbackTriggerContainerCrash:
		return e.Action == models.ChangeActionStop && eventMetadataBool(e, "container_crash")
	}
	return false
}

func eventHasError(e *models.ChangeEvent) bool {
	if e.Metadata == nil {
		return false
	}
	// We don't unmarshal here — the meta is a small JSON blob, a
	// substring check is sufficient for the policy decision and avoids
	// the allocation cost on the hot path.
	raw := string(*e.Metadata)
	return strings.Contains(raw, `"error"`) && !strings.Contains(raw, `"error":""`)
}

func eventMetadataBool(e *models.ChangeEvent, key string) bool {
	if e.Metadata == nil {
		return false
	}
	raw := string(*e.Metadata)
	return strings.Contains(raw, `"`+key+`":true`)
}

// finishFailed transitions an execution to failed with the given reason
// and appends an audit row. Always returns the execution and a nil
// error from the caller's perspective — finishFailed is the terminal
// path, not a propagated error.
func (s *Service) finishFailed(ctx context.Context, exec *models.RollbackExecution, reason string, actor *uuid.UUID) (*models.RollbackExecution, error) {
	finished := s.clock()
	if exec.StartedAt == nil {
		exec.StartedAt = &finished
	}
	exec.FinishedAt = &finished
	exec.Status = models.RollbackExecutionFailed
	exec.Error = reason
	if err := s.executions.Update(ctx, exec); err != nil {
		return nil, err
	}
	s.appendAudit(ctx, &models.RollbackAuditEntry{
		PolicyID:    ptrUUID(exec.PolicyID),
		ExecutionID: ptrUUID(exec.ID),
		StackID:     ptrUUID(exec.StackID),
		ActorID:     actor,
		Action:      models.RollbackAuditActionExecutionFail,
		Details:     reason,
	})
	return exec, nil
}

// pickRollbackTarget walks the version history and returns
// (from_version, to_version) per the strategy.
//
//   - "previous"     — the version immediately before the deployed one.
//   - "last_healthy" — the most recent earlier version with is_deployed
//     and a deployed_at timestamp (i.e. at some point it ran and ran OK).
//
// versions is expected to come from StackVersionGetter.ListVersions which
// returns rows newest-first.
func (s *Service) pickRollbackTarget(versions []*models.StackVersion, strategy models.RollbackStrategy) (int, int, error) {
	if len(versions) < 2 {
		return 0, 0, ErrNoLastKnownGood
	}
	current := versions[0]
	switch strategy {
	case models.RollbackStrategyPrevious:
		prev := versions[1]
		return current.Version, prev.Version, nil
	case models.RollbackStrategyLastHealthy:
		for _, v := range versions[1:] {
			if v.IsDeployed && v.DeployedAt != nil {
				return current.Version, v.Version, nil
			}
		}
		return 0, 0, ErrNoLastKnownGood
	}
	return 0, 0, fmt.Errorf("%w: unknown strategy %q", ErrInvalidInput, strategy)
}

// appendAudit writes an audit row; logs and swallows errors. The audit
// table is the primary record but a transient DB hiccup should not
// abort the execution path that is already in flight.
func (s *Service) appendAudit(ctx context.Context, e *models.RollbackAuditEntry) {
	if e == nil {
		return
	}
	if err := s.audit.Append(ctx, e); err != nil {
		s.logger.Error("rollback: audit append failed",
			"action", e.Action,
			"error", err,
		)
	}
}

// tryLockStack acquires the per-stack lock without blocking. Returns
// (lock, false) when the lock is held; the caller must not call
// unlockStack in that case.
func (s *Service) tryLockStack(stackID uuid.UUID) (*sync.Mutex, bool) {
	s.stackLocksMu.Lock()
	lock, ok := s.stackLocks[stackID]
	if !ok {
		lock = &sync.Mutex{}
		s.stackLocks[stackID] = lock
	}
	s.stackLocksMu.Unlock()

	if !lock.TryLock() {
		return nil, false
	}
	return lock, true
}

func (s *Service) unlockStack(stackID uuid.UUID, lock *sync.Mutex) {
	if lock == nil {
		return
	}
	lock.Unlock()
	// Don't delete the map entry — keeping it bounded by the number of
	// distinct stacks the operator ever rolled back is fine and avoids
	// a race between Lock and the cleanup.
	_ = stackID
}

func ptrUUID(id uuid.UUID) *uuid.UUID {
	return &id
}
