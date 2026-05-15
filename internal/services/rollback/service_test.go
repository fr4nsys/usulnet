// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package rollback

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ============================================================================
// In-memory fakes
// ============================================================================

type fakePolicyRepo struct {
	mu       sync.Mutex
	policies map[uuid.UUID]*models.RollbackPolicy
}

func newFakePolicyRepo() *fakePolicyRepo {
	return &fakePolicyRepo{policies: make(map[uuid.UUID]*models.RollbackPolicy)}
}
func (f *fakePolicyRepo) Create(_ context.Context, p *models.RollbackPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	cp := *p
	f.policies[p.ID] = &cp
	return nil
}
func (f *fakePolicyRepo) GetByID(_ context.Context, id uuid.UUID) (*models.RollbackPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.policies[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *p
	return &cp, nil
}
func (f *fakePolicyRepo) List(_ context.Context) ([]models.RollbackPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.RollbackPolicy, 0, len(f.policies))
	for _, p := range f.policies {
		out = append(out, *p)
	}
	return out, nil
}
func (f *fakePolicyRepo) ListEnabled(_ context.Context) ([]models.RollbackPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []models.RollbackPolicy
	for _, p := range f.policies {
		if p.Enabled {
			out = append(out, *p)
		}
	}
	return out, nil
}
func (f *fakePolicyRepo) Update(_ context.Context, p *models.RollbackPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.policies[p.ID]; !ok {
		return errors.New("not found")
	}
	cp := *p
	f.policies[p.ID] = &cp
	return nil
}
func (f *fakePolicyRepo) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.policies[id]; !ok {
		return errors.New("not found")
	}
	delete(f.policies, id)
	return nil
}

type fakeExecRepo struct {
	mu    sync.Mutex
	rows  map[uuid.UUID]*models.RollbackExecution
	order []uuid.UUID
}

func newFakeExecRepo() *fakeExecRepo {
	return &fakeExecRepo{rows: make(map[uuid.UUID]*models.RollbackExecution)}
}
func (f *fakeExecRepo) Create(_ context.Context, e *models.RollbackExecution) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	cp := *e
	f.rows[e.ID] = &cp
	f.order = append(f.order, e.ID)
	return nil
}
func (f *fakeExecRepo) Update(_ context.Context, e *models.RollbackExecution) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.rows[e.ID]; !ok {
		return errors.New("not found")
	}
	cp := *e
	f.rows[e.ID] = &cp
	return nil
}
func (f *fakeExecRepo) GetByID(_ context.Context, id uuid.UUID) (*models.RollbackExecution, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.rows[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *e
	return &cp, nil
}
func (f *fakeExecRepo) List(_ context.Context, _ models.RollbackExecutionListOptions) ([]models.RollbackExecution, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.RollbackExecution, 0, len(f.rows))
	for _, e := range f.rows {
		out = append(out, *e)
	}
	return out, len(out), nil
}
func (f *fakeExecRepo) MostRecentForStack(_ context.Context, stackID uuid.UUID) (*models.RollbackExecution, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var best *models.RollbackExecution
	for _, e := range f.rows {
		if e.StackID != stackID {
			continue
		}
		if best == nil || e.CreatedAt.After(best.CreatedAt) {
			cp := *e
			best = &cp
		}
	}
	return best, nil
}

type fakeAuditRepo struct {
	mu   sync.Mutex
	rows []models.RollbackAuditEntry
}

func (f *fakeAuditRepo) Append(_ context.Context, e *models.RollbackAuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	f.rows = append(f.rows, *e)
	return nil
}
func (f *fakeAuditRepo) List(_ context.Context, _, _ uuid.UUID, _, _ int) ([]models.RollbackAuditEntry, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.RollbackAuditEntry, len(f.rows))
	copy(out, f.rows)
	return out, len(out), nil
}

type fakeStacks struct {
	mu           sync.Mutex
	stacks       map[uuid.UUID]*models.Stack
	versions     map[uuid.UUID][]*models.StackVersion
	restoreError error
	restoreCalls []restoreCall
}

type restoreCall struct {
	StackID uuid.UUID
	Version int
}

func (f *fakeStacks) Get(_ context.Context, id uuid.UUID) (*models.Stack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.stacks[id]
	if !ok {
		return nil, errors.New("stack not found")
	}
	cp := *s
	return &cp, nil
}
func (f *fakeStacks) ListVersions(_ context.Context, stackID uuid.UUID) ([]*models.StackVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.versions[stackID], nil
}
func (f *fakeStacks) RestoreVersion(_ context.Context, stackID uuid.UUID, version int, _ string, _ *uuid.UUID) (*models.Stack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restoreCalls = append(f.restoreCalls, restoreCall{StackID: stackID, Version: version})
	if f.restoreError != nil {
		return nil, f.restoreError
	}
	return f.stacks[stackID], nil
}

// ============================================================================
// Test helpers
// ============================================================================

func newServiceWithFakes() (*Service, *fakePolicyRepo, *fakeExecRepo, *fakeAuditRepo, *fakeStacks) {
	pol := newFakePolicyRepo()
	exec := newFakeExecRepo()
	audit := &fakeAuditRepo{}
	stacks := &fakeStacks{
		stacks:   make(map[uuid.UUID]*models.Stack),
		versions: make(map[uuid.UUID][]*models.StackVersion),
	}
	svc := NewService(pol, exec, audit, stacks, nil)
	return svc, pol, exec, audit, stacks
}

func makeStack(name string) *models.Stack {
	return &models.Stack{
		ID:   uuid.New(),
		Name: name,
	}
}

func makeVersions(stackID uuid.UUID) []*models.StackVersion {
	now := time.Now()
	// Newest first: current (v3) failed, v2 healthy, v1 healthy.
	t2 := now.Add(-1 * time.Hour)
	t1 := now.Add(-2 * time.Hour)
	return []*models.StackVersion{
		{ID: uuid.New(), StackID: stackID, Version: 3, CreatedAt: now, IsDeployed: false},
		{ID: uuid.New(), StackID: stackID, Version: 2, CreatedAt: t2, IsDeployed: true, DeployedAt: &t2},
		{ID: uuid.New(), StackID: stackID, Version: 1, CreatedAt: t1, IsDeployed: true, DeployedAt: &t1},
	}
}

// ============================================================================
// Tests
// ============================================================================

func TestCreatePolicyValidatesScope(t *testing.T) {
	svc, _, _, _, _ := newServiceWithFakes()
	ctx := context.Background()

	_, err := svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{
		Name:  "",
		Scope: models.RollbackScopeAll,
	}, nil)
	if err == nil || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput on empty name, got %v", err)
	}

	_, err = svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{
		Name:  "p1",
		Scope: models.RollbackScopeStack, // requires scope_stack_id
	}, nil)
	if err == nil || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for stack scope w/o id, got %v", err)
	}

	_, err = svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{
		Name:        "p1",
		TriggerKind: "garbage",
	}, nil)
	if err == nil || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for unknown trigger, got %v", err)
	}
}

func TestCreatePolicyAppliesDefaults(t *testing.T) {
	svc, _, _, audit, _ := newServiceWithFakes()
	ctx := context.Background()
	p, err := svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{Name: "p1"}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.Scope != models.RollbackScopeAll {
		t.Fatalf("expected default scope=all, got %q", p.Scope)
	}
	if p.TriggerKind != models.RollbackTriggerDeployFailed {
		t.Fatalf("expected default trigger=deploy_failed, got %q", p.TriggerKind)
	}
	if p.LastGoodStrategy != models.RollbackStrategyLastHealthy {
		t.Fatalf("expected default strategy=last_healthy, got %q", p.LastGoodStrategy)
	}
	if len(audit.rows) != 1 || audit.rows[0].Action != models.RollbackAuditActionPolicyCreated {
		t.Fatalf("expected one policy_created audit row, got %+v", audit.rows)
	}
}

func TestUpdatePolicyTracksEnabledTransitions(t *testing.T) {
	svc, _, _, audit, _ := newServiceWithFakes()
	ctx := context.Background()
	p, _ := svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{Name: "p1", Enabled: false}, nil)

	enabled := true
	_, err := svc.UpdatePolicy(ctx, p.ID, models.UpdateRollbackPolicyInput{Enabled: &enabled}, nil)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	lastAction := audit.rows[len(audit.rows)-1].Action
	if lastAction != models.RollbackAuditActionPolicyEnabled {
		t.Fatalf("expected policy_enabled audit, got %q", lastAction)
	}

	disabled := false
	_, _ = svc.UpdatePolicy(ctx, p.ID, models.UpdateRollbackPolicyInput{Enabled: &disabled}, nil)
	lastAction = audit.rows[len(audit.rows)-1].Action
	if lastAction != models.RollbackAuditActionPolicyDisabled {
		t.Fatalf("expected policy_disabled audit, got %q", lastAction)
	}
}

func TestDeletePolicyAppendsAudit(t *testing.T) {
	svc, _, _, audit, _ := newServiceWithFakes()
	ctx := context.Background()
	p, _ := svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{Name: "p1"}, nil)
	if err := svc.DeletePolicy(ctx, p.ID, nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
	lastAction := audit.rows[len(audit.rows)-1].Action
	if lastAction != models.RollbackAuditActionPolicyDeleted {
		t.Fatalf("expected policy_deleted audit, got %q", lastAction)
	}
}

func TestPickRollbackTargetLastHealthySkipsFailedVersion(t *testing.T) {
	svc, _, _, _, _ := newServiceWithFakes()
	stackID := uuid.New()
	versions := makeVersions(stackID)

	from, to, err := svc.pickRollbackTarget(versions, models.RollbackStrategyLastHealthy)
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	if from != 3 {
		t.Fatalf("expected from=3 (current), got %d", from)
	}
	if to != 2 {
		t.Fatalf("expected to=2 (last healthy), got %d", to)
	}
}

func TestPickRollbackTargetPreviousAlwaysPickN1(t *testing.T) {
	svc, _, _, _, _ := newServiceWithFakes()
	stackID := uuid.New()
	versions := makeVersions(stackID)

	from, to, err := svc.pickRollbackTarget(versions, models.RollbackStrategyPrevious)
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	if from != 3 || to != 2 {
		t.Fatalf("expected (3,2), got (%d,%d)", from, to)
	}
}

func TestPickRollbackTargetReturnsErrorWhenSingleVersion(t *testing.T) {
	svc, _, _, _, _ := newServiceWithFakes()
	versions := []*models.StackVersion{{Version: 1, IsDeployed: true}}
	_, _, err := svc.pickRollbackTarget(versions, models.RollbackStrategyLastHealthy)
	if !errors.Is(err, ErrNoLastKnownGood) {
		t.Fatalf("expected ErrNoLastKnownGood, got %v", err)
	}
}

func TestMatchesEventScopeAll(t *testing.T) {
	svc, _, _, _, _ := newServiceWithFakes()
	stack := makeStack("api")
	p := &models.RollbackPolicy{Enabled: true, Scope: models.RollbackScopeAll}
	e := &models.ChangeEvent{ResourceType: models.ChangeResourceStack, ResourceID: stack.ID.String()}
	if !svc.MatchesEvent(p, e, stack) {
		t.Fatal("expected match")
	}
}

func TestMatchesEventScopeStack(t *testing.T) {
	svc, _, _, _, _ := newServiceWithFakes()
	stack := makeStack("api")
	other := uuid.New()
	p := &models.RollbackPolicy{Enabled: true, Scope: models.RollbackScopeStack, ScopeStackID: &other}
	e := &models.ChangeEvent{ResourceType: models.ChangeResourceStack, ResourceID: stack.ID.String()}
	if svc.MatchesEvent(p, e, stack) {
		t.Fatal("expected no match (different stack id)")
	}
	id := stack.ID
	p.ScopeStackID = &id
	if !svc.MatchesEvent(p, e, stack) {
		t.Fatal("expected match")
	}
}

func TestMatchesEventScopeTagSubstring(t *testing.T) {
	svc, _, _, _, _ := newServiceWithFakes()
	stack := makeStack("api-prod")
	p := &models.RollbackPolicy{Enabled: true, Scope: models.RollbackScopeTag, ScopeValue: "prod"}
	e := &models.ChangeEvent{ResourceType: models.ChangeResourceStack, ResourceID: stack.ID.String()}
	if !svc.MatchesEvent(p, e, stack) {
		t.Fatal("expected match")
	}
	p.ScopeValue = "staging"
	if svc.MatchesEvent(p, e, stack) {
		t.Fatal("expected no match")
	}
}

func TestMatchesEventDisabledPolicyIgnored(t *testing.T) {
	svc, _, _, _, _ := newServiceWithFakes()
	stack := makeStack("api")
	p := &models.RollbackPolicy{Enabled: false, Scope: models.RollbackScopeAll}
	e := &models.ChangeEvent{ResourceType: models.ChangeResourceStack, ResourceID: stack.ID.String()}
	if svc.MatchesEvent(p, e, stack) {
		t.Fatal("expected disabled policy to not match")
	}
}

func TestTriggerMatchesActionDeployFailed(t *testing.T) {
	meta := json.RawMessage(`{"error":"image pull failed"}`)
	e := &models.ChangeEvent{Action: models.ChangeActionDeploy, Metadata: &meta}
	if !triggerMatchesAction(models.RollbackTriggerDeployFailed, e) {
		t.Fatal("expected deploy_failed to match")
	}
	// No error metadata — should not fire.
	emptyMeta := json.RawMessage(`{"error":""}`)
	e.Metadata = &emptyMeta
	if triggerMatchesAction(models.RollbackTriggerDeployFailed, e) {
		t.Fatal("expected empty error to not match")
	}
}

func TestTriggerMatchesIgnoresRollbackAction(t *testing.T) {
	meta := json.RawMessage(`{"error":"x"}`)
	e := &models.ChangeEvent{Action: models.ChangeActionRollback, Metadata: &meta}
	if triggerMatchesAction(models.RollbackTriggerDeployFailed, e) {
		t.Fatal("rollback action must not trigger another rollback")
	}
}

func TestExecuteSucceeds(t *testing.T) {
	svc, _, execRepo, audit, stacks := newServiceWithFakes()
	ctx := context.Background()
	stack := makeStack("api")
	stacks.stacks[stack.ID] = stack
	stacks.versions[stack.ID] = makeVersions(stack.ID)

	p, _ := svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{
		Name:    "p1",
		Enabled: true,
		Scope:   models.RollbackScopeAll,
	}, nil)

	exec, err := svc.Execute(ctx, p, stack, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if exec.Status != models.RollbackExecutionSucceeded {
		t.Fatalf("expected status=succeeded, got %q", exec.Status)
	}
	if exec.ToVersion == nil || *exec.ToVersion != 2 {
		t.Fatalf("expected to_version=2, got %+v", exec.ToVersion)
	}
	if len(stacks.restoreCalls) != 1 {
		t.Fatalf("expected one restore call, got %d", len(stacks.restoreCalls))
	}
	// Audit should have policy_created, execution_fired, execution_done.
	actions := []string{}
	for _, e := range audit.rows {
		actions = append(actions, e.Action)
	}
	if len(actions) < 3 {
		t.Fatalf("expected ≥3 audit rows, got %v", actions)
	}
	if actions[len(actions)-1] != models.RollbackAuditActionExecutionDone {
		t.Fatalf("expected last audit=execution_done, got %q", actions[len(actions)-1])
	}
	// Execution row count.
	if len(execRepo.rows) != 1 {
		t.Fatalf("expected one execution row, got %d", len(execRepo.rows))
	}
}

func TestExecuteHonorsDryRunPolicy(t *testing.T) {
	svc, _, _, _, stacks := newServiceWithFakes()
	ctx := context.Background()
	stack := makeStack("api")
	stacks.stacks[stack.ID] = stack
	stacks.versions[stack.ID] = makeVersions(stack.ID)

	p, _ := svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{
		Name:    "p1",
		Enabled: true,
		Scope:   models.RollbackScopeAll,
		DryRun:  true,
	}, nil)
	exec, err := svc.Execute(ctx, p, stack, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if exec.Status != models.RollbackExecutionDryRun {
		t.Fatalf("expected status=dry_run, got %q", exec.Status)
	}
	if len(stacks.restoreCalls) != 0 {
		t.Fatalf("dry-run must not call RestoreVersion")
	}
}

func TestExecuteRespectsCooldown(t *testing.T) {
	svc, _, _, _, stacks := newServiceWithFakes()
	ctx := context.Background()
	stack := makeStack("api")
	stacks.stacks[stack.ID] = stack
	stacks.versions[stack.ID] = makeVersions(stack.ID)

	// Fix the clock so the second run is "now" relative to the first.
	t0 := time.Now()
	svc.SetClock(func() time.Time { return t0 })

	p, _ := svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{
		Name:            "p1",
		Enabled:         true,
		Scope:           models.RollbackScopeAll,
		CooldownSeconds: 60,
	}, nil)

	if _, err := svc.Execute(ctx, p, stack, nil, nil); err != nil {
		t.Fatalf("first execute: %v", err)
	}
	if len(stacks.restoreCalls) != 1 {
		t.Fatalf("first execute did not call restore")
	}

	// Bump clock 10s, still inside cooldown.
	svc.SetClock(func() time.Time { return t0.Add(10 * time.Second) })

	exec, err := svc.Execute(ctx, p, stack, nil, nil)
	if err != nil {
		t.Fatalf("second execute: %v", err)
	}
	if exec.Status != models.RollbackExecutionSkipped {
		t.Fatalf("expected second run to be skipped (cooldown), got %q", exec.Status)
	}
	if len(stacks.restoreCalls) != 1 {
		t.Fatalf("cooldown did not block second restore call")
	}
}

func TestExecuteFailsWhenNoLastKnownGood(t *testing.T) {
	svc, _, _, _, stacks := newServiceWithFakes()
	ctx := context.Background()
	stack := makeStack("api")
	stacks.stacks[stack.ID] = stack
	stacks.versions[stack.ID] = []*models.StackVersion{
		{Version: 1, IsDeployed: false},
	}

	p, _ := svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{
		Name:    "p1",
		Enabled: true,
		Scope:   models.RollbackScopeAll,
	}, nil)
	exec, err := svc.Execute(ctx, p, stack, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if exec.Status != models.RollbackExecutionFailed {
		t.Fatalf("expected status=failed, got %q", exec.Status)
	}
}

func TestExecuteRecordsRestoreError(t *testing.T) {
	svc, _, _, _, stacks := newServiceWithFakes()
	ctx := context.Background()
	stack := makeStack("api")
	stacks.stacks[stack.ID] = stack
	stacks.versions[stack.ID] = makeVersions(stack.ID)
	stacks.restoreError = errors.New("docker compose down failed")

	p, _ := svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{
		Name:    "p1",
		Enabled: true,
		Scope:   models.RollbackScopeAll,
	}, nil)
	exec, err := svc.Execute(ctx, p, stack, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if exec.Status != models.RollbackExecutionFailed {
		t.Fatalf("expected status=failed, got %q", exec.Status)
	}
	if exec.Error == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestExecuteHoldsPerStackLock(t *testing.T) {
	svc, _, _, _, stacks := newServiceWithFakes()
	ctx := context.Background()
	stack := makeStack("api")
	stacks.stacks[stack.ID] = stack
	stacks.versions[stack.ID] = makeVersions(stack.ID)

	p, _ := svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{
		Name:    "p1",
		Enabled: true,
		Scope:   models.RollbackScopeAll,
	}, nil)

	// Manually take the lock from a goroutine, then try to execute and
	// confirm we get ErrStackBusy.
	lock, ok := svc.tryLockStack(stack.ID)
	if !ok {
		t.Fatal("could not acquire lock")
	}
	defer svc.unlockStack(stack.ID, lock)

	if _, err := svc.Execute(ctx, p, stack, nil, nil); !errors.Is(err, ErrStackBusy) {
		t.Fatalf("expected ErrStackBusy, got %v", err)
	}
}

func TestExecuteOnEventFiresMatchingPolicy(t *testing.T) {
	svc, _, _, _, stacks := newServiceWithFakes()
	ctx := context.Background()
	stack := makeStack("api")
	stacks.stacks[stack.ID] = stack
	stacks.versions[stack.ID] = makeVersions(stack.ID)

	_, _ = svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{
		Name:        "p1",
		Enabled:     true,
		Scope:       models.RollbackScopeAll,
		TriggerKind: models.RollbackTriggerDeployFailed,
	}, nil)

	meta := json.RawMessage(`{"error":"image pull failed"}`)
	e := &models.ChangeEvent{
		ID:           uuid.New(),
		ResourceType: models.ChangeResourceStack,
		ResourceID:   stack.ID.String(),
		Action:       models.ChangeActionDeploy,
		Metadata:     &meta,
	}

	exec, err := svc.ExecuteOnEvent(ctx, e)
	if err != nil {
		t.Fatalf("execute on event: %v", err)
	}
	if exec == nil {
		t.Fatal("expected execution row, got nil")
	}
	if exec.Status != models.RollbackExecutionSucceeded {
		t.Fatalf("expected succeeded, got %q", exec.Status)
	}
}

func TestExecuteOnEventNoMatchReturnsNil(t *testing.T) {
	svc, _, _, _, stacks := newServiceWithFakes()
	ctx := context.Background()
	stack := makeStack("api")
	stacks.stacks[stack.ID] = stack
	stacks.versions[stack.ID] = makeVersions(stack.ID)

	// No policies => no match.
	meta := json.RawMessage(`{"error":"x"}`)
	e := &models.ChangeEvent{
		ID:           uuid.New(),
		ResourceType: models.ChangeResourceStack,
		ResourceID:   stack.ID.String(),
		Action:       models.ChangeActionDeploy,
		Metadata:     &meta,
	}

	exec, err := svc.ExecuteOnEvent(ctx, e)
	if err != nil {
		t.Fatalf("execute on event: %v", err)
	}
	if exec != nil {
		t.Fatalf("expected nil execution, got %+v", exec)
	}
}

func TestDryRunDoesNotInvokeRestore(t *testing.T) {
	svc, _, _, _, stacks := newServiceWithFakes()
	ctx := context.Background()
	stack := makeStack("api")
	stacks.stacks[stack.ID] = stack
	stacks.versions[stack.ID] = makeVersions(stack.ID)

	p, _ := svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{
		Name:    "p1",
		Enabled: true,
		Scope:   models.RollbackScopeAll,
	}, nil)

	res, err := svc.DryRun(ctx, p.ID, stack.ID, nil)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !res.Matched {
		t.Fatal("expected dry-run to match")
	}
	if res.ToVersion == nil || *res.ToVersion != 2 {
		t.Fatalf("expected to_version=2, got %+v", res.ToVersion)
	}
	if len(stacks.restoreCalls) != 0 {
		t.Fatal("dry-run must not invoke RestoreVersion")
	}
}

func TestListAuditAppendOnly(t *testing.T) {
	svc, _, _, _, _ := newServiceWithFakes()
	ctx := context.Background()
	p, _ := svc.CreatePolicy(ctx, models.CreateRollbackPolicyInput{Name: "p1"}, nil)

	entries, _, err := svc.ListAudit(ctx, p.ID, uuid.Nil, 50, 0)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit row, got %d", len(entries))
	}
}
