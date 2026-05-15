// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package firewall

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ----------------------------------------------------------------------------
// In-memory mock repositories
// ----------------------------------------------------------------------------

type mockRuleRepo struct {
	mu    sync.Mutex
	rules map[uuid.UUID]*models.FirewallRule
}

func newMockRuleRepo() *mockRuleRepo {
	return &mockRuleRepo{rules: map[uuid.UUID]*models.FirewallRule{}}
}

func (r *mockRuleRepo) Create(_ context.Context, rule *models.FirewallRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *rule
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	cp.UpdatedAt = cp.CreatedAt
	r.rules[cp.ID] = &cp
	return nil
}

func (r *mockRuleRepo) GetByID(_ context.Context, id uuid.UUID) (*models.FirewallRule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rule, ok := r.rules[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *rule
	return &cp, nil
}

func (r *mockRuleRepo) List(_ context.Context, hostID uuid.UUID) ([]models.FirewallRule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []models.FirewallRule
	for _, rule := range r.rules {
		if rule.HostID == hostID {
			out = append(out, *rule)
		}
	}
	return out, nil
}

func (r *mockRuleRepo) Update(_ context.Context, rule *models.FirewallRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rules[rule.ID]; !ok {
		return errors.New("not found")
	}
	cp := *rule
	cp.UpdatedAt = time.Now()
	cp.Applied = false
	r.rules[cp.ID] = &cp
	return nil
}

func (r *mockRuleRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rules[id]; !ok {
		return errors.New("not found")
	}
	delete(r.rules, id)
	return nil
}

func (r *mockRuleRepo) MarkApplied(_ context.Context, hostID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rule := range r.rules {
		if rule.HostID == hostID && rule.Enabled {
			rule.Applied = true
		}
	}
	return nil
}

func (r *mockRuleRepo) NextPosition(_ context.Context, hostID uuid.UUID, chain string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	max := -1
	for _, rule := range r.rules {
		if rule.HostID == hostID && string(rule.Chain) == chain {
			if rule.Position > max {
				max = rule.Position
			}
		}
	}
	return max + 1, nil
}

type mockAuditRepo struct {
	mu      sync.Mutex
	entries []*models.FirewallAuditLog
}

func (r *mockAuditRepo) Create(_ context.Context, entry *models.FirewallAuditLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *entry
	if cp.ID == uuid.Nil {
		cp.ID = uuid.New()
	}
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	r.entries = append(r.entries, &cp)
	return nil
}

func (r *mockAuditRepo) List(_ context.Context, hostID uuid.UUID, limit, offset int) ([]models.FirewallAuditLog, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var filtered []models.FirewallAuditLog
	for _, e := range r.entries {
		if e.HostID == hostID {
			filtered = append(filtered, *e)
		}
	}
	if offset >= len(filtered) {
		return nil, len(filtered), nil
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[offset:end], len(filtered), nil
}

func (r *mockAuditRepo) entriesByAction(action string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

func newTestService() (*Service, *mockRuleRepo, *mockAuditRepo) {
	rules := newMockRuleRepo()
	audit := &mockAuditRepo{}
	svc := NewService(rules, audit, logger.Nop())
	return svc, rules, audit
}

func validCreateInput() models.CreateFirewallRuleInput {
	return models.CreateFirewallRuleInput{
		Name:      "Allow SSH",
		Chain:     models.FirewallChainInput,
		Protocol:  "tcp",
		DstPort:   "22",
		Action:    models.FirewallActionAccept,
		Direction: "inbound",
		Enabled:   true,
	}
}

// ----------------------------------------------------------------------------
// CRUD tests
// ----------------------------------------------------------------------------

func TestCreateRule_HappyPath(t *testing.T) {
	t.Parallel()
	svc, rules, audit := newTestService()
	hostID := uuid.New()

	rule, err := svc.CreateRule(context.Background(), hostID, validCreateInput(), nil)
	if err != nil {
		t.Fatalf("CreateRule returned error: %v", err)
	}
	if rule.ID == uuid.Nil {
		t.Errorf("expected rule to have ID assigned")
	}
	if rule.Position != 0 {
		t.Errorf("expected first rule position 0, got %d", rule.Position)
	}
	if len(rules.rules) != 1 {
		t.Errorf("expected 1 rule stored, got %d", len(rules.rules))
	}
	if audit.entriesByAction("create") != 1 {
		t.Errorf("expected 1 create audit entry, got %d", audit.entriesByAction("create"))
	}
}

func TestCreateRule_AssignsNextPosition(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	hostID := uuid.New()

	for i := 0; i < 3; i++ {
		_, err := svc.CreateRule(context.Background(), hostID, validCreateInput(), nil)
		if err != nil {
			t.Fatalf("CreateRule %d failed: %v", i, err)
		}
	}
	rules, _ := svc.ListRules(context.Background(), hostID)
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	positions := map[int]bool{}
	for _, r := range rules {
		positions[r.Position] = true
	}
	for _, want := range []int{0, 1, 2} {
		if !positions[want] {
			t.Errorf("expected position %d to be present", want)
		}
	}
}

func TestCreateRule_DefaultsProtocolAndDirection(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	in := models.CreateFirewallRuleInput{
		Name:    "Drop all",
		Chain:   models.FirewallChainInput,
		Action:  models.FirewallActionDrop,
		Enabled: true,
	}

	rule, err := svc.CreateRule(context.Background(), uuid.New(), in, nil)
	if err != nil {
		t.Fatalf("CreateRule returned error: %v", err)
	}
	if rule.Protocol != "all" {
		t.Errorf("expected default protocol 'all', got %q", rule.Protocol)
	}
	if rule.Direction != "inbound" {
		t.Errorf("expected default direction 'inbound', got %q", rule.Direction)
	}
}

func TestCreateRule_RejectsInvalidChain(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	in := validCreateInput()
	in.Chain = "NOPE"

	_, err := svc.CreateRule(context.Background(), uuid.New(), in, nil)
	if err == nil {
		t.Fatal("expected error for invalid chain, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateRule_RejectsInvalidAction(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	in := validCreateInput()
	in.Action = "EXPLODE"

	_, err := svc.CreateRule(context.Background(), uuid.New(), in, nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateRule_RejectsInvalidProtocol(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	in := validCreateInput()
	in.Protocol = "sctp"

	_, err := svc.CreateRule(context.Background(), uuid.New(), in, nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateRule_RejectsBlankName(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	in := validCreateInput()
	in.Name = "   "

	_, err := svc.CreateRule(context.Background(), uuid.New(), in, nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateRule_RejectsZeroHostID(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()

	_, err := svc.CreateRule(context.Background(), uuid.Nil, validCreateInput(), nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestUpdateRule_PartialPatch(t *testing.T) {
	t.Parallel()
	svc, _, audit := newTestService()
	hostID := uuid.New()

	rule, err := svc.CreateRule(context.Background(), hostID, validCreateInput(), nil)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	newComment := "managed by usulnet"
	disabled := false
	upd := models.UpdateFirewallRuleInput{
		Comment: &newComment,
		Enabled: &disabled,
	}
	updated, err := svc.UpdateRule(context.Background(), rule.ID, upd, nil)
	if err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}
	if updated.Comment != newComment {
		t.Errorf("expected comment %q, got %q", newComment, updated.Comment)
	}
	if updated.Enabled {
		t.Errorf("expected rule disabled after update")
	}
	if updated.Name != rule.Name {
		t.Errorf("expected name preserved, got %q", updated.Name)
	}
	if audit.entriesByAction("update") != 1 {
		t.Errorf("expected 1 update audit entry, got %d", audit.entriesByAction("update"))
	}
}

func TestUpdateRule_RejectsInvalidChain(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	hostID := uuid.New()

	rule, _ := svc.CreateRule(context.Background(), hostID, validCreateInput(), nil)
	badChain := models.FirewallChain("ROUTING")

	_, err := svc.UpdateRule(context.Background(), rule.ID, models.UpdateFirewallRuleInput{
		Chain: &badChain,
	}, nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestDeleteRule_AuditsPreDeleteSummary(t *testing.T) {
	t.Parallel()
	svc, rules, audit := newTestService()
	hostID := uuid.New()

	rule, _ := svc.CreateRule(context.Background(), hostID, validCreateInput(), nil)
	if err := svc.DeleteRule(context.Background(), rule.ID, nil); err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}
	if len(rules.rules) != 0 {
		t.Errorf("expected rule deleted from repo")
	}
	if audit.entriesByAction("delete") != 1 {
		t.Errorf("expected 1 delete audit entry, got %d", audit.entriesByAction("delete"))
	}
}

func TestListRules_FiltersByHost(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	host1 := uuid.New()
	host2 := uuid.New()

	for i := 0; i < 2; i++ {
		_, _ = svc.CreateRule(context.Background(), host1, validCreateInput(), nil)
	}
	_, _ = svc.CreateRule(context.Background(), host2, validCreateInput(), nil)

	got1, _ := svc.ListRules(context.Background(), host1)
	got2, _ := svc.ListRules(context.Background(), host2)
	if len(got1) != 2 {
		t.Errorf("expected 2 rules for host1, got %d", len(got1))
	}
	if len(got2) != 1 {
		t.Errorf("expected 1 rule for host2, got %d", len(got2))
	}
}

func TestGetRule_NotFound(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	_, err := svc.GetRule(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error for missing rule, got nil")
	}
}

// ----------------------------------------------------------------------------
// Agent command tests
// ----------------------------------------------------------------------------

type mockSender struct {
	mu         sync.Mutex
	calls      []*protocol.Command
	resultData any
	resultErr  *protocol.CommandError
	sendErr    error
}

func (m *mockSender) SendCommand(_ context.Context, _ uuid.UUID, cmd *protocol.Command) (*protocol.CommandResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, cmd)
	if m.sendErr != nil {
		return nil, m.sendErr
	}
	return &protocol.CommandResult{
		CommandID: cmd.ID,
		Status:    protocol.CommandStatusCompleted,
		Data:      m.resultData,
		Error:     m.resultErr,
	}, nil
}

func TestDetectBackend_NoSender_ReturnsUnknown(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	status, err := svc.DetectBackend(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("DetectBackend returned error: %v", err)
	}
	if status.Backend != models.FirewallBackendUnknown {
		t.Errorf("expected backend unknown, got %q", status.Backend)
	}
}

func TestDetectBackend_WithSender_ParsesResponse(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	sender := &mockSender{
		resultData: map[string]any{"backend": "ufw", "version": "0.36"},
	}
	svc.SetCommandSender(sender)

	status, err := svc.DetectBackend(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("DetectBackend returned error: %v", err)
	}
	if status.Backend != models.FirewallBackendUFW {
		t.Errorf("expected backend ufw, got %q", status.Backend)
	}
	if status.Version != "0.36" {
		t.Errorf("expected version '0.36', got %q", status.Version)
	}
	if len(sender.calls) != 1 || sender.calls[0].Type != protocol.CmdFirewallDetect {
		t.Errorf("expected one CmdFirewallDetect call, got %#v", sender.calls)
	}
}

func TestApplyRules_NoSenderReturnsErrSenderNotConfigured(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	err := svc.ApplyRules(context.Background(), uuid.New(), nil)
	if !errors.Is(err, ErrSenderNotConfigured) {
		t.Errorf("expected ErrSenderNotConfigured, got %v", err)
	}
}

func TestApplyRules_FiltersDisabled(t *testing.T) {
	t.Parallel()
	svc, _, audit := newTestService()
	sender := &mockSender{
		resultData: map[string]any{"backend": "ufw"},
	}
	svc.SetCommandSender(sender)
	hostID := uuid.New()

	r1, _ := svc.CreateRule(context.Background(), hostID, validCreateInput(), nil)
	disabled := validCreateInput()
	disabled.Enabled = false
	disabled.Name = "Disabled rule"
	_, _ = svc.CreateRule(context.Background(), hostID, disabled, nil)

	if err := svc.ApplyRules(context.Background(), hostID, nil); err != nil {
		t.Fatalf("ApplyRules failed: %v", err)
	}

	// Calls: DetectBackend, then FirewallApply.
	if len(sender.calls) < 2 {
		t.Fatalf("expected at least 2 sender calls, got %d", len(sender.calls))
	}
	var applyCall *protocol.Command
	for _, c := range sender.calls {
		if c.Type == protocol.CmdFirewallApply {
			applyCall = c
			break
		}
	}
	if applyCall == nil {
		t.Fatal("expected a CmdFirewallApply call")
	}
	if applyCall.Params.FirewallRules == "" {
		t.Error("expected FirewallRules payload to be non-empty")
	}
	// The payload should reference only one rule (the enabled one).
	if got := audit.entriesByAction("apply"); got != 1 {
		t.Errorf("expected 1 apply audit entry, got %d", got)
	}
	// MarkApplied should have flipped applied=true on the enabled rule.
	updated, _ := svc.GetRule(context.Background(), r1.ID)
	if !updated.Applied {
		t.Error("expected enabled rule to be marked Applied after ApplyRules")
	}
}

func TestApplyRules_NoEnabledRules_IsNoOp(t *testing.T) {
	t.Parallel()
	svc, _, audit := newTestService()
	sender := &mockSender{}
	svc.SetCommandSender(sender)
	hostID := uuid.New()

	disabled := validCreateInput()
	disabled.Enabled = false
	_, _ = svc.CreateRule(context.Background(), hostID, disabled, nil)

	if err := svc.ApplyRules(context.Background(), hostID, nil); err != nil {
		t.Fatalf("ApplyRules failed: %v", err)
	}
	for _, c := range sender.calls {
		if c.Type == protocol.CmdFirewallApply {
			t.Error("expected no CmdFirewallApply call when nothing enabled")
		}
	}
	if audit.entriesByAction("apply") != 0 {
		t.Error("expected no apply audit entry when nothing enabled")
	}
}

func TestApplyRules_AgentErrorIsSurfaced(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	sender := &mockSender{
		resultData: map[string]any{"backend": "ufw"},
		resultErr:  &protocol.CommandError{Code: "FW_FAIL", Message: "iptables: command not found"},
	}
	svc.SetCommandSender(sender)
	hostID := uuid.New()
	_, _ = svc.CreateRule(context.Background(), hostID, validCreateInput(), nil)

	err := svc.ApplyRules(context.Background(), hostID, nil)
	if err == nil {
		t.Fatal("expected error from agent failure, got nil")
	}
}

func TestSyncFromHost_ReturnsOutput(t *testing.T) {
	t.Parallel()
	svc, _, audit := newTestService()
	sender := &mockSender{
		resultData: map[string]any{"output": "Status: active\n"},
	}
	svc.SetCommandSender(sender)

	out, err := svc.SyncFromHost(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatalf("SyncFromHost returned error: %v", err)
	}
	if out != "Status: active\n" {
		t.Errorf("unexpected output %q", out)
	}
	if audit.entriesByAction("sync") != 1 {
		t.Errorf("expected 1 sync audit entry")
	}
}

func TestSyncFromHost_NoSender(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	_, err := svc.SyncFromHost(context.Background(), uuid.New(), nil)
	if !errors.Is(err, ErrSenderNotConfigured) {
		t.Errorf("expected ErrSenderNotConfigured, got %v", err)
	}
}

func TestListAuditLogs_Paginates(t *testing.T) {
	t.Parallel()
	svc, _, _ := newTestService()
	hostID := uuid.New()

	for i := 0; i < 5; i++ {
		_, err := svc.CreateRule(context.Background(), hostID, validCreateInput(), nil)
		if err != nil {
			t.Fatalf("create %d failed: %v", i, err)
		}
	}

	entries, total, err := svc.ListAuditLogs(context.Background(), hostID, 3, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs returned error: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if len(entries) != 3 {
		t.Errorf("expected limit 3, got %d", len(entries))
	}
}

// Ensure mockSender satisfies CommandSender at compile time.
var _ CommandSender = (*mockSender)(nil)
