// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package egress

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ---------------------------------------------------------------------------
// In-memory fakes
// ---------------------------------------------------------------------------

type fakePolicyRepo struct {
	mu        sync.Mutex
	policies  []models.EgressPolicy
	createErr error
	listErr   error
}

func (f *fakePolicyRepo) Create(_ context.Context, p *models.EgressPolicy) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().Add(time.Duration(len(f.policies)) * time.Millisecond)
	}
	f.policies = append(f.policies, *p)
	return nil
}

func (f *fakePolicyRepo) ListByHost(_ context.Context, hostID uuid.UUID) ([]models.EgressPolicy, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.EgressPolicy, 0, len(f.policies))
	for _, p := range f.policies {
		if p.HostID == hostID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakePolicyRepo) GetByID(_ context.Context, id uuid.UUID) (*models.EgressPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.policies {
		if f.policies[i].ID == id {
			cp := f.policies[i]
			return &cp, nil
		}
	}
	return nil, errors.New("not found")
}

func (f *fakePolicyRepo) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.policies {
		if f.policies[i].ID == id {
			f.policies = append(f.policies[:i], f.policies[i+1:]...)
			return nil
		}
	}
	return errors.New("not found")
}

type fakeAudit struct {
	mu      sync.Mutex
	entries []models.EgressAuditLog
}

func (f *fakeAudit) Insert(_ context.Context, e *models.EgressAuditLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	f.entries = append(f.entries, *e)
	return nil
}

func (f *fakeAudit) ListByHost(_ context.Context, hostID uuid.UUID, limit int) ([]models.EgressAuditLog, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.EgressAuditLog, 0)
	for i := len(f.entries) - 1; i >= 0; i-- {
		if f.entries[i].HostID == hostID {
			out = append(out, f.entries[i])
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func newTestService() (*Service, *fakePolicyRepo, *fakeAudit) {
	repo := &fakePolicyRepo{}
	audit := &fakeAudit{}
	return NewService(repo, audit, nil), repo, audit
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestEvaluate_ZeroPoliciesPassThrough(t *testing.T) {
	svc, _, _ := newTestService()
	res, err := svc.Evaluate(context.Background(), uuid.New(), "github.com")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !res.Allow {
		t.Fatalf("expected pass-through allow for host with zero policies, got deny")
	}
	if res.Matched != nil {
		t.Fatalf("expected nil Matched, got %v", res.Matched)
	}
	if res.PolicyCount != 0 {
		t.Fatalf("expected PolicyCount=0, got %d", res.PolicyCount)
	}
}

func TestEvaluate_AllowSpecificDenyEverythingElse(t *testing.T) {
	// The acceptance criteria scenario: allow *.github.com, deny *.
	// This pins the brief's worked example so a future refactor does
	// not silently flip first-match-wins to last-match-wins.
	svc, _, _ := newTestService()
	hostID := uuid.New()
	ctx := context.Background()

	if _, err := svc.CreatePolicy(ctx, hostID, models.CreateEgressPolicyInput{TargetGlob: "*.github.com", Allow: true}); err != nil {
		t.Fatalf("CreatePolicy allow: %v", err)
	}
	if _, err := svc.CreatePolicy(ctx, hostID, models.CreateEgressPolicyInput{TargetGlob: "*", Allow: false}); err != nil {
		t.Fatalf("CreatePolicy deny: %v", err)
	}

	cases := []struct {
		target string
		allow  bool
	}{
		{"api.github.com", true},
		{"raw.github.com", true},
		{"evil.cn", false},
		{"example.com", false},
		// A subdomain of github.com — the * in "*.github.com" matches any
		// labels because hostnames have no '/' separator.
		{"a.b.github.com", true},
		// Bare 'github.com' — *.github.com does NOT match (the * needs
		// at least one prefix label before the dot). The catch-all deny
		// wins.
		{"github.com", false},
	}
	for _, tc := range cases {
		got, err := svc.Evaluate(ctx, hostID, tc.target)
		if err != nil {
			t.Fatalf("Evaluate %q: %v", tc.target, err)
		}
		if got.Allow != tc.allow {
			t.Errorf("Evaluate %q: allow=%v want=%v (matched=%v)", tc.target, got.Allow, tc.allow, got.Matched)
		}
	}
}

func TestEvaluate_DefaultDenyWhenNoMatch(t *testing.T) {
	// One policy, no explicit catch-all. evil.cn does not match the
	// single allow, so it gets default-denied — not pass-through.
	svc, _, _ := newTestService()
	hostID := uuid.New()
	ctx := context.Background()

	if _, err := svc.CreatePolicy(ctx, hostID, models.CreateEgressPolicyInput{TargetGlob: "github.com", Allow: true}); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	res, err := svc.Evaluate(ctx, hostID, "evil.cn")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Allow {
		t.Fatalf("expected default-deny for unmatched target with ≥1 policy, got allow")
	}
}

func TestEvaluate_CaseInsensitive(t *testing.T) {
	svc, _, _ := newTestService()
	hostID := uuid.New()
	ctx := context.Background()
	if _, err := svc.CreatePolicy(ctx, hostID, models.CreateEgressPolicyInput{TargetGlob: "*.GitHub.com", Allow: true}); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	res, err := svc.Evaluate(ctx, hostID, "API.GITHUB.COM")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !res.Allow {
		t.Fatalf("case-insensitive match failed: %v", res)
	}
}

func TestEvaluate_FirstMatchWins(t *testing.T) {
	// A deny rule created BEFORE the allow rule for the same host
	// should win — the evaluator scans in created_at ASC.
	svc, repo, _ := newTestService()
	hostID := uuid.New()
	ctx := context.Background()

	first := models.EgressPolicy{
		HostID:     hostID,
		TargetGlob: "api.github.com",
		Allow:      false,
		CreatedAt:  time.Now(),
	}
	second := models.EgressPolicy{
		HostID:     hostID,
		TargetGlob: "*.github.com",
		Allow:      true,
		CreatedAt:  time.Now().Add(time.Minute),
	}
	if err := repo.Create(ctx, &first); err != nil {
		t.Fatalf("seed first: %v", err)
	}
	if err := repo.Create(ctx, &second); err != nil {
		t.Fatalf("seed second: %v", err)
	}

	res, err := svc.Evaluate(ctx, hostID, "api.github.com")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Allow {
		t.Fatalf("expected first-match-wins deny, got allow (matched=%v)", res.Matched)
	}
}

func TestRecordDeny_WritesAudit(t *testing.T) {
	svc, _, audit := newTestService()
	hostID := uuid.New()
	svc.RecordDeny(context.Background(), hostID, "evil.cn", "GET")
	entries, err := audit.ListByHost(context.Background(), hostID, 10)
	if err != nil {
		t.Fatalf("ListByHost: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit row, got %d", len(entries))
	}
	if entries[0].Target != "evil.cn" || entries[0].Method != "GET" || entries[0].Decision != "deny" {
		t.Errorf("unexpected audit row: %+v", entries[0])
	}
}

func TestCreatePolicy_ValidatesInput(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	if _, err := svc.CreatePolicy(ctx, uuid.Nil, models.CreateEgressPolicyInput{TargetGlob: "*"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput for nil host, got %v", err)
	}
	if _, err := svc.CreatePolicy(ctx, uuid.New(), models.CreateEgressPolicyInput{TargetGlob: "  "}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput for blank glob, got %v", err)
	}
}

func TestEgressMatch_Direct(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "github.com", false},
		{"github.com", "github.com", true},
		{"*", "anything.example", true},
		{"api.*", "api.github.com", true},
		{"api.*", "evil.example", false},
		{"", "github.com", false},
	}
	for _, tc := range cases {
		got := models.EgressMatch(tc.pattern, tc.host)
		if got != tc.want {
			t.Errorf("EgressMatch(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}
