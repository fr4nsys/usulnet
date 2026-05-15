// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package opa

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

type mockRepo struct {
	policies []*models.OPAPolicy
	results  map[uuid.UUID][]*models.OPAEvaluationResult
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		results: make(map[uuid.UUID][]*models.OPAEvaluationResult),
	}
}

func (m *mockRepo) CreatePolicy(_ context.Context, p *models.OPAPolicy) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	m.policies = append(m.policies, p)
	return nil
}

func (m *mockRepo) GetPolicy(_ context.Context, id uuid.UUID) (*models.OPAPolicy, error) {
	for _, p := range m.policies {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, fmt.Errorf("policy %s not found", id)
}

func (m *mockRepo) GetPolicyByName(_ context.Context, name string) (*models.OPAPolicy, error) {
	for _, p := range m.policies {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, fmt.Errorf("policy %q not found", name)
}

func (m *mockRepo) ListPolicies(_ context.Context, category string) ([]*models.OPAPolicy, error) {
	if category == "" {
		return m.policies, nil
	}
	var filtered []*models.OPAPolicy
	for _, p := range m.policies {
		if p.Category == category {
			filtered = append(filtered, p)
		}
	}
	return filtered, nil
}

func (m *mockRepo) UpdatePolicy(_ context.Context, _ *models.OPAPolicy) error {
	return nil
}

func (m *mockRepo) DeletePolicy(_ context.Context, _ uuid.UUID) error {
	return nil
}

func (m *mockRepo) TogglePolicy(_ context.Context, _ uuid.UUID, _ bool) error {
	return nil
}

func (m *mockRepo) IncrementEvaluation(_ context.Context, _ uuid.UUID, _ bool) error {
	return nil
}

func (m *mockRepo) SaveResult(_ context.Context, result *models.OPAEvaluationResult) error {
	m.results[result.PolicyID] = append(m.results[result.PolicyID], result)
	return nil
}

func (m *mockRepo) ListResults(_ context.Context, policyID uuid.UUID, _ int) ([]*models.OPAEvaluationResult, error) {
	return m.results[policyID], nil
}

func (m *mockRepo) GetResultsByTarget(_ context.Context, _, _ string) ([]*models.OPAEvaluationResult, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	repo := newMockRepo()
	cfg := DefaultConfig()
	svc := NewService(repo, cfg, nil) // nil logger exercises fallback
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.repo != repo {
		t.Fatal("expected repo to be set")
	}
	if !svc.config.Enabled {
		t.Fatal("expected config.Enabled to be true by default")
	}
	if svc.compiledPolicies == nil {
		t.Fatal("expected compiledPolicies map to be initialized")
	}
}

func TestListPolicies_Empty(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, DefaultConfig(), logger.Nop())

	policies, err := svc.ListPolicies(context.Background(), "")
	if err != nil {
		t.Fatalf("ListPolicies returned unexpected error: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("expected 0 policies, got %d", len(policies))
	}
}

func TestSeedDefaultPolicies(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, DefaultConfig(), logger.Nop())

	if err := svc.SeedDefaultPolicies(context.Background()); err != nil {
		t.Fatalf("SeedDefaultPolicies returned unexpected error: %v", err)
	}

	// defaultPolicies() returns 10 built-in policies.
	expected := len(defaultPolicies())
	if len(repo.policies) != expected {
		t.Fatalf("expected %d policies after seed, got %d", expected, len(repo.policies))
	}

	// Verify no duplicates are created on a second call.
	if err := svc.SeedDefaultPolicies(context.Background()); err != nil {
		t.Fatalf("second SeedDefaultPolicies returned unexpected error: %v", err)
	}
	if len(repo.policies) != expected {
		t.Fatalf("expected %d policies after second seed (no duplicates), got %d",
			expected, len(repo.policies))
	}
}

func TestEvaluateContainer_NoPolicies(t *testing.T) {
	repo := newMockRepo()
	cfg := DefaultConfig()
	svc := NewService(repo, cfg, logger.Nop())

	// With no policies in the repo, evaluation should return an empty result set.
	containerData := map[string]interface{}{
		"id":         "abc123",
		"name":       "test-container",
		"privileged": false,
	}

	results, err := svc.EvaluateContainer(context.Background(), containerData)
	if err != nil {
		t.Fatalf("EvaluateContainer returned unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 evaluation results with no policies, got %d", len(results))
	}
}
