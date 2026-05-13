// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package compliance

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
	frameworks  []*models.ComplianceFramework
	controls    map[uuid.UUID][]*models.ComplianceControl
	assessments map[uuid.UUID][]*models.ComplianceAssessment
	evidence    map[uuid.UUID][]*models.ComplianceEvidence

	createdFrameworks  []*models.ComplianceFramework
	createdControls    []*models.ComplianceControl
	createdAssessments []*models.ComplianceAssessment

	getFrameworkErr error
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		controls:    make(map[uuid.UUID][]*models.ComplianceControl),
		assessments: make(map[uuid.UUID][]*models.ComplianceAssessment),
		evidence:    make(map[uuid.UUID][]*models.ComplianceEvidence),
	}
}

func (m *mockRepo) CreateFramework(_ context.Context, f *models.ComplianceFramework) error {
	m.frameworks = append(m.frameworks, f)
	m.createdFrameworks = append(m.createdFrameworks, f)
	return nil
}

func (m *mockRepo) GetFramework(_ context.Context, id uuid.UUID) (*models.ComplianceFramework, error) {
	if m.getFrameworkErr != nil {
		return nil, m.getFrameworkErr
	}
	for _, f := range m.frameworks {
		if f.ID == id {
			return f, nil
		}
	}
	return nil, fmt.Errorf("framework %s not found", id)
}

func (m *mockRepo) GetFrameworkByName(_ context.Context, name string) (*models.ComplianceFramework, error) {
	for _, f := range m.frameworks {
		if f.Name == name {
			return f, nil
		}
	}
	return nil, fmt.Errorf("framework %q not found", name)
}

func (m *mockRepo) ListFrameworks(_ context.Context) ([]*models.ComplianceFramework, error) {
	return m.frameworks, nil
}

func (m *mockRepo) UpdateFramework(_ context.Context, f *models.ComplianceFramework) error {
	return nil
}

func (m *mockRepo) DeleteFramework(_ context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockRepo) CreateControl(_ context.Context, c *models.ComplianceControl) error {
	m.controls[c.FrameworkID] = append(m.controls[c.FrameworkID], c)
	m.createdControls = append(m.createdControls, c)
	return nil
}

func (m *mockRepo) ListControls(_ context.Context, frameworkID uuid.UUID) ([]*models.ComplianceControl, error) {
	return m.controls[frameworkID], nil
}

func (m *mockRepo) UpdateControlStatus(_ context.Context, controlID uuid.UUID, status string) error {
	return nil
}

func (m *mockRepo) CreateAssessment(_ context.Context, a *models.ComplianceAssessment) error {
	m.assessments[a.FrameworkID] = append(m.assessments[a.FrameworkID], a)
	m.createdAssessments = append(m.createdAssessments, a)
	return nil
}

func (m *mockRepo) GetAssessment(_ context.Context, id uuid.UUID) (*models.ComplianceAssessment, error) {
	for _, list := range m.assessments {
		for _, a := range list {
			if a.ID == id {
				return a, nil
			}
		}
	}
	return nil, fmt.Errorf("assessment %s not found", id)
}

func (m *mockRepo) ListAssessments(_ context.Context, frameworkID uuid.UUID) ([]*models.ComplianceAssessment, error) {
	return m.assessments[frameworkID], nil
}

func (m *mockRepo) UpdateAssessment(_ context.Context, a *models.ComplianceAssessment) error {
	return nil
}

func (m *mockRepo) CreateEvidence(_ context.Context, e *models.ComplianceEvidence) error {
	m.evidence[e.AssessmentID] = append(m.evidence[e.AssessmentID], e)
	return nil
}

func (m *mockRepo) ListEvidence(_ context.Context, assessmentID uuid.UUID) ([]*models.ComplianceEvidence, error) {
	return m.evidence[assessmentID], nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(nil, nil) // exercises nil-logger path
	if svc == nil {
		t.Fatal("NewService returned nil when called with nil repo and nil logger")
	}

	log := logger.Nop()
	svc2 := &Service{repo: repo, logger: log.Named("compliance")}
	if svc2.repo == nil {
		t.Fatal("expected repo to be set")
	}
}

func TestListFrameworks_Empty(t *testing.T) {
	repo := newMockRepo()
	svc := &Service{repo: repo, logger: logger.Nop()}

	frameworks, err := svc.ListFrameworks(context.Background())
	if err != nil {
		t.Fatalf("ListFrameworks returned unexpected error: %v", err)
	}
	if len(frameworks) != 0 {
		t.Fatalf("expected 0 frameworks, got %d", len(frameworks))
	}
}

func TestSeedFrameworks(t *testing.T) {
	repo := newMockRepo()
	svc := &Service{repo: repo, logger: logger.Nop()}

	if err := svc.SeedFrameworks(context.Background()); err != nil {
		t.Fatalf("SeedFrameworks returned unexpected error: %v", err)
	}

	// The service should have created exactly 3 frameworks (SOC2, HIPAA, PCI-DSS).
	if len(repo.createdFrameworks) != 3 {
		t.Fatalf("expected 3 created frameworks, got %d", len(repo.createdFrameworks))
	}

	expectedNames := map[string]bool{
		models.FrameworkSOC2:   false,
		models.FrameworkHIPAA:  false,
		models.FrameworkPCIDSS: false,
	}
	for _, fw := range repo.createdFrameworks {
		if _, ok := expectedNames[fw.Name]; !ok {
			t.Errorf("unexpected framework name: %s", fw.Name)
		}
		expectedNames[fw.Name] = true
	}
	for name, found := range expectedNames {
		if !found {
			t.Errorf("framework %q was not created", name)
		}
	}

	// Verify that controls were also created for each framework.
	if len(repo.createdControls) == 0 {
		t.Fatal("expected controls to be created, got 0")
	}

	// Calling SeedFrameworks again should not create duplicates because
	// GetFrameworkByName will now find the existing frameworks.
	before := len(repo.createdFrameworks)
	if err := svc.SeedFrameworks(context.Background()); err != nil {
		t.Fatalf("second SeedFrameworks call returned unexpected error: %v", err)
	}
	if len(repo.createdFrameworks) != before {
		t.Fatalf("expected no new frameworks on second seed, got %d new",
			len(repo.createdFrameworks)-before)
	}
}

func TestRunAssessment_NotFound(t *testing.T) {
	repo := newMockRepo()
	svc := &Service{repo: repo, logger: logger.Nop()}

	// Attempt to run an assessment on a framework that does not exist.
	unknownID := uuid.New()
	_, err := svc.RunAssessment(context.Background(), unknownID, nil)
	if err == nil {
		t.Fatal("expected error for non-existent framework, got nil")
	}
}
