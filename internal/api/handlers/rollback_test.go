// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// stubRollbackSvc records calls and returns canned results so the
// handler can be exercised without a real service.
type stubRollbackSvc struct {
	policies  map[uuid.UUID]*models.RollbackPolicy
	created   *models.CreateRollbackPolicyInput
	updateID  uuid.UUID
	deleteID  uuid.UUID
	dryRunPol uuid.UUID
	dryRunStk uuid.UUID
	dryRunRes *models.RollbackDryRunResult
}

func newStubRollbackSvc() *stubRollbackSvc {
	return &stubRollbackSvc{policies: make(map[uuid.UUID]*models.RollbackPolicy)}
}

func (s *stubRollbackSvc) CreatePolicy(_ context.Context, in models.CreateRollbackPolicyInput, _ *uuid.UUID) (*models.RollbackPolicy, error) {
	s.created = &in
	p := &models.RollbackPolicy{
		ID:               uuid.New(),
		Name:             in.Name,
		Enabled:          in.Enabled,
		Scope:            in.Scope,
		ScopeStackID:     in.ScopeStackID,
		ScopeValue:       in.ScopeValue,
		TriggerKind:      in.TriggerKind,
		LastGoodStrategy: in.LastGoodStrategy,
		CooldownSeconds:  in.CooldownSeconds,
		DryRun:           in.DryRun,
	}
	s.policies[p.ID] = p
	return p, nil
}
func (s *stubRollbackSvc) UpdatePolicy(_ context.Context, id uuid.UUID, _ models.UpdateRollbackPolicyInput, _ *uuid.UUID) (*models.RollbackPolicy, error) {
	s.updateID = id
	if p, ok := s.policies[id]; ok {
		return p, nil
	}
	return nil, nil
}
func (s *stubRollbackSvc) DeletePolicy(_ context.Context, id uuid.UUID, _ *uuid.UUID) error {
	s.deleteID = id
	delete(s.policies, id)
	return nil
}
func (s *stubRollbackSvc) GetPolicy(_ context.Context, id uuid.UUID) (*models.RollbackPolicy, error) {
	return s.policies[id], nil
}
func (s *stubRollbackSvc) ListPolicies(_ context.Context) ([]models.RollbackPolicy, error) {
	out := make([]models.RollbackPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, *p)
	}
	return out, nil
}
func (s *stubRollbackSvc) ListExecutions(_ context.Context, _ models.RollbackExecutionListOptions) ([]models.RollbackExecution, int, error) {
	return nil, 0, nil
}
func (s *stubRollbackSvc) GetExecution(_ context.Context, _ uuid.UUID) (*models.RollbackExecution, error) {
	return nil, nil
}
func (s *stubRollbackSvc) ListAudit(_ context.Context, _, _ uuid.UUID, _, _ int) ([]models.RollbackAuditEntry, int, error) {
	return nil, 0, nil
}
func (s *stubRollbackSvc) DryRun(_ context.Context, policyID, stackID uuid.UUID, _ *uuid.UUID) (*models.RollbackDryRunResult, error) {
	s.dryRunPol = policyID
	s.dryRunStk = stackID
	if s.dryRunRes != nil {
		return s.dryRunRes, nil
	}
	return &models.RollbackDryRunResult{
		Matched:    true,
		PolicyID:   policyID,
		StackID:    &stackID,
		StackName:  "api",
		NextStatus: models.RollbackExecutionDryRun,
	}, nil
}

// newRollbackTestServer wires the handler with stub svc behind a chi
// mux. Auth middleware is skipped (tests target the handler logic, not
// the middleware chain).
func newRollbackTestServer(t *testing.T, svc *stubRollbackSvc) (*chi.Mux, *RollbackHandler) {
	t.Helper()
	h := NewRollbackHandler(svc, nil)
	r := chi.NewRouter()
	r.Route("/policies", func(r chi.Router) {
		r.Get("/", h.ListPolicies)
		r.Post("/", h.CreatePolicy)
		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", h.GetPolicy)
			r.Put("/", h.UpdatePolicy)
			r.Delete("/", h.DeletePolicy)
			r.Post("/dry-run", h.DryRun)
		})
	})
	r.Get("/executions", h.ListExecutions)
	r.Get("/audit", h.ListAudit)
	return r, h
}

func TestRollbackCreatePolicy(t *testing.T) {
	svc := newStubRollbackSvc()
	mux, _ := newRollbackTestServer(t, svc)
	body := `{
		"name":"p1",
		"scope":"all",
		"trigger_kind":"deploy_failed",
		"last_good_strategy":"last_healthy",
		"cooldown_seconds":60,
		"enabled":true
	}`
	req := httptest.NewRequest(http.MethodPost, "/policies/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if svc.created == nil || svc.created.Name != "p1" {
		t.Fatalf("service not called with expected input: %+v", svc.created)
	}
}

func TestRollbackListPoliciesEmpty(t *testing.T) {
	svc := newStubRollbackSvc()
	mux, _ := newRollbackTestServer(t, svc)
	req := httptest.NewRequest(http.MethodGet, "/policies/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp []RollbackPolicyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, w.Body.String())
	}
	if len(resp) != 0 {
		t.Fatalf("expected empty list, got %d", len(resp))
	}
}

func TestRollbackDryRun(t *testing.T) {
	svc := newStubRollbackSvc()
	policyID := uuid.New()
	svc.policies[policyID] = &models.RollbackPolicy{ID: policyID, Name: "p1"}

	mux, _ := newRollbackTestServer(t, svc)
	stackID := uuid.New()
	body := `{"stack_id":"` + stackID.String() + `"}`
	req := httptest.NewRequest(http.MethodPost, "/policies/"+policyID.String()+"/dry-run", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if svc.dryRunPol != policyID || svc.dryRunStk != stackID {
		t.Fatalf("dry-run not invoked with expected ids; got policy=%s stack=%s", svc.dryRunPol, svc.dryRunStk)
	}
	if !strings.Contains(w.Body.String(), `"matched":true`) {
		t.Fatalf("response missing matched=true: %s", w.Body.String())
	}
}

func TestRollbackDeletePolicy(t *testing.T) {
	svc := newStubRollbackSvc()
	id := uuid.New()
	svc.policies[id] = &models.RollbackPolicy{ID: id}

	mux, _ := newRollbackTestServer(t, svc)
	req := httptest.NewRequest(http.MethodDelete, "/policies/"+id.String()+"/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if svc.deleteID != id {
		t.Fatalf("delete called with wrong ID: %s", svc.deleteID)
	}
}

func TestRollbackHandlerServiceUnavailable(t *testing.T) {
	h := NewRollbackHandler(nil, nil)
	r := chi.NewRouter()
	r.Get("/policies", h.ListPolicies)
	req := httptest.NewRequest(http.MethodGet, "/policies", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestRollbackHandlerDryRunInvalidStackID(t *testing.T) {
	svc := newStubRollbackSvc()
	mux, _ := newRollbackTestServer(t, svc)
	body := `{"stack_id":"not-a-uuid"}`
	req := httptest.NewRequest(http.MethodPost, "/policies/"+uuid.New().String()+"/dry-run", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}
