// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/models"
	egresssvc "github.com/fr4nsys/usulnet/internal/services/egress"
)

type stubEgressSvc struct {
	listResult     []models.EgressPolicy
	listErr        error
	createResult   *models.EgressPolicy
	createErr      error
	deleteErr      error
	deniesResult   []models.EgressAuditLog
	deniesErr      error
	lastCreateHost uuid.UUID
	lastCreateIn   models.CreateEgressPolicyInput
	lastDeleteID   uuid.UUID
}

func (s *stubEgressSvc) ListPolicies(_ context.Context, _ uuid.UUID) ([]models.EgressPolicy, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.listResult, nil
}

func (s *stubEgressSvc) CreatePolicy(_ context.Context, hostID uuid.UUID, in models.CreateEgressPolicyInput) (*models.EgressPolicy, error) {
	s.lastCreateHost = hostID
	s.lastCreateIn = in
	if s.createErr != nil {
		return nil, s.createErr
	}
	if s.createResult != nil {
		return s.createResult, nil
	}
	return &models.EgressPolicy{
		ID:         uuid.New(),
		HostID:     hostID,
		TargetGlob: in.TargetGlob,
		Allow:      in.Allow,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}, nil
}

func (s *stubEgressSvc) DeletePolicy(_ context.Context, id uuid.UUID) error {
	s.lastDeleteID = id
	return s.deleteErr
}

func (s *stubEgressSvc) RecentDenies(_ context.Context, _ uuid.UUID, _ int) ([]models.EgressAuditLog, error) {
	if s.deniesErr != nil {
		return nil, s.deniesErr
	}
	return s.deniesResult, nil
}

func egressTestHandler(svc *stubEgressSvc) *handlers.EgressHandler {
	return handlers.NewEgressHandler(svc, nil)
}

func reqWithHostID(method, path string, body []byte, hostID uuid.UUID) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.ContentLength = int64(len(body))
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("hostID", hostID.String())
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestEgressHandler_List_HappyPath(t *testing.T) {
	hostID := uuid.New()
	svc := &stubEgressSvc{
		listResult: []models.EgressPolicy{
			{ID: uuid.New(), HostID: hostID, TargetGlob: "*.github.com", Allow: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		},
	}
	h := egressTestHandler(svc)

	w := httptest.NewRecorder()
	h.List(w, reqWithHostID(http.MethodGet, "/"+hostID.String()+"/policies", nil, hostID))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var resp []handlers.EgressPolicyResponse
	mustUnmarshal(t, w.Body.Bytes(), &resp)
	if len(resp) != 1 || resp[0].TargetGlob != "*.github.com" || !resp[0].Allow {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestEgressHandler_List_BadHostID(t *testing.T) {
	svc := &stubEgressSvc{}
	h := egressTestHandler(svc)

	r := httptest.NewRequest(http.MethodGet, "/not-a-uuid/policies", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("hostID", "not-a-uuid")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.List(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestEgressHandler_List_NilService_503(t *testing.T) {
	h := handlers.NewEgressHandler(nil, nil)
	w := httptest.NewRecorder()
	h.List(w, reqWithHostID(http.MethodGet, "/foo/policies", nil, uuid.New()))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestEgressHandler_Create_HappyPath(t *testing.T) {
	hostID := uuid.New()
	svc := &stubEgressSvc{}
	h := egressTestHandler(svc)

	body, _ := json.Marshal(map[string]interface{}{"target_glob": "*.github.com", "allow": true})
	w := httptest.NewRecorder()
	h.Create(w, reqWithHostID(http.MethodPost, "/"+hostID.String()+"/policies", body, hostID))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", w.Code, w.Body.String())
	}
	if svc.lastCreateHost != hostID {
		t.Errorf("hostID not forwarded; got %v want %v", svc.lastCreateHost, hostID)
	}
	if svc.lastCreateIn.TargetGlob != "*.github.com" || !svc.lastCreateIn.Allow {
		t.Errorf("input not forwarded: %+v", svc.lastCreateIn)
	}
}

func TestEgressHandler_Create_InvalidInputFromService(t *testing.T) {
	// Service returns ErrInvalidInput → handler maps it to 400.
	hostID := uuid.New()
	svc := &stubEgressSvc{createErr: egresssvc.ErrInvalidInput}
	h := egressTestHandler(svc)

	body, _ := json.Marshal(map[string]interface{}{"target_glob": "*.github.com", "allow": false})
	w := httptest.NewRecorder()
	h.Create(w, reqWithHostID(http.MethodPost, "/"+hostID.String()+"/policies", body, hostID))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for ErrInvalidInput, got %d", w.Code)
	}
}

func TestEgressHandler_Delete_HappyPath(t *testing.T) {
	svc := &stubEgressSvc{}
	h := egressTestHandler(svc)

	id := uuid.New()
	r := httptest.NewRequest(http.MethodDelete, "/policies/"+id.String(), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.Delete(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body=%s", w.Code, w.Body.String())
	}
	if svc.lastDeleteID != id {
		t.Errorf("delete id not forwarded; got %v want %v", svc.lastDeleteID, id)
	}
}

func TestEgressHandler_Delete_ServiceError_Returns500(t *testing.T) {
	svc := &stubEgressSvc{deleteErr: errors.New("boom")}
	h := egressTestHandler(svc)

	id := uuid.New()
	r := httptest.NewRequest(http.MethodDelete, "/policies/"+id.String(), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.Delete(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestEgressHandler_Denies_HappyPath(t *testing.T) {
	hostID := uuid.New()
	svc := &stubEgressSvc{
		deniesResult: []models.EgressAuditLog{
			{ID: uuid.New(), HostID: hostID, Target: "evil.cn", Method: "GET", Decision: "deny", CreatedAt: time.Now()},
		},
	}
	h := egressTestHandler(svc)

	w := httptest.NewRecorder()
	h.Denies(w, reqWithHostID(http.MethodGet, "/"+hostID.String()+"/denies", nil, hostID))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d want 200, body=%s", w.Code, w.Body.String())
	}
	var resp []handlers.EgressDenyResponse
	mustUnmarshal(t, w.Body.Bytes(), &resp)
	if len(resp) != 1 || resp[0].Target != "evil.cn" || resp[0].Decision != "deny" {
		t.Errorf("unexpected denies: %+v", resp)
	}
}

func TestEgressHandler_Routes_Surface(t *testing.T) {
	// Pin the four documented routes — a maintainer change that drops
	// one of them fails fast instead of via an integration test.
	h := handlers.NewEgressHandler(&stubEgressSvc{}, nil)
	walked := walkRoutes(h.Routes(), "")
	want := []string{
		"GET /{hostID}/policies",
		"POST /{hostID}/policies",
		"GET /{hostID}/denies",
		"DELETE /policies/{id}",
	}
	for _, w := range want {
		if !sliceContains(walked, w) {
			t.Errorf("missing route %q in %v", w, walked)
		}
	}
}

func mustUnmarshal(t *testing.T, body []byte, v any) {
	t.Helper()
	// Strip a possible JSON envelope wrapper used by some endpoints.
	if err := json.Unmarshal(body, v); err == nil {
		return
	}
	// Fallback: try the {"data": ...} envelope.
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, body)
	}
	if err := json.Unmarshal(env.Data, v); err != nil {
		t.Fatalf("unmarshal envelope.data: %v (body=%s)", err, body)
	}
}

func walkRoutes(r chi.Router, prefix string) []string {
	var out []string
	_ = chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		// Routes from sub-mounts already include their prefix when chi
		// walks them; we trim a trailing slash so list comparisons are
		// straightforward.
		route = strings.TrimSuffix(route, "/")
		out = append(out, method+" "+prefix+route)
		return nil
	})
	return out
}

func sliceContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
