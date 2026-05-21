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
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
	yarasvc "github.com/fr4nsys/usulnet/internal/services/yara"
)

type stubYARASvc struct {
	res         *yarasvc.Result
	err         error
	lastTarget  yarasvc.ScanTarget
	lastRuleset string
}

func (s *stubYARASvc) Scan(_ context.Context, target yarasvc.ScanTarget, ruleset string) (*yarasvc.Result, error) {
	s.lastTarget = target
	s.lastRuleset = ruleset
	if s.err != nil {
		return nil, s.err
	}
	if s.res != nil {
		return s.res, nil
	}
	return &yarasvc.Result{
		Ruleset:   ruleset,
		Target:    "stub",
		StartedAt: time.Now(),
		Duration:  "10ms",
	}, nil
}

func yaraTestHandler(svc *stubYARASvc) *handlers.YARAHandler {
	return handlers.NewYARAHandler(svc, nil)
}

func TestYARAHandler_ListRulesets_IncludesEmbedded(t *testing.T) {
	h := yaraTestHandler(&stubYARASvc{})
	r := httptest.NewRequest(http.MethodGet, "/rulesets", nil)
	w := httptest.NewRecorder()
	h.ListRulesets(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp handlers.RulesetsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	found := false
	for _, n := range resp.Rulesets {
		if n == "linux-elf-suspicious" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected linux-elf-suspicious in %v", resp.Rulesets)
	}
}

func TestYARAHandler_Scan_HappyPath(t *testing.T) {
	svc := &stubYARASvc{
		res: &yarasvc.Result{
			Ruleset:   "linux-elf-suspicious",
			Target:    "/etc/hosts",
			Matches:   []yarasvc.Match{{Rule: "r1", Tags: []string{"a", "b"}, Target: "/etc/hosts"}},
			StartedAt: time.Now(),
			Duration:  "5ms",
		},
	}
	h := yaraTestHandler(svc)

	body, _ := json.Marshal(map[string]string{
		"ruleset":   "linux-elf-suspicious",
		"host_path": "/etc/hosts",
	})
	r := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	h.Scan(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if svc.lastRuleset != "linux-elf-suspicious" {
		t.Errorf("ruleset not forwarded: %q", svc.lastRuleset)
	}
	if svc.lastTarget.HostPath != "/etc/hosts" {
		t.Errorf("host_path not forwarded: %+v", svc.lastTarget)
	}
	var resp handlers.YARAScanResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	if len(resp.Matches) != 1 || resp.Matches[0].Rule != "r1" {
		t.Errorf("matches: %+v", resp.Matches)
	}
}

func TestYARAHandler_Scan_InvalidTarget_400(t *testing.T) {
	svc := &stubYARASvc{err: yarasvc.ErrInvalidTarget}
	h := yaraTestHandler(svc)

	body, _ := json.Marshal(map[string]string{"ruleset": "linux-elf-suspicious", "host_path": "rel/path"})
	r := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	h.Scan(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid target; got %d", w.Code)
	}
}

func TestYARAHandler_Scan_UnknownRuleset_400(t *testing.T) {
	svc := &stubYARASvc{err: yarasvc.ErrUnknownRuleset}
	h := yaraTestHandler(svc)

	body, _ := json.Marshal(map[string]string{"ruleset": "nope", "host_path": "/etc/hosts"})
	r := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	h.Scan(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown ruleset; got %d", w.Code)
	}
}

func TestYARAHandler_Scan_NilService_503(t *testing.T) {
	h := handlers.NewYARAHandler(nil, nil)
	body, _ := json.Marshal(map[string]string{"ruleset": "x", "host_path": "/etc/hosts"})
	r := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	h.Scan(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for nil service; got %d", w.Code)
	}
}

func TestYARAHandler_ContainerScan_URLContainerWins(t *testing.T) {
	svc := &stubYARASvc{}
	h := yaraTestHandler(svc)

	body, _ := json.Marshal(map[string]string{
		"ruleset":      "linux-elf-suspicious",
		"path":         "/usr/local/bin/app",
		"container_id": "ignored-because-url-supplies",
	})
	r := httptest.NewRequest(http.MethodPost, "/containers/host/abc123/yara-scan", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("hostID", "host")
	rctx.URLParams.Add("containerID", "abc123")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.ContainerScan(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if svc.lastTarget.ContainerID != "abc123" {
		t.Errorf("expected URL containerID abc123; got %q", svc.lastTarget.ContainerID)
	}
	if svc.lastTarget.Path != "/usr/local/bin/app" {
		t.Errorf("path not forwarded: %q", svc.lastTarget.Path)
	}
}

func TestYARAHandler_ContainerScan_MissingPath_400(t *testing.T) {
	svc := &stubYARASvc{}
	h := yaraTestHandler(svc)

	body, _ := json.Marshal(map[string]string{"ruleset": "linux-elf-suspicious"})
	r := httptest.NewRequest(http.MethodPost, "/containers/host/abc/yara-scan", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("containerID", "abc")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.ContainerScan(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing path; got %d", w.Code)
	}
}

func TestYARAHandler_Scan_ServiceErrorMaps_500(t *testing.T) {
	svc := &stubYARASvc{err: errors.New("unexpected")}
	h := yaraTestHandler(svc)
	body, _ := json.Marshal(map[string]string{"ruleset": "x", "host_path": "/etc/hosts"})
	r := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	h.Scan(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for unmapped error; got %d", w.Code)
	}
}
