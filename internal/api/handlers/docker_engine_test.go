// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

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

	dockerconfigsvc "github.com/fr4nsys/usulnet/internal/services/dockerconfig"
)

// stubDockerEngineSvc records calls and returns canned results.
type stubDockerEngineSvc struct {
	rawJSON       string
	parsed        *dockerconfigsvc.DaemonConfig
	configPath    string
	reloadTimeout time.Duration
	snapshots     []dockerconfigsvc.Snapshot

	applyResult *dockerconfigsvc.UpdateResult
	applyErr    error
	applyRaw    []byte
	applyReason string

	restoreID     string
	restoreResult *dockerconfigsvc.UpdateResult
	restoreErr    error
}

func (s *stubDockerEngineSvc) Read(_ context.Context) (*dockerconfigsvc.DaemonConfig, error) {
	if s.parsed != nil {
		return s.parsed, nil
	}
	return &dockerconfigsvc.DaemonConfig{}, nil
}

func (s *stubDockerEngineSvc) ReadRaw(_ context.Context) (string, error) {
	if s.rawJSON == "" {
		return "{}\n", nil
	}
	return s.rawJSON, nil
}

func (s *stubDockerEngineSvc) Apply(_ context.Context, raw []byte, reason string) (*dockerconfigsvc.UpdateResult, error) {
	s.applyRaw = append([]byte(nil), raw...)
	s.applyReason = reason
	return s.applyResult, s.applyErr
}

func (s *stubDockerEngineSvc) Restore(_ context.Context, id, _ string) (*dockerconfigsvc.UpdateResult, error) {
	s.restoreID = id
	return s.restoreResult, s.restoreErr
}

func (s *stubDockerEngineSvc) ListSnapshots(_ context.Context) ([]dockerconfigsvc.Snapshot, error) {
	return s.snapshots, nil
}

func (s *stubDockerEngineSvc) ConfigPath() string {
	if s.configPath == "" {
		return "/etc/docker/daemon.json"
	}
	return s.configPath
}

func (s *stubDockerEngineSvc) ReloadTimeout() time.Duration {
	if s.reloadTimeout == 0 {
		return 60 * time.Second
	}
	return s.reloadTimeout
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newDockerEngineRouter(svc DockerEngineService) chi.Router {
	r := chi.NewRouter()
	h := NewDockerEngineHandler(svc, nil)
	r.Get("/config", h.GetConfig)
	r.Put("/config", h.PutConfig)
	r.Get("/config/history", h.ListHistory)
	r.Post("/config/restore/{snapshot_id}", h.Restore)
	return r
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDockerEngine_GetConfig(t *testing.T) {
	svc := &stubDockerEngineSvc{
		rawJSON: `{"log-driver":"local"}`,
	}
	r := newDockerEngineRouter(svc)

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp DockerEngineConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.RawJSON != `{"log-driver":"local"}` {
		t.Errorf("raw_json: got %q", resp.RawJSON)
	}
	if resp.Path != "/etc/docker/daemon.json" {
		t.Errorf("path: got %q", resp.Path)
	}
	if len(resp.SettingsMeta) == 0 {
		t.Error("settings_meta empty")
	}
}

func TestDockerEngine_PutConfig_Success(t *testing.T) {
	svc := &stubDockerEngineSvc{
		applyResult: &dockerconfigsvc.UpdateResult{
			SnapshotID:    "20260514-103045-aabbcc",
			ApplyMode:     dockerconfigsvc.ApplyReload,
			ChangedFields: []string{"registry-mirrors"},
			Reloaded:      true,
		},
	}
	r := newDockerEngineRouter(svc)

	body := []byte(`{"raw":{"registry-mirrors":["https://mirror.example.com"]},"reason":"unit"}`)
	req := httptest.NewRequest(http.MethodPut, "/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", w.Code, w.Body.String())
	}
	if svc.applyReason != "unit" {
		t.Errorf("reason not forwarded: got %q", svc.applyReason)
	}
	if !bytes.Contains(svc.applyRaw, []byte("registry-mirrors")) {
		t.Errorf("raw not forwarded: %s", svc.applyRaw)
	}

	var resp DockerEngineUpdateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Reloaded {
		t.Error("reloaded should be true")
	}
	if resp.SnapshotID != "20260514-103045-aabbcc" {
		t.Errorf("snapshot id: %q", resp.SnapshotID)
	}
}

// TestDockerEngine_PutConfig_Rollback ensures the handler emits 409
// with a structured Result body when the service signals a forced
// rollback. The UI relies on the 409 status to paint the rollback
// banner without making a second call.
func TestDockerEngine_PutConfig_Rollback(t *testing.T) {
	svc := &stubDockerEngineSvc{
		applyResult: &dockerconfigsvc.UpdateResult{
			SnapshotID: "snap-1",
			RolledBack: true,
		},
		applyErr: errors.New("daemon did not return healthy within 60s"),
	}
	r := newDockerEngineRouter(svc)

	body := []byte(`{"raw":{"log-driver":"local"}}`)
	req := httptest.NewRequest(http.MethodPut, "/config", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409; body=%s", w.Code, w.Body.String())
	}
	var env struct {
		Error  string                     `json:"error"`
		Result DockerEngineUpdateResponse `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !env.Result.RolledBack {
		t.Error("rolled_back missing in response")
	}
	if env.Error == "" {
		t.Error("error message missing")
	}
}

func TestDockerEngine_PutConfig_RejectsEmptyBody(t *testing.T) {
	svc := &stubDockerEngineSvc{}
	r := newDockerEngineRouter(svc)

	req := httptest.NewRequest(http.MethodPut, "/config", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", w.Code)
	}
}

func TestDockerEngine_PutConfig_RejectsMissingRaw(t *testing.T) {
	svc := &stubDockerEngineSvc{}
	r := newDockerEngineRouter(svc)

	req := httptest.NewRequest(http.MethodPut, "/config", bytes.NewReader([]byte(`{"reason":"x"}`)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", w.Code)
	}
}

func TestDockerEngine_ListHistory(t *testing.T) {
	svc := &stubDockerEngineSvc{
		snapshots: []dockerconfigsvc.Snapshot{
			{ID: "20260514-103045-aabbcc", Size: 128, Timestamp: time.Now().UTC()},
			{ID: "20260513-090000-001122", Size: 96, Timestamp: time.Now().UTC().Add(-24 * time.Hour)},
		},
	}
	r := newDockerEngineRouter(svc)

	req := httptest.NewRequest(http.MethodGet, "/config/history", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d", w.Code)
	}
	var resp HistoryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 2 || len(resp.Snapshots) != 2 {
		t.Errorf("history: %+v", resp)
	}
}

func TestDockerEngine_Restore(t *testing.T) {
	svc := &stubDockerEngineSvc{
		restoreResult: &dockerconfigsvc.UpdateResult{
			SnapshotID:    "snap-1",
			ApplyMode:     dockerconfigsvc.ApplyReload,
			ChangedFields: []string{"registry-mirrors"},
			Reloaded:      true,
		},
	}
	r := newDockerEngineRouter(svc)

	req := httptest.NewRequest(http.MethodPost, "/config/restore/20260514-103045-aabbcc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", w.Code, w.Body.String())
	}
	if svc.restoreID != "20260514-103045-aabbcc" {
		t.Errorf("snapshot id not forwarded: %q", svc.restoreID)
	}
}

// TestDockerEngine_NilService_Returns503 ensures every endpoint
// degrades gracefully when the service is not wired.
func TestDockerEngine_NilService_Returns503(t *testing.T) {
	r := newDockerEngineRouter(nil)
	cases := []struct {
		method string
		path   string
		body   []byte
	}{
		{http.MethodGet, "/config", nil},
		{http.MethodPut, "/config", []byte(`{"raw":{}}`)},
		{http.MethodGet, "/config/history", nil},
		{http.MethodPost, "/config/restore/abc", nil},
	}
	for _, c := range cases {
		var body *bytes.Reader
		if c.body != nil {
			body = bytes.NewReader(c.body)
		}
		var req *http.Request
		if body == nil {
			req = httptest.NewRequest(c.method, c.path, nil)
		} else {
			req = httptest.NewRequest(c.method, c.path, body)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: got %d want 503; body=%s", c.method, c.path, w.Code, w.Body.String())
		}
	}
}
