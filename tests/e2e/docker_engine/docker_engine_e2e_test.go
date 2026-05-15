// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build e2e

// Package docker_engine_e2e exercises the v26.5.1 Docker engine config
// editor API end-to-end against a running usulnet instance. The suite
// is driven by docker-compose.test.yml and skipped when
// USULNET_TEST_API_URL is unset.
//
// The smoke flow walks the path the spec calls out:
//
//  1. GET /api/v1/docker-engine/config — read current daemon.json.
//  2. PUT /api/v1/docker-engine/config — apply a log-driver tweak.
//  3. GET /api/v1/docker-engine/config/history — verify a snapshot row
//     was recorded.
//  4. POST /api/v1/docker-engine/config/restore/{id} — restore the
//     pre-edit snapshot to leave the host's daemon.json clean.
//
// Build tag `e2e` keeps this out of the default `go test ./...` run.
package docker_engine_e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

type config struct {
	APIURL string
	Token  string
}

func loadConfig(t *testing.T) config {
	t.Helper()
	c := config{
		APIURL: os.Getenv("USULNET_TEST_API_URL"),
		Token:  os.Getenv("USULNET_TEST_TOKEN"),
	}
	if c.APIURL == "" {
		t.Skip("USULNET_TEST_API_URL not set; docker-engine e2e test requires a running API")
	}
	if c.Token == "" {
		t.Skip("USULNET_TEST_TOKEN not set; docker-engine e2e test requires an admin JWT")
	}
	return c
}

func httpDo(t *testing.T, c config, method, path, contentType string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, c.APIURL+path, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	client := &http.Client{Timeout: 90 * time.Second} // apply may wait for reload
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do %s %s: %v", method, path, err)
	}
	return resp
}

func expectStatus(t *testing.T, resp *http.Response, want int) []byte {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("%s %s -> status=%d, want %d. Body: %s",
			resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want, string(body))
	}
	return body
}

// TestE2E_DockerEngine_Smoke walks the read → apply → history →
// restore path. The apply payload is a no-op-ish change to the
// log-driver section (registry-mirrors carries reload semantics
// without restarting dockerd, so the daemon survives the round-trip
// even on a host with no operator-side recovery).
func TestE2E_DockerEngine_Smoke(t *testing.T) {
	cfg := loadConfig(t)

	// 1) GET current config.
	getResp := httpDo(t, cfg, http.MethodGet, "/api/v1/docker-engine/config", "", nil)
	getBody := expectStatus(t, getResp, http.StatusOK)
	var current map[string]any
	if err := json.Unmarshal(getBody, &current); err != nil {
		t.Fatalf("decode get: %v: %s", err, string(getBody))
	}
	if _, ok := current["raw_json"]; !ok {
		t.Fatalf("get response missing raw_json: %v", current)
	}

	// 2) PUT a registry-mirrors update — reload-only so the daemon
	// stays up.
	put := map[string]any{
		"raw":    map[string]any{"registry-mirrors": []string{"https://registry-1.docker.io"}},
		"reason": "e2e smoke",
	}
	putBody, _ := json.Marshal(put)
	putResp := httpDo(t, cfg, http.MethodPut, "/api/v1/docker-engine/config", "application/json", bytes.NewReader(putBody))
	putGot := expectStatus(t, putResp, http.StatusOK)
	var applied map[string]any
	if err := json.Unmarshal(putGot, &applied); err != nil {
		t.Fatalf("decode apply: %v: %s", err, string(putGot))
	}
	snapID, _ := applied["snapshot_id"].(string)
	if snapID == "" {
		t.Fatalf("apply response missing snapshot_id: %v", applied)
	}

	// 3) GET history must surface the snapshot row.
	histResp := httpDo(t, cfg, http.MethodGet, "/api/v1/docker-engine/config/history", "", nil)
	histGot := expectStatus(t, histResp, http.StatusOK)
	var hist map[string]any
	if err := json.Unmarshal(histGot, &hist); err != nil {
		t.Fatalf("decode history: %v: %s", err, string(histGot))
	}
	snaps, _ := hist["snapshots"].([]any)
	found := false
	for _, s := range snaps {
		if m, ok := s.(map[string]any); ok {
			if id, _ := m["id"].(string); id == snapID {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("snapshot %q not found in history: %v", snapID, snaps)
	}

	// 4) Restore the snapshot we just wrote — it captures the
	// pre-edit state, so this returns the daemon.json to baseline.
	restoreResp := httpDo(t, cfg, http.MethodPost, "/api/v1/docker-engine/config/restore/"+snapID, "", nil)
	_ = expectStatus(t, restoreResp, http.StatusOK)
}

// TestE2E_DockerEngine_RejectsInvalid asserts the API surfaces 400 for
// validation failures rather than mangling daemon.json. Sends an
// invalid log driver name; expects 400.
func TestE2E_DockerEngine_RejectsInvalid(t *testing.T) {
	cfg := loadConfig(t)

	body := map[string]any{
		"raw":    map[string]any{"log-driver": "definitely-not-a-driver"},
		"reason": "e2e validation",
	}
	raw, _ := json.Marshal(body)
	resp := httpDo(t, cfg, http.MethodPut, "/api/v1/docker-engine/config", "application/json", bytes.NewReader(raw))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 for invalid log-driver, got %d. Body: %s", resp.StatusCode, out)
	}
}
