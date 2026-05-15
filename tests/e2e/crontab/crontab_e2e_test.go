// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build e2e

// Package crontab_e2e exercises the v26.5.1 crontab REST API end-to-end
// against a running usulnet instance. The suite is driven by
// `docker-compose.test.yml` and is skipped automatically when
// USULNET_TEST_API_URL is unset.
//
// The smoke test walks the full path:
//
//  1. POST /api/v1/crontab/entries — create an entry (expect 201).
//  2. GET  /api/v1/crontab/entries — confirm the entry appears.
//  3. POST /api/v1/crontab/entries/{id}/run — force-run.
//  4. GET  /api/v1/crontab/executions?entry_id={id} — observe a row.
//  5. DELETE /api/v1/crontab/entries/{id} — clean up.
//
// Build tag `e2e` keeps this out of the default `go test ./...` run.
package crontab_e2e

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
	HostID string
}

func loadConfig(t *testing.T) config {
	t.Helper()
	c := config{
		APIURL: os.Getenv("USULNET_TEST_API_URL"),
		Token:  os.Getenv("USULNET_TEST_TOKEN"),
		HostID: os.Getenv("USULNET_TEST_HOST_ID"),
	}
	if c.APIURL == "" {
		t.Skip("USULNET_TEST_API_URL not set; crontab e2e test requires a running API")
	}
	if c.Token == "" {
		t.Skip("USULNET_TEST_TOKEN not set; crontab e2e test requires an admin JWT")
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
	if c.HostID != "" {
		req.Header.Set("X-Host-ID", c.HostID)
	}
	client := &http.Client{Timeout: 30 * time.Second}
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
		t.Fatalf("%s %s → status=%d, want %d. Body: %s",
			resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want, string(body))
	}
	return body
}

func postJSON(t *testing.T, c config, path string, body any, wantStatus int) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httpDo(t, c, http.MethodPost, path, "application/json", bytes.NewReader(raw))
	got := expectStatus(t, r, wantStatus)
	if len(got) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("decode response from %s: %v: %s", path, err, string(got))
	}
	return out
}

// TestE2E_Crontab_CRUDAndRunNow walks create -> list -> run-now -> verify
// execution -> delete. The shell command intentionally exits 0 so the
// execution row should appear as "success".
func TestE2E_Crontab_CRUDAndRunNow(t *testing.T) {
	cfg := loadConfig(t)

	// 1) Create.
	created := postJSON(t, cfg, "/api/v1/crontab/entries", map[string]any{
		"name":         "e2e: echo smoke",
		"description":  "e2e smoke entry",
		"schedule":     "*/30 * * * *",
		"command_type": "shell",
		"command":      "echo hello-from-e2e",
		"enabled":      true,
	}, http.StatusCreated)

	entryID, _ := created["id"].(string)
	if entryID == "" {
		t.Fatalf("created entry missing id: %v", created)
	}
	defer func() {
		_ = httpDo(t, cfg, http.MethodDelete, "/api/v1/crontab/entries/"+entryID, "", nil).Body.Close()
	}()

	// 2) List.
	listResp := httpDo(t, cfg, http.MethodGet, "/api/v1/crontab/entries", "", nil)
	listBody := expectStatus(t, listResp, http.StatusOK)
	var entries []map[string]any
	if err := json.Unmarshal(listBody, &entries); err != nil {
		t.Fatalf("decode list: %v: %s", err, string(listBody))
	}
	found := false
	for _, e := range entries {
		if id, _ := e["id"].(string); id == entryID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("created entry %s not in list response", entryID)
	}

	// 3) Force-run.
	_ = postJSON(t, cfg, "/api/v1/crontab/entries/"+entryID+"/run", map[string]any{}, http.StatusAccepted)

	// 4) Wait for the execution row to appear.
	deadline := time.Now().Add(10 * time.Second)
	var execTotal float64
	var firstStatus string
	for time.Now().Before(deadline) {
		r := httpDo(t, cfg, http.MethodGet, "/api/v1/crontab/executions?entry_id="+entryID, "", nil)
		body := expectStatus(t, r, http.StatusOK)
		var page struct {
			Entries []map[string]any `json:"entries"`
			Total   float64          `json:"total"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatalf("decode executions: %v: %s", err, string(body))
		}
		execTotal = page.Total
		if execTotal >= 1 && len(page.Entries) > 0 {
			firstStatus, _ = page.Entries[0]["status"].(string)
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if execTotal < 1 {
		t.Fatalf("expected at least one execution row after force-run")
	}
	if firstStatus != "success" {
		t.Errorf("expected status=success for echo command, got %q", firstStatus)
	}

	// 5) Delete.
	delResp := httpDo(t, cfg, http.MethodDelete, "/api/v1/crontab/entries/"+entryID, "", nil)
	_ = expectStatus(t, delResp, http.StatusNoContent)
}

// TestE2E_Crontab_Stats_ReturnsCounts checks the /stats endpoint works
// after creating one enabled entry.
func TestE2E_Crontab_Stats_ReturnsCounts(t *testing.T) {
	cfg := loadConfig(t)
	created := postJSON(t, cfg, "/api/v1/crontab/entries", map[string]any{
		"name":     "e2e: stats sample",
		"schedule": "0 0 * * *",
		"command":  "true",
		"enabled":  true,
	}, http.StatusCreated)
	entryID, _ := created["id"].(string)
	defer func() {
		_ = httpDo(t, cfg, http.MethodDelete, "/api/v1/crontab/entries/"+entryID, "", nil).Body.Close()
	}()

	resp := httpDo(t, cfg, http.MethodGet, "/api/v1/crontab/stats", "", nil)
	body := expectStatus(t, resp, http.StatusOK)
	var stats map[string]any
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("decode stats: %v: %s", err, string(body))
	}
	if total, _ := stats["total"].(float64); total < 1 {
		t.Errorf("expected total >= 1, got %v", stats["total"])
	}
}
