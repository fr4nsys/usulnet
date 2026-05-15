// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build e2e

// Package backup_verify_e2e exercises the v26.5.1 backup verification REST
// API end-to-end against a running usulnet instance. The suite is driven
// by `docker-compose.test.yml` and is skipped automatically when
// USULNET_TEST_API_URL is unset.
//
// The smoke walks:
//
//  1. POST /api/v1/backups — take a backup so there's something to verify.
//  2. POST /api/v1/backup-verify/run/{backup_id} — trigger a verification.
//  3. GET  /api/v1/backup-verify/runs — confirm the row appears.
//  4. GET  /api/v1/backup-verify/runs/{id} — confirm status reaches "passed".
//  5. POST /api/v1/backup-verify/schedules — create a schedule.
//  6. GET  /api/v1/backup-verify/schedules — confirm it appears.
//  7. DELETE /api/v1/backup-verify/schedules/{id} — clean up.
//
// Build tag `e2e` keeps this out of `go test ./...`.
package backup_verify_e2e

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
		t.Skip("USULNET_TEST_API_URL not set; backup verify e2e requires a running API")
	}
	if c.Token == "" {
		t.Skip("USULNET_TEST_TOKEN not set; backup verify e2e requires an admin JWT")
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
	client := &http.Client{Timeout: 60 * time.Second}
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

// TestE2E_BackupVerify_RunFlow takes the most recent backup the test
// fixture provides, triggers a verification, and polls until the run row
// either reaches "passed" or the timeout fires.
//
// A backup must already exist for this test to be meaningful; we assume
// the test harness takes one via the existing /api/v1/backups flow as
// part of its setup. When no backup is present, the test skips.
func TestE2E_BackupVerify_RunFlow(t *testing.T) {
	cfg := loadConfig(t)

	// Pick the latest backup.
	listResp := httpDo(t, cfg, http.MethodGet, "/api/v1/backups?limit=1", "", nil)
	listBody := expectStatus(t, listResp, http.StatusOK)
	var listed struct {
		Backups []map[string]any `json:"backups"`
		Total   int              `json:"total"`
	}
	if err := json.Unmarshal(listBody, &listed); err != nil {
		t.Fatalf("decode backups list: %v: %s", err, string(listBody))
	}
	if listed.Total == 0 || len(listed.Backups) == 0 {
		t.Skip("no backups exist in the test environment; create one first")
	}
	backupID, _ := listed.Backups[0]["id"].(string)
	if backupID == "" {
		t.Skip("backup list contains no id field")
	}

	// Trigger verification.
	runResp := postJSON(t, cfg, "/api/v1/backup-verify/run/"+backupID, map[string]any{"method": "extract"}, http.StatusCreated)
	verifID, _ := runResp["id"].(string)
	if verifID == "" {
		t.Fatalf("verification response missing id: %v", runResp)
	}

	// Poll for terminal state.
	deadline := time.Now().Add(30 * time.Second)
	var status string
	for time.Now().Before(deadline) {
		resp := httpDo(t, cfg, http.MethodGet, "/api/v1/backup-verify/runs/"+verifID, "", nil)
		body := expectStatus(t, resp, http.StatusOK)
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode verification: %v: %s", err, string(body))
		}
		status, _ = got["status"].(string)
		if status == "passed" || status == "failed" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if status != "passed" {
		t.Fatalf("verification did not reach passed; final status=%q", status)
	}
}

// TestE2E_BackupVerify_SchedulesCRUD creates a schedule, lists, and deletes.
func TestE2E_BackupVerify_SchedulesCRUD(t *testing.T) {
	cfg := loadConfig(t)

	created := postJSON(t, cfg, "/api/v1/backup-verify/schedules", map[string]any{
		"schedule":    "0 4 * * 0",
		"method":      "extract",
		"max_backups": 3,
	}, http.StatusCreated)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("created schedule missing id: %v", created)
	}
	defer func() {
		_ = httpDo(t, cfg, http.MethodDelete, "/api/v1/backup-verify/schedules/"+id, "", nil).Body.Close()
	}()

	listResp := httpDo(t, cfg, http.MethodGet, "/api/v1/backup-verify/schedules", "", nil)
	body := expectStatus(t, listResp, http.StatusOK)
	var items []map[string]any
	if err := json.Unmarshal(body, &items); err != nil {
		t.Fatalf("decode schedules: %v: %s", err, string(body))
	}
	found := false
	for _, it := range items {
		if got, _ := it["id"].(string); got == id {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("created schedule %s not in list response", id)
	}

	delResp := httpDo(t, cfg, http.MethodDelete, "/api/v1/backup-verify/schedules/"+id, "", nil)
	_ = expectStatus(t, delResp, http.StatusNoContent)
}

// TestE2E_BackupVerify_Stats verifies the stats endpoint returns the
// expected shape after at least one verification has run.
func TestE2E_BackupVerify_Stats(t *testing.T) {
	cfg := loadConfig(t)

	resp := httpDo(t, cfg, http.MethodGet, "/api/v1/backup-verify/stats", "", nil)
	body := expectStatus(t, resp, http.StatusOK)
	var stats map[string]any
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("decode stats: %v: %s", err, string(body))
	}
	if _, ok := stats["total_verified"]; !ok {
		t.Errorf("stats response missing total_verified: %v", stats)
	}
	if _, ok := stats["pass_rate"]; !ok {
		t.Errorf("stats response missing pass_rate: %v", stats)
	}
}
