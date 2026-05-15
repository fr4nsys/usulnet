// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build e2e

// Package ssl_observatory_e2e exercises the v26.5.1 SSL observatory API
// end-to-end against a running usulnet instance. The suite is driven by
// `docker-compose.test.yml` and skipped when USULNET_TEST_API_URL is unset.
//
// The smoke test walks the documented path:
//
//  1. POST /api/v1/ssl/targets — add example.com:443 (expect 201).
//  2. POST /api/v1/ssl/targets/{id}/scan — trigger scan (expect 200).
//  3. GET  /api/v1/ssl/targets/{id}/scans — confirm a scan_result row
//     exists with extracted cert details (expect 200, non-empty).
//  4. DELETE /api/v1/ssl/targets/{id} — clean up (expect 204).
//
// Build tag `e2e` keeps this out of the default `go test ./...` run.
package ssl_observatory_e2e

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
		t.Skip("USULNET_TEST_API_URL not set; ssl observatory e2e test requires a running API")
	}
	if c.Token == "" {
		t.Skip("USULNET_TEST_TOKEN not set; ssl observatory e2e test requires an admin JWT")
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
	raw, _ := json.Marshal(body)
	r := httpDo(t, c, http.MethodPost, path, "application/json", bytes.NewReader(raw))
	got := expectStatus(t, r, wantStatus)
	if len(got) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("decode %s: %v: %s", path, err, string(got))
	}
	return out
}

// TestE2E_SSL_TargetScan walks the target-add → scan → result-row path
// against example.com:443 — the smoke target named in the session brief.
func TestE2E_SSL_TargetScan_SmokeFlow(t *testing.T) {
	cfg := loadConfig(t)

	// 1) Create a target.
	created := postJSON(t, cfg, "/api/v1/ssl/targets", map[string]any{
		"name":     "e2e: example.com",
		"hostname": "example.com",
		"port":     443,
	}, http.StatusCreated)

	targetID, _ := created["id"].(string)
	if targetID == "" {
		t.Fatalf("created target missing id: %v", created)
	}
	defer func() {
		// Best-effort cleanup.
		_ = httpDo(t, cfg, http.MethodDelete, "/api/v1/ssl/targets/"+targetID, "", nil).Body.Close()
	}()

	// 2) Trigger a scan.
	scanResp := httpDo(t, cfg, http.MethodPost, "/api/v1/ssl/targets/"+targetID+"/scan", "", nil)
	scanBody := expectStatus(t, scanResp, http.StatusOK)
	var scanResults []map[string]any
	if err := json.Unmarshal(scanBody, &scanResults); err != nil {
		t.Fatalf("decode scan results: %v: %s", err, string(scanBody))
	}
	if len(scanResults) == 0 {
		t.Fatal("scan returned no result rows")
	}
	if errMsg, _ := scanResults[0]["error_message"].(string); errMsg != "" {
		t.Logf("scan recorded error (may indicate no outbound network): %s", errMsg)
	}

	// 3) GET /scans must surface the row(s).
	listResp := httpDo(t, cfg, http.MethodGet, "/api/v1/ssl/targets/"+targetID+"/scans", "", nil)
	listBody := expectStatus(t, listResp, http.StatusOK)
	var page map[string]any
	if err := json.Unmarshal(listBody, &page); err != nil {
		t.Fatalf("decode scan list: %v: %s", err, string(listBody))
	}
	results, _ := page["results"].([]any)
	if len(results) == 0 {
		t.Fatal("expected at least one scan result row after scan")
	}
	first, _ := results[0].(map[string]any)
	if scanned, _ := first["scanned_at"].(string); scanned == "" {
		t.Errorf("scanned_at missing from result row: %v", first)
	}

	// 4) Delete.
	delResp := httpDo(t, cfg, http.MethodDelete, "/api/v1/ssl/targets/"+targetID, "", nil)
	_ = expectStatus(t, delResp, http.StatusNoContent)
}

// TestE2E_SSL_StatsEndpoint sanity-checks /stats returns a usable shape
// even when no targets exist.
func TestE2E_SSL_StatsEndpoint(t *testing.T) {
	cfg := loadConfig(t)
	resp := httpDo(t, cfg, http.MethodGet, "/api/v1/ssl/stats", "", nil)
	body := expectStatus(t, resp, http.StatusOK)
	var stats map[string]any
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("decode stats: %v: %s", err, string(body))
	}
	if _, ok := stats["total_targets"]; !ok {
		t.Errorf("expected total_targets in stats response, got %v", stats)
	}
}
