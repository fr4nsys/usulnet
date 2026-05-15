// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build e2e

// Package firewall_e2e exercises the v26.5.1 firewall API end-to-end
// against a running usulnet instance. The suite is driven by
// `docker-compose.test.yml` and is skipped automatically when
// USULNET_TEST_API_URL is unset.
//
// The smoke test walks the full CRUD path:
//
//  1. POST /api/v1/firewall/rules — create a rule (expect 201).
//  2. GET  /api/v1/firewall/rules — confirm the rule appears.
//  3. GET  /api/v1/firewall/rules/{id} — fetch by ID.
//  4. PUT  /api/v1/firewall/rules/{id} — toggle Enabled=false.
//  5. DELETE /api/v1/firewall/rules/{id} — expect 204.
//
// Build tag `e2e` keeps this out of the default `go test ./...` run.
package firewall_e2e

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

// ============================================================================
// Test config (mirrors tests/e2e/recon/metadata_e2e_test.go)
// ============================================================================

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
		t.Skip("USULNET_TEST_API_URL not set; firewall e2e test requires a running API")
	}
	if c.Token == "" {
		t.Skip("USULNET_TEST_TOKEN not set; firewall e2e test requires an admin JWT")
	}
	return c
}

// httpDo issues a request with auth headers and a sensible timeout.
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

// expectStatus drains the body and fails the test if status differs.
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

// postJSON encodes body to JSON, issues a POST, and decodes the
// expected-status response.
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

func putJSON(t *testing.T, c config, path string, body any, wantStatus int) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httpDo(t, c, http.MethodPut, path, "application/json", bytes.NewReader(raw))
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

// ============================================================================
// Smoke test: create -> list -> get -> update -> delete
// ============================================================================

func TestE2E_Firewall_CRUD_SmokeFlow(t *testing.T) {
	cfg := loadConfig(t)

	// 1) Create a rule.
	created := postJSON(t, cfg, "/api/v1/firewall/rules", map[string]any{
		"name":      "e2e: allow SSH from anywhere",
		"chain":     "INPUT",
		"protocol":  "tcp",
		"dst_port":  "22",
		"action":    "ACCEPT",
		"direction": "inbound",
		"enabled":   true,
		"comment":   "e2e smoke",
	}, http.StatusCreated)

	ruleID, _ := created["id"].(string)
	if ruleID == "" {
		t.Fatalf("created rule missing id: %v", created)
	}
	defer func() {
		// Best-effort cleanup if the test panics before delete.
		_ = httpDo(t, cfg, http.MethodDelete, "/api/v1/firewall/rules/"+ruleID, "", nil).Body.Close()
	}()

	// 2) List, confirm presence.
	listResp := httpDo(t, cfg, http.MethodGet, "/api/v1/firewall/rules", "", nil)
	listBody := expectStatus(t, listResp, http.StatusOK)
	var rules []map[string]any
	if err := json.Unmarshal(listBody, &rules); err != nil {
		t.Fatalf("decode list: %v: %s", err, string(listBody))
	}
	found := false
	for _, r := range rules {
		if id, _ := r["id"].(string); id == ruleID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("created rule %s not in list response", ruleID)
	}

	// 3) Fetch by ID.
	getResp := httpDo(t, cfg, http.MethodGet, "/api/v1/firewall/rules/"+ruleID, "", nil)
	getBody := expectStatus(t, getResp, http.StatusOK)
	var got map[string]any
	if err := json.Unmarshal(getBody, &got); err != nil {
		t.Fatalf("decode get: %v: %s", err, string(getBody))
	}
	if got["name"] != "e2e: allow SSH from anywhere" {
		t.Errorf("expected name preserved, got %v", got["name"])
	}
	if got["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", got["enabled"])
	}

	// 4) Patch via PUT: toggle enabled off.
	disabled := false
	updated := putJSON(t, cfg, "/api/v1/firewall/rules/"+ruleID, map[string]any{
		"enabled": &disabled,
	}, http.StatusOK)
	if updated["enabled"] != false {
		t.Errorf("expected enabled=false after update, got %v", updated["enabled"])
	}

	// 5) Delete.
	delResp := httpDo(t, cfg, http.MethodDelete, "/api/v1/firewall/rules/"+ruleID, "", nil)
	_ = expectStatus(t, delResp, http.StatusNoContent)

	// Subsequent GET should be 404.
	r404 := httpDo(t, cfg, http.MethodGet, "/api/v1/firewall/rules/"+ruleID, "", nil)
	if r404.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(r404.Body)
		_ = r404.Body.Close()
		t.Errorf("expected 404 after delete, got %d: %s", r404.StatusCode, string(body))
	} else {
		_ = r404.Body.Close()
	}
}

// TestE2E_Firewall_StatusEndpoint_ReturnsBackend asserts /status responds
// 200 with a backend field, even when no agent is wired (the service
// returns FirewallBackendUnknown rather than erroring).
func TestE2E_Firewall_StatusEndpoint_ReturnsBackend(t *testing.T) {
	cfg := loadConfig(t)
	resp := httpDo(t, cfg, http.MethodGet, "/api/v1/firewall/status", "", nil)
	body := expectStatus(t, resp, http.StatusOK)
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode status: %v: %s", err, string(body))
	}
	if _, ok := got["backend"]; !ok {
		t.Errorf("expected backend field in status response, got %v", got)
	}
}
