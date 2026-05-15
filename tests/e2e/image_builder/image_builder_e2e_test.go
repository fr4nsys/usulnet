// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build e2e

// Package image_builder_e2e exercises the v26.5.1 image builder API
// end-to-end against a running usulnet instance with a real Docker
// daemon. The suite is driven by `docker-compose.test.yml` and is
// skipped automatically when USULNET_TEST_API_URL is unset.
//
// The smoke test walks:
//
//  1. POST /api/v1/builds       — build a tiny `FROM alpine:3.21` image
//  2. Poll the row until status leaves "building"
//  3. Confirm the resulting status is success and an image_id was set
//  4. GET  /api/v1/builds       — confirm the new row appears in the list
//
// Build tag `e2e` keeps this out of the default `go test ./...` run.
package image_builder_e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
		t.Skip("USULNET_TEST_API_URL not set; image builder e2e test requires a running API")
	}
	if c.Token == "" {
		t.Skip("USULNET_TEST_TOKEN not set; image builder e2e test requires an admin JWT")
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

// TestE2E_ImageBuilder_BuildAlpineSmoke exercises the full build path
// end-to-end. The image is intentionally trivial (`FROM alpine:3.21`)
// so the e2e harness completes well within the per-step timeout.
func TestE2E_ImageBuilder_BuildAlpineSmoke(t *testing.T) {
	cfg := loadConfig(t)

	tag := fmt.Sprintf("usulnet-e2e/imagebuilder:%d", time.Now().Unix())
	build := postJSON(t, cfg, "/api/v1/builds", map[string]any{
		"name":       "e2e: smoke alpine",
		"tags":       []string{tag},
		"dockerfile": "FROM alpine:3.21\nCMD [\"echo\", \"usulnet image-builder smoke ok\"]\n",
	}, http.StatusAccepted)

	buildID, _ := build["id"].(string)
	if buildID == "" {
		t.Fatalf("build id missing in response: %v", build)
	}

	deadline := time.Now().Add(2 * time.Minute)
	var final map[string]any
	for time.Now().Before(deadline) {
		resp := httpDo(t, cfg, http.MethodGet, "/api/v1/builds/"+buildID, "", nil)
		body := expectStatus(t, resp, http.StatusOK)
		var b map[string]any
		if err := json.Unmarshal(body, &b); err != nil {
			t.Fatalf("decode build: %v: %s", err, string(body))
		}
		status, _ := b["status"].(string)
		if status != "building" && status != "pending" {
			final = b
			break
		}
		time.Sleep(2 * time.Second)
	}

	if final == nil {
		t.Fatalf("build %s did not finish within 2m", buildID)
	}
	if status := final["status"]; status != "success" {
		t.Fatalf("expected success, got status=%v message=%v", status, final["error_message"])
	}
	if id := final["image_id"]; id == "" || id == nil {
		t.Fatalf("expected image_id to be populated on success, got %v", id)
	}

	// Confirm the row shows up in the list.
	listResp := httpDo(t, cfg, http.MethodGet, "/api/v1/builds", "", nil)
	listBody := expectStatus(t, listResp, http.StatusOK)
	var page map[string]any
	if err := json.Unmarshal(listBody, &page); err != nil {
		t.Fatalf("decode list: %v: %s", err, string(listBody))
	}
	rows, _ := page["builds"].([]any)
	found := false
	for _, r := range rows {
		row, _ := r.(map[string]any)
		if id, _ := row["id"].(string); id == buildID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("build %s not present in /api/v1/builds list", buildID)
	}
}
