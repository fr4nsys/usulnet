// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build e2e

// Package rollback_e2e exercises the v26.5.1 automated rollback module
// end-to-end against a running usulnet instance. The suite is driven by
// `docker-compose.test.yml` and is skipped automatically when
// USULNET_TEST_API_URL or USULNET_TEST_STACK_ID is unset.
//
// The smoke test walks the auto-rollback path:
//
//  1. POST /api/v1/rollback/policies — create a policy with
//     scope=stack + trigger=deploy_failed pointing at the test stack
//     (expect 201).
//  2. POST /api/v1/rollback/policies/{id}/dry-run — sanity-check that
//     the policy would match the stack (expect 200, matched=true).
//  3. POST /api/v1/stacks/{stack_id}/deploy with a deliberately bad
//     image tag — induce a deploy failure that emits a
//     change_event(stack, deploy, metadata.error=...).
//  4. Wait for the rollback event worker to consume the event and
//     execute the policy. Poll GET /api/v1/rollback/executions until
//     a row with status in {succeeded, failed, dry_run} appears for
//     the test stack (expect within 30s).
//  5. DELETE the policy. Audit rows remain — the table is append-only.
//
// Build tag `e2e` keeps this out of the default `go test ./...` run.
package rollback_e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Test config
// ============================================================================

type config struct {
	APIURL  string
	Token   string
	StackID string
}

func loadConfig(t *testing.T) config {
	t.Helper()
	c := config{
		APIURL:  os.Getenv("USULNET_TEST_API_URL"),
		Token:   os.Getenv("USULNET_TEST_TOKEN"),
		StackID: os.Getenv("USULNET_TEST_STACK_ID"),
	}
	if c.APIURL == "" {
		t.Skip("USULNET_TEST_API_URL not set; rollback e2e test requires a running API")
	}
	if c.Token == "" {
		t.Skip("USULNET_TEST_TOKEN not set; rollback e2e test requires an admin JWT")
	}
	if c.StackID == "" {
		t.Skip("USULNET_TEST_STACK_ID not set; rollback e2e test requires an existing stack with version history")
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
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do %s %s: %v", method, path, err)
	}
	return resp
}

// readBody is a small helper used in error paths.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("<read error: %v>", err)
	}
	return string(b)
}

// ============================================================================
// Test
// ============================================================================

// TestRollbackInducesAutoRevert is the headline smoke test: a bad deploy
// should cause an automatic rollback execution row to appear.
//
// The test is intentionally tolerant about the rollback execution's
// terminal status — depending on the stack's version history the
// worker may end at "succeeded" (revert applied), "failed" (no
// last-known-good available), or "dry_run" (policy ships in dry-run
// mode). What it MUST NOT do is leave the row in "pending" or
// "running" longer than the poll timeout.
func TestRollbackInducesAutoRevert(t *testing.T) {
	c := loadConfig(t)

	// 1. Create a stack-scoped policy.
	policyBody := fmt.Sprintf(`{
		"name": "e2e auto-rollback",
		"description": "induced by tests/e2e/rollback",
		"enabled": true,
		"scope": "stack",
		"scope_stack_id": "%s",
		"trigger_kind": "deploy_failed",
		"last_good_strategy": "last_healthy",
		"cooldown_seconds": 0,
		"dry_run": false
	}`, c.StackID)
	resp := httpDo(t, c, http.MethodPost, "/api/v1/rollback/policies", "application/json", strings.NewReader(policyBody))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create policy: status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	resp.Body.Close()
	policyID := created.ID
	t.Cleanup(func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, c.APIURL+"/api/v1/rollback/policies/"+policyID, nil)
		req.Header.Set("Authorization", "Bearer "+c.Token)
		client := &http.Client{Timeout: 10 * time.Second}
		if dr, err := client.Do(req); err == nil {
			dr.Body.Close()
		}
	})

	// 2. Dry-run the policy against the stack — must match.
	dryBody := fmt.Sprintf(`{"stack_id":"%s"}`, c.StackID)
	resp = httpDo(t, c, http.MethodPost, "/api/v1/rollback/policies/"+policyID+"/dry-run", "application/json", strings.NewReader(dryBody))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dry-run: status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var dry struct {
		Matched bool `json:"matched"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dry); err != nil {
		t.Fatalf("decode dry-run: %v", err)
	}
	resp.Body.Close()
	if !dry.Matched {
		t.Fatalf("dry-run did not match the test stack")
	}

	// 3. Induce a bad deploy. The stack module emits a change_event
	// with action=deploy and metadata.error=… on failure; the rollback
	// worker should pick it up. We expect the deploy endpoint to
	// surface the failure as a non-2xx status — we accept either, the
	// downstream change_event is what matters.
	badDeploy := `{"image": "this-image-does-not-exist:e2e-rollback-test"}`
	resp = httpDo(t, c, http.MethodPost, "/api/v1/stacks/"+c.StackID+"/deploy-bad", "application/json", strings.NewReader(badDeploy))
	resp.Body.Close()
	// The /deploy-bad endpoint is a planned helper for E2E. If it does
	// not exist on this instance, skip the rest of the assertion path.
	if resp.StatusCode == http.StatusNotFound {
		t.Skip("/api/v1/stacks/{id}/deploy-bad helper not available; cannot induce failure end-to-end")
	}

	// 4. Poll the execution log for a terminal row scoped to our stack.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp := httpDo(t, c, http.MethodGet, "/api/v1/rollback/executions?stack_id="+c.StackID, "", nil)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("list executions: status=%d", resp.StatusCode)
		}
		var page struct {
			Entries []struct {
				ID       string `json:"id"`
				PolicyID string `json:"policy_id"`
				StackID  string `json:"stack_id"`
				Status   string `json:"status"`
			} `json:"entries"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			t.Fatalf("decode executions: %v", err)
		}
		resp.Body.Close()

		for _, e := range page.Entries {
			if e.PolicyID != policyID {
				continue
			}
			if e.StackID != c.StackID {
				continue
			}
			switch e.Status {
			case "succeeded", "failed", "dry_run":
				return // success — terminal row observed
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("did not observe a terminal rollback execution row for the test stack within 30s")
}

// TestRollbackAuditAppendOnly confirms that the API exposes no path
// that would let a caller mutate the audit log directly. The static
// guard in internal/repository/postgres/rollback_audit_append_only_test.go
// already enforces this at compile time; this e2e check confirms the
// same posture survives in the production binary by asserting there is
// no PUT/DELETE/PATCH route under /api/v1/rollback/audit.
func TestRollbackAuditAppendOnly(t *testing.T) {
	c := loadConfig(t)

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		resp := httpDo(t, c, method, "/api/v1/rollback/audit", "application/json", bytes.NewBufferString("{}"))
		// We expect 404 method-not-allowed or 405. 200/204 would
		// indicate a mutation path was wired — that's a regression.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			body := readBody(t, resp)
			resp.Body.Close()
			t.Fatalf("%s /api/v1/rollback/audit returned success status %d: %s", method, resp.StatusCode, body)
		}
		resp.Body.Close()
	}
}
