// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build e2e

package recon_e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestE2E_Recon_EmailExposureLite_HappyPath walks the end-to-end
// recon flow for the email-exposure-lite profile:
//
//  1. Acknowledge the recon legal notice.
//  2. Create an email target for a known-clean address.
//  3. Self-assert ownership (E2E uses self_assert; the configured
//     test domain has a pre-set DNS TXT record for the dns_txt path,
//     but self_assert keeps the test infra dependency footprint
//     small).
//  4. Look up the built-in email-exposure-lite profile.
//  5. Start a scan against the target with that profile.
//  6. Poll until the scan terminates and assert status=completed.
//  7. Assert zero `critical` findings — the test email is clean.
//
// The test reads the target email from USULNET_TEST_RECON_EMAIL so the
// CI environment can swap it for whatever the configured test domain
// resolves to. A default of recon-e2e@example.test keeps the test
// hermetic when run locally.
func TestE2E_Recon_EmailExposureLite_HappyPath(t *testing.T) {
	cfg := loadConfig(t)

	email := os.Getenv("USULNET_TEST_RECON_EMAIL")
	if email == "" {
		email = "recon-e2e@example.test"
	}

	// 1) Ack.
	if r := httpDo(t, cfg, http.MethodPost, "/api/v1/recon/_ack", "", nil); r.StatusCode != http.StatusNoContent && r.StatusCode != http.StatusOK {
		_ = r.Body.Close()
		t.Fatalf("ack returned %d", r.StatusCode)
	}

	// 2) Create target.
	target := postJSON(t, cfg, "/api/v1/recon/targets", map[string]any{
		"type":  "email",
		"value": email,
		"label": "e2e",
	}, http.StatusCreated)
	targetID := target["id"].(string)

	// 3) Self-assert ownership.
	if _ = postJSON(t, cfg,
		"/api/v1/recon/targets/"+targetID+"/ownership/verify",
		map[string]any{"method": "self_assert"},
		http.StatusOK); targetID == "" {
		t.Fatal("ownership verification did not populate proof")
	}

	// 4) Find the email-exposure-lite profile id.
	profiles := getList(t, cfg, "/api/v1/recon/profiles")
	var profileID string
	for _, p := range profiles {
		if name, _ := p["name"].(string); name == "email-exposure-lite" {
			profileID, _ = p["id"].(string)
			break
		}
	}
	if profileID == "" {
		t.Fatalf("email-exposure-lite profile not found in seeded profiles: %v", profiles)
	}

	// 5) Start the scan.
	scan := postJSON(t, cfg, "/api/v1/recon/scans", map[string]any{
		"target_id":  targetID,
		"profile_id": profileID,
	}, http.StatusCreated)
	scanID := scan["id"].(string)

	// 6) Poll until terminal.
	deadline := time.Now().Add(5 * time.Minute)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("scan %s did not terminate within deadline", scanID)
		}
		s := getJSON(t, cfg, "/api/v1/recon/scans/"+scanID)
		status, _ := s["status"].(string)
		switch status {
		case "completed":
			// 7) Assert zero critical findings.
			findings := getList(t, cfg, "/api/v1/recon/scans/"+scanID+"/findings?severity=critical")
			if len(findings) != 0 {
				t.Errorf("expected zero critical findings for a clean email, got %d: %+v",
					len(findings), findings)
			}
			// Also assert the report endpoints behave correctly.
			r := httpDo(t, cfg, http.MethodGet, "/api/v1/recon/scans/"+scanID+"/report.json", "", nil)
			expectStatus(t, r, http.StatusOK)
			r = httpDo(t, cfg, http.MethodGet, "/api/v1/recon/scans/"+scanID+"/report.csv", "", nil)
			expectStatus(t, r, http.StatusOK)
			r = httpDo(t, cfg, http.MethodGet, "/api/v1/recon/scans/"+scanID+"/report.pdf", "", nil)
			body := expectStatus(t, r, http.StatusOK)
			if !bytes.HasPrefix(body, []byte("%PDF-")) {
				t.Errorf("PDF response missing %%PDF- magic, got prefix %q", body[:min(len(body), 16)])
			}
			return

		case "failed", "cancelled":
			t.Fatalf("scan terminated with status=%s: %+v", status, s)
		}
		time.Sleep(3 * time.Second)
	}
}

// ============================================================================
// Helpers
// ============================================================================

func postJSON(t *testing.T, cfg config, path string, body any, wantStatus int) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httpDo(t, cfg, http.MethodPost, path, "application/json", bytes.NewReader(raw))
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

func getJSON(t *testing.T, cfg config, path string) map[string]any {
	t.Helper()
	r := httpDo(t, cfg, http.MethodGet, path, "", nil)
	body := expectStatus(t, r, http.StatusOK)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %s: %v: %s", path, err, string(body))
	}
	return out
}

func getList(t *testing.T, cfg config, path string) []map[string]any {
	t.Helper()
	r := httpDo(t, cfg, http.MethodGet, path, "", nil)
	body := expectStatus(t, r, http.StatusOK)
	var out []map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode list %s: %v: %s", path, err, string(body))
	}
	return out
}
