// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build e2e

// Package recon_e2e exercises the v26.5.0 recon API end-to-end against
// a running usulnet instance. The suite is driven by
// `docker-compose.test.yml` and is skipped automatically when
// USULNET_TEST_API_URL is unset.
//
// Two test files live in this package:
//
//   - metadata_e2e_test.go (this file) — uploads a JPEG fixture with
//     known EXIF, asserts that GET …/jobs/{id}/artifacts surfaces the
//     extracted Software tag, then asserts that the stripped artifact
//     has no Software tag.
//   - scan_e2e_test.go — registers an email target, runs self-assert
//     ownership against the configured test domain, starts the
//     email-exposure-lite profile, and waits for completion. The
//     scan asserts status=completed and zero critical findings —
//     the test email is configured to be clean.
//
// Build tag e2e keeps this out of the default `go test ./...` run.
package recon_e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Test config (mirrors tests/e2e/e2e_test.go)
// ============================================================================

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
		t.Skip("USULNET_TEST_API_URL not set; recon e2e tests require a running API")
	}
	if c.Token == "" {
		t.Skip("USULNET_TEST_TOKEN not set; recon e2e tests require an admin JWT")
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

// ============================================================================
// Metadata: upload → extract → strip
// ============================================================================

func TestE2E_Metadata_UploadExtractsAndStripsEXIF(t *testing.T) {
	cfg := loadConfig(t)

	// Acknowledge the recon legal notice (idempotent).
	ackResp := httpDo(t, cfg, http.MethodPost, "/api/v1/recon/_ack", "", nil)
	if ackResp.StatusCode != http.StatusNoContent && ackResp.StatusCode != http.StatusOK {
		_ = ackResp.Body.Close()
		t.Fatalf("ack returned %d", ackResp.StatusCode)
	}
	_ = ackResp.Body.Close()

	// Build the multipart body. The metadata handler expects a
	// `files` part with one or more JPEGs.
	imgBytes := makeJPEGWithEXIF(t, "usulnet-e2e-test")

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": []string{`form-data; name="files"; filename="sample.jpg"`},
		"Content-Type":        []string{"image/jpeg"},
	})
	if err != nil {
		t.Fatalf("create part: %v", err)
	}
	if _, err := fw.Write(imgBytes); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := mw.WriteField("mode", "both"); err != nil {
		t.Fatalf("write field mode: %v", err)
	}
	_ = mw.Close()

	resp := httpDo(t, cfg, http.MethodPost, "/api/v1/metadata/jobs", mw.FormDataContentType(), &body)
	respBody := expectStatus(t, resp, http.StatusCreated)

	var job struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(respBody, &job); err != nil {
		t.Fatalf("decode job: %v: %s", err, string(respBody))
	}
	if job.ID == "" {
		t.Fatalf("no job id in response: %s", string(respBody))
	}

	// Poll for terminal status (completed/failed/cancelled).
	deadline := time.Now().Add(2 * time.Minute)
	var artifactID string
	var extracted map[string]any
	for {
		if time.Now().After(deadline) {
			t.Fatalf("job %s did not finish within deadline", job.ID)
		}
		resp := httpDo(t, cfg, http.MethodGet, "/api/v1/metadata/jobs/"+job.ID, "", nil)
		raw := expectStatus(t, resp, http.StatusOK)
		var got struct {
			Status    string `json:"status"`
			Artifacts []struct {
				ID        string         `json:"id"`
				Filename  string         `json:"filename"`
				Extracted map[string]any `json:"extracted"`
			} `json:"artifacts"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("decode poll: %v: %s", err, string(raw))
		}
		if got.Status == "completed" {
			if len(got.Artifacts) == 0 {
				t.Fatalf("job completed without artifacts: %s", string(raw))
			}
			artifactID = got.Artifacts[0].ID
			extracted = got.Artifacts[0].Extracted
			break
		}
		if got.Status == "failed" || got.Status == "cancelled" {
			t.Fatalf("job terminated with status=%s: %s", got.Status, string(raw))
		}
		time.Sleep(2 * time.Second)
	}

	// Assert the extracted EXIF surfaces our Software tag.
	if !extractedContains(extracted, "usulnet-e2e-test") {
		t.Errorf("expected extracted metadata to mention 'usulnet-e2e-test', got %v", extracted)
	}

	// Download the stripped artifact and assert it has no Software EXIF.
	resp = httpDo(t, cfg, http.MethodGet,
		"/api/v1/metadata/artifacts/"+artifactID+"/stripped", "", nil)
	stripped := expectStatus(t, resp, http.StatusOK)
	if bytes.Contains(stripped, []byte("usulnet-e2e-test")) {
		t.Errorf("stripped JPEG still contains the EXIF Software tag")
	}
}

// extractedContains returns true if any value in the (possibly
// nested) extracted map contains substr. Used because the extractor
// output keys vary by tool (exiftool emits "Software" but oletools
// would use a different key shape).
func extractedContains(m map[string]any, substr string) bool {
	for _, v := range m {
		switch t := v.(type) {
		case string:
			if strings.Contains(t, substr) {
				return true
			}
		case map[string]any:
			if extractedContains(t, substr) {
				return true
			}
		case []any:
			for _, e := range t {
				if s, ok := e.(string); ok && strings.Contains(s, substr) {
					return true
				}
			}
		}
	}
	return false
}

// ============================================================================
// JPEG fixture generator
// ============================================================================

// makeJPEGWithEXIF builds a minimal valid JPEG that carries an EXIF
// APP1 segment with Software=tag in IFD0. The generator is
// deterministic — same input → same byte output — so a fixture-diff
// review is meaningful.
//
// JPEG layout produced:
//
//   SOI (FFD8)
//   APP1 (FFE1, length, "Exif\0\0", TIFF header, IFD0 with Software)
//   The rest is a stock 2x2 grey JPEG body (DQT, SOF, DHT, SOS, scan, EOI).
//
// The function intentionally avoids importing image/jpeg so the
// fixture remains transparent to a reviewer.
func makeJPEGWithEXIF(t *testing.T, software string) []byte {
	t.Helper()

	// 1) Build the EXIF APP1 payload (without the marker + length).
	exif := bytes.Buffer{}
	exif.WriteString("Exif")
	exif.WriteByte(0x00)
	exif.WriteByte(0x00)

	// TIFF header: little-endian, magic 0x002A, offset to IFD0 = 8.
	exif.WriteByte('I')
	exif.WriteByte('I')
	exif.Write([]byte{0x2A, 0x00})
	exif.Write([]byte{0x08, 0x00, 0x00, 0x00})

	// IFD0: one entry — Software (tag 0x0131, ASCII, count = len+1 for NUL).
	swBytes := append([]byte(software), 0x00)
	exif.Write([]byte{0x01, 0x00}) // entry count = 1
	// Tag (LE)
	exif.Write([]byte{0x31, 0x01})
	// Type = 2 (ASCII)
	exif.Write([]byte{0x02, 0x00})
	// Count (4 bytes)
	exif.Write(u32LE(uint32(len(swBytes))))
	// Value: offset into the TIFF if >4 bytes, inline otherwise.
	// Our IFD entry list is 2 + 1*12 + 4 = 18 bytes; TIFF header is
	// 8 bytes; so the string sits at offset 8 + 18 = 26.
	if len(swBytes) <= 4 {
		// Pad inline (4 bytes).
		buf := make([]byte, 4)
		copy(buf, swBytes)
		exif.Write(buf)
	} else {
		exif.Write(u32LE(26))
	}
	// Next IFD = 0 (no IFD1)
	exif.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// String value
	if len(swBytes) > 4 {
		exif.Write(swBytes)
	}

	// 2) Build the APP1 segment with the right length.
	app1 := bytes.Buffer{}
	app1.Write([]byte{0xFF, 0xE1})
	// Length includes itself (the 2 length bytes) and the EXIF
	// payload that follows.
	length := uint16(2 + exif.Len())
	app1.Write([]byte{byte(length >> 8), byte(length)})
	app1.Write(exif.Bytes())

	// 3) Stock 2x2 grey JPEG body — SOI is replaced with our SOI +
	// APP1. The minimal JPEG body was generated once with
	// imagemagick and frozen here. Bytes are taken from a fresh
	// `convert -size 2x2 xc:gray jpeg:-` (libjpeg-turbo 2.1.5) and
	// embedded inline. Update only if the JPEG body becomes
	// invalid (e.g., libjpeg-turbo encoder change).
	body := []byte{
		// DQT (luminance)
		0xFF, 0xDB, 0x00, 0x43, 0x00,
		0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14,
		0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A,
		0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C,
		0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32,
		// SOF0 (baseline DCT) — 2x2 grayscale
		0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x02, 0x00, 0x02, 0x01, 0x01, 0x11, 0x00,
		// DHT (DC luminance)
		0xFF, 0xC4, 0x00, 0x1F, 0x00,
		0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
		// DHT (AC luminance) — minimal
		0xFF, 0xC4, 0x00, 0xB5, 0x10,
		0x00, 0x02, 0x01, 0x03, 0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
		0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
		0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0,
		0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
		0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
		0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
		0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5,
		0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
		0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
		0xF9, 0xFA,
		// SOS
		0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
		// Entropy-coded data (one byte for a 2x2 all-grey image)
		0xFC, 0xAA, 0x28, 0xA2, 0x80,
		// EOI
		0xFF, 0xD9,
	}

	out := bytes.Buffer{}
	out.Write([]byte{0xFF, 0xD8}) // SOI
	out.Write(app1.Bytes())
	out.Write(body)
	return out.Bytes()
}

// u32LE encodes a uint32 in little-endian order.
func u32LE(v uint32) []byte {
	return []byte{
		byte(v),
		byte(v >> 8),
		byte(v >> 16),
		byte(v >> 24),
	}
}

// Compile-time guarantee that fmt is referenced (linter happiness).
var _ = fmt.Sprintf
