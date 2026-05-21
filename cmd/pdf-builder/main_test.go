// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalReportJSON returns a Report JSON the binary can render. The
// shape mirrors `internal/services/recon/report.Report`. Every UUID
// field is set to the canonical zero UUID so the JSON decoder accepts
// the input without us needing to import google/uuid here.
const minimalReportJSON = `{
  "scan_id": "00000000-0000-0000-0000-000000000001",
  "target": {
    "id": "00000000-0000-0000-0000-000000000002",
    "type": "domain",
    "value": "example.com"
  },
  "profile": {
    "id": "00000000-0000-0000-0000-000000000003",
    "name": "domain-surface"
  },
  "summary": {
    "counts": {"info": 2, "low": 0, "medium": 0, "high": 0, "critical": 0},
    "grade": "A",
    "total": 2
  },
  "categories": [
    {
      "category": "dns",
      "highest_severity": "info",
      "findings": [
        {
          "id": "00000000-0000-0000-0000-000000000010",
          "module": "sfp_dnsresolve",
          "severity": "info",
          "value": "example.com",
          "confidence": 50,
          "first_seen": "2026-05-16T12:00:00Z",
          "last_seen":  "2026-05-16T12:00:00Z"
        }
      ]
    },
    {
      "category": "certificate",
      "highest_severity": "info",
      "findings": [
        {
          "id": "00000000-0000-0000-0000-000000000011",
          "module": "sfp_crt",
          "severity": "info",
          "value": "example.com",
          "confidence": 50,
          "first_seen": "2026-05-16T12:00:00Z",
          "last_seen":  "2026-05-16T12:00:00Z"
        }
      ]
    }
  ],
  "generated_at": "2026-05-16T12:00:00Z"
}`

func TestRun_ReadsStdinWritesPDF(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{}, strings.NewReader(minimalReportJSON), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}
	bytes := stdout.Bytes()
	if len(bytes) == 0 {
		t.Fatalf("expected PDF bytes on stdout, got 0")
	}
	if !strings.HasPrefix(string(bytes), "%PDF-") {
		t.Fatalf("stdout did not start with %%PDF-, got %q", string(bytes[:8]))
	}
	if !strings.Contains(string(bytes), "%%EOF") {
		t.Fatalf("stdout did not contain %%EOF")
	}
}

func TestRun_DeterministicAcrossInvocations(t *testing.T) {
	var a, b bytes.Buffer
	if err := run([]string{}, strings.NewReader(minimalReportJSON), &a, io.Discard); err != nil {
		t.Fatalf("run (a): %v", err)
	}
	if err := run([]string{}, strings.NewReader(minimalReportJSON), &b, io.Discard); err != nil {
		t.Fatalf("run (b): %v", err)
	}
	// The AGPL report.GeneratePDF calls pdf.SetCatalogSort + pins
	// CreationDate / ModDate to r.GeneratedAt, so two runs of the
	// same Report produce byte-identical output. This is the contract
	// the cloud R2 key relies on (content-addressed by SHA-256 of the
	// bytes).
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("two renders of the same JSON produced different bytes (lens %d vs %d)", a.Len(), b.Len())
	}
}

func TestRun_InputFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte(minimalReportJSON), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout bytes.Buffer
	err := run([]string{"-input", path}, strings.NewReader("ignored"), &stdout, io.Discard)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.HasPrefix(stdout.String(), "%PDF-") {
		t.Fatalf("stdout did not start with %%PDF-")
	}
}

func TestRun_EmptyInputIsError(t *testing.T) {
	var stderr bytes.Buffer
	err := run([]string{}, strings.NewReader(""), io.Discard, &stderr)
	if err == nil {
		t.Fatalf("expected error on empty input, got nil")
	}
	if exitCodeFor(err) != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCodeFor(err))
	}
}

func TestRun_BadJSONIsError(t *testing.T) {
	var stderr bytes.Buffer
	err := run([]string{}, strings.NewReader("{this is not JSON"), io.Discard, &stderr)
	if err == nil {
		t.Fatalf("expected error on malformed JSON, got nil")
	}
	if exitCodeFor(err) != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCodeFor(err))
	}
}

func TestRun_TolerantToUnknownFields(t *testing.T) {
	// The cloud Worker may add extra metadata. The binary should
	// accept it (retrying with non-strict decode) rather than erroring.
	input := strings.Replace(
		minimalReportJSON,
		`"generated_at": "2026-05-16T12:00:00Z"`,
		`"generated_at": "2026-05-16T12:00:00Z", "cloud_extra": "noop"`,
		1,
	)
	var stdout bytes.Buffer
	err := run([]string{}, strings.NewReader(input), &stdout, io.Discard)
	if err != nil {
		t.Fatalf("run: %v (expected tolerant decode)", err)
	}
	if !strings.HasPrefix(stdout.String(), "%PDF-") {
		t.Fatalf("stdout did not start with %%PDF-")
	}
}

func TestRun_MissingInputFileIsExit3(t *testing.T) {
	var stderr bytes.Buffer
	err := run([]string{"-input", "/this/path/does/not/exist.json"}, strings.NewReader(""), io.Discard, &stderr)
	if err == nil {
		t.Fatalf("expected error on missing input file, got nil")
	}
	if exitCodeFor(err) != 3 {
		t.Fatalf("expected exit code 3 (I/O), got %d", exitCodeFor(err))
	}
}
