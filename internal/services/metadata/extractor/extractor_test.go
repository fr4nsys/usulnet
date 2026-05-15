// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package extractor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/metadata"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// stubLauncher implements recon.ContainerLauncher for the extractor
// tests. It records every RunOnce call and returns programmed
// output/exitCode by subcommand (cmd[0]).
type stubLauncher struct {
	mu     sync.Mutex
	canned map[string]stubResult
	calls  []recon.ContainerSpec
}

type stubResult struct {
	output []byte
	code   int
	err    error
}

func newStubLauncher() *stubLauncher {
	return &stubLauncher{canned: make(map[string]stubResult)}
}

func (s *stubLauncher) program(subcommand, output string, code int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.canned[subcommand] = stubResult{output: []byte(output), code: code, err: err}
}

func (s *stubLauncher) EnsureRunning(_ context.Context, _ recon.ContainerSpec) (string, error) {
	return "", errors.New("EnsureRunning not implemented")
}

func (s *stubLauncher) RunOnce(_ context.Context, spec recon.ContainerSpec) ([]byte, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, spec)
	if len(spec.Command) == 0 {
		return nil, 2, nil
	}
	if r, ok := s.canned[spec.Command[0]]; ok {
		return r.output, r.code, r.err
	}
	return nil, 2, nil
}

func (s *stubLauncher) RunOnceWithCopy(_ context.Context, spec recon.ContainerSpec, copyPath string) ([]byte, []byte, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, spec)
	res := s.canned[spec.Command[0]]
	copied := s.canned[copyPath]
	return res.output, copied.output, res.code, res.err
}

func (s *stubLauncher) Stop(_ context.Context, _ string) error { return nil }

// ---------------------------------------------------------------------------
// ExifTool
// ---------------------------------------------------------------------------

func TestExifTool_HappyPath(t *testing.T) {
	stub := newStubLauncher()
	stub.program("extract", `{"requested_mime":"image/jpeg","detected_mime":"image/jpeg","exiftool":{"FileName":"x.jpg","FileType":"JPEG"}}`, 0, nil)

	e, err := NewExifTool(stub, "img", 0, logger.Nop())
	if err != nil {
		t.Fatalf("NewExifTool: %v", err)
	}
	got, err := e.Extract(context.Background(), metadata.ExtractInput{
		Path:     "/var/data/foo/original",
		Filename: "x.jpg",
		MIME:     "image/jpeg",
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got["detected_mime"] != "image/jpeg" {
		t.Errorf("detected_mime missing: %v", got)
	}
	if _, ok := got["exiftool"]; !ok {
		t.Errorf("exiftool sub-map missing: %v", got)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(stub.calls))
	}
	spec := stub.calls[0]
	if !spec.NoNetwork {
		t.Error("metadata extractor must set NoNetwork=true")
	}
	if len(spec.Mounts) != 1 || spec.Mounts[0].Target != ContainerInputDir {
		t.Errorf("mount = %v, want target %q", spec.Mounts, ContainerInputDir)
	}
	wantPath := ContainerInputDir + "/original"
	foundPath := false
	for _, a := range spec.Command {
		if a == wantPath {
			foundPath = true
		}
	}
	if !foundPath {
		t.Errorf("command does not reference %q: %v", wantPath, spec.Command)
	}
}

func TestExifTool_ErrorEnvelope(t *testing.T) {
	stub := newStubLauncher()
	stub.program("extract", `{"error":"input_missing","message":"no such file"}`, 2, nil)

	e, _ := NewExifTool(stub, "img", 0, logger.Nop())
	_, err := e.Extract(context.Background(), metadata.ExtractInput{
		Path: "/v/original",
		MIME: "image/jpeg",
	})
	if err == nil {
		t.Fatal("expected error for exit code 2")
	}
}

func TestExifTool_ParsesErrorKeyEvenOnSuccessExit(t *testing.T) {
	stub := newStubLauncher()
	// Some entrypoint paths emit an error object with exit 0 — still
	// surface it as a Go error so callers see the failure.
	stub.program("extract", `{"error":"strip_failed","message":"mat2 could not process"}`, 0, nil)

	e, _ := NewExifTool(stub, "img", 0, logger.Nop())
	_, err := e.Extract(context.Background(), metadata.ExtractInput{
		Path: "/v/original",
		MIME: "image/jpeg",
	})
	if err == nil {
		t.Fatal("expected error envelope to surface")
	}
}

// ---------------------------------------------------------------------------
// Dispatch — MIME routing
// ---------------------------------------------------------------------------

func TestDispatch_PDFRoutesToPDFID(t *testing.T) {
	stub := newStubLauncher()
	stub.program("extract", `{"exiftool":{"FileType":"PDF"}}`, 0, nil)
	stub.program("pdfid", `{"path":"/work/input/original","raw":"PDFiD ... /JS 1 /JavaScript 1"}`, 0, nil)

	exif, _ := NewExifTool(stub, "img", 0, logger.Nop())
	pdf, _ := NewPDFID(stub, "img", 0, logger.Nop())
	d, err := NewDispatch(exif, pdf, nil, logger.Nop())
	if err != nil {
		t.Fatalf("NewDispatch: %v", err)
	}
	out, err := d.Extract(context.Background(), metadata.ExtractInput{
		Path: "/v/original",
		MIME: "application/pdf",
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if _, ok := out["exiftool"]; !ok {
		t.Errorf("missing exiftool key: %v", keys(out))
	}
	if _, ok := out["pdfid"]; !ok {
		t.Errorf("missing pdfid key: %v", keys(out))
	}
}

func TestDispatch_OfficeRoutesToOleTools(t *testing.T) {
	stub := newStubLauncher()
	stub.program("extract", `{"exiftool":{"FileType":"DOCX"}}`, 0, nil)
	stub.program("oletools", `{"path":"/work/input/original","raw":"author=alice"}`, 0, nil)

	exif, _ := NewExifTool(stub, "img", 0, logger.Nop())
	ole, _ := NewOleTools(stub, "img", 0, logger.Nop())
	d, _ := NewDispatch(exif, nil, ole, logger.Nop())
	out, err := d.Extract(context.Background(), metadata.ExtractInput{
		Path: "/v/original",
		MIME: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if _, ok := out["oletools"]; !ok {
		t.Errorf("missing oletools key: %v", keys(out))
	}
}

func TestDispatch_ImageOnlyRunsExiftool(t *testing.T) {
	stub := newStubLauncher()
	stub.program("extract", `{"exiftool":{"FileType":"JPEG"}}`, 0, nil)

	exif, _ := NewExifTool(stub, "img", 0, logger.Nop())
	pdf, _ := NewPDFID(stub, "img", 0, logger.Nop())
	ole, _ := NewOleTools(stub, "img", 0, logger.Nop())
	d, _ := NewDispatch(exif, pdf, ole, logger.Nop())
	out, err := d.Extract(context.Background(), metadata.ExtractInput{
		Path: "/v/original",
		MIME: "image/jpeg",
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if _, ok := out["pdfid"]; ok {
		t.Errorf("image-only input should not run pdfid: %v", keys(out))
	}
	if _, ok := out["oletools"]; ok {
		t.Errorf("image-only input should not run oletools: %v", keys(out))
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.calls) != 1 {
		t.Errorf("expected 1 launcher call, got %d", len(stub.calls))
	}
}

func TestDispatch_AugmentedToolFailureDoesNotKillRun(t *testing.T) {
	stub := newStubLauncher()
	stub.program("extract", `{"exiftool":{"FileType":"PDF"}}`, 0, nil)
	stub.program("pdfid", `{"error":"tool_failed","message":"oof"}`, 1, nil)

	exif, _ := NewExifTool(stub, "img", 0, logger.Nop())
	pdf, _ := NewPDFID(stub, "img", 0, logger.Nop())
	d, _ := NewDispatch(exif, pdf, nil, logger.Nop())
	out, err := d.Extract(context.Background(), metadata.ExtractInput{
		Path: "/v/original",
		MIME: "application/pdf",
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	sub, ok := out["pdfid"].(map[string]any)
	if !ok {
		t.Fatalf("pdfid output is not a map: %T", out["pdfid"])
	}
	if sub["error"] != "tool_failed" {
		t.Errorf("pdfid.error = %v, want tool_failed", sub["error"])
	}
}

func TestNewDispatch_NilExifToolRejected(t *testing.T) {
	_, err := NewDispatch(nil, nil, nil, logger.Nop())
	if err == nil {
		t.Fatal("expected error for nil exiftool")
	}
}

func TestIsOfficeMIME(t *testing.T) {
	cases := map[string]bool{
		"application/pdf":          false,
		"application/msword":       true,
		"application/vnd.ms-excel": true,
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true,
		"application/vnd.oasis.opendocument.text":                                 true,
		"image/jpeg": false,
		"":           false,
	}
	for in, want := range cases {
		if got := isOfficeMIME(in); got != want {
			t.Errorf("isOfficeMIME(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDecodeJSON_StripsLeadingNonJSON(t *testing.T) {
	b := decodeJSON([]byte("garbage\n  {\"a\":1}"))
	if !strings.HasPrefix(string(b), "{\"a\"") {
		t.Errorf("decodeJSON = %q", string(b))
	}
}

// keys returns the sorted set of keys in m, for diagnostic output.
func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
