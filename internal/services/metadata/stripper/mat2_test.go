// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package stripper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/metadata"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// stubLauncher implements recon.ContainerLauncher for the stripper
// tests. It echoes a programmed (stdout, copied, code) tuple for
// every RunOnceWithCopy call.
type stubLauncher struct {
	mu       sync.Mutex
	stdout   []byte
	copied   []byte
	code     int
	err      error
	specs    []recon.ContainerSpec
	copyPath string
}

func (s *stubLauncher) EnsureRunning(_ context.Context, _ recon.ContainerSpec) (string, error) {
	return "", errors.New("EnsureRunning not implemented")
}

func (s *stubLauncher) RunOnce(_ context.Context, _ recon.ContainerSpec) ([]byte, int, error) {
	return nil, 0, errors.New("RunOnce not implemented in stripper stub")
}

func (s *stubLauncher) RunOnceWithCopy(_ context.Context, spec recon.ContainerSpec, copyPath string) ([]byte, []byte, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.specs = append(s.specs, spec)
	s.copyPath = copyPath
	return s.stdout, s.copied, s.code, s.err
}

func (s *stubLauncher) Stop(_ context.Context, _ string) error { return nil }

// ---------------------------------------------------------------------------

func TestMat2_HappyPath(t *testing.T) {
	cleaned := []byte("scrubbed JPEG bytes")
	sum := sha256.Sum256(cleaned)
	hexSum := hex.EncodeToString(sum[:])

	stub := &stubLauncher{
		stdout: []byte(`{"sha256":"` + hexSum + `","size":` + itoa(len(cleaned)) + `,"path":"/work/out/cleaned"}`),
		copied: cleaned,
		code:   0,
	}

	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	if err := os.WriteFile(original, []byte("payload with metadata"), 0o600); err != nil {
		t.Fatalf("write original: %v", err)
	}

	m, err := NewMat2(stub, "img", 0, logger.Nop())
	if err != nil {
		t.Fatalf("NewMat2: %v", err)
	}
	res, err := m.Strip(context.Background(), metadata.StripInput{
		Path:     original,
		Filename: "x.jpg",
		MIME:     "image/jpeg",
	})
	if err != nil {
		t.Fatalf("Strip: %v", err)
	}
	if res.SizeBytes != int64(len(cleaned)) {
		t.Errorf("size = %d, want %d", res.SizeBytes, len(cleaned))
	}
	if hex.EncodeToString(res.SHA256) != hexSum {
		t.Errorf("sha256 = %x, want %s", res.SHA256, hexSum)
	}
	if filepath.Base(res.CleanedPath) != strippedFilename {
		t.Errorf("cleaned filename = %q, want %q", filepath.Base(res.CleanedPath), strippedFilename)
	}
	gotBytes, err := os.ReadFile(res.CleanedPath)
	if err != nil {
		t.Fatalf("read cleaned: %v", err)
	}
	if string(gotBytes) != string(cleaned) {
		t.Errorf("cleaned file content mismatch")
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.specs) != 1 {
		t.Fatalf("expected 1 launcher call, got %d", len(stub.specs))
	}
	spec := stub.specs[0]
	if !spec.NoNetwork {
		t.Error("stripper must run with NoNetwork=true")
	}
	if stub.copyPath != ContainerCleanedPath {
		t.Errorf("copyPath = %q, want %q", stub.copyPath, ContainerCleanedPath)
	}
	if len(spec.Mounts) != 1 || spec.Mounts[0].Target != ContainerInputDir {
		t.Errorf("mount = %v", spec.Mounts)
	}
}

func TestMat2_NonZeroExitSurfacesEnvelope(t *testing.T) {
	stub := &stubLauncher{
		stdout: []byte(`{"error":"strip_failed","message":"mat2 could not process image/svg+xml"}`),
		code:   2,
	}

	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	_ = os.WriteFile(original, []byte("svg"), 0o600)

	m, _ := NewMat2(stub, "img", 0, logger.Nop())
	_, err := m.Strip(context.Background(), metadata.StripInput{
		Path:     original,
		Filename: "x.svg",
		MIME:     "image/svg+xml",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMat2_SHA256MismatchFails(t *testing.T) {
	stub := &stubLauncher{
		// reported sha doesn't match the bytes we copied
		stdout: []byte(`{"sha256":"deadbeef","size":4,"path":"/work/out/cleaned"}`),
		copied: []byte("real"),
		code:   0,
	}
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	_ = os.WriteFile(original, []byte("p"), 0o600)

	m, _ := NewMat2(stub, "img", 0, logger.Nop())
	_, err := m.Strip(context.Background(), metadata.StripInput{
		Path: original,
		MIME: "image/jpeg",
	})
	if err == nil {
		t.Fatal("expected sha256 mismatch error")
	}
}

func TestMat2_EmptyCleanedFails(t *testing.T) {
	stub := &stubLauncher{
		stdout: []byte(`{"sha256":"x","size":0,"path":"/work/out/cleaned"}`),
		copied: nil,
		code:   0,
	}
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	_ = os.WriteFile(original, []byte("p"), 0o600)

	m, _ := NewMat2(stub, "img", 0, logger.Nop())
	_, err := m.Strip(context.Background(), metadata.StripInput{Path: original, MIME: "image/jpeg"})
	if err == nil {
		t.Fatal("expected empty-copy error")
	}
}

func TestMat2_NilLauncherRejected(t *testing.T) {
	_, err := NewMat2(nil, "img", 0, logger.Nop())
	if err == nil {
		t.Fatal("expected error for nil launcher")
	}
}

func TestMat2_EmptyImageRejected(t *testing.T) {
	_, err := NewMat2(&stubLauncher{}, "", 0, logger.Nop())
	if err == nil {
		t.Fatal("expected error for empty image")
	}
}

func TestParseStripReport_ToleratesLeadingGarbage(t *testing.T) {
	raw := []byte("INFO some log line\n{\"sha256\":\"abc\",\"size\":3,\"path\":\"/work/out/cleaned\"}\n")
	r := parseStripReport(raw)
	if r.SHA256 != "abc" {
		t.Errorf("sha256 = %q, want abc", r.SHA256)
	}
	if r.Size != 3 {
		t.Errorf("size = %d, want 3", r.Size)
	}
}

func itoa(n int) string {
	// avoid pulling strconv into a tiny helper
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
