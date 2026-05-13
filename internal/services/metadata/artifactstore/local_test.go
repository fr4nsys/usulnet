// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package artifactstore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fr4nsys/usulnet/internal/services/metadata"
	"github.com/fr4nsys/usulnet/internal/services/metadata/artifactstore"
)

func newStore(t *testing.T) *artifactstore.LocalStore {
	t.Helper()
	root := t.TempDir()
	s, err := artifactstore.NewLocalStore(root)
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	return s
}

func TestLocalStore_PutOpenRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	payload := []byte("the quick brown fox jumps over the lazy dog\n")
	want := sha256.Sum256(payload)

	ref, sum, err := s.Put(ctx, "job-x/artifact-y", bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if ref != "job-x/artifact-y" {
		t.Errorf("ref = %q, want job-x/artifact-y", ref)
	}
	if !bytes.Equal(sum, want[:]) {
		t.Errorf("sha256 mismatch: got %x, want %x", sum, want[:])
	}

	rc, err := s.Open(ctx, ref)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close() //nolint:errcheck
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch")
	}
}

// TestLocalStore_PutMatchesKnownSHA256 pins the SHA-256 against a
// known fixture (the SHA-256 of the empty string).
func TestLocalStore_PutMatchesKnownSHA256(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	_, sum, err := s.Put(ctx, "j/a", bytes.NewReader(nil), 0)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	const emptySha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := hex.EncodeToString(sum); got != emptySha {
		t.Errorf("empty sha = %s, want %s", got, emptySha)
	}
}

func TestLocalStore_PathTraversalRejected(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	cases := []string{
		"../outside",
		"job/../../etc",
		"/absolute/path",
		"",
		"..",
	}
	for _, c := range cases {
		_, _, err := s.Put(ctx, c, bytes.NewReader([]byte("x")), 1)
		if !errors.Is(err, metadata.ErrPathEscape) {
			t.Errorf("Put(%q): err = %v, want ErrPathEscape", c, err)
		}
	}
}

func TestLocalStore_OpenMissingReturnsTypedError(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	_, err := s.Open(ctx, "nope/missing")
	if !errors.Is(err, metadata.ErrArtifactNotFound) {
		t.Errorf("err = %v, want ErrArtifactNotFound", err)
	}
}

func TestLocalStore_DeleteRemovesDirectory(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	ref, _, err := s.Put(ctx, "del/me", bytes.NewReader([]byte("bye")), 3)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	if err := s.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := s.Open(ctx, ref); !errors.Is(err, metadata.ErrArtifactNotFound) {
		t.Errorf("after delete: err = %v, want ErrArtifactNotFound", err)
	}

	// Deleting a missing artifact is a no-op.
	if err := s.Delete(ctx, ref); err != nil {
		t.Errorf("Delete (second): %v", err)
	}
}

// TestLocalStore_PutRejectsOversize asserts the store's own
// last-resort size check fires when the reader produces more than the
// declared size. (The Service has its own pre-check via the
// CreateJob input.)
func TestLocalStore_PutRejectsOversize(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Declared size is 4 but the reader has 10 bytes.
	_, _, err := s.Put(ctx, "j/a", strings.NewReader("0123456789"), 4)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "exceeded declared size") {
		t.Errorf("err = %v, want 'exceeded declared size'", err)
	}
}

func TestLocalStore_ResolveStaysInRoot(t *testing.T) {
	s := newStore(t)
	got, err := s.Resolve("a/b")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.HasPrefix(got, s.Root()+string(filepath.Separator)) {
		t.Errorf("Resolve returned %q, not under %q", got, s.Root())
	}

	if _, err := s.Resolve("../up"); !errors.Is(err, metadata.ErrPathEscape) {
		t.Errorf("Resolve(../up) err = %v, want ErrPathEscape", err)
	}
}

// TestLocalStore_PutWritesToDisk asserts the file lands at the exact
// path documented in the package comment.
func TestLocalStore_PutWritesToDisk(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	_, _, err := s.Put(ctx, "JJ/AA", bytes.NewReader([]byte("hi")), 2)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	expected := filepath.Join(s.Root(), "JJ", "AA", "original")
	if _, err := os.Stat(expected); err != nil {
		t.Errorf("expected file at %q: %v", expected, err)
	}
}
