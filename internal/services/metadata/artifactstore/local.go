// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package artifactstore provides ArtifactStore implementations for the
// metadata module. The local store writes uploaded artifacts to a
// disk-backed directory under USULNET_DATA_DIR; an S3-backed store is
// planned for a later release.
package artifactstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fr4nsys/usulnet/internal/services/metadata"
)

// originalFilename is the on-disk name used for the unmodified upload
// inside <root>/<storageRef>/. Keeping it constant lets the Stripper
// write a sibling "stripped" file without coordinating filenames.
const originalFilename = "original"

// LocalStore is an ArtifactStore backed by a directory on the local
// filesystem. The directory layout is:
//
//	<root>/<storageRef>/original    — the user's bytes, untouched
//	<root>/<storageRef>/stripped    — optional, written by the Stripper
//
// storageRef is supplied by the caller; the Service is responsible for
// constructing a value (typically "<job_id>/<artifact_id>") that
// guarantees per-artifact isolation. The store treats storageRef as an
// opaque path fragment but refuses any value that would resolve outside
// of root.
type LocalStore struct {
	root string
}

// NewLocalStore constructs a LocalStore rooted at root. The directory
// is created (mode 0o700) if it does not already exist. The store
// is safe for concurrent use; per-artifact writes operate on
// non-overlapping paths.
func NewLocalStore(root string) (*LocalStore, error) {
	if root == "" {
		return nil, fmt.Errorf("artifactstore: empty root")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("artifactstore: absolute root: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("artifactstore: create root: %w", err)
	}
	return &LocalStore{root: abs}, nil
}

// Root returns the absolute path the store writes into. Exposed for
// tests and so callers (Stripper implementations) can compute sibling
// paths without re-resolving.
func (s *LocalStore) Root() string { return s.root }

// Resolve returns the absolute path for storageRef, after checking it
// stays under the store's root. It is exposed so the Service and the
// Stripper can locate the original file or write a sibling stripped
// file without duplicating the path-escape check.
func (s *LocalStore) Resolve(storageRef string) (string, error) {
	return s.safeJoin(storageRef)
}

// Put writes r into <root>/<storageRef>/original, returning the
// canonical storageRef (as passed in) and the sha256 of the bytes
// written. The caller is responsible for passing a non-empty,
// directory-style storageRef.
func (s *LocalStore) Put(_ context.Context, storageRef string, r io.Reader, size int64) (string, []byte, error) {
	dir, err := s.safeJoin(storageRef)
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, fmt.Errorf("artifactstore: mkdir: %w", err)
	}

	full := filepath.Join(dir, originalFilename)
	f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", nil, fmt.Errorf("artifactstore: open: %w", err)
	}

	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(f, hasher), io.LimitReader(r, size+1))
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("artifactstore: write: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("artifactstore: close: %w", closeErr)
	}
	if written > size {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("artifactstore: write exceeded declared size %d", size)
	}
	return storageRef, hashSum(hasher), nil
}

// Open returns a ReadCloser over the original bytes at storageRef. The
// caller is responsible for closing it. A missing artifact returns
// metadata.ErrArtifactNotFound so handlers can map it to 404 without
// inspecting the underlying os error.
func (s *LocalStore) Open(_ context.Context, storageRef string) (io.ReadCloser, error) {
	dir, err := s.safeJoin(storageRef)
	if err != nil {
		return nil, err
	}
	full := filepath.Join(dir, originalFilename)
	f, err := os.Open(full)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, metadata.ErrArtifactNotFound
		}
		return nil, fmt.Errorf("artifactstore: open: %w", err)
	}
	return f, nil
}

// Delete removes the directory at storageRef and every file underneath.
// It is idempotent: deleting a missing artifact is not an error.
func (s *LocalStore) Delete(_ context.Context, storageRef string) error {
	dir, err := s.safeJoin(storageRef)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("artifactstore: remove: %w", err)
	}
	return nil
}

// safeJoin resolves storageRef under the store's root and refuses any
// value that escapes it (via .., absolute paths, symlink-style tricks
// in the textual form, etc.). It does not follow symlinks; if the path
// later becomes a symlink, the higher layers must validate that
// separately.
func (s *LocalStore) safeJoin(storageRef string) (string, error) {
	if storageRef == "" {
		return "", metadata.ErrPathEscape
	}
	cleaned := filepath.Clean(storageRef)
	if filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "..") {
		return "", metadata.ErrPathEscape
	}
	joined := filepath.Join(s.root, cleaned)
	// filepath.Join already calls Clean; double-check the result is
	// still rooted at s.root. We compare with a trailing separator on
	// the root so that "/foo" vs "/foobar" are distinct.
	rootWithSep := s.root + string(filepath.Separator)
	if joined != s.root && !strings.HasPrefix(joined, rootWithSep) {
		return "", metadata.ErrPathEscape
	}
	return joined, nil
}

func hashSum(h hash.Hash) []byte {
	out := make([]byte, h.Size())
	return h.Sum(out[:0])
}

// Compile-time assertion that *LocalStore satisfies metadata.ArtifactStore.
var _ metadata.ArtifactStore = (*LocalStore)(nil)
