// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package stripper provides metadata.Stripper implementations. The
// production stripper (mat2 inside the recon-toolkit container) lands
// in Session 07; this stub is used by service-layer and worker tests
// until then.
package stripper

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/fr4nsys/usulnet/internal/services/metadata"
)

// strippedFilename is the on-disk name written next to the original
// upload. Keeping it in sync with artifactstore.LocalStore's internal
// "stripped" sibling convention lets future code share the same path.
const strippedFilename = "stripped"

// Stub is a deterministic Stripper for tests. It copies the original
// file to a sibling "stripped" path with no transformation, and
// returns the sha256 of the copy. Tests that want a different "clean"
// payload can supply OverrideContent.
type Stub struct {
	// OverrideContent, when non-nil, replaces the bytes written to the
	// stripped sibling. The sha256 is computed against this override.
	OverrideContent []byte

	// Err, if non-nil, is returned from every Strip call.
	Err error
}

// Strip writes a sibling "stripped" file next to input.Path and
// returns its metadata.StripResult. The result's CleanedPath is the
// absolute on-disk path; callers persist it as the Artifact's
// stripped_sha256 + storage_ref-derived path.
func (s *Stub) Strip(_ context.Context, input metadata.StripInput) (metadata.StripResult, error) {
	if s.Err != nil {
		return metadata.StripResult{}, s.Err
	}

	dir := filepath.Dir(input.Path)
	cleaned := filepath.Join(dir, strippedFilename)

	if s.OverrideContent != nil {
		if err := os.WriteFile(cleaned, s.OverrideContent, 0o600); err != nil {
			return metadata.StripResult{}, fmt.Errorf("stripper: write override: %w", err)
		}
		sum := sha256.Sum256(s.OverrideContent)
		return metadata.StripResult{
			CleanedPath: cleaned,
			SHA256:      sum[:],
			SizeBytes:   int64(len(s.OverrideContent)),
		}, nil
	}

	src, err := os.Open(input.Path)
	if err != nil {
		return metadata.StripResult{}, fmt.Errorf("stripper: open original: %w", err)
	}
	defer src.Close() //nolint:errcheck

	dst, err := os.OpenFile(cleaned, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return metadata.StripResult{}, fmt.Errorf("stripper: create stripped: %w", err)
	}

	hasher := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(dst, hasher), src)
	closeErr := dst.Close()
	if copyErr != nil {
		return metadata.StripResult{}, fmt.Errorf("stripper: copy: %w", copyErr)
	}
	if closeErr != nil {
		return metadata.StripResult{}, fmt.Errorf("stripper: close: %w", closeErr)
	}
	sum := hasher.Sum(nil)
	return metadata.StripResult{
		CleanedPath: cleaned,
		SHA256:      sum,
		SizeBytes:   n,
	}, nil
}

// ErrCannotStripMIME is returned by future real strippers when mat2
// cannot process the given MIME type. The stub never returns it.
var ErrCannotStripMIME = errors.New("stripper: cannot strip this MIME type")

// Compile-time assertion that *Stub satisfies metadata.Stripper.
var _ metadata.Stripper = (*Stub)(nil)
