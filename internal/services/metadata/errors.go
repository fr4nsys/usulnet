// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package metadata

import "errors"

// Sentinel errors returned by the Service and the local ArtifactStore.
// API handlers translate them into the structured codes documented in
// docs/v26.5/technical-notes.md ("Error response shape").
var (
	// ErrJobNotFound is returned when the supplied job id does not match
	// any persisted row.
	ErrJobNotFound = errors.New("metadata job not found")

	// ErrArtifactNotFound is returned when the supplied artifact id does
	// not match any persisted row.
	ErrArtifactNotFound = errors.New("metadata artifact not found")

	// ErrInvalidFilename is returned by CreateJob when an uploaded
	// filename fails canonicalization (contains a path separator, is
	// empty, equals "." or "..", or differs from filepath.Clean(name)).
	ErrInvalidFilename = errors.New("invalid filename")

	// ErrArtifactTooLarge is returned by CreateJob when the declared
	// size or the bytes actually read from the upload exceed
	// Config.MaxFileBytes.
	ErrArtifactTooLarge = errors.New("artifact too large")

	// ErrUnsupportedMode is returned when Job.Mode is not one of
	// metadata.ModeExtract / ModeStrip / ModeBoth.
	ErrUnsupportedMode = errors.New("unsupported job mode")

	// ErrStripNotReady is returned by OpenStripped when the artifact
	// row has no stripped_sha256 yet (the strip operation has not run
	// or has not produced a clean copy).
	ErrStripNotReady = errors.New("stripped copy not ready")

	// ErrPathEscape is returned by the local ArtifactStore when the
	// computed on-disk path would escape the store's root. It is a
	// defense in depth against operator mistakes — the Service should
	// have already rejected unsafe filenames via ErrInvalidFilename.
	ErrPathEscape = errors.New("path escapes artifact store root")

	// ErrInvalidScanState is returned when RunJob is invoked on a job
	// that is not in the queued state.
	ErrInvalidJobState = errors.New("invalid job state")

	// ErrNoFiles is returned by CreateJob for upload-mode requests with
	// an empty file list.
	ErrNoFiles = errors.New("no files supplied")
)
