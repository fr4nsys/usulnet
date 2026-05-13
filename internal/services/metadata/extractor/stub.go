// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package extractor provides metadata.Extractor implementations. The
// production extractor (exiftool / pdfid / oletools inside the recon
// toolkit container) lands in Session 07; this stub is used by
// service-layer and worker tests until then.
package extractor

import (
	"context"
	"errors"

	"github.com/fr4nsys/usulnet/internal/services/metadata"
)

// Stub is a deterministic Extractor for tests. Each invocation returns
// a fresh map so callers cannot accidentally mutate shared state.
//
// The zero value is usable; the default behaviour is to return a
// minimal map describing the input.
type Stub struct {
	// Fixed is the map to return verbatim from Extract. If nil, Stub
	// synthesizes a map from the ExtractInput.
	Fixed map[string]any

	// Err, if non-nil, is returned from every Extract call.
	Err error
}

// Extract returns the configured fixed map (deep-copied so callers
// cannot mutate stub state) or, if no fixed map is set, a synthetic
// one keyed off the ExtractInput.
func (s *Stub) Extract(_ context.Context, input metadata.ExtractInput) (map[string]any, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	if s.Fixed != nil {
		return cloneMap(s.Fixed), nil
	}
	return map[string]any{
		"Filename": input.Filename,
		"MIME":     input.MIME,
		"Path":     input.Path,
		"Stub":     true,
	}, nil
}

// cloneMap returns a shallow copy of m so the caller cannot mutate the
// original. Nested values are not copied — tests should treat extracted
// metadata as read-only.
func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ErrUnsupportedMIME is returned by future real extractors when the
// MIME type is outside the supported set. The stub never returns it;
// it is exported so callers can switch on it without importing two
// packages.
var ErrUnsupportedMIME = errors.New("extractor: unsupported MIME type")

// Compile-time assertion that *Stub satisfies metadata.Extractor.
var _ metadata.Extractor = (*Stub)(nil)
