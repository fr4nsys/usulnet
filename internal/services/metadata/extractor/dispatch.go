// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package extractor

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/fr4nsys/usulnet/internal/observability"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/metadata"
)

// Dispatch is the production metadata.Extractor used by the service.
// It owns one exiftool extractor (run for every input) plus the
// MIME-specific extractors (pdfid for PDFs, oletools for Office
// documents). Each per-extractor output is keyed under that
// extractor's name in the returned map; downstream callers can
// inspect specific tools' output without coupling to the dispatch
// table.
type Dispatch struct {
	exiftool *ExifTool
	pdfid    *PDFID
	oletools *OleTools
	log      *logger.Logger
}

// Compile-time assertion that *Dispatch satisfies metadata.Extractor.
var _ metadata.Extractor = (*Dispatch)(nil)

// NewDispatch constructs a Dispatch from three already-constructed
// per-tool extractors. exiftool must be non-nil because it runs for
// every input; pdfid and oletools may be nil (the corresponding MIME
// classes simply skip the augmented extractor in that case).
func NewDispatch(exiftool *ExifTool, pdfid *PDFID, oletools *OleTools, log *logger.Logger) (*Dispatch, error) {
	if exiftool == nil {
		return nil, errors.New("extractor dispatch: nil exiftool")
	}
	if log == nil {
		log = logger.Nop()
	}
	return &Dispatch{
		exiftool: exiftool,
		pdfid:    pdfid,
		oletools: oletools,
		log:      log.Named("metadata.extractor.dispatch"),
	}, nil
}

// Extract runs every extractor that the input's MIME type maps to and
// merges the results into a single map keyed by extractor name.
//
// exiftool is the universal extractor: it runs for every MIME. PDFs
// and Office documents pick up the augmented analysis tools on top.
// If a per-tool extractor fails, its key is set to a structured
// error stub so the operator sees the failure without losing the
// other tools' output.
func (d *Dispatch) Extract(ctx context.Context, input metadata.ExtractInput) (map[string]any, error) {
	ctx, span := observability.StartSpan(ctx, "metadata.extractor.dispatch.Extract")
	defer span.End()

	out := make(map[string]any, 3)

	exifResult, err := d.exiftool.Extract(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("extractor dispatch: exiftool: %w", err)
	}
	out["exiftool"] = exifResult

	for _, tool := range d.toolsForMIME(input.MIME) {
		res, err := tool.extractor.Extract(ctx, input)
		if err != nil {
			d.log.Warn("extractor: augmented tool failed",
				"tool", tool.name,
				"mime", input.MIME,
				"error", err,
			)
			out[tool.name] = map[string]any{
				"error":   "tool_failed",
				"message": err.Error(),
			}
			continue
		}
		out[tool.name] = res
	}

	return out, nil
}

// toolEntry is one row of the dispatch table: the extractor and the
// key it lands under in the merged output.
type toolEntry struct {
	name      string
	extractor metadata.Extractor
}

// toolsForMIME returns the extra extractors that should run for a
// given MIME type, in dispatch order. exiftool is implicit and never
// listed here. The map is consulted prefix-aware so we treat
// "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
// as Office regardless of subtype.
func (d *Dispatch) toolsForMIME(mime string) []toolEntry {
	mime = strings.ToLower(strings.TrimSpace(mime))
	out := make([]toolEntry, 0, 2)

	switch {
	case mime == "application/pdf":
		if d.pdfid != nil {
			out = append(out, toolEntry{name: "pdfid", extractor: d.pdfid})
		}
	case isOfficeMIME(mime):
		if d.oletools != nil {
			out = append(out, toolEntry{name: "oletools", extractor: d.oletools})
		}
	}
	return out
}

// isOfficeMIME reports whether mime is one of the OLE / Office Open
// XML types that oletools can analyse. The list mirrors the most
// common upload classes; unknown variants fall through to exiftool
// only, which still pulls authorship/timestamps for almost every
// office format.
func isOfficeMIME(mime string) bool {
	if strings.HasPrefix(mime, "application/vnd.openxmlformats-officedocument.") {
		return true
	}
	if strings.HasPrefix(mime, "application/vnd.ms-") {
		return true
	}
	switch mime {
	case "application/msword",
		"application/vnd.ms-excel",
		"application/vnd.ms-powerpoint",
		"application/vnd.oasis.opendocument.text",
		"application/vnd.oasis.opendocument.spreadsheet",
		"application/vnd.oasis.opendocument.presentation":
		return true
	}
	return false
}
