// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package extractor

import (
	"context"
	"errors"
	"time"

	"github.com/fr4nsys/usulnet/internal/observability"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/metadata"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// PDFID runs the toolkit container's `pdfid` subcommand (which wraps
// Didier Stevens' pdfid.py inside the entrypoint shim) and returns
// the parsed JSON object. It is only useful for PDF inputs; the
// MIME-router in dispatch.go decides when to route here.
type PDFID struct {
	launcher recon.ContainerLauncher
	image    string
	timeout  time.Duration
	log      *logger.Logger
}

// Compile-time assertion that *PDFID satisfies metadata.Extractor.
var _ metadata.Extractor = (*PDFID)(nil)

// NewPDFID constructs a pdfid-backed extractor.
func NewPDFID(launcher recon.ContainerLauncher, image string, timeout time.Duration, log *logger.Logger) (*PDFID, error) {
	if launcher == nil {
		return nil, errors.New("extractor: nil launcher")
	}
	if image == "" {
		return nil, errors.New("extractor: empty image")
	}
	if timeout <= 0 {
		timeout = DefaultExtractTimeout
	}
	if log == nil {
		log = logger.Nop()
	}
	return &PDFID{
		launcher: launcher,
		image:    image,
		timeout:  timeout,
		log:      log.Named("metadata.extractor.pdfid"),
	}, nil
}

// Extract invokes the `pdfid` subcommand against the input file.
func (p *PDFID) Extract(ctx context.Context, input metadata.ExtractInput) (map[string]any, error) {
	ctx, span := observability.StartSpan(ctx, "metadata.extractor.pdfid.Extract")
	defer span.End()

	cmd := []string{"pdfid", "--path", inContainerPath(input.Path)}
	return runToolkit(ctx, p.launcher, p.image, input.Path, cmd, p.timeout, p.log)
}
