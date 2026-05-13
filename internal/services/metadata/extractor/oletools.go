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

// OleTools runs the toolkit container's `oletools` subcommand
// (olemeta inside the entrypoint shim) and returns the parsed JSON
// object. It is only useful for OLE / Office Open XML inputs; the
// MIME-router in dispatch.go decides when to route here.
type OleTools struct {
	launcher recon.ContainerLauncher
	image    string
	timeout  time.Duration
	log      *logger.Logger
}

// Compile-time assertion that *OleTools satisfies metadata.Extractor.
var _ metadata.Extractor = (*OleTools)(nil)

// NewOleTools constructs an oletools-backed extractor.
func NewOleTools(launcher recon.ContainerLauncher, image string, timeout time.Duration, log *logger.Logger) (*OleTools, error) {
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
	return &OleTools{
		launcher: launcher,
		image:    image,
		timeout:  timeout,
		log:      log.Named("metadata.extractor.oletools"),
	}, nil
}

// Extract invokes the `oletools` subcommand against the input file.
func (o *OleTools) Extract(ctx context.Context, input metadata.ExtractInput) (map[string]any, error) {
	ctx, span := observability.StartSpan(ctx, "metadata.extractor.oletools.Extract")
	defer span.End()

	cmd := []string{"oletools", "--path", inContainerPath(input.Path)}
	return runToolkit(ctx, o.launcher, o.image, input.Path, cmd, o.timeout, o.log)
}
