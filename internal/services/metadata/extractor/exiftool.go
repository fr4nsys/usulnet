// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package extractor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/fr4nsys/usulnet/internal/observability"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/metadata"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// ContainerInputDir is the in-container mount target where each
// extractor expects the input file to live. The host directory
// containing the artifact is bind-mounted read-only here.
const ContainerInputDir = "/work/input"

// DefaultExtractTimeout is the wall-clock cap applied to a single
// toolkit container invocation when ExtractInput-level config does
// not override it. exiftool / pdfid / oletools are well-behaved on
// small uploads; the cap exists to bound mat2 corner cases.
const DefaultExtractTimeout = 30 * time.Second

// ExifTool runs the toolkit container's `extract` subcommand (which
// wraps exiftool -json -groupNames inside the entrypoint shim) and
// returns the parsed JSON object.
type ExifTool struct {
	launcher recon.ContainerLauncher
	image    string
	timeout  time.Duration
	log      *logger.Logger
}

// Compile-time assertion that *ExifTool satisfies metadata.Extractor.
var _ metadata.Extractor = (*ExifTool)(nil)

// NewExifTool constructs an exiftool-backed extractor. launcher must
// be non-nil; image is the fully-qualified toolkit image reference
// (callers usually pass recon.ToolkitImage()). A zero timeout falls
// back to DefaultExtractTimeout.
func NewExifTool(launcher recon.ContainerLauncher, image string, timeout time.Duration, log *logger.Logger) (*ExifTool, error) {
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
	return &ExifTool{
		launcher: launcher,
		image:    image,
		timeout:  timeout,
		log:      log.Named("metadata.extractor.exiftool"),
	}, nil
}

// Extract invokes `recon-toolkit extract --path <in-container path>
// --mime <mime>` and parses the resulting JSON object.
func (e *ExifTool) Extract(ctx context.Context, input metadata.ExtractInput) (map[string]any, error) {
	ctx, span := observability.StartSpan(ctx, "metadata.extractor.exiftool.Extract")
	defer span.End()

	cmd := []string{"extract", "--path", inContainerPath(input.Path), "--mime", input.MIME}
	return runToolkit(ctx, e.launcher, e.image, input.Path, cmd, e.timeout, e.log)
}

// runToolkit is the shared body of every extractor: build a spec that
// bind-mounts the host file's parent at ContainerInputDir, invoke
// RunOnce, parse stdout as JSON, and surface any error/code as a
// typed error.
func runToolkit(
	ctx context.Context,
	launcher recon.ContainerLauncher,
	image string,
	hostPath string,
	cmd []string,
	timeout time.Duration,
	log *logger.Logger,
) (map[string]any, error) {
	hostDir := filepath.Dir(hostPath)
	if hostDir == "" {
		return nil, errors.New("extractor: empty host path")
	}

	spec := recon.ContainerSpec{
		Image:   image,
		Command: cmd,
		Mounts: []recon.ContainerMount{
			{Source: hostDir, Target: ContainerInputDir, ReadOnly: true},
		},
		NoNetwork: true,
		Timeout:   timeout,
		Labels:    map[string]string{"usulnet.recon.role": "metadata-extract"},
	}

	output, code, err := launcher.RunOnce(ctx, spec)
	if err != nil {
		log.Warn("extractor: container failed", "cmd", cmd[0], "error", err)
		return nil, fmt.Errorf("extractor: run toolkit: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("extractor: %s exited %d: %s", cmd[0], code, truncate(output, 256))
	}

	out := map[string]any{}
	if err := json.Unmarshal(decodeJSON(output), &out); err != nil {
		return nil, fmt.Errorf("extractor: parse %s output: %w", cmd[0], err)
	}
	// Surface the entrypoint's structured-error contract as a typed Go
	// error rather than letting the caller receive a map with a single
	// "error" key.
	if code, ok := out["error"].(string); ok && code != "" {
		message, _ := out["message"].(string)
		return nil, fmt.Errorf("extractor: %s: %s: %s", cmd[0], code, message)
	}
	return out, nil
}

// inContainerPath maps a host artifact path (typically
// .../<job>/<artifact>/original) to the in-container path the
// toolkit entrypoint expects. The launcher bind-mounts the host file's
// parent directory at ContainerInputDir, so the path inside the
// container is ContainerInputDir + base.
func inContainerPath(hostPath string) string {
	return filepath.Join(ContainerInputDir, filepath.Base(hostPath))
}

// truncate caps a byte slice for inclusion in error messages so a
// runaway tool output cannot blow up logs.
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// decodeJSON strips any control bytes that some Docker log streams
// prepend (the 8-byte multiplexed header) before passing the rest to
// json.Unmarshal. The capture path in the launcher already strips
// these in the common case; this is belt-and-braces for log drivers
// that leave them in.
func decodeJSON(b []byte) []byte {
	// JSON starts with either '{' or '[' (or whitespace). Find the
	// first such byte and return the slice from there.
	for i, c := range b {
		switch c {
		case '{', '[':
			return b[i:]
		case ' ', '\t', '\n', '\r':
			continue
		}
	}
	return b
}
