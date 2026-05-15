// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package stripper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fr4nsys/usulnet/internal/observability"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/metadata"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// sha256Bytes returns the SHA-256 digest of b as a byte slice (not
// the hex form). The wrapper exists so callers can compose with
// hex.EncodeToString and metadata.StripResult.SHA256 without doing
// the array→slice conversion at each call site.
func sha256Bytes(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// ContainerInputDir is the in-container mount target where the input
// file lives (bind-mounted read-only from the host).
const ContainerInputDir = "/work/input"

// ContainerCleanedPath is the in-container path mat2 writes the
// cleaned copy to. The launcher mounts /work/out as a tmpfs and
// copies this file back to the host via ContainerCopyFileStream.
const ContainerCleanedPath = "/work/out/cleaned"

// DefaultStripTimeout caps a single mat2 invocation. mat2 is fast on
// normal files; the cap exists to surface pathological inputs
// quickly.
const DefaultStripTimeout = 60 * time.Second

// Mat2 is the production metadata.Stripper. It invokes
// `recon-toolkit strip --path /work/input/<file> --mime <mime>`
// inside the toolkit container, then pulls the cleaned bytes back
// out via the launcher's RunOnceWithCopy method.
type Mat2 struct {
	launcher recon.ContainerLauncher
	image    string
	timeout  time.Duration
	log      *logger.Logger
}

// Compile-time assertion that *Mat2 satisfies metadata.Stripper.
var _ metadata.Stripper = (*Mat2)(nil)

// NewMat2 constructs a mat2-backed stripper. launcher must be
// non-nil; image is the fully-qualified toolkit image reference. A
// zero timeout falls back to DefaultStripTimeout.
func NewMat2(launcher recon.ContainerLauncher, image string, timeout time.Duration, log *logger.Logger) (*Mat2, error) {
	if launcher == nil {
		return nil, errors.New("stripper: nil launcher")
	}
	if image == "" {
		return nil, errors.New("stripper: empty image")
	}
	if timeout <= 0 {
		timeout = DefaultStripTimeout
	}
	if log == nil {
		log = logger.Nop()
	}
	return &Mat2{
		launcher: launcher,
		image:    image,
		timeout:  timeout,
		log:      log.Named("metadata.stripper.mat2"),
	}, nil
}

// stripJSON is the schema entrypoint.sh's `strip` subcommand emits
// on stdout: sha256 + size + the path of the cleaned file inside the
// container.
type stripJSON struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Path   string `json:"path"`
	// Error fields surfaced when the entrypoint's err() helper fires.
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Strip runs mat2 against the input file and writes the cleaned
// bytes next to the original at <dir>/stripped. The returned
// StripResult carries the sha256 of the cleaned bytes (matching the
// hash the entrypoint computed in-container as a cross-check) plus
// the on-disk path.
func (m *Mat2) Strip(ctx context.Context, input metadata.StripInput) (metadata.StripResult, error) {
	ctx, span := observability.StartSpan(ctx, "metadata.stripper.mat2.Strip")
	defer span.End()

	hostDir := filepath.Dir(input.Path)
	if hostDir == "" {
		return metadata.StripResult{}, errors.New("stripper: empty host path")
	}

	containerPath := filepath.Join(ContainerInputDir, filepath.Base(input.Path))
	spec := recon.ContainerSpec{
		Image:   m.image,
		Command: []string{"strip", "--path", containerPath, "--mime", input.MIME},
		Mounts: []recon.ContainerMount{
			{Source: hostDir, Target: ContainerInputDir, ReadOnly: true},
		},
		NoNetwork: true,
		Timeout:   m.timeout,
		Labels:    map[string]string{"usulnet.recon.role": "metadata-strip"},
	}

	output, cleaned, code, err := m.launcher.RunOnceWithCopy(ctx, spec, ContainerCleanedPath)
	if err != nil {
		return metadata.StripResult{}, fmt.Errorf("stripper: run toolkit: %w", err)
	}
	if code != 0 {
		// The entrypoint emits structured JSON on failure; surface it
		// so the caller can show a useful error rather than the raw
		// exit code.
		report := parseStripReport(output)
		if report.Error != "" {
			return metadata.StripResult{}, fmt.Errorf("stripper: mat2 %s: %s", report.Error, report.Message)
		}
		return metadata.StripResult{}, fmt.Errorf("stripper: mat2 exited %d", code)
	}

	report := parseStripReport(output)
	if report.Error != "" {
		return metadata.StripResult{}, fmt.Errorf("stripper: mat2 %s: %s", report.Error, report.Message)
	}
	if len(cleaned) == 0 {
		return metadata.StripResult{}, errors.New("stripper: empty cleaned payload from container")
	}

	// Cross-check the in-container sha256 against the bytes we copied
	// back. A mismatch would suggest the tmpfs got reused or the
	// container produced an artifact at a different path; fail loudly
	// rather than write a stale copy.
	if report.SHA256 != "" {
		gotSum := hex.EncodeToString(sha256Bytes(cleaned))
		if gotSum != report.SHA256 {
			return metadata.StripResult{}, fmt.Errorf("stripper: sha256 mismatch: container reported %s, host computed %s", report.SHA256, gotSum)
		}
	}

	dst := filepath.Join(hostDir, strippedFilename)
	if err := os.WriteFile(dst, cleaned, 0o600); err != nil {
		return metadata.StripResult{}, fmt.Errorf("stripper: write cleaned: %w", err)
	}

	sum := sha256Bytes(cleaned)
	return metadata.StripResult{
		CleanedPath: dst,
		SHA256:      sum,
		SizeBytes:   int64(len(cleaned)),
	}, nil
}

// parseStripReport decodes the JSON line entrypoint.sh prints. Any
// garbage before the JSON (header bytes from log drivers, the like)
// is skipped.
func parseStripReport(output []byte) stripJSON {
	// Find the first '{' so log-mux prefixes don't trip Unmarshal.
	start := -1
	for i, c := range output {
		if c == '{' {
			start = i
			break
		}
	}
	if start < 0 {
		return stripJSON{}
	}
	var r stripJSON
	if err := json.Unmarshal(output[start:], &r); err != nil {
		// Multi-line: try just the last line that begins with '{'.
		last := lastJSONLine(output[start:])
		if last == nil {
			return stripJSON{}
		}
		_ = json.Unmarshal(last, &r)
	}
	return r
}

// lastJSONLine walks back from the end of b to find a line that
// starts with '{', so callers reading a stream that includes
// progress prints can still decode the final JSON record.
func lastJSONLine(b []byte) []byte {
	start := 0
	for i, c := range b {
		if c == '\n' && i+1 < len(b) && b[i+1] == '{' {
			start = i + 1
		}
	}
	if start == 0 && len(b) > 0 && b[0] == '{' {
		return b
	}
	if start == 0 {
		return nil
	}
	end := len(b)
	for i := start; i < len(b); i++ {
		if b[i] == '\n' {
			end = i
			break
		}
	}
	return b[start:end]
}
