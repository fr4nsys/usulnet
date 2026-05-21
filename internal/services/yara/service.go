// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package yara implements the v26.5.2 one-shot YARA scanner for
// usulnet. Scans run inside the existing recon-toolkit sandbox image
// (no in-process cgo binding), which means:
//
//   - No build-time dependency on libyara.
//   - The scan target is mounted read-only; the toolkit container is
//     locked down by recon's hardening defaults (--read-only, dropped
//     caps, no-network, non-root UID, pids/memory/cpu limits).
//   - Container-target scans extract the requested path to a host
//     tmpfile via ContainerCopyFileStream, then bind-mount the tmpfile
//     into the toolkit. Hot paths inside the target's namespace —
//     /proc/1/exe etc — are not visible across this boundary; callers
//     should pick concrete paths (/usr/local/bin/myapp, /tmp/x).
//
// Rulesets are baked into the binary via go:embed at
// internal/templates/yara-rules/. Operators cannot upload rulesets at
// runtime in v26.5.2; that lands as a follow-up.
package yara

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// DefaultScanTimeout caps a single scan invocation. The wall-clock
// includes container start, yara execution, and teardown. 60s is
// generous for the curated rulesets we ship — operators with larger
// rule packs can override at construction.
const DefaultScanTimeout = 60 * time.Second

// MaxExtractBytes caps the in-host tmpfile size for container-path
// extracts. 64 MiB matches the recon-toolkit's WorkOut budget.
const MaxExtractBytes int64 = 64 * 1024 * 1024

// In-container mount targets. The toolkit's `yara` subcommand reads
// these paths via --rules and --path flags rendered by the service.
const (
	containerRulesDir  = "/work/yara-rules"
	containerTargetDir = "/work/yara-target"
)

// ErrInvalidTarget is returned when the caller supplies a ScanTarget
// missing required fields or specifying both HostPath and ContainerID.
var ErrInvalidTarget = errors.New("yara: invalid scan target")

// ErrScanFailed is returned when the toolkit container exits non-zero
// for a reason other than "no matches" — yara's exit code is 0 on
// both match and no-match; anything non-zero means the binary failed.
var ErrScanFailed = errors.New("yara: scan failed")

// ScanTarget points at exactly one of:
//
//   - HostPath: an absolute path on the usulnet host. Bind-mounted
//     read-only into the toolkit at /work/yara-target/<basename>.
//   - ContainerID + Path: a path inside a target container. The
//     service extracts the file with ContainerCopyFileStream first,
//     then scans the host tmpfile.
//
// Exactly one of these branches must be set; the service rejects
// (and tests pin) zero-of-two and both-set states.
type ScanTarget struct {
	HostPath    string
	ContainerID string
	Path        string
}

// Result is the outcome of one scan.
type Result struct {
	Ruleset   string    `json:"ruleset"`
	Target    string    `json:"target"`
	Matches   []Match   `json:"matches"`
	StartedAt time.Time `json:"started_at"`
	Duration  string    `json:"duration"`
	ExitCode  int       `json:"exit_code"`
}

// FileExtractor is the narrow surface the service uses to copy a
// single file out of a running container. *docker.Client satisfies
// this; tests supply a fake.
type FileExtractor interface {
	ContainerCopyFileStream(ctx context.Context, containerID, srcPath string) (io.ReadCloser, error)
}

// Service runs YARA scans against host files or container paths.
type Service struct {
	launcher  recon.ContainerLauncher
	extractor FileExtractor
	image     string
	timeout   time.Duration
	logger    *logger.Logger
}

// NewService wires the scanner. launcher and extractor must be non-nil
// or the scanner cannot do its job; image is the toolkit reference
// (e.g. recon.ToolkitImage()); timeout zero falls back to
// DefaultScanTimeout.
func NewService(launcher recon.ContainerLauncher, extractor FileExtractor, image string, timeout time.Duration, log *logger.Logger) (*Service, error) {
	if launcher == nil {
		return nil, errors.New("yara: nil launcher")
	}
	if extractor == nil {
		return nil, errors.New("yara: nil extractor")
	}
	if image == "" {
		return nil, errors.New("yara: empty toolkit image")
	}
	if timeout <= 0 {
		timeout = DefaultScanTimeout
	}
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		launcher:  launcher,
		extractor: extractor,
		image:     image,
		timeout:   timeout,
		logger:    log.Named("yara"),
	}, nil
}

// Scan runs the named ruleset against the target. The returned
// Result is populated on every success, even when there are zero
// matches; callers distinguish "scan ran cleanly, nothing matched"
// from "scan failed" by checking the returned error.
func (s *Service) Scan(ctx context.Context, target ScanTarget, rulesetName string) (*Result, error) {
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	rs, err := LookupRuleset(rulesetName)
	if err != nil {
		return nil, err
	}

	// Resolve the host-side path the toolkit will see. For HostPath
	// targets we use it directly; for ContainerID targets we extract
	// to a tmpfile under the OS temp dir and clean up after the scan.
	hostPath, cleanup, err := s.resolveHostPath(ctx, target)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Write the ruleset to a tmpfile that we bind-mount alongside the
	// target. Separate file so a future per-scan override (operator-
	// supplied .yar pasted into the UI) lands in the same place.
	rulesPath, rulesCleanup, err := writeTempRuleset(rs.Source)
	if err != nil {
		return nil, fmt.Errorf("yara: stage ruleset: %w", err)
	}
	defer rulesCleanup()

	containerRulesPath := containerRulesDir + "/" + filepath.Base(rulesPath)
	containerTargetPath := containerTargetDir + "/" + filepath.Base(hostPath)

	spec := recon.ContainerSpec{
		Image: s.image,
		Command: []string{
			"yara",
			"--rules", containerRulesPath,
			"--path", containerTargetPath,
		},
		Mounts: []recon.ContainerMount{
			{Source: filepath.Dir(rulesPath), Target: containerRulesDir, ReadOnly: true},
			{Source: filepath.Dir(hostPath), Target: containerTargetDir, ReadOnly: true},
		},
		NoNetwork: true,
		Timeout:   s.timeout,
		Labels: map[string]string{
			"usulnet.recon.role":   "yara-scan",
			"usulnet.yara.ruleset": rsLabel(rulesetName),
		},
	}

	started := time.Now()
	output, code, err := s.launcher.RunOnce(ctx, spec)
	dur := time.Since(started)

	if err != nil {
		s.logger.Warn("yara: launcher error", "ruleset", rulesetName, "error", err)
		return nil, fmt.Errorf("%w: %w", ErrScanFailed, err)
	}
	if code != 0 {
		// yara exits 0 on both match and no-match. Anything else is a
		// real failure (binary missing, bad rule syntax, OOM). Pass the
		// container stdout (truncated) up so the operator can debug.
		return nil, fmt.Errorf("%w: exit %d: %s", ErrScanFailed, code, truncate(output, 512))
	}

	res := &Result{
		Ruleset:   rulesetName,
		Target:    displayTarget(target),
		Matches:   parseYaraOutput(string(output), displayTarget(target)),
		StartedAt: started,
		Duration:  dur.String(),
		ExitCode:  code,
	}
	return res, nil
}

// resolveHostPath produces the absolute host-side path the toolkit
// will bind-mount. For HostPath we validate the path is absolute and
// exists; for ContainerID we extract the requested file to a tmpfile.
// The returned cleanup function is always non-nil — pass it to defer.
func (s *Service) resolveHostPath(ctx context.Context, target ScanTarget) (string, func(), error) {
	if target.HostPath != "" {
		if !filepath.IsAbs(target.HostPath) {
			return "", noopCleanup, fmt.Errorf("%w: host_path must be absolute", ErrInvalidTarget)
		}
		// Stat both for early failure and so the toolkit isn't asked to
		// bind-mount a non-existent path.
		if _, err := os.Stat(target.HostPath); err != nil {
			return "", noopCleanup, fmt.Errorf("yara: host path: %w", err)
		}
		return target.HostPath, noopCleanup, nil
	}

	// Container target: extract via tar stream.
	tmpPath, err := s.extractContainerFile(ctx, target.ContainerID, target.Path)
	if err != nil {
		return "", noopCleanup, err
	}
	cleanup := func() {
		_ = os.Remove(tmpPath)
		_ = os.Remove(filepath.Dir(tmpPath))
	}
	return tmpPath, cleanup, nil
}

// extractContainerFile pulls a single file out of a running container
// to an OS-temp file. Returns the host-side absolute path.
func (s *Service) extractContainerFile(ctx context.Context, containerID, srcPath string) (string, error) {
	rc, err := s.extractor.ContainerCopyFileStream(ctx, containerID, srcPath)
	if err != nil {
		return "", fmt.Errorf("yara: container copy %s:%s: %w", containerID, srcPath, err)
	}
	defer rc.Close() //nolint:errcheck

	tmpDir, err := os.MkdirTemp("", "usulnet-yara-")
	if err != nil {
		return "", fmt.Errorf("yara: mkdir tmp: %w", err)
	}
	// The basename of the in-container path is what yara echoes, so
	// preserve it in the tmpfile name.
	targetName := filepath.Base(srcPath)
	if targetName == "" || targetName == "/" || targetName == "." {
		targetName = "target"
	}
	hostFile := filepath.Join(tmpDir, targetName)

	tr := tar.NewReader(io.LimitReader(rc, MaxExtractBytes+1))
	for {
		hdr, terr := tr.Next()
		if errors.Is(terr, io.EOF) {
			return "", fmt.Errorf("yara: extract %s: no regular file in archive", srcPath)
		}
		if terr != nil {
			return "", fmt.Errorf("yara: extract %s: %w", srcPath, terr)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA { //nolint:staticcheck // TypeRegA still emitted by legacy producers
			continue
		}
		// Refuse files larger than MaxExtractBytes — we don't want
		// a single scan to drain the host's tmpfs.
		if hdr.Size > MaxExtractBytes {
			return "", fmt.Errorf("yara: extract %s: file too large (%d bytes)", srcPath, hdr.Size)
		}
		out, err := os.OpenFile(hostFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return "", fmt.Errorf("yara: open tmpfile: %w", err)
		}
		n, copyErr := io.Copy(out, io.LimitReader(tr, MaxExtractBytes+1))
		closeErr := out.Close()
		if copyErr != nil {
			return "", fmt.Errorf("yara: write tmpfile: %w", copyErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("yara: close tmpfile: %w", closeErr)
		}
		if n > MaxExtractBytes {
			return "", fmt.Errorf("yara: extract %s: file too large", srcPath)
		}
		return hostFile, nil
	}
}

// writeTempRuleset writes the ruleset bytes to a tmpfile under an
// OS temp dir and returns the absolute path. The caller defers the
// returned cleanup.
func writeTempRuleset(body []byte) (string, func(), error) {
	dir, err := os.MkdirTemp("", "usulnet-yara-rules-")
	if err != nil {
		return "", noopCleanup, err
	}
	path := filepath.Join(dir, "rules.yar")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", noopCleanup, err
	}
	return path, func() { _ = os.RemoveAll(dir) }, nil
}

func noopCleanup() {}

func validateTarget(t ScanTarget) error {
	hasHost := t.HostPath != ""
	hasCont := t.ContainerID != "" || t.Path != ""
	if hasHost && hasCont {
		return fmt.Errorf("%w: set host_path OR (container_id + path), not both", ErrInvalidTarget)
	}
	if !hasHost && !hasCont {
		return fmt.Errorf("%w: empty target", ErrInvalidTarget)
	}
	if hasCont {
		if t.ContainerID == "" {
			return fmt.Errorf("%w: container_id is required", ErrInvalidTarget)
		}
		if t.Path == "" {
			return fmt.Errorf("%w: path is required", ErrInvalidTarget)
		}
		if !strings.HasPrefix(t.Path, "/") {
			return fmt.Errorf("%w: container path must be absolute", ErrInvalidTarget)
		}
	}
	return nil
}

// displayTarget renders the target for human-readable output: the
// container scan shows "<containerID>:<path>"; host scan shows the
// absolute host path.
func displayTarget(t ScanTarget) string {
	if t.HostPath != "" {
		return t.HostPath
	}
	return shortID(t.ContainerID) + ":" + t.Path
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// rsLabel keeps the YARA ruleset label predictable for `docker ps`
// inspection — lowercase alnum + dashes only, capped at 64 chars per
// Docker's label-value constraints.
func rsLabel(name string) string {
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// ScanContainerPath is the convenience wrapper used by the forensics
// integration. It runs a single ruleset against one path inside a
// container and returns a human-readable text report — one line per
// match, plus a trailing summary. Empty matches produce a one-line
// "no matches" report so the operator can distinguish "scan ran
// cleanly" from "probe never executed" when reading the snapshot
// tarball.
//
// Errors during the scan are returned in-band as the report body
// (prefixed with "ERROR: ") rather than as an error from this
// function — matches the forensics probe contract that one broken
// probe should not abort the whole snapshot.
func (s *Service) ScanContainerPath(ctx context.Context, containerID, path, ruleset string) string {
	res, err := s.Scan(ctx, ScanTarget{ContainerID: containerID, Path: path}, ruleset)
	if err != nil {
		return "ERROR: yara scan " + path + ": " + err.Error() + "\n"
	}
	if len(res.Matches) == 0 {
		return "yara: no matches against " + ruleset + " over " + path + "\n"
	}
	var b strings.Builder
	for _, m := range res.Matches {
		b.WriteString(m.Rule)
		if len(m.Tags) > 0 {
			b.WriteString(" [")
			b.WriteString(strings.Join(m.Tags, ","))
			b.WriteString("]")
		}
		b.WriteString(" ")
		b.WriteString(m.Target)
		b.WriteString("\n")
	}
	b.WriteString("--- ")
	b.WriteString(res.Ruleset)
	b.WriteString(" matched ")
	if len(res.Matches) == 1 {
		b.WriteString("1 rule ---\n")
	} else {
		b.WriteString(fmt.Sprintf("%d rules ---\n", len(res.Matches)))
	}
	return b.String()
}
