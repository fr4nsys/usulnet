// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package forensics produces an incident-response snapshot of a
// running container — process list, open files, listening sockets,
// recently-modified files, the container's resolv.conf and hosts
// file, and a copy of the container's runtime inspect blob.
//
// The snapshot is delivered as a single tarball the operator can
// download from the UI. There is no persistent storage; the bytes
// are generated on demand and streamed through the response. The
// design constraint is "useful out of the box, even on a busybox
// image": every command in the probe list is fan-shaped so that
// failures (binary missing, permission denied, signal received)
// reduce to a labelled "command unavailable" line in the output
// instead of aborting the whole snapshot.
package forensics

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	dockersvc "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// DockerClient is the narrow surface forensics needs from the
// internal/docker package. Declared here so tests can supply a
// fake without depending on the real Docker SDK transport.
type DockerClient interface {
	ContainerExec(ctx context.Context, containerID string, cmd []string, opts dockersvc.ExecOptions) (*dockersvc.ExecResult, error)
}

// YARARunner is the optional surface forensics depends on for the
// in-snapshot YARA probe (v26.5.2). When the snapshot is invoked with
// ProbeOptions.YARAELFScan=true AND a runner has been registered via
// WithYARAScanner, the snapshot tar gains a yara-elf-scan.txt entry
// describing the matches.
//
// The interface is intentionally string-out: forensics does not parse
// individual matches, it just stages the report as one more file in
// the tarball alongside ps/netstat/lsof. The yara service's
// ScanContainerPath method satisfies this interface.
type YARARunner interface {
	ScanContainerPath(ctx context.Context, containerID, path, ruleset string) string
}

// ProbeOptions toggles optional probes that go beyond the default
// baseline. The zero value (all booleans false) reproduces the v26.5.1
// behaviour, so existing callers of Snapshot are unaffected.
//
// v26.5.2 ships a single optional probe — YARAELFScan — gated by an
// internal toggle. There is no API or CLI surface to flip it yet;
// callers wire it in code (e.g. an admin runbook helper). The
// follow-up PR will hoist this to a config flag.
type ProbeOptions struct {
	// YARAELFScan runs the linux-elf-suspicious ruleset over the
	// configured YARAPath inside the target container via the optional
	// YARARunner. Ignored when no runner has been registered.
	YARAELFScan bool

	// YARARuleset overrides the default ruleset name. Empty falls
	// back to DefaultYARARuleset.
	YARARuleset string

	// YARAPath overrides the in-container scan path. Empty falls
	// back to DefaultYARAPath. The path must resolve to a regular
	// file the yara binary can read.
	YARAPath string
}

// DefaultYARARuleset is the ruleset name used when ProbeOptions
// does not override it.
const DefaultYARARuleset = "linux-elf-suspicious"

// DefaultYARAPath is the in-container path scanned by the YARA probe
// when ProbeOptions does not override it. /proc/1/exe is a symlink to
// the running entrypoint binary, which Docker's archive extraction
// resolves to a single file. Operators with multi-binary scan needs
// (e.g. /usr/local/bin/*) drive the scanner directly via /scan/yara
// — the in-snapshot probe stays single-file by design so the
// snapshot tarball remains bounded.
const DefaultYARAPath = "/proc/1/exe"

// Service produces the forensics snapshot. Constructor injection
// follows the rest of the codebase — pass a DockerClient and a
// logger; the service is stateless apart from the optional YARA
// runner registered via WithYARAScanner.
type Service struct {
	docker DockerClient
	logger *logger.Logger
	yara   YARARunner
}

// NewService wires the service.
func NewService(docker DockerClient, log *logger.Logger) *Service {
	return &Service{docker: docker, logger: log}
}

// WithYARAScanner registers the optional YARA runner used by the
// YARAELFScan probe. Returns the receiver so the registration chains
// cleanly in init code: `forensics.NewService(...).WithYARAScanner(y)`.
// Passing nil clears the registration.
func (s *Service) WithYARAScanner(runner YARARunner) *Service {
	s.yara = runner
	return s
}

// Probe describes one command run inside the container and the
// filename its stdout/stderr should be written to inside the tarball.
type Probe struct {
	// Name is the filename in the tarball (no slash).
	Name string

	// Cmd is the command vector to execute. The first element is
	// the binary; subsequent elements are arguments. Probes that
	// must compose shell features wrap the command in
	// ("sh", "-c", "<pipeline>") — the alternative (a long native
	// argv) misses many of the busybox / alpine command variants.
	Cmd []string

	// MaxBytes caps the captured output per probe. Some probes
	// (find /, ps auxf) can produce many megabytes; we ship the
	// first chunk and label the truncation. Zero means no cap.
	MaxBytes int
}

// defaultProbes is the read-only baseline probe list. New probes
// added here ship to every container. Avoid relying on tools that
// only live on full distros — alpine and distroless images carry
// less than a Debian base. When a probe is missing the container
// returns an exec failure that the service records, not a fatal
// error.
var defaultProbes = []Probe{
	{Name: "ps-auxf.txt", Cmd: []string{"sh", "-c", "ps auxf 2>/dev/null || ps -ef 2>/dev/null || ps"}, MaxBytes: 256 * 1024},
	{Name: "netstat.txt", Cmd: []string{"sh", "-c", "ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || netstat -an"}, MaxBytes: 256 * 1024},
	{Name: "lsof.txt", Cmd: []string{"sh", "-c", "lsof -nP 2>/dev/null || ls -la /proc/*/fd/ 2>/dev/null | head -2000"}, MaxBytes: 1024 * 1024},
	{Name: "mounts.txt", Cmd: []string{"sh", "-c", "cat /proc/mounts 2>/dev/null"}, MaxBytes: 64 * 1024},
	{Name: "env.txt", Cmd: []string{"sh", "-c", "ls -la /proc/1/environ 2>/dev/null && cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n'"}, MaxBytes: 64 * 1024},
	{Name: "etc-passwd.txt", Cmd: []string{"sh", "-c", "cat /etc/passwd 2>/dev/null"}, MaxBytes: 32 * 1024},
	{Name: "etc-hosts.txt", Cmd: []string{"sh", "-c", "cat /etc/hosts 2>/dev/null"}, MaxBytes: 16 * 1024},
	{Name: "etc-resolv-conf.txt", Cmd: []string{"sh", "-c", "cat /etc/resolv.conf 2>/dev/null"}, MaxBytes: 16 * 1024},
	{Name: "recent-files.txt", Cmd: []string{"sh", "-c", "find / -xdev -mmin -1440 -type f 2>/dev/null | head -5000"}, MaxBytes: 512 * 1024},
	{Name: "loaded-libraries.txt", Cmd: []string{"sh", "-c", "ldconfig -p 2>/dev/null || ls /lib /usr/lib 2>/dev/null"}, MaxBytes: 128 * 1024},
}

// ErrContainerRequired is returned when no container ID is supplied.
var ErrContainerRequired = errors.New("forensics: container ID is required")

// Snapshot runs every default probe against the container and packs
// the results into a single tar (uncompressed — the operator
// usually wants to grep the output, gzipping just adds friction).
//
// Layout inside the tar:
//
//	<containerID>/MANIFEST.txt           — human-readable header
//	<containerID>/ps-auxf.txt            — one file per probe
//	<containerID>/netstat.txt
//	...
//
// Probe failures (binary missing, exec error) are recorded in the
// per-probe file as a short "ERROR: …" line, NOT propagated as a
// hard error from this method. The operator wants partial data over
// no data.
func (s *Service) Snapshot(ctx context.Context, containerID string) ([]byte, error) {
	return s.SnapshotWithOptions(ctx, containerID, ProbeOptions{})
}

// SnapshotWithOptions is the configurable variant of Snapshot. The
// zero-value opts reproduces the default behaviour; callers that need
// the YARA probe (or any future opt-in probe) pass ProbeOptions
// directly.
func (s *Service) SnapshotWithOptions(ctx context.Context, containerID string, opts ProbeOptions) ([]byte, error) {
	if strings.TrimSpace(containerID) == "" {
		return nil, ErrContainerRequired
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	timestamp := time.Now().UTC()
	manifest := buildManifest(containerID, timestamp, defaultProbes)
	if err := writeTarEntry(tw, containerID+"/MANIFEST.txt", []byte(manifest), timestamp); err != nil {
		return nil, fmt.Errorf("forensics: write manifest: %w", err)
	}

	for _, probe := range defaultProbes {
		body := s.runProbe(ctx, containerID, probe)
		path := containerID + "/" + probe.Name
		if err := writeTarEntry(tw, path, body, timestamp); err != nil {
			return nil, fmt.Errorf("forensics: write %s: %w", probe.Name, err)
		}
	}

	// Opt-in YARA probe (v26.5.2). Skipped when the option is off OR
	// when no YARA runner has been registered, so existing installs
	// without a wired scanner produce identical tarballs.
	if opts.YARAELFScan && s.yara != nil {
		ruleset := opts.YARARuleset
		if ruleset == "" {
			ruleset = DefaultYARARuleset
		}
		path := opts.YARAPath
		if path == "" {
			path = DefaultYARAPath
		}
		body := s.yara.ScanContainerPath(ctx, containerID, path, ruleset)
		if err := writeTarEntry(tw, containerID+"/yara-elf-scan.txt", []byte(body), timestamp); err != nil {
			return nil, fmt.Errorf("forensics: write yara-elf-scan: %w", err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("forensics: close tar: %w", err)
	}
	return buf.Bytes(), nil
}

// runProbe executes one probe and returns the file body to embed.
// Errors are downgraded to in-band "ERROR:" prefixed text — see the
// Snapshot doc comment for the rationale.
func (s *Service) runProbe(ctx context.Context, containerID string, probe Probe) []byte {
	res, err := s.docker.ContainerExec(ctx, containerID, probe.Cmd, dockersvc.DefaultExecOptions())
	if err != nil {
		return []byte("ERROR: " + err.Error() + "\n")
	}

	var out bytes.Buffer
	if res.Stdout != "" {
		out.WriteString(res.Stdout)
	}
	if res.Stderr != "" {
		out.WriteString("\n--- stderr ---\n")
		out.WriteString(res.Stderr)
	}
	if res.ExitCode != 0 {
		out.WriteString(fmt.Sprintf("\n--- exit code %d ---\n", res.ExitCode))
	}

	if probe.MaxBytes > 0 && out.Len() > probe.MaxBytes {
		truncated := out.Bytes()[:probe.MaxBytes]
		return append(truncated, []byte(fmt.Sprintf("\n--- TRUNCATED at %d bytes ---\n", probe.MaxBytes))...)
	}
	return out.Bytes()
}

// buildManifest returns the contents of MANIFEST.txt at the root of
// the tarball — a stable, human-readable index of which probes ran
// against which container at what wall-clock time. Useful for chain
// of custody on incident-response tickets.
func buildManifest(containerID string, ts time.Time, probes []Probe) string {
	var b strings.Builder
	fmt.Fprintf(&b, "usulnet container forensics snapshot\n")
	fmt.Fprintf(&b, "container_id: %s\n", containerID)
	fmt.Fprintf(&b, "captured_at:  %s\n", ts.Format(time.RFC3339Nano))
	fmt.Fprintf(&b, "probe_count:  %d\n", len(probes))
	fmt.Fprintf(&b, "\nProbes:\n")
	for _, p := range probes {
		fmt.Fprintf(&b, "  - %s\n      cmd: %s\n", p.Name, strings.Join(p.Cmd, " "))
	}
	return b.String()
}

func writeTarEntry(tw *tar.Writer, name string, body []byte, ts time.Time) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    int64(len(body)),
		ModTime: ts,
		Format:  tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(body); err != nil {
		return err
	}
	return nil
}
