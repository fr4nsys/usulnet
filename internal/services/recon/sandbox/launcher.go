// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/observability"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// Sentinel errors so callers can distinguish failure modes without
// substring matching.
var (
	// ErrNilClient is returned when NewLauncher receives a nil docker
	// client.
	ErrNilClient = errors.New("recon sandbox: nil docker client")

	// ErrOutputTooLarge is returned when a RunOnce target produces
	// more stdout/stderr than Config.MaxOutputBytes.
	ErrOutputTooLarge = errors.New("recon sandbox: container output exceeded cap")

	// ErrLauncherClosed is returned when methods are called after the
	// launcher has been stopped/closed (reserved for future use).
	ErrLauncherClosed = errors.New("recon sandbox: launcher closed")
)

// DefaultMaxOutputBytes caps RunOnce stdout+stderr at 16 MiB.
const DefaultMaxOutputBytes = 16 * 1024 * 1024

// DefaultStopGrace is the SIGTERM→SIGKILL grace period used by Stop.
const DefaultStopGrace = 5 * time.Second

// Config configures a Launcher.  Zero-valued fields fall back to the
// constants documented on each field.
type Config struct {
	// NetworkName is the name of the dedicated recon bridge.
	// Empty → DefaultNetworkName ("usulnet-recon").
	NetworkName string

	// NetworkSubnet is the IPAM subnet for the network.  Empty →
	// DefaultNetworkSubnet.
	NetworkSubnet string

	// EgressAllowlist is the list of CIDRs the launcher is *allowed*
	// to talk to.  Empty → "public Internet HTTP/HTTPS only".  Today
	// this is informational only; iptables programming lands later.
	EgressAllowlist []string

	// DefaultTimeout is the fallback timeout when a ContainerSpec
	// does not set one.  Empty → DefaultTimeout (15m).
	DefaultTimeout time.Duration

	// MaxOutputBytes caps RunOnce stdout+stderr.
	// Zero → DefaultMaxOutputBytes (16 MiB).
	MaxOutputBytes int64

	// StopGrace is the SIGTERM grace period before SIGKILL during Stop.
	// Zero → DefaultStopGrace (5s).
	StopGrace time.Duration
}

func (c *Config) withDefaults() {
	if c.NetworkName == "" {
		c.NetworkName = DefaultNetworkName
	}
	if c.NetworkSubnet == "" {
		c.NetworkSubnet = DefaultNetworkSubnet
	}
	if c.DefaultTimeout <= 0 {
		c.DefaultTimeout = DefaultTimeout
	}
	if c.MaxOutputBytes <= 0 {
		c.MaxOutputBytes = DefaultMaxOutputBytes
	}
	if c.StopGrace <= 0 {
		c.StopGrace = DefaultStopGrace
	}
}

// dockerAPI is the slice of *docker.Client behaviour the launcher
// needs.  Defining it here keeps the launcher mockable in unit tests
// without pulling the docker SDK in.
type dockerAPI interface {
	ContainerCreate(ctx context.Context, opts docker.ContainerCreateOptions) (string, error)
	ContainerStart(ctx context.Context, containerID string) error
	ContainerKill(ctx context.Context, containerID string, signal string) error
	ContainerRemove(ctx context.Context, containerID string, force, removeVolumes bool) error
	ContainerWait(ctx context.Context, containerID string) (int64, error)
	ContainerLogs(ctx context.Context, containerID string, opts docker.LogOptions) (io.ReadCloser, error)
	ContainerList(ctx context.Context, opts docker.ContainerListOptions) ([]docker.Container, error)
	ContainerCopyFileStream(ctx context.Context, containerID, srcPath string) (io.ReadCloser, error)
	NetworkCreate(ctx context.Context, opts docker.NetworkCreateOptions) (*docker.Network, error)
	NetworkGetByName(ctx context.Context, name string) (*docker.Network, error)
}

// Compile-time assertion: the existing *docker.Client must satisfy our
// minimal interface.  If a method changes signature upstream the
// build breaks here rather than at the first runtime call.
var _ dockerAPI = (*docker.Client)(nil)

// Launcher is the recon module's sandbox launcher.  It owns the
// `usulnet-recon` network and renders every container the recon
// service runs under the hardening baseline defined in spec.go.
type Launcher struct {
	client dockerAPI
	cfg    Config
	log    *logger.Logger
}

// NewLauncher constructs a Launcher.  client must be non-nil; cfg
// zero-values are replaced with the package defaults.  Passing a nil
// logger is allowed and produces a no-op logger.
func NewLauncher(client *docker.Client, cfg Config, log *logger.Logger) (*Launcher, error) {
	if client == nil {
		return nil, ErrNilClient
	}
	return newLauncher(client, cfg, log)
}

// newLauncher is the test-friendly constructor that takes the
// interface directly.  External callers go through NewLauncher.
func newLauncher(client dockerAPI, cfg Config, log *logger.Logger) (*Launcher, error) {
	if client == nil {
		return nil, ErrNilClient
	}
	cfg.withDefaults()
	if log == nil {
		log = logger.Nop()
	}
	return &Launcher{
		client: client,
		cfg:    cfg,
		log:    log.Named("recon.sandbox"),
	}, nil
}

// EnsureRunning returns the ID of a container matching spec, starting
// a new one if none is already running.  Matching is by the
// usulnet.recon.spec_hash label so two specs that differ in image or
// command get distinct containers even within the same module.
func (l *Launcher) EnsureRunning(ctx context.Context, spec recon.ContainerSpec) (string, error) {
	ctx, span := observability.StartSpan(ctx, "recon.sandbox.EnsureRunning")
	defer span.End()

	hash := specHash(spec)
	log := l.log.With("image", spec.Image, "spec_hash", hash)
	log.Debug("recon sandbox: ensure running")

	netName, err := l.ensureNetwork(ctx)
	if err != nil {
		return "", err
	}

	// Lookup an existing running container for this spec.
	existing, err := l.client.ContainerList(ctx, docker.ContainerListOptions{
		All: false,
		Filters: map[string][]string{
			"label": {
				LabelModule + "=" + LabelModuleValue,
				LabelSpecHash + "=" + hash,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("recon sandbox: list containers: %w", err)
	}
	if len(existing) > 0 {
		log.Debug("recon sandbox: reusing running container", "container_id", existing[0].ID)
		return existing[0].ID, nil
	}

	create := hardenSpec(spec, netName)
	create.Labels[LabelSpecHash] = hash

	id, err := l.client.ContainerCreate(ctx, create)
	if err != nil {
		return "", fmt.Errorf("recon sandbox: create container: %w", err)
	}
	if err := l.client.ContainerStart(ctx, id); err != nil {
		// Best-effort cleanup: a created but unstarted container is
		// useless and will only trip future EnsureRunning calls.
		_ = l.client.ContainerRemove(ctx, id, true, false)
		return "", fmt.Errorf("recon sandbox: start container: %w", err)
	}
	log.Info("recon sandbox: container started", "container_id", id)
	return id, nil
}

// RunOnce starts a container, captures stdout+stderr up to
// Config.MaxOutputBytes, waits for it to exit (subject to the spec's
// timeout), and force-removes it.  The returned output and exitCode
// are best-effort: on error they may still hold partial data the
// caller can log.
func (l *Launcher) RunOnce(ctx context.Context, spec recon.ContainerSpec) ([]byte, int, error) {
	out, _, code, err := l.runOnce(ctx, spec, "")
	return out, code, err
}

// RunOnceWithCopy executes a one-shot container exactly like RunOnce,
// then before removing it copies a single file out of the container's
// filesystem and returns its bytes alongside stdout/stderr.  Used by
// the metadata stripper to retrieve the cleaned file produced by mat2
// without poking holes in the read-only mount discipline.
//
// copyPath is the absolute path of the file inside the container
// (typically a tmpfs path such as /work/out/cleaned).  When the
// command fails (non-zero exit) the copy is skipped and copied is
// returned nil; the caller decides what to do with the stdout.
func (l *Launcher) RunOnceWithCopy(ctx context.Context, spec recon.ContainerSpec, copyPath string) ([]byte, []byte, int, error) {
	return l.runOnce(ctx, spec, copyPath)
}

// runOnce is the shared body of RunOnce and RunOnceWithCopy.  copyPath
// is "" for the bare RunOnce flow; when non-empty the container is
// kept alive just long enough to copy the file out before removal.
func (l *Launcher) runOnce(ctx context.Context, spec recon.ContainerSpec, copyPath string) ([]byte, []byte, int, error) {
	ctx, span := observability.StartSpan(ctx, "recon.sandbox.RunOnce")
	defer span.End()

	log := l.log.With("image", spec.Image)
	log.Debug("recon sandbox: run once")

	netName, err := l.ensureNetwork(ctx)
	if err != nil {
		return nil, nil, -1, err
	}

	create := hardenSpec(spec, netName)
	create.Labels[LabelSpecHash] = specHash(spec)

	id, err := l.client.ContainerCreate(ctx, create)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("recon sandbox: create container: %w", err)
	}
	defer func() {
		// Force-remove regardless of how we exited; ignore errors
		// (the container may have auto-removed in theory, though we
		// disable AutoRemove in hardenSpec).
		_ = l.client.ContainerRemove(context.WithoutCancel(ctx), id, true, false)
	}()

	if err := l.client.ContainerStart(ctx, id); err != nil {
		return nil, nil, -1, fmt.Errorf("recon sandbox: start container: %w", err)
	}

	timeout := timeoutOrDefault(spec)
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// ContainerWait blocks on either the wait result or the context.
	// We run it in a goroutine so we can race it against the log
	// capture and apply our own timeout-driven kill.
	type waitResult struct {
		code int64
		err  error
	}
	waitCh := make(chan waitResult, 1)
	go func() {
		c, err := l.client.ContainerWait(waitCtx, id)
		waitCh <- waitResult{code: c, err: err}
	}()

	// Start log capture.  Errors from log reading aren't fatal to the
	// run — they only mean we report a truncated output.
	output := l.captureLogs(ctx, id, log)

	select {
	case res := <-waitCh:
		out := output()
		if res.err != nil {
			// Distinguish timeout from generic wait failure.
			if errors.Is(res.err, context.DeadlineExceeded) || errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				l.killAndRemove(ctx, id, log)
				return out, nil, -1, fmt.Errorf("recon sandbox: container timed out after %s: %w", timeout, context.DeadlineExceeded)
			}
			if errors.Is(res.err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				l.killAndRemove(ctx, id, log)
				return out, nil, -1, fmt.Errorf("recon sandbox: run cancelled: %w", context.Canceled)
			}
			return out, nil, -1, fmt.Errorf("recon sandbox: wait: %w", res.err)
		}
		code := int(res.code)
		var copied []byte
		if copyPath != "" && code == 0 {
			copied, err = l.copyFile(ctx, id, copyPath)
			if err != nil {
				return out, nil, code, fmt.Errorf("recon sandbox: copy %s: %w", copyPath, err)
			}
		}
		return out, copied, code, nil
	case <-ctx.Done():
		l.killAndRemove(ctx, id, log)
		return output(), nil, -1, fmt.Errorf("recon sandbox: parent context cancelled: %w", ctx.Err())
	}
}

// copyFile reads a single regular file out of containerID by streaming
// the tar archive Docker hands back from CopyFromContainer and
// extracting the first regular entry.  Any leading directory entries
// are skipped silently.
func (l *Launcher) copyFile(ctx context.Context, containerID, srcPath string) ([]byte, error) {
	rc, err := l.client.ContainerCopyFileStream(ctx, containerID, srcPath)
	if err != nil {
		return nil, fmt.Errorf("copy stream: %w", err)
	}
	defer rc.Close() //nolint:errcheck

	tr := tar.NewReader(io.LimitReader(rc, l.cfg.MaxOutputBytes+1))
	for {
		hdr, terr := tr.Next()
		if terr == io.EOF {
			return nil, fmt.Errorf("no file in archive for %s", srcPath)
		}
		if terr != nil {
			return nil, fmt.Errorf("tar next: %w", terr)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA { //nolint:staticcheck // TypeRegA is deprecated but still valid in legacy archives
			continue
		}
		buf := &bytes.Buffer{}
		n, cerr := io.Copy(buf, io.LimitReader(tr, l.cfg.MaxOutputBytes+1))
		if cerr != nil {
			return nil, fmt.Errorf("read entry: %w", cerr)
		}
		if n > l.cfg.MaxOutputBytes {
			return nil, ErrOutputTooLarge
		}
		return buf.Bytes(), nil
	}
}

// Stop terminates a long-lived container.  It sends SIGTERM, waits
// Config.StopGrace, then SIGKILLs, and finally force-removes the
// container.  Errors at each step are logged but only the final
// removal error is returned, because that is the one a caller can act
// on (e.g. surface to the operator).
func (l *Launcher) Stop(ctx context.Context, containerID string) error {
	ctx, span := observability.StartSpan(ctx, "recon.sandbox.Stop")
	defer span.End()

	log := l.log.With("container_id", containerID)
	log.Debug("recon sandbox: stop")

	if err := l.client.ContainerKill(ctx, containerID, "SIGTERM"); err != nil {
		// If the container is already gone, that's success.
		if isNotFound(err) {
			return nil
		}
		log.Warn("recon sandbox: SIGTERM failed", "error", err)
	}

	// Brief grace period before SIGKILL.  We do not race ContainerWait
	// here because the launcher should never block the caller longer
	// than StopGrace; if the container ignores SIGTERM the SIGKILL
	// path is the right one to drop into.
	select {
	case <-time.After(l.cfg.StopGrace):
	case <-ctx.Done():
		// Caller asked to stop waiting; fall through to force-remove.
	}

	if err := l.client.ContainerKill(ctx, containerID, "SIGKILL"); err != nil && !isNotFound(err) {
		log.Warn("recon sandbox: SIGKILL failed", "error", err)
	}

	if err := l.client.ContainerRemove(ctx, containerID, true, false); err != nil && !isNotFound(err) {
		return fmt.Errorf("recon sandbox: remove container: %w", err)
	}
	log.Info("recon sandbox: container stopped")
	return nil
}

// captureLogs starts streaming the container's logs into a bounded
// buffer in the background and returns a getter the caller invokes
// once the run is done.  The getter blocks briefly to let any tail
// bytes drain.
func (l *Launcher) captureLogs(ctx context.Context, id string, log *logger.Logger) func() []byte {
	cap := l.cfg.MaxOutputBytes
	var buf bytes.Buffer
	done := make(chan struct{})

	go func() {
		defer close(done)
		rc, err := l.client.ContainerLogs(ctx, id, docker.LogOptions{
			Stdout: true,
			Stderr: true,
			Follow: true,
			Tail:   "all",
		})
		if err != nil {
			log.Warn("recon sandbox: open logs failed", "error", err)
			return
		}
		defer rc.Close() //nolint:errcheck
		// Bound the copy by cap+1 so we can detect overrun.
		limited := io.LimitReader(rc, cap+1)
		_, _ = io.Copy(&buf, limited)
	}()

	return func() []byte {
		<-done
		if int64(buf.Len()) > cap {
			truncated := buf.Bytes()[:cap]
			return append(truncated, []byte("\n[truncated]\n")...)
		}
		return append([]byte(nil), buf.Bytes()...)
	}
}

// killAndRemove force-terminates a container after a run failure.
// Errors are logged but not propagated: the caller already has a
// primary error to surface.
func (l *Launcher) killAndRemove(ctx context.Context, id string, log *logger.Logger) {
	// Use a detached context so cancellation of the parent does not
	// abort the cleanup.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := l.client.ContainerKill(cleanupCtx, id, "SIGKILL"); err != nil && !isNotFound(err) {
		log.Warn("recon sandbox: kill on timeout failed", "error", err)
	}
	if err := l.client.ContainerRemove(cleanupCtx, id, true, false); err != nil && !isNotFound(err) {
		log.Warn("recon sandbox: remove on timeout failed", "error", err)
	}
}

// specHash returns a stable, short hash over the spec fields that
// define a container's identity.  It is used both for the
// usulnet.recon.spec_hash label and for EnsureRunning lookups.
func specHash(spec recon.ContainerSpec) string {
	h := sha256.New()
	h.Write([]byte(spec.Image))
	h.Write([]byte{0})
	for _, c := range spec.Command {
		h.Write([]byte(c))
		h.Write([]byte{0})
	}
	// Maps are non-deterministic; sort keys before mixing in.
	envKeys := sortedKeys(spec.Env)
	for _, k := range envKeys {
		h.Write([]byte(k))
		h.Write([]byte{'='})
		h.Write([]byte(spec.Env[k]))
		h.Write([]byte{0})
	}
	labelKeys := sortedKeys(spec.Labels)
	for _, k := range labelKeys {
		h.Write([]byte(k))
		h.Write([]byte{'='})
		h.Write([]byte(spec.Labels[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
