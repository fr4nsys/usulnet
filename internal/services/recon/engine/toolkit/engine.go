// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package toolkit implements recon.Engine for the atomic OSINT tools
// shipped in the recon-toolkit container (holehe, phoneinfoga,
// subfinder, katana). Profile module entries that target this engine
// carry the `toolkit:` prefix; the engine strips the prefix and
// dispatches each module to its per-tool wrapper sequentially. Every
// invocation goes through recon.ContainerLauncher; no `docker` or
// host-side tool execution happens here.
package toolkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/observability"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// EngineName is the stable identifier the recon module uses to look
// up this engine. It lands in `recon_scans.engine` for every scan
// this adapter drives.
const EngineName = "toolkit"

// ModulePrefix flags profile module entries that belong to this
// engine. The Profile struct carries entries like "toolkit:holehe";
// the prefix is stripped before dispatch.
const ModulePrefix = "toolkit:"

// DefaultRunTimeout caps each per-module container invocation. The
// holehe / phoneinfoga / subfinder / katana wrappers are all
// "passive" so 5 minutes is a generous upper bound; the launcher's
// own timeout still applies on top.
const DefaultRunTimeout = 5 * time.Minute

// DefaultEventChanSize is the buffer size of the channel returned by
// Events. 64 absorbs short bursts (subfinder can emit hundreds of
// subdomains for popular targets) while keeping back-pressure
// available to a slow consumer.
const DefaultEventChanSize = 64

// Sentinel errors.
var (
	// ErrNoModules is returned by Start when the profile resolves to
	// zero toolkit modules. The caller should route the scan to a
	// different engine instead.
	ErrNoModules = errors.New("toolkit: no toolkit modules in profile")

	// ErrUnknownModule is returned when a `toolkit:<name>` module is
	// not implemented by any wrapper. Wrappers are registered in
	// New(); adding a new tool means adding both a wrapper and a
	// registration entry.
	ErrUnknownModule = errors.New("toolkit: unknown module")

	// ErrRunNotFound is returned by Events / Cancel / Status when the
	// run ID has not been seen (e.g., never started, or already
	// reaped).
	ErrRunNotFound = errors.New("toolkit: run not found")
)

// Options configures a new Engine. All fields are optional.
type Options struct {
	// Image is the fully-qualified toolkit image reference (callers
	// usually pass recon.ToolkitImage()). Empty → recon.ToolkitImage().
	Image string

	// RunTimeout caps each per-module container invocation.
	// Zero → DefaultRunTimeout.
	RunTimeout time.Duration

	// EventChanSize is the buffer size of the channel returned by
	// Events. Zero → DefaultEventChanSize.
	EventChanSize int
}

func (o *Options) withDefaults() {
	if o.Image == "" {
		o.Image = recon.ToolkitImage()
	}
	if o.RunTimeout <= 0 {
		o.RunTimeout = DefaultRunTimeout
	}
	if o.EventChanSize <= 0 {
		o.EventChanSize = DefaultEventChanSize
	}
}

// moduleRunner is the contract every per-tool wrapper satisfies. The
// engine looks up the runner for a module name and hands it the
// scan's target, the launcher, the image, and a per-run timeout; the
// runner returns a slice of normalised EngineEvent records. Errors
// are surfaced; per-event mapping decisions stay in the wrapper.
type moduleRunner interface {
	Module() string
	Run(ctx context.Context, target recon.Target, launcher recon.ContainerLauncher, image string, timeout time.Duration) ([]recon.EngineEvent, error)
}

// runState tracks one in-flight Start invocation. Cancel atomically
// flips the cancelled flag, which the dispatch loop checks between
// modules; the loop emits a final empty events batch and exits.
type runState struct {
	cancel context.CancelFunc
	status recon.ScanStatus
	mu     sync.Mutex
}

// Engine implements recon.Engine for the atomic OSINT toolkit.
type Engine struct {
	launcher recon.ContainerLauncher
	runners  map[string]moduleRunner
	opts     Options
	log      *logger.Logger

	mu   sync.Mutex
	runs map[string]*runState
	// queued events stash the dispatcher's output until Events is
	// called for that run. Wrappers run synchronously inside Start
	// today; the queue keeps the design open to async wrappers
	// without changing the public surface.
	queued map[string][]recon.EngineEvent
}

// Compile-time assertion.
var _ recon.Engine = (*Engine)(nil)

// New constructs an Engine wired to the given launcher. launcher
// must be non-nil; opts.Image falls back to recon.ToolkitImage().
// The four builtin runners (holehe, phoneinfoga, subfinder, katana)
// are registered automatically.
func New(launcher recon.ContainerLauncher, opts Options, log *logger.Logger) (*Engine, error) {
	if launcher == nil {
		return nil, errors.New("toolkit: nil launcher")
	}
	opts.withDefaults()
	if log == nil {
		log = logger.Nop()
	}
	runners := map[string]moduleRunner{
		holeheModule:      &holeheRunner{},
		phoneinfogaModule: &phoneinfogaRunner{},
		subfinderModule:   &subfinderRunner{},
		katanaModule:      &katanaRunner{},
	}
	return &Engine{
		launcher: launcher,
		runners:  runners,
		opts:     opts,
		log:      log.Named("recon.engine.toolkit"),
		runs:     make(map[string]*runState),
		queued:   make(map[string][]recon.EngineEvent),
	}, nil
}

// Name implements recon.Engine.
func (e *Engine) Name() string { return EngineName }

// Start implements recon.Engine. It filters the profile down to
// `toolkit:*` modules, dispatches each one to its wrapper
// sequentially, and collects the EngineEvents. Cancellation via
// ctx (or Cancel) tears down whatever container the current wrapper
// has running.
//
// Start returns once dispatch has finished (or been cancelled); the
// resulting EngineEvents wait in an internal queue until Events is
// called.
func (e *Engine) Start(ctx context.Context, req recon.EngineStartRequest) (string, error) {
	ctx, span := observability.StartSpan(ctx, "recon.engine.toolkit.Start")
	defer span.End()

	mods := FilterToolkitModules(req.Profile.Modules)
	if len(mods) == 0 {
		return "", ErrNoModules
	}
	for _, m := range mods {
		if _, ok := e.runners[m]; !ok {
			return "", fmt.Errorf("%w: %s", ErrUnknownModule, m)
		}
	}

	runID := uuid.New().String()
	runCtx, cancel := context.WithCancel(ctx)
	state := &runState{cancel: cancel, status: recon.ScanRunning}

	e.mu.Lock()
	e.runs[runID] = state
	e.mu.Unlock()

	events, finalStatus := e.dispatch(runCtx, runID, req.Target, mods)

	state.mu.Lock()
	state.status = finalStatus
	state.mu.Unlock()

	e.mu.Lock()
	e.queued[runID] = events
	e.mu.Unlock()

	e.log.Info("toolkit: scan dispatched",
		"run_id", runID,
		"scan_id", req.Target.ID.String(),
		"modules", mods,
		"event_count", len(events),
		"status", string(finalStatus),
	)
	return runID, nil
}

// dispatch runs every module wrapper sequentially. On context
// cancellation it stops dispatching and returns whatever events the
// already-completed wrappers produced.
func (e *Engine) dispatch(ctx context.Context, runID string, target recon.Target, mods []string) ([]recon.EngineEvent, recon.ScanStatus) {
	out := make([]recon.EngineEvent, 0, 16)
	for _, m := range mods {
		if err := ctx.Err(); err != nil {
			e.log.Info("toolkit: dispatch cancelled mid-run", "run_id", runID, "next_module", m)
			return out, recon.ScanCancelled
		}
		runner := e.runners[m]
		events, err := runner.Run(ctx, target, e.launcher, e.opts.Image, e.opts.RunTimeout)
		if err != nil {
			if ctx.Err() != nil {
				return out, recon.ScanCancelled
			}
			e.log.Warn("toolkit: module failed", "module", m, "error", err)
			return out, recon.ScanFailed
		}
		out = append(out, events...)
	}
	return out, recon.ScanCompleted
}

// Events implements recon.Engine. Because dispatch is synchronous in
// Start, the queued events are already available; we drain them into
// a buffered channel and close it.
func (e *Engine) Events(ctx context.Context, runID string) (<-chan recon.EngineEvent, error) {
	if runID == "" {
		return nil, errors.New("toolkit: empty run id")
	}
	e.mu.Lock()
	_, ok := e.runs[runID]
	events := e.queued[runID]
	delete(e.queued, runID)
	e.mu.Unlock()
	if !ok {
		return nil, ErrRunNotFound
	}

	size := e.opts.EventChanSize
	if len(events) > size {
		size = len(events)
	}
	ch := make(chan recon.EngineEvent, size)
	go func() {
		defer close(ch)
		for _, evt := range events {
			select {
			case <-ctx.Done():
				return
			case ch <- evt:
			}
		}
	}()
	return ch, nil
}

// Cancel implements recon.Engine. It cancels the run's context,
// which propagates into whichever wrapper has a container running
// via the launcher's RunOnce ctx → kill path.
func (e *Engine) Cancel(_ context.Context, runID string) error {
	if runID == "" {
		return errors.New("toolkit: empty run id")
	}
	e.mu.Lock()
	state, ok := e.runs[runID]
	e.mu.Unlock()
	if !ok {
		return ErrRunNotFound
	}
	state.cancel()
	return nil
}

// Status implements recon.Engine.
func (e *Engine) Status(_ context.Context, runID string) (recon.EngineStatus, error) {
	if runID == "" {
		return recon.EngineStatus{}, errors.New("toolkit: empty run id")
	}
	e.mu.Lock()
	state, ok := e.runs[runID]
	e.mu.Unlock()
	if !ok {
		return recon.EngineStatus{}, ErrRunNotFound
	}
	state.mu.Lock()
	st := state.status
	state.mu.Unlock()
	return recon.EngineStatus{Status: st, Progress: 0}, nil
}

// FilterToolkitModules returns the subset of mods that belong to
// this engine, with the `toolkit:` prefix stripped. Whitespace and
// empty entries are dropped. Exported so callers (the recon Service
// dispatcher) can route scans to the right engine.
func FilterToolkitModules(mods []string) []string {
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		m = strings.TrimSpace(m)
		if !strings.HasPrefix(m, ModulePrefix) {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(m, ModulePrefix))
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

// jsonStart returns the index of the first JSON-opening byte in b
// ('{' or '['), or -1 if none.  Shared by every wrapper.
func jsonStart(b []byte) int {
	for i, c := range b {
		switch c {
		case '{', '[':
			return i
		case ' ', '\t', '\n', '\r':
			continue
		}
		return -1
	}
	return -1
}

// decodeJSON returns the JSON portion of b, trimming any control
// bytes some log drivers prepend.
func decodeJSON(b []byte) []byte {
	if i := jsonStart(b); i >= 0 {
		return b[i:]
	}
	return b
}

// errorJSON is the shared error envelope entrypoint.sh emits when a
// subcommand fails (the err() helper). Wrappers parse it to surface
// a useful message rather than silently dropping the failure.
type errorJSON struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// asErrorReport returns a non-nil error if b decodes to an
// errorJSON whose Error field is set; otherwise nil. Used by the
// per-tool wrappers' Run methods.
func asErrorReport(b []byte) error {
	b = decodeJSON(b)
	var r errorJSON
	if err := json.Unmarshal(b, &r); err != nil {
		return nil
	}
	if r.Error == "" {
		return nil
	}
	return fmt.Errorf("toolkit: %s: %s", r.Error, r.Message)
}

// runToolkitJSON is the shared invocation helper: build a network-
// enabled spec, RunOnce, parse stdout into the wrapper-supplied
// destination struct. The OSINT wrappers all share this body; the
// per-tool runner only customises the command and the destination.
func runToolkitJSON(
	ctx context.Context,
	launcher recon.ContainerLauncher,
	image string,
	cmd []string,
	timeout time.Duration,
	dst any,
) ([]byte, error) {
	spec := recon.ContainerSpec{
		Image:     image,
		Command:   cmd,
		NoNetwork: false,
		Timeout:   timeout,
		Labels:    map[string]string{"usulnet.recon.role": "osint-toolkit"},
	}
	output, code, err := launcher.RunOnce(ctx, spec)
	if err != nil {
		return output, fmt.Errorf("toolkit: run %s: %w", cmd[0], err)
	}
	if code != 0 {
		if rerr := asErrorReport(output); rerr != nil {
			return output, rerr
		}
		return output, fmt.Errorf("toolkit: %s exited %d", cmd[0], code)
	}
	if rerr := asErrorReport(output); rerr != nil {
		return output, rerr
	}
	if dst == nil {
		return output, nil
	}
	b := decodeJSON(output)
	if err := json.Unmarshal(b, dst); err != nil {
		return output, fmt.Errorf("toolkit: parse %s output: %w", cmd[0], err)
	}
	return output, nil
}
