// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package spiderfoot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/observability"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// EngineName is the stable identifier the recon module uses to look
// up this engine. It also lands in the `recon_scans.engine` column
// for every scan this adapter starts.
const EngineName = "spiderfoot"

// ToolkitPrefix flags profile module entries that belong to the
// toolkit engine, not SpiderFoot. The adapter strips them from its
// own module list when calling /scanstartlist.
const ToolkitPrefix = "toolkit:"

// DefaultPollInterval is the cadence at which Events polls
// /scaneventresults and /scanstatus.
const DefaultPollInterval = 5 * time.Second

// DefaultCancelTimeout is how long Cancel waits for SpiderFoot to
// transition the scan to ABORTED before returning a timeout error.
const DefaultCancelTimeout = 30 * time.Second

// DefaultEventChanSize is the buffer size of the channel returned by
// Events. 64 absorbs short bursts from /scaneventresults while still
// providing back-pressure to a slow consumer.
const DefaultEventChanSize = 64

// Sentinel errors.
var (
	// ErrNoModules is returned by Start when the profile's module
	// list resolves to zero SpiderFoot modules (e.g., a phone-only
	// profile that lives entirely on the toolkit engine). The caller
	// should route the scan to the appropriate engine instead.
	ErrNoModules = errors.New("spiderfoot: no SpiderFoot modules in profile")

	// ErrCancelTimeout is returned when /scandelete is accepted but
	// SpiderFoot does not report ABORTED within the timeout.
	ErrCancelTimeout = errors.New("spiderfoot: cancel timed out")
)

// Options configures a new Engine. Every field is optional; the
// zero-value picks sensible defaults documented per field.
type Options struct {
	// PollInterval governs how often Events polls SpiderFoot.
	// Zero → DefaultPollInterval.
	PollInterval time.Duration

	// CancelTimeout caps Cancel's wait for the ABORTED status.
	// Zero → DefaultCancelTimeout.
	CancelTimeout time.Duration

	// EventChanSize is the buffer size of the channel returned by
	// Events. Zero → DefaultEventChanSize.
	EventChanSize int
}

func (o *Options) withDefaults() {
	if o.PollInterval <= 0 {
		o.PollInterval = DefaultPollInterval
	}
	if o.CancelTimeout <= 0 {
		o.CancelTimeout = DefaultCancelTimeout
	}
	if o.EventChanSize <= 0 {
		o.EventChanSize = DefaultEventChanSize
	}
}

// Engine implements recon.Engine against a SpiderFoot container.
type Engine struct {
	client *Client
	opts   Options
	log    *logger.Logger
}

// Compile-time assertion.
var _ recon.Engine = (*Engine)(nil)

// New constructs an Engine. client must be non-nil (it carries the
// base URL the launcher resolved). Passing a nil logger is allowed.
func New(client *Client, opts Options, log *logger.Logger) (*Engine, error) {
	if client == nil {
		return nil, errors.New("spiderfoot: nil client")
	}
	opts.withDefaults()
	if log == nil {
		log = logger.Nop()
	}
	return &Engine{
		client: client,
		opts:   opts,
		log:    log.Named("recon.engine.spiderfoot"),
	}, nil
}

// Name implements recon.Engine.
func (e *Engine) Name() string { return EngineName }

// Start implements recon.Engine. It filters the profile's module
// list down to SpiderFoot modules (stripping `toolkit:` entries),
// names the scan deterministically as "usulnet/<scan-uuid>" so the
// SpiderFoot DB carries a reverse-lookupable key, and POSTs to
// /scanstartlist.
func (e *Engine) Start(ctx context.Context, req recon.EngineStartRequest) (string, error) {
	ctx, span := observability.StartSpan(ctx, "recon.engine.spiderfoot.Start")
	defer span.End()

	mods := FilterSpiderFootModules(req.Profile.Modules)
	if len(mods) == 0 {
		return "", ErrNoModules
	}

	name := scanName(req)
	target := strings.TrimSpace(req.Target.Value)
	if target == "" {
		return "", errors.New("spiderfoot: empty target value")
	}

	id, err := e.client.StartScan(ctx, name, target, mods)
	if err != nil {
		return "", err
	}
	e.log.Info("spiderfoot: scan started",
		"scan_id", req.Target.ID.String(),
		"run_id", id,
		"module_count", len(mods),
	)
	return id, nil
}

// Events implements recon.Engine. It returns a buffered channel; a
// goroutine polls SpiderFoot on opts.PollInterval, de-duplicates by
// event hash, maps each event through MapEventType, and pushes it to
// the channel. The goroutine closes the channel when /scanstatus
// reports a terminal status or ctx is canceled.
func (e *Engine) Events(ctx context.Context, runID string) (<-chan recon.EngineEvent, error) {
	if runID == "" {
		return nil, errors.New("spiderfoot: empty run id")
	}
	ch := make(chan recon.EngineEvent, e.opts.EventChanSize)

	go e.streamEvents(ctx, runID, ch)
	return ch, nil
}

// streamEvents is the goroutine body for Events. It is responsible
// for closing ch.
func (e *Engine) streamEvents(ctx context.Context, runID string, ch chan<- recon.EngineEvent) {
	defer close(ch)

	seen := make(map[string]struct{})
	ticker := time.NewTicker(e.opts.PollInterval)
	defer ticker.Stop()

	log := e.log.With("run_id", runID)

	// First poll immediately so callers see early events without
	// waiting a full interval.
	if done := e.pollOnce(ctx, runID, seen, ch, log); done {
		return
	}

	for {
		select {
		case <-ctx.Done():
			log.Debug("spiderfoot: events context canceled", "error", ctx.Err())
			return
		case <-ticker.C:
			if done := e.pollOnce(ctx, runID, seen, ch, log); done {
				return
			}
		}
	}
}

// pollOnce fetches one batch of events and the current scan status.
// It returns true when the scan has reached a terminal state and the
// caller should stop polling.
func (e *Engine) pollOnce(
	ctx context.Context,
	runID string,
	seen map[string]struct{},
	ch chan<- recon.EngineEvent,
	log *logger.Logger,
) bool {
	events, err := e.client.ScanEventResults(ctx, runID)
	if err != nil {
		// Transient errors should not kill the stream; log and try
		// again on the next tick. Context cancellation is handled in
		// the outer select.
		if ctx.Err() != nil {
			return true
		}
		log.Warn("spiderfoot: scaneventresults failed", "error", err)
	}
	for _, evt := range events {
		key := dedupeKey(evt)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		mapped := toEngineEvent(evt)
		select {
		case ch <- mapped:
		case <-ctx.Done():
			return true
		}
	}

	st, err := e.client.ScanStatus(ctx, runID)
	if err != nil {
		if ctx.Err() != nil {
			return true
		}
		if errors.Is(err, ErrScanNotFound) {
			// The scan was deleted out from under us. Treat as a
			// terminal condition.
			log.Info("spiderfoot: scan no longer present", "run_id", runID)
			return true
		}
		log.Warn("spiderfoot: scanstatus failed", "error", err)
		return false
	}
	return isTerminal(st.Status)
}

// Cancel implements recon.Engine. It POSTs /scandelete, then polls
// /scanstatus until the scan reports ABORTED or the engine's cancel
// timeout elapses.
func (e *Engine) Cancel(ctx context.Context, runID string) error {
	ctx, span := observability.StartSpan(ctx, "recon.engine.spiderfoot.Cancel")
	defer span.End()

	if runID == "" {
		return errors.New("spiderfoot: empty run id")
	}

	if err := e.client.DeleteScan(ctx, runID); err != nil {
		return err
	}

	deadline := time.Now().Add(e.opts.CancelTimeout)
	// Poll on a short interval to keep the cancel snappy; clamp to
	// 500ms so we don't busy-loop and don't oversleep the deadline.
	wait := e.opts.PollInterval
	if wait > 500*time.Millisecond {
		wait = 500 * time.Millisecond
	}
	for {
		st, err := e.client.ScanStatus(ctx, runID)
		if err != nil {
			if errors.Is(err, ErrScanNotFound) {
				// The scan vanished, which is what cancel asked for.
				return nil
			}
			// Keep retrying until the deadline; transient errors are
			// normal while SpiderFoot is in ABORT-REQUESTED.
			e.log.Debug("spiderfoot: cancel poll error", "error", err)
		} else if st.Status == StatusAborted {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("%w: after %s", ErrCancelTimeout, e.opts.CancelTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// Status implements recon.Engine.
func (e *Engine) Status(ctx context.Context, runID string) (recon.EngineStatus, error) {
	ctx, span := observability.StartSpan(ctx, "recon.engine.spiderfoot.Status")
	defer span.End()

	st, err := e.client.ScanStatus(ctx, runID)
	if err != nil {
		return recon.EngineStatus{}, err
	}
	mapped := mapStatus(st.Status)
	if mapped == recon.ScanRunning && !isKnownRunningStatus(st.Status) {
		e.log.Debug("spiderfoot: unknown status mapped to running", "status", st.Status)
	}
	return recon.EngineStatus{
		Status: mapped,
		// SpiderFoot's API does not expose per-scan progress; the
		// progress column stays zero until a future SpiderFoot
		// release surfaces it.
		Progress: 0,
	}, nil
}

// FilterSpiderFootModules returns the subset of mods that belong to
// SpiderFoot (i.e., everything that does not carry the toolkit:
// prefix). Whitespace and empty entries are dropped. The function is
// exported so tests in callers can assert routing.
func FilterSpiderFootModules(mods []string) []string {
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if strings.HasPrefix(m, ToolkitPrefix) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// scanName builds the deterministic scan name used to register a
// scan inside SpiderFoot: "usulnet/<scan_uuid>". The Target struct
// already carries the scan-side UUID via its ID, which is what the
// service hands to the engine. Using a stable scheme makes the
// SpiderFoot DB greppable from a usulnet support session.
func scanName(req recon.EngineStartRequest) string {
	return "usulnet/" + req.Target.ID.String()
}

// dedupeKey is the key used to de-duplicate events received from
// /scaneventresults across polling rounds. SpiderFoot guarantees a
// per-event hash; when it's missing (older versions, or rows
// SpiderFoot built before the hash field was added) we fall back to
// a synthetic key over the row's identifying fields.
func dedupeKey(evt ScanEvent) string {
	if evt.Hash != "" {
		return evt.Hash
	}
	return evt.SourceModule + "\x00" + evt.EventType + "\x00" + evt.Data
}

// toEngineEvent applies the type mapping table and packs the
// original SpiderFoot row into the raw-payload field for later
// auditing.
func toEngineEvent(evt ScanEvent) recon.EngineEvent {
	m := MapEventType(evt.EventType)
	confidence := m.Confidence
	if evt.Confidence > 0 {
		confidence = evt.Confidence
	}
	raw, err := json.Marshal(evt)
	if err != nil {
		// json.Marshal of a struct with only strings/ints cannot
		// fail; if it ever does, fall back to no payload rather
		// than dropping the event.
		raw = nil
	}
	return recon.EngineEvent{
		Module:     evt.SourceModule,
		Category:   m.Category,
		Severity:   m.Severity,
		Value:      evt.Data,
		Source:     evt.SourceData,
		Confidence: confidence,
		RawPayload: raw,
	}
}

// mapStatus implements the SpiderFoot → recon.ScanStatus table.
// Unknown statuses fall through to ScanRunning so a stalled scan
// does not silently disappear; the caller logs at debug level when
// it sees an unknown value.
func mapStatus(s string) recon.ScanStatus {
	switch s {
	case StatusCreated, StatusStarting, StatusStarted, StatusRunning, StatusAbortRequested:
		return recon.ScanRunning
	case StatusFinished:
		return recon.ScanCompleted
	case StatusAborted:
		return recon.ScanCancelled
	}
	if strings.HasPrefix(s, ErrorPrefix) {
		return recon.ScanFailed
	}
	return recon.ScanRunning
}

// isTerminal reports whether a SpiderFoot status string is one we
// consider terminal: the scan is done and Events should close its
// channel.
func isTerminal(s string) bool {
	if s == StatusFinished || s == StatusAborted {
		return true
	}
	return strings.HasPrefix(s, ErrorPrefix)
}

// isKnownRunningStatus is used purely for log filtering: if the
// status is not one of these and we still mapped it to ScanRunning,
// we emit a debug log so unknown states show up in support bundles.
func isKnownRunningStatus(s string) bool {
	switch s {
	case StatusCreated, StatusStarting, StatusStarted, StatusRunning, StatusAbortRequested:
		return true
	}
	return false
}
