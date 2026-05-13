// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package stub is a deterministic recon.Engine implementation used by
// unit tests and by `make test-e2e` runs that should not spin up
// SpiderFoot. It emits a configurable list of events, in order, and
// then closes the events channel. The real SpiderFoot adapter lands in
// Session 06 (see docs/v26.5/sessions/06-spiderfoot-engine.md).
package stub

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// Name is the engine identifier the stub registers under. The recon
// Service picks it up via `cfg.DefaultEngine = stub.Name` when running
// in tests.
const Name = "stub"

// Engine is a deterministic stub recon.Engine. All exported fields are
// configurable; the zero value emits a single info-severity event.
type Engine struct {
	// CannedEvents is the list of EngineEvents the engine emits, in
	// order, when Events() is called for a run started via Start().
	CannedEvents []recon.EngineEvent

	// StartErr, EventsErr, CancelErr, StatusErr override the return
	// of the matching method when non-nil. Used by failure-path tests.
	StartErr  error
	EventsErr error
	CancelErr error
	StatusErr error

	mu     sync.Mutex
	runIDs map[string]bool
}

// New constructs a stub engine with the supplied canned events. nil
// events is equivalent to passing []recon.EngineEvent{} — the engine
// will report scan completion immediately on Events().
func New(events []recon.EngineEvent) *Engine {
	return &Engine{CannedEvents: append([]recon.EngineEvent(nil), events...), runIDs: map[string]bool{}}
}

// Name returns recon's stable engine identifier.
func (e *Engine) Name() string { return Name }

// Start records a new run id and returns it. The configured StartErr
// short-circuits everything before any state changes.
func (e *Engine) Start(_ context.Context, _ recon.EngineStartRequest) (string, error) {
	if e.StartErr != nil {
		return "", e.StartErr
	}
	runID := uuid.New().String()
	e.mu.Lock()
	if e.runIDs == nil {
		e.runIDs = map[string]bool{}
	}
	e.runIDs[runID] = true
	e.mu.Unlock()
	return runID, nil
}

// Events returns a channel buffered to len(e.Events)+1 that emits the
// canned events in order and then closes. The closed channel is the
// signal recon.Service treats as "engine finished cleanly".
func (e *Engine) Events(ctx context.Context, runID string) (<-chan recon.EngineEvent, error) {
	if e.EventsErr != nil {
		return nil, e.EventsErr
	}
	e.mu.Lock()
	if !e.runIDs[runID] {
		e.mu.Unlock()
		return nil, ErrUnknownRunID
	}
	e.mu.Unlock()

	out := make(chan recon.EngineEvent, len(e.CannedEvents)+1)
	go func() {
		defer close(out)
		for _, ev := range e.CannedEvents {
			select {
			case <-ctx.Done():
				return
			case out <- ev:
			}
		}
	}()
	return out, nil
}

// Cancel forgets the run id and returns CancelErr when configured.
func (e *Engine) Cancel(_ context.Context, runID string) error {
	if e.CancelErr != nil {
		return e.CancelErr
	}
	e.mu.Lock()
	delete(e.runIDs, runID)
	e.mu.Unlock()
	return nil
}

// Status reports completed for any unknown run id (the stub does not
// model running state). The configured StatusErr overrides the
// return.
func (e *Engine) Status(_ context.Context, runID string) (recon.EngineStatus, error) {
	if e.StatusErr != nil {
		return recon.EngineStatus{}, e.StatusErr
	}
	e.mu.Lock()
	_, known := e.runIDs[runID]
	e.mu.Unlock()
	if known {
		return recon.EngineStatus{Status: recon.ScanRunning, Progress: 50}, nil
	}
	return recon.EngineStatus{Status: recon.ScanCompleted, Progress: 100}, nil
}

// ErrUnknownRunID is returned by Events when called with a runID the
// engine never issued.
var ErrUnknownRunID = unknownRunIDError{}

type unknownRunIDError struct{}

func (unknownRunIDError) Error() string { return "stub engine: unknown run id" }
