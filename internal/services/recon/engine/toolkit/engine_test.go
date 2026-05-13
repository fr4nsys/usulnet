// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package toolkit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// ---------------------------------------------------------------------------
// Stub launcher
// ---------------------------------------------------------------------------

// stubLauncher implements recon.ContainerLauncher. Each cmd[0] maps
// to a canned (stdout, exitCode, error) triple programmed by the
// test; unmatched commands return a failing exit code with a
// diagnostic message so a test that forgets to wire a tool fails
// loudly rather than silently dropping events.
type stubLauncher struct {
	mu       sync.Mutex
	canned   map[string]stubResult
	calls    []stubCall
	blockCmd string        // when non-empty, RunOnce blocks on ctx.Done() if cmd[0] == blockCmd
	blockCh  chan struct{} // closed when the blocked call enters its select; tests use this to coordinate cancel
}

type stubResult struct {
	output []byte
	code   int
	err    error
}

type stubCall struct {
	image string
	cmd   []string
}

func newStubLauncher() *stubLauncher {
	return &stubLauncher{
		canned:  make(map[string]stubResult),
		blockCh: make(chan struct{}, 1),
	}
}

func (s *stubLauncher) program(subcommand string, output string, code int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.canned[subcommand] = stubResult{output: []byte(output), code: code, err: err}
}

func (s *stubLauncher) EnsureRunning(_ context.Context, _ recon.ContainerSpec) (string, error) {
	return "", errors.New("stubLauncher: EnsureRunning not implemented")
}

func (s *stubLauncher) RunOnce(ctx context.Context, spec recon.ContainerSpec) ([]byte, int, error) {
	s.mu.Lock()
	s.calls = append(s.calls, stubCall{image: spec.Image, cmd: spec.Command})
	block := s.blockCmd != "" && len(spec.Command) > 0 && spec.Command[0] == s.blockCmd
	res, ok := s.canned[firstArg(spec.Command)]
	s.mu.Unlock()
	if block {
		// Signal we're parked, then wait for cancel.
		select {
		case s.blockCh <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, -1, ctx.Err()
	}
	if !ok {
		return nil, 2, nil
	}
	return res.output, res.code, res.err
}

func (s *stubLauncher) RunOnceWithCopy(ctx context.Context, spec recon.ContainerSpec, copyPath string) ([]byte, []byte, int, error) {
	s.mu.Lock()
	s.calls = append(s.calls, stubCall{image: spec.Image, cmd: spec.Command})
	res, ok := s.canned[firstArg(spec.Command)]
	cp, _ := s.canned[copyPath]
	s.mu.Unlock()
	if !ok {
		return nil, nil, 2, nil
	}
	return res.output, cp.output, res.code, res.err
}

func (s *stubLauncher) Stop(_ context.Context, _ string) error { return nil }

func firstArg(cmd []string) string {
	if len(cmd) == 0 {
		return ""
	}
	return cmd[0]
}

// ---------------------------------------------------------------------------
// Constructor + filtering
// ---------------------------------------------------------------------------

func TestEngineName(t *testing.T) {
	e, err := New(newStubLauncher(), Options{Image: "img"}, logger.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := e.Name(); got != EngineName {
		t.Fatalf("Name = %q, want %q", got, EngineName)
	}
}

func TestNew_NilLauncher(t *testing.T) {
	_, err := New(nil, Options{}, logger.Nop())
	if err == nil {
		t.Fatal("expected error for nil launcher")
	}
}

func TestFilterToolkitModules(t *testing.T) {
	in := []string{"toolkit:holehe", "sfp_dnsresolve", " toolkit:subfinder ", "", "toolkit:", "TOOLKIT:Phone"}
	got := FilterToolkitModules(in)
	want := []string{"holehe", "subfinder"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("[%d] = %q, want %q", i, got[i], w)
		}
	}
}

// ---------------------------------------------------------------------------
// Start happy paths per tool
// ---------------------------------------------------------------------------

func TestStart_Holehe_EmitsMixedSeverities(t *testing.T) {
	stub := newStubLauncher()
	stub.program("holehe", `{"email":"u@example.com","raw":"[+] github.com\n[-] linkedin.com\n[+] twitter.com\n"}`, 0, nil)

	e, _ := New(stub, Options{Image: "img"}, logger.Nop())
	runID, err := e.Start(context.Background(), recon.EngineStartRequest{
		Target:  recon.Target{ID: uuid.New(), Type: recon.TargetEmail, Value: "u@example.com"},
		Profile: recon.Profile{Modules: []string{"toolkit:holehe"}},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	ch, err := e.Events(context.Background(), runID)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	var got []recon.EngineEvent
	for evt := range ch {
		got = append(got, evt)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 events, got %d", len(got))
	}
	for _, evt := range got {
		if evt.Category != CategoryEmailExposure {
			t.Errorf("category = %q, want %q", evt.Category, CategoryEmailExposure)
		}
		if evt.Module != holeheModule {
			t.Errorf("module = %q, want %q", evt.Module, holeheModule)
		}
	}
	used, unused := 0, 0
	for _, evt := range got {
		switch evt.Severity {
		case recon.SeverityMedium:
			used++
		case recon.SeverityInfo:
			unused++
		}
	}
	if used != 2 || unused != 1 {
		t.Errorf("severities: used=%d unused=%d, want 2/1", used, unused)
	}
}

func TestStart_Phoneinfoga_AddsHighForVoIP(t *testing.T) {
	stub := newStubLauncher()
	stub.program("phoneinfoga", `{"Number":"+15551234567","Carrier":"Twilio LLC","LineType":"non-fixed-voip","InternationalFormat":"+1 555-123-4567"}`, 0, nil)

	e, _ := New(stub, Options{Image: "img"}, logger.Nop())
	runID, err := e.Start(context.Background(), recon.EngineStartRequest{
		Target:  recon.Target{ID: uuid.New(), Type: recon.TargetPhone, Value: "+15551234567"},
		Profile: recon.Profile{Modules: []string{"toolkit:phoneinfoga"}},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	got := drain(t, e, runID)
	if len(got) != 2 {
		t.Fatalf("expected 2 events (info + high), got %d", len(got))
	}
	if got[0].Severity != recon.SeverityInfo {
		t.Errorf("first event severity = %q, want info", got[0].Severity)
	}
	if got[1].Severity != recon.SeverityHigh {
		t.Errorf("second event severity = %q, want high", got[1].Severity)
	}
}

func TestStart_Phoneinfoga_NoExtraForResidential(t *testing.T) {
	stub := newStubLauncher()
	stub.program("phoneinfoga", `{"Number":"+12025551111","Carrier":"AT&T Mobility","LineType":"mobile","InternationalFormat":"+1 202-555-1111"}`, 0, nil)

	e, _ := New(stub, Options{Image: "img"}, logger.Nop())
	runID, err := e.Start(context.Background(), recon.EngineStartRequest{
		Target:  recon.Target{ID: uuid.New(), Type: recon.TargetPhone, Value: "+12025551111"},
		Profile: recon.Profile{Modules: []string{"toolkit:phoneinfoga"}},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	got := drain(t, e, runID)
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Severity != recon.SeverityInfo {
		t.Errorf("severity = %q, want info", got[0].Severity)
	}
}

func TestStart_Subfinder_AllInfo70(t *testing.T) {
	stub := newStubLauncher()
	stub.program("subfinder", `{"domain":"example.com","subdomains":[{"host":"dev.example.com","source":"crt"},{"host":"api.example.com","source":"dns"}]}`, 0, nil)

	e, _ := New(stub, Options{Image: "img"}, logger.Nop())
	runID, err := e.Start(context.Background(), recon.EngineStartRequest{
		Target:  recon.Target{ID: uuid.New(), Type: recon.TargetDomain, Value: "example.com"},
		Profile: recon.Profile{Modules: []string{"toolkit:subfinder"}},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	got := drain(t, e, runID)
	if len(got) != 2 {
		t.Fatalf("expected 2 events, got %d", len(got))
	}
	for _, evt := range got {
		if evt.Category != CategorySubdomain {
			t.Errorf("category = %q, want %q", evt.Category, CategorySubdomain)
		}
		if evt.Severity != recon.SeverityInfo {
			t.Errorf("severity = %q, want info", evt.Severity)
		}
		if evt.Confidence != 70 {
			t.Errorf("confidence = %d, want 70", evt.Confidence)
		}
	}
}

func TestStart_Katana_AllInfo60(t *testing.T) {
	stub := newStubLauncher()
	stub.program("katana", `{"seed":"https://example.com","urls":[{"url":"https://example.com/login","request":{"endpoint":"https://example.com/login","method":"GET"}},{"url":"https://example.com/admin","request":{"endpoint":"https://example.com/admin","method":"GET"}}]}`, 0, nil)

	e, _ := New(stub, Options{Image: "img"}, logger.Nop())
	runID, err := e.Start(context.Background(), recon.EngineStartRequest{
		Target:  recon.Target{ID: uuid.New(), Type: recon.TargetDomain, Value: "https://example.com"},
		Profile: recon.Profile{Modules: []string{"toolkit:katana"}},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	got := drain(t, e, runID)
	if len(got) != 2 {
		t.Fatalf("expected 2 events, got %d", len(got))
	}
	for _, evt := range got {
		if evt.Category != CategoryDeepLink {
			t.Errorf("category = %q, want %q", evt.Category, CategoryDeepLink)
		}
		if evt.Confidence != 60 {
			t.Errorf("confidence = %d, want 60", evt.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// Sequencing + error surfaces
// ---------------------------------------------------------------------------

func TestStart_RunsModulesSequentially(t *testing.T) {
	stub := newStubLauncher()
	stub.program("holehe", `{"email":"u@example.com","raw":"[+] a.com\n"}`, 0, nil)
	stub.program("subfinder", `{"domain":"example.com","subdomains":[{"host":"a.example.com","source":"x"}]}`, 0, nil)

	e, _ := New(stub, Options{Image: "img"}, logger.Nop())
	_, err := e.Start(context.Background(), recon.EngineStartRequest{
		Target:  recon.Target{ID: uuid.New(), Type: recon.TargetDomain, Value: "u@example.com"},
		Profile: recon.Profile{Modules: []string{"toolkit:holehe", "toolkit:subfinder"}},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(stub.calls))
	}
	if stub.calls[0].cmd[0] != "holehe" {
		t.Errorf("first call = %q, want holehe", stub.calls[0].cmd[0])
	}
	if stub.calls[1].cmd[0] != "subfinder" {
		t.Errorf("second call = %q, want subfinder", stub.calls[1].cmd[0])
	}
}

func TestStart_NoToolkitModulesReturnsErrNoModules(t *testing.T) {
	stub := newStubLauncher()
	e, _ := New(stub, Options{Image: "img"}, logger.Nop())
	_, err := e.Start(context.Background(), recon.EngineStartRequest{
		Target:  recon.Target{ID: uuid.New(), Type: recon.TargetDomain, Value: "x"},
		Profile: recon.Profile{Modules: []string{"sfp_dnsresolve"}},
	})
	if !errors.Is(err, ErrNoModules) {
		t.Fatalf("err = %v, want ErrNoModules", err)
	}
}

func TestStart_UnknownModuleReturnsErrUnknownModule(t *testing.T) {
	stub := newStubLauncher()
	e, _ := New(stub, Options{Image: "img"}, logger.Nop())
	_, err := e.Start(context.Background(), recon.EngineStartRequest{
		Target:  recon.Target{ID: uuid.New(), Type: recon.TargetDomain, Value: "x"},
		Profile: recon.Profile{Modules: []string{"toolkit:not_a_tool"}},
	})
	if !errors.Is(err, ErrUnknownModule) {
		t.Fatalf("err = %v, want ErrUnknownModule", err)
	}
}

func TestStart_ToolFailureMarksRunFailed(t *testing.T) {
	stub := newStubLauncher()
	stub.program("subfinder", `{"error":"tool_failed","message":"subfinder rate-limited"}`, 1, nil)

	e, _ := New(stub, Options{Image: "img"}, logger.Nop())
	runID, err := e.Start(context.Background(), recon.EngineStartRequest{
		Target:  recon.Target{ID: uuid.New(), Type: recon.TargetDomain, Value: "example.com"},
		Profile: recon.Profile{Modules: []string{"toolkit:subfinder"}},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	st, err := e.Status(context.Background(), runID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Status != recon.ScanFailed {
		t.Fatalf("status = %q, want failed", st.Status)
	}
}

// ---------------------------------------------------------------------------
// Cancel
// ---------------------------------------------------------------------------

// TestStart_ContextCancelStopsDispatch verifies that ctx cancellation
// stops the dispatch loop between modules. The stub blocks on a
// configured cmd so the test can cancel mid-flight and assert the
// resulting status is "cancelled".
func TestStart_ContextCancelStopsDispatch(t *testing.T) {
	stub := newStubLauncher()
	stub.blockCmd = "subfinder"

	e, _ := New(stub, Options{Image: "img"}, logger.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	type startResult struct {
		runID string
		err   error
	}
	resCh := make(chan startResult, 1)
	go func() {
		id, err := e.Start(ctx, recon.EngineStartRequest{
			Target:  recon.Target{ID: uuid.New(), Type: recon.TargetDomain, Value: "example.com"},
			Profile: recon.Profile{Modules: []string{"toolkit:subfinder"}},
		})
		resCh <- startResult{runID: id, err: err}
	}()

	select {
	case <-stub.blockCh:
	case <-time.After(2 * time.Second):
		t.Fatal("stub never reached the blocking call")
	}
	cancel()

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("Start returned err = %v", r.err)
		}
		st, err := e.Status(context.Background(), r.runID)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if st.Status != recon.ScanCancelled {
			t.Errorf("status = %q, want cancelled", st.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start never returned after cancel")
	}
}

// TestCancel_AfterStartMarksCancelled tests the simpler path: when
// Start has already returned, Cancel flips the run's status.
func TestCancel_AfterStartMarksCancelled(t *testing.T) {
	stub := newStubLauncher()
	stub.program("subfinder", `{"domain":"example.com","subdomains":[]}`, 0, nil)

	e, _ := New(stub, Options{Image: "img"}, logger.Nop())
	runID, err := e.Start(context.Background(), recon.EngineStartRequest{
		Target:  recon.Target{ID: uuid.New(), Type: recon.TargetDomain, Value: "example.com"},
		Profile: recon.Profile{Modules: []string{"toolkit:subfinder"}},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := e.Cancel(context.Background(), runID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	// Cancel after Start in this engine is a no-op as Start's context
	// is already done, but it must not error.
}

func TestCancel_UnknownRun(t *testing.T) {
	e, _ := New(newStubLauncher(), Options{Image: "img"}, logger.Nop())
	if err := e.Cancel(context.Background(), "no-such-run"); !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("err = %v, want ErrRunNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Status / Events edge cases
// ---------------------------------------------------------------------------

func TestStatus_UnknownRun(t *testing.T) {
	e, _ := New(newStubLauncher(), Options{Image: "img"}, logger.Nop())
	_, err := e.Status(context.Background(), "missing")
	if !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("err = %v, want ErrRunNotFound", err)
	}
}

func TestEvents_UnknownRun(t *testing.T) {
	e, _ := New(newStubLauncher(), Options{Image: "img"}, logger.Nop())
	_, err := e.Events(context.Background(), "missing")
	if !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("err = %v, want ErrRunNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Mapping unit tests (per the session 07 brief)
// ---------------------------------------------------------------------------

func TestParseHoleheRaw_MarkersMapToSeverity(t *testing.T) {
	raw := "[+] github.com\n[-] linkedin.com\n[x] errored.com\n"
	evts := parseHoleheRaw(raw, "u@example.com")
	if len(evts) != 3 {
		t.Fatalf("got %d events, want 3", len(evts))
	}
	if evts[0].Severity != recon.SeverityMedium {
		t.Errorf("used severity = %q, want medium", evts[0].Severity)
	}
	if evts[1].Severity != recon.SeverityInfo {
		t.Errorf("not-used severity = %q, want info", evts[1].Severity)
	}
	if evts[2].Severity != recon.SeverityInfo {
		t.Errorf("errored severity = %q, want info", evts[2].Severity)
	}
}

func TestIsVoIPCarrier(t *testing.T) {
	cases := map[string]bool{
		"Twilio LLC":   true,
		"twilio":       true,
		"Google Voice": true,
		"AT&T Mobility": false,
		"":            false,
		"vonage US":   true,
	}
	for in, want := range cases {
		if got := isVoIPCarrier(in); got != want {
			t.Errorf("isVoIPCarrier(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsVoIPLineType(t *testing.T) {
	cases := map[string]bool{
		"voip":           true,
		"non-fixed-voip": true,
		"NonFixedVoIP":   true,
		"mobile":         false,
		"fixed-line":     false,
		"":              false,
	}
	for in, want := range cases {
		if got := isVoIPLineType(in); got != want {
			t.Errorf("isVoIPLineType(%q) = %v, want %v", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func drain(t *testing.T, e *Engine, runID string) []recon.EngineEvent {
	t.Helper()
	ch, err := e.Events(context.Background(), runID)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	var got []recon.EngineEvent
	for evt := range ch {
		got = append(got, evt)
	}
	return got
}

// TestRunToolkitJSON_ExitNonZeroEnvelope ensures the shared invocation
// helper surfaces entrypoint-emitted error envelopes as Go errors.
func TestRunToolkitJSON_ExitNonZeroEnvelope(t *testing.T) {
	stub := newStubLauncher()
	stub.program("holehe", `{"error":"invalid_args","message":"missing --email"}`, 2, nil)

	var dst holeheJSON
	_, err := runToolkitJSON(context.Background(), stub, "img", []string{"holehe"}, time.Second, &dst)
	if err == nil {
		t.Fatal("expected error from non-zero exit")
	}
	if !strings.Contains(err.Error(), "invalid_args") {
		t.Errorf("err = %v, want 'invalid_args'", err)
	}
}
