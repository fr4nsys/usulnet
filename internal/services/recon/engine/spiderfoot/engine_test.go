// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package spiderfoot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// fixturePath resolves a fixture file relative to the test file.
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("fixtures", name)
}

// loadFixture reads a fixture file or fails the test.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(fixturePath(t, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// fakeServer is a programmable httptest.Server that returns fixtures
// per request path and tracks the form values it received so tests
// can assert what the client sent.
type fakeServer struct {
	mu        sync.Mutex
	server    *httptest.Server
	responses map[string][]byte // path → body
	statuses  map[string]int    // path → http status (default 200)

	// statusSeq lets a test return different /scanstatus bodies on
	// successive calls (e.g., RUNNING then FINISHED).
	statusSeq    [][]byte
	statusCalled int32

	// captured form values per path
	lastForm map[string]url.Values
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{
		responses: map[string][]byte{},
		statuses:  map[string]int{},
		lastForm:  map[string]url.Values{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/scanstartlist", fs.handle)
	mux.HandleFunc("/scanstatus", fs.handleStatus)
	mux.HandleFunc("/scaneventresults", fs.handle)
	mux.HandleFunc("/scandelete", fs.handle)
	fs.server = httptest.NewServer(mux)
	t.Cleanup(fs.server.Close)
	return fs
}

func (f *fakeServer) URL() string { return f.server.URL }

func (f *fakeServer) set(path string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[path] = body
}

func (f *fakeServer) setStatus(path string, code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses[path] = code
}

func (f *fakeServer) setStatusSequence(bodies [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusSeq = bodies
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.lastForm[r.URL.Path] = r.Form
	body := f.responses[r.URL.Path]
	code := f.statuses[r.URL.Path]
	f.mu.Unlock()
	if code == 0 {
		code = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if body != nil {
		_, _ = w.Write(body)
	}
}

func (f *fakeServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.lastForm[r.URL.Path] = r.Form
	var body []byte
	if len(f.statusSeq) > 0 {
		idx := int(atomic.AddInt32(&f.statusCalled, 1)) - 1
		if idx >= len(f.statusSeq) {
			idx = len(f.statusSeq) - 1
		}
		body = f.statusSeq[idx]
	} else {
		body = f.responses[r.URL.Path]
	}
	code := f.statuses[r.URL.Path]
	f.mu.Unlock()
	if code == 0 {
		code = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if body != nil {
		_, _ = w.Write(body)
	}
}

func (f *fakeServer) lastFormFor(path string) url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastForm[path]
}

func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	c, err := NewClient(baseURL, time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func newTestEngine(t *testing.T, baseURL string) *Engine {
	t.Helper()
	c := newTestClient(t, baseURL)
	e, err := New(c, Options{
		PollInterval:  20 * time.Millisecond,
		CancelTimeout: 2 * time.Second,
		EventChanSize: 16,
	}, logger.Nop())
	if err != nil {
		t.Fatalf("New engine: %v", err)
	}
	return e
}

func sampleStartRequest() recon.EngineStartRequest {
	id := uuid.MustParse("6e3c1c5a-19a8-4b9c-9f0f-1d2e3f4a5b6c")
	return recon.EngineStartRequest{
		Target: recon.Target{
			ID:    id,
			Type:  recon.TargetDomain,
			Value: "example.com",
		},
		Profile: recon.Profile{
			Name:    "domain-surface",
			Modules: []string{"sfp_dnsresolve", "sfp_crt", "toolkit:subfinder"},
		},
	}
}

func TestEngineName(t *testing.T) {
	t.Parallel()
	e, err := New(&Client{baseURL: "http://x"}, Options{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := e.Name(); got != "spiderfoot" {
		t.Errorf("Name() = %q, want %q", got, "spiderfoot")
	}
}

func TestNewClient_RejectsEmptyURL(t *testing.T) {
	t.Parallel()
	if _, err := NewClient("", 0); err == nil {
		t.Fatalf("expected error for empty URL")
	}
}

func TestNewClient_TrimsTrailingSlash(t *testing.T) {
	t.Parallel()
	c, err := NewClient("http://example.test/", 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.BaseURL() != "http://example.test" {
		t.Errorf("BaseURL = %q, want trailing slash trimmed", c.BaseURL())
	}
}

func TestStart_HappyPath(t *testing.T) {
	t.Parallel()
	fs := newFakeServer(t)
	fs.set("/scanstartlist", loadFixture(t, "scanstartlist_success.json"))

	e := newTestEngine(t, fs.URL())

	id, err := e.Start(context.Background(), sampleStartRequest())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if id != "5C7E3F8A4B6D4E2F9A1C8B7D6E5F4A3B" {
		t.Errorf("run ID = %q, want fixture id", id)
	}

	form := fs.lastFormFor("/scanstartlist")
	if form.Get("scantarget") != "example.com" {
		t.Errorf("scantarget = %q, want example.com", form.Get("scantarget"))
	}
	if got := form.Get("scanname"); got != "usulnet/6e3c1c5a-19a8-4b9c-9f0f-1d2e3f4a5b6c" {
		t.Errorf("scanname = %q, want deterministic usulnet/<uuid>", got)
	}
	ml := form.Get("modulelist")
	if !strings.Contains(ml, "module_sfp_dnsresolve") || !strings.Contains(ml, "module_sfp_crt") {
		t.Errorf("modulelist = %q, want module_ prefixed SpiderFoot modules", ml)
	}
	if strings.Contains(ml, "toolkit") {
		t.Errorf("modulelist = %q, must not contain toolkit: modules", ml)
	}
}

func TestStart_ErrorResponse(t *testing.T) {
	t.Parallel()
	fs := newFakeServer(t)
	fs.set("/scanstartlist", loadFixture(t, "scanstartlist_error.json"))
	e := newTestEngine(t, fs.URL())

	_, err := e.Start(context.Background(), sampleStartRequest())
	if err == nil {
		t.Fatal("expected error from ERROR response")
	}
	if !strings.Contains(err.Error(), "Invalid target type") {
		t.Errorf("error = %v, want SpiderFoot error message", err)
	}
}

func TestStart_NoSpiderFootModules(t *testing.T) {
	t.Parallel()
	fs := newFakeServer(t)
	e := newTestEngine(t, fs.URL())
	req := sampleStartRequest()
	req.Profile.Modules = []string{"toolkit:phoneinfoga", "toolkit:holehe"}

	_, err := e.Start(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "no SpiderFoot modules") {
		t.Fatalf("expected ErrNoModules, got %v", err)
	}
}

func TestEvents_CompletesOnFinished(t *testing.T) {
	t.Parallel()
	fs := newFakeServer(t)
	fs.set("/scaneventresults", loadFixture(t, "scaneventresults_full.json"))
	fs.setStatusSequence([][]byte{
		loadFixture(t, "scanstatus_running.json"),
		loadFixture(t, "scanstatus_finished.json"),
	})
	e := newTestEngine(t, fs.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := e.Events(ctx, "abc123")
	if err != nil {
		t.Fatalf("Events: %v", err)
	}

	var received []recon.EngineEvent
	for evt := range ch {
		received = append(received, evt)
	}
	if len(received) < 5 {
		t.Errorf("got %d events, want >= 5 (fixture has 8)", len(received))
	}
	// Spot check: dedup keeps each fixture hash unique.
	seen := map[string]struct{}{}
	for _, evt := range received {
		if _, dup := seen[evt.Value+evt.Module]; dup {
			t.Errorf("duplicate event for %s/%s", evt.Module, evt.Value)
		}
		seen[evt.Value+evt.Module] = struct{}{}
	}
	// Mapping spot check: an INTERNET_NAME event should land in
	// category "domain".
	found := false
	for _, evt := range received {
		if evt.Value == "www.example.com" {
			found = true
			if evt.Category != "domain" {
				t.Errorf("www.example.com category = %q, want domain", evt.Category)
			}
		}
	}
	if !found {
		t.Errorf("expected www.example.com event in stream")
	}
}

func TestEvents_StopsOnContextCancel(t *testing.T) {
	t.Parallel()
	fs := newFakeServer(t)
	fs.set("/scaneventresults", []byte("[]"))
	fs.set("/scanstatus", loadFixture(t, "scanstatus_running.json"))
	e := newTestEngine(t, fs.URL())

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := e.Events(ctx, "abc")
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	cancel()

	deadline := time.After(time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return // channel closed — success
			}
		case <-deadline:
			t.Fatal("Events channel did not close after context cancel")
		}
	}
}

func TestEvents_StopsOnErrorStatus(t *testing.T) {
	t.Parallel()
	fs := newFakeServer(t)
	fs.set("/scaneventresults", []byte("[]"))
	fs.set("/scanstatus", loadFixture(t, "scanstatus_error_failed.json"))
	e := newTestEngine(t, fs.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := e.Events(ctx, "abc")
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	for range ch {
	}
}

func TestCancel_HappyPath(t *testing.T) {
	t.Parallel()
	fs := newFakeServer(t)
	fs.set("/scandelete", loadFixture(t, "scandelete_success.json"))
	fs.setStatusSequence([][]byte{
		loadFixture(t, "scanstatus_running.json"),
		loadFixture(t, "scanstatus_aborted.json"),
	})
	e := newTestEngine(t, fs.URL())

	if err := e.Cancel(context.Background(), "abc"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
}

func TestCancel_TimesOut(t *testing.T) {
	t.Parallel()
	fs := newFakeServer(t)
	fs.set("/scandelete", loadFixture(t, "scandelete_success.json"))
	fs.set("/scanstatus", loadFixture(t, "scanstatus_running.json"))
	c, _ := NewClient(fs.URL(), time.Second)
	e, _ := New(c, Options{
		PollInterval:  10 * time.Millisecond,
		CancelTimeout: 50 * time.Millisecond,
	}, logger.Nop())

	err := e.Cancel(context.Background(), "abc")
	if err == nil {
		t.Fatal("expected ErrCancelTimeout")
	}
	if !strings.Contains(err.Error(), "cancel timed out") {
		t.Errorf("err = %v, want cancel timeout", err)
	}
}

func TestStatus_AllTransitions(t *testing.T) {
	t.Parallel()
	fs := newFakeServer(t)
	e := newTestEngine(t, fs.URL())

	cases := []struct {
		fixture string
		want    recon.ScanStatus
	}{
		{"scanstatus_running.json", recon.ScanRunning},
		{"scanstatus_finished.json", recon.ScanCompleted},
		{"scanstatus_aborted.json", recon.ScanCancelled},
		{"scanstatus_error_failed.json", recon.ScanFailed},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.fixture, func(t *testing.T) {
			fs.set("/scanstatus", loadFixture(t, tc.fixture))
			st, err := e.Status(context.Background(), "abc")
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if st.Status != tc.want {
				t.Errorf("status = %q, want %q", st.Status, tc.want)
			}
		})
	}
}

func TestMapStatus_UnknownFallsToRunning(t *testing.T) {
	t.Parallel()
	if got := mapStatus("WAT-UNEXPECTED"); got != recon.ScanRunning {
		t.Errorf("mapStatus(unknown) = %q, want ScanRunning", got)
	}
	if got := mapStatus(""); got != recon.ScanRunning {
		t.Errorf("mapStatus(empty) = %q, want ScanRunning", got)
	}
	if got := mapStatus("ERROR-ANYTHING"); got != recon.ScanFailed {
		t.Errorf("mapStatus(ERROR-*) = %q, want ScanFailed", got)
	}
}

func TestFilterSpiderFootModules(t *testing.T) {
	t.Parallel()
	got := FilterSpiderFootModules([]string{
		"sfp_dnsresolve",
		"toolkit:phoneinfoga",
		"  sfp_crt  ",
		"",
		"toolkit:holehe",
	})
	want := []string{"sfp_dnsresolve", "sfp_crt"}
	if len(got) != len(want) {
		t.Fatalf("filtered = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("filtered[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMapEventType_TableExhaustive(t *testing.T) {
	t.Parallel()
	// Every entry must produce a non-empty category and a real
	// severity value.
	for _, evt := range KnownEventTypes() {
		m := MapEventType(evt)
		if m.Category == "" {
			t.Errorf("%s: empty category", evt)
		}
		switch m.Severity {
		case recon.SeverityInfo, recon.SeverityLow, recon.SeverityMedium,
			recon.SeverityHigh, recon.SeverityCritical:
		default:
			t.Errorf("%s: unknown severity %q", evt, m.Severity)
		}
		if m.Confidence < 0 || m.Confidence > 100 {
			t.Errorf("%s: confidence out of range: %d", evt, m.Confidence)
		}
	}
}

// TestMapEventType_BuiltinProfileTypes asserts the table covers every
// SpiderFoot event type that the four built-in profiles can produce.
// The list mirrors the modules in migration 044.
func TestMapEventType_BuiltinProfileTypes(t *testing.T) {
	t.Parallel()
	required := []string{
		// email-exposure-lite
		"EMAILADDR", "BREACH_DATA", "EMAILADDR_COMPROMISED",
		"MALICIOUS_EMAILADDR", "SOCIAL_MEDIA", "ACCOUNT_EXTERNAL_OWNED",
		"RAW_RIR_DATA",
		// domain-surface
		"IP_ADDRESS", "INTERNET_NAME", "AFFILIATE_DOMAIN_NAME",
		"AFFILIATE_INTERNET_NAME", "DOMAIN_NAME",
		"SSL_CERTIFICATE_ISSUED", "SSL_CERTIFICATE_ISSUER",
		// username-presence
		"USERNAME", "HUMAN_NAME",
		// phone-public-info (handled by toolkit; SpiderFoot has none)
	}
	for _, evt := range required {
		m := MapEventType(evt)
		if m == UnknownMapping {
			t.Errorf("%s: not in mapping table", evt)
		}
	}
}

func TestMapEventType_UnknownFallback(t *testing.T) {
	t.Parallel()
	m := MapEventType("THIS_TYPE_DOES_NOT_EXIST_IN_SPIDERFOOT")
	if m.Category != "unknown" {
		t.Errorf("unknown category = %q, want unknown", m.Category)
	}
	if m.Severity != recon.SeverityInfo {
		t.Errorf("unknown severity = %q, want info", m.Severity)
	}
	if m.Confidence != 20 {
		t.Errorf("unknown confidence = %d, want 20", m.Confidence)
	}
}

func TestClient_ScanEventResults_ParsesFixture(t *testing.T) {
	t.Parallel()
	fs := newFakeServer(t)
	fs.set("/scaneventresults", loadFixture(t, "scaneventresults_partial.json"))
	c := newTestClient(t, fs.URL())

	events, err := c.ScanEventResults(context.Background(), "abc")
	if err != nil {
		t.Fatalf("ScanEventResults: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	if events[1].EventType != "IP_ADDRESS" || events[1].Data != "93.184.216.34" {
		t.Errorf("event[1] = %+v, want IP_ADDRESS row", events[1])
	}
	if events[1].Hash == "" {
		t.Errorf("expected hash to be parsed")
	}
}

func TestClient_ScanStatus_NotFound(t *testing.T) {
	t.Parallel()
	fs := newFakeServer(t)
	fs.set("/scanstatus", []byte("[]"))
	c := newTestClient(t, fs.URL())

	_, err := c.ScanStatus(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected ErrScanNotFound")
	}
}

func TestClient_StartScan_SendsModulePrefix(t *testing.T) {
	t.Parallel()
	fs := newFakeServer(t)
	fs.set("/scanstartlist", loadFixture(t, "scanstartlist_success.json"))
	c := newTestClient(t, fs.URL())

	_, err := c.StartScan(context.Background(), "n", "example.com",
		[]string{"sfp_dnsresolve", "module_sfp_crt"})
	if err != nil {
		t.Fatalf("StartScan: %v", err)
	}
	form := fs.lastFormFor("/scanstartlist")
	ml := form.Get("modulelist")
	// Already-prefixed entries are not double-prefixed.
	if strings.Contains(ml, "module_module_") {
		t.Errorf("modulelist double-prefixed: %q", ml)
	}
	for _, want := range []string{"module_sfp_dnsresolve", "module_sfp_crt"} {
		if !strings.Contains(ml, want) {
			t.Errorf("modulelist missing %q in %q", want, ml)
		}
	}
}
