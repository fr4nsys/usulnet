// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeEvaluator implements the Evaluator interface for proxy tests
// without spinning up a full service + repo.
type fakeEvaluator struct {
	mu    sync.Mutex
	allow map[string]bool
	err   error

	deniedMu sync.Mutex
	denied   []string
}

func newFakeEvaluator() *fakeEvaluator { return &fakeEvaluator{allow: map[string]bool{}} }

func (f *fakeEvaluator) setAllow(host string, allow bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allow[host] = allow
}

func (f *fakeEvaluator) Evaluate(_ context.Context, _ uuid.UUID, target string) (EvaluateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return EvaluateResult{}, f.err
	}
	allow, ok := f.allow[target]
	res := EvaluateResult{Allow: allow, PolicyCount: 1}
	if !ok {
		// Mimic the service: no rule = deny when at least one policy is
		// declared. PolicyCount stays > 0 for tests.
		res.Allow = false
	}
	return res, nil
}

func (f *fakeEvaluator) RecordDeny(_ context.Context, _ uuid.UUID, target, _ string) {
	f.deniedMu.Lock()
	defer f.deniedMu.Unlock()
	f.denied = append(f.denied, target)
}

func (f *fakeEvaluator) deniesFor(target string) int {
	f.deniedMu.Lock()
	defer f.deniedMu.Unlock()
	n := 0
	for _, t := range f.denied {
		if t == target {
			n++
		}
	}
	return n
}

// freePort returns an OS-assigned free TCP port for the test's proxy
// listener. Avoids hard-coded :18080 which would collide with parallel
// test runs.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func startProxy(t *testing.T, eval Evaluator) *Proxy {
	t.Helper()
	p := NewProxy(ProxyConfig{
		ListenAddr:  freePort(t),
		HostID:      uuid.New(),
		DialTimeout: 2 * time.Second,
	}, eval, nil)
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Stop(ctx)
	})
	// Tiny sleep so the goroutine binds before clients connect. Without
	// this the first request races the listener.
	time.Sleep(20 * time.Millisecond)
	return p
}

// ---------------------------------------------------------------------------
// HTTP (absolute-form) — allow + deny
// ---------------------------------------------------------------------------

func TestProxy_AbsoluteForm_Allowed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	eval := newFakeEvaluator()
	eval.setAllow(upstreamURL.Hostname(), true)
	proxy := startProxy(t, eval)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxy.Addr()})},
		Timeout:   3 * time.Second,
	}
	resp, err := client.Get(upstream.URL + "/path")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello-from-upstream" {
		t.Fatalf("unexpected response: status=%d body=%q", resp.StatusCode, body)
	}
}

func TestProxy_AbsoluteForm_Denied(t *testing.T) {
	eval := newFakeEvaluator()
	// No allow entry for evil.example → denied. Use a host that won't
	// resolve to avoid hitting real DNS in the off-chance the proxy
	// forwards.
	proxy := startProxy(t, eval)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxy.Addr()})},
		Timeout:   3 * time.Second,
	}
	resp, err := client.Get("http://evil.example.invalid/")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Egress-Decision"); got != "deny" {
		t.Errorf("expected X-Egress-Decision=deny, got %q", got)
	}
	if got := eval.deniesFor("evil.example.invalid"); got != 1 {
		t.Errorf("expected 1 recorded deny, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// CONNECT — allow + deny
// ---------------------------------------------------------------------------

func TestProxy_Connect_Allowed_TunnelsBytes(t *testing.T) {
	// HTTPS upstream so CONNECT is the right protocol. The client
	// trusts the upstream's TLS cert via httptest's transport.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tunneled-bytes")
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	eval := newFakeEvaluator()
	eval.setAllow(upstreamURL.Hostname(), true)
	proxy := startProxy(t, eval)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: proxy.Addr()}),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(upstream.URL + "/path")
	if err != nil {
		t.Fatalf("GET via CONNECT: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "tunneled-bytes" {
		t.Fatalf("unexpected response: status=%d body=%q", resp.StatusCode, body)
	}
}

func TestProxy_Connect_Denied(t *testing.T) {
	eval := newFakeEvaluator()
	proxy := startProxy(t, eval)

	// Issue a raw CONNECT request and read the proxy's response. The
	// stdlib http client wraps CONNECT failures inside a transport
	// error, so a raw TCP dial gives us the exact wire response.
	conn, err := net.DialTimeout("tcp", proxy.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT evil.example.invalid:443 HTTP/1.1\r\nHost: evil.example.invalid:443\r\n\r\n")
	if err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on CONNECT deny, got %d", resp.StatusCode)
	}
	if got := eval.deniesFor("evil.example.invalid"); got != 1 {
		t.Errorf("expected 1 recorded deny, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Lifecycle: Start/Stop, no listen-leak after Stop
// ---------------------------------------------------------------------------

func TestProxy_StopIsIdempotentAndGraceful(t *testing.T) {
	addr := freePort(t)
	eval := newFakeEvaluator()
	p := NewProxy(ProxyConfig{ListenAddr: addr, HostID: uuid.New(), DialTimeout: time.Second}, eval, nil)
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatalf("first stop: %v", err)
	}
	// Stop is safe to call again on an already-stopped proxy.
	if err := p.Stop(context.Background()); err != nil {
		t.Fatalf("second stop: %v", err)
	}
	// And on a never-started proxy.
	p2 := NewProxy(ProxyConfig{ListenAddr: freePort(t), HostID: uuid.New()}, eval, nil)
	if err := p2.Stop(context.Background()); err != nil {
		t.Fatalf("stop without start: %v", err)
	}
}

func TestProxy_Evaluator_Error_ReturnsBadGateway(t *testing.T) {
	eval := newFakeEvaluator()
	eval.err = errors.New("simulated")
	proxy := startProxy(t, eval)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxy.Addr()})},
		Timeout:   3 * time.Second,
	}
	resp, err := client.Get("http://anything.invalid/")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 on evaluator error, got %d", resp.StatusCode)
	}
}
