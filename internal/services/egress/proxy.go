// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet
//
// proxy.go is the in-process HTTP forward proxy half of internal/services/
// egress. It listens on a configurable TCP port, accepts forward-proxy
// requests (absolute-form GET / POST, CONNECT for TLS), evaluates each
// against the operator's per-host policies, and either forwards or
// returns 403. The proxy never decrypts TLS; CONNECT is evaluated on
// the cleartext Host header and then bytes are tunneled.

package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Evaluator is the narrow surface Proxy needs from *Service. Declared
// here so the proxy can be unit-tested with a fake without spinning up
// the full service stack.
type Evaluator interface {
	Evaluate(ctx context.Context, hostID uuid.UUID, target string) (EvaluateResult, error)
	RecordDeny(ctx context.Context, hostID uuid.UUID, target, method string)
}

// ProxyConfig configures the forward proxy listener.
type ProxyConfig struct {
	// ListenAddr is the TCP address the proxy binds to. Default ":18080".
	ListenAddr string

	// HostID is the host UUID whose policies the proxy enforces. In
	// standalone mode this is the default host; multi-host installs
	// would need separate listeners per host (out of scope for v26.5.2).
	HostID uuid.UUID

	// DialTimeout caps the time spent dialing the upstream for both
	// CONNECT and absolute-form requests. Default 10s.
	DialTimeout time.Duration

	// ReadHeaderTimeout protects against slowloris clients. Default 10s.
	ReadHeaderTimeout time.Duration
}

// Proxy is the forward-proxy listener. Start launches the listener in
// a goroutine; Stop performs a graceful shutdown.
type Proxy struct {
	cfg       ProxyConfig
	eval      Evaluator
	logger    *logger.Logger
	transport *http.Transport

	mu      sync.Mutex
	server  *http.Server
	started bool
}

// NewProxy wires a proxy. Caller must call Start(ctx) to bring it up.
func NewProxy(cfg ProxyConfig, eval Evaluator, log *logger.Logger) *Proxy {
	if log == nil {
		log = logger.Nop()
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":18080"
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.ReadHeaderTimeout == 0 {
		cfg.ReadHeaderTimeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: cfg.DialTimeout}
	return &Proxy{
		cfg:    cfg,
		eval:   eval,
		logger: log.Named("egress.proxy"),
		transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   cfg.DialTimeout,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// The forward proxy is on a trusted local network; disable
			// HTTP/2 to keep transport behavior predictable — h2 over
			// plaintext is rare for outbound traffic.
			ForceAttemptHTTP2: false,
		},
	}
}

// Addr returns the configured listener address.
func (p *Proxy) Addr() string { return p.cfg.ListenAddr }

// Start binds the listener and serves forward-proxy requests in a
// goroutine. Returns an error only if the bind itself fails. Subsequent
// Start calls are no-ops.
func (p *Proxy) Start(_ context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return nil
	}
	ln, err := net.Listen("tcp", p.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("egress proxy listen %s: %w", p.cfg.ListenAddr, err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(p.handle),
		ReadHeaderTimeout: p.cfg.ReadHeaderTimeout,
	}
	p.server = srv
	p.started = true
	// Capture srv locally so Stop() niling p.server cannot race the
	// goroutine into a nil-deref before Serve has started.
	go func() {
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.logger.Error("egress proxy serve stopped", "error", err)
		}
	}()
	p.logger.Info("egress proxy listening", "addr", p.cfg.ListenAddr, "host_id", p.cfg.HostID)
	return nil
}

// Stop performs a graceful shutdown. Safe to call multiple times and on
// a non-started proxy.
func (p *Proxy) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started || p.server == nil {
		return nil
	}
	err := p.server.Shutdown(ctx)
	p.started = false
	p.server = nil
	return err
}

// handle is the single forward-proxy handler. CONNECT goes to handleConnect;
// everything else is treated as an absolute-form proxy GET/POST.
func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	target := requestHost(r)
	if target == "" {
		http.Error(w, "egress: missing host", http.StatusBadRequest)
		return
	}
	res, err := p.eval.Evaluate(r.Context(), p.cfg.HostID, target)
	if err != nil {
		p.logger.Warn("egress: evaluate failed", "target", target, "error", err)
		http.Error(w, "egress: evaluator error", http.StatusBadGateway)
		return
	}
	if !res.Allow {
		p.eval.RecordDeny(r.Context(), p.cfg.HostID, target, r.Method)
		w.Header().Set("X-Egress-Decision", "deny")
		http.Error(w, "egress denied by policy: "+target, http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// requestHost extracts the bare hostname (port stripped) from a forward-
// proxy request. CONNECT uses r.Host ("example.com:443"); absolute-form
// requests use r.URL.Host (set by the http server when the request line
// is "GET http://example.com/path HTTP/1.1").
func requestHost(r *http.Request) string {
	h := r.Host
	if r.URL != nil && r.URL.Host != "" {
		h = r.URL.Host
	}
	// Strip port — IPv6 form "[::1]:443" needs the bracketed split.
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		return hostOnly
	}
	return h
}

// handleConnect tunnels bytes between the client and the upstream after
// the policy allow. The proxy never sees the TLS plaintext.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}
	dst, err := net.DialTimeout("tcp", target, p.cfg.DialTimeout)
	if err != nil {
		http.Error(w, "egress: dial target: "+err.Error(), http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = dst.Close()
		http.Error(w, "egress: hijack not supported", http.StatusInternalServerError)
		return
	}
	src, _, err := hijacker.Hijack()
	if err != nil {
		_ = dst.Close()
		http.Error(w, "egress: hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.WriteString(src, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = src.Close()
		_ = dst.Close()
		return
	}

	// Bidirectional copy. When either side EOFs we close the other end
	// to unblock the paired io.Copy. Close errors are intentionally
	// ignored — the connection is already done.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(dst, src)
		_ = dst.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(src, dst)
		_ = src.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}

// handleHTTP forwards an absolute-form HTTP request to the upstream
// and copies the response back. Hop-by-hop headers per RFC 7230 §6.1
// are stripped before forwarding.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || r.URL.Host == "" {
		http.Error(w, "egress: not an absolute-form request", http.StatusBadRequest)
		return
	}
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	// The transport requires a scheme. The proxy only handles cleartext
	// HTTP via absolute-form here; HTTPS arrives via CONNECT.
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	stripHopByHop(outReq.Header)

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "egress: upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	stripHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// hopByHopHeaders are connection-scoped per RFC 7230 §6.1 and must not
// be forwarded by a proxy.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func stripHopByHop(h http.Header) {
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
