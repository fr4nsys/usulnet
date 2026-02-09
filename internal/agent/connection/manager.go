// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package connection provides NATS connection management for the usulnet agent.
package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// State represents the connection state.
type State int

const (
	StateDisconnected State = iota
	StateConnecting
	StateConnected
	StateReconnecting
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// Config holds connection configuration.
type Config struct {
	URL           string
	Token         string
	Name          string
	MaxReconnects int
	ReconnectWait time.Duration
	PingInterval  time.Duration
	MaxPingsOut   int
	Timeout       time.Duration
	// TLS
	TLSEnabled bool
	TLSCert    string
	TLSKey     string
	TLSCA      string
	TLSSkipVerify bool
}

// DefaultConfig returns default connection configuration.
func DefaultConfig() Config {
	return Config{
		URL:           nats.DefaultURL,
		MaxReconnects: -1, // Infinite
		ReconnectWait: 5 * time.Second,
		PingInterval:  2 * time.Minute,
		MaxPingsOut:   2,
		Timeout:       10 * time.Second,
	}
}

// Manager manages the NATS connection for the agent.
type Manager struct {
	config    Config
	conn      *nats.Conn
	state     State
	stateMu   sync.RWMutex
	log       *logger.Logger

	// Callbacks
	onConnect    func()
	onDisconnect func(error)
	onReconnect  func()

	// Metrics
	connectCount    int
	disconnectCount int
	lastConnectTime time.Time
	lastError       error
	metricsMu       sync.RWMutex
}

// NewManager creates a new connection manager.
func NewManager(cfg Config, log *logger.Logger) *Manager {
	return &Manager{
		config: cfg,
		state:  StateDisconnected,
		log:    log.Named("connection"),
	}
}

// OnConnect sets the callback for successful connections.
func (m *Manager) OnConnect(fn func()) {
	m.onConnect = fn
}

// OnDisconnect sets the callback for disconnections.
func (m *Manager) OnDisconnect(fn func(error)) {
	m.onDisconnect = fn
}

// OnReconnect sets the callback for reconnections.
func (m *Manager) OnReconnect(fn func()) {
	m.onReconnect = fn
}

// Connect establishes the NATS connection.
func (m *Manager) Connect(ctx context.Context) error {
	m.setState(StateConnecting)

	opts, err := m.buildOptions()
	if err != nil {
		m.setState(StateDisconnected)
		return fmt.Errorf("failed to build options: %w", err)
	}

	conn, err := nats.Connect(m.config.URL, opts...)
	if err != nil {
		m.setState(StateDisconnected)
		m.setLastError(err)
		return fmt.Errorf("failed to connect: %w", err)
	}

	m.conn = conn
	m.setState(StateConnected)
	m.recordConnect()

	m.log.Info("Connected to NATS",
		"url", m.config.URL,
		"server", conn.ConnectedServerName(),
	)

	if m.onConnect != nil {
		m.onConnect()
	}

	return nil
}

// buildOptions builds NATS connection options.
func (m *Manager) buildOptions() ([]nats.Option, error) {
	opts := []nats.Option{
		nats.MaxReconnects(m.config.MaxReconnects),
		nats.ReconnectWait(m.config.ReconnectWait),
		nats.PingInterval(m.config.PingInterval),
		nats.MaxPingsOutstanding(m.config.MaxPingsOut),
		nats.Timeout(m.config.Timeout),
		nats.ReconnectBufSize(8 * 1024 * 1024), // 8MB
	}

	if m.config.Name != "" {
		opts = append(opts, nats.Name(m.config.Name))
	}

	if m.config.Token != "" {
		opts = append(opts, nats.Token(m.config.Token))
	}

	// TLS configuration
	if m.config.TLSEnabled {
		tlsConfig, err := m.buildTLSConfig()
		if err != nil {
			return nil, err
		}
		opts = append(opts, nats.Secure(tlsConfig))
	}

	// Handlers
	opts = append(opts, nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
		m.setState(StateReconnecting)
		m.recordDisconnect()
		m.setLastError(err)
		m.log.Warn("Disconnected from NATS", "error", err)
		if m.onDisconnect != nil {
			m.onDisconnect(err)
		}
	}))

	opts = append(opts, nats.ReconnectHandler(func(nc *nats.Conn) {
		m.setState(StateConnected)
		m.recordConnect()
		m.log.Info("Reconnected to NATS", "server", nc.ConnectedServerName())
		if m.onReconnect != nil {
			m.onReconnect()
		}
	}))

	opts = append(opts, nats.ClosedHandler(func(nc *nats.Conn) {
		m.setState(StateClosed)
		m.log.Info("NATS connection closed")
	}))

	opts = append(opts, nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
		m.setLastError(err)
		m.log.Error("NATS error",
			"subject", sub.Subject,
			"error", err,
		)
	}))

	return opts, nil
}

// buildTLSConfig builds TLS configuration.
func (m *Manager) buildTLSConfig() (*tls.Config, error) {
	config := &tls.Config{
		InsecureSkipVerify: m.config.TLSSkipVerify,
	}

	// Load CA cert
	if m.config.TLSCA != "" {
		caCert, err := os.ReadFile(m.config.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		config.RootCAs = caCertPool
	}

	// Load client cert
	if m.config.TLSCert != "" && m.config.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(m.config.TLSCert, m.config.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	return config, nil
}

// Close closes the connection.
func (m *Manager) Close() error {
	m.setState(StateClosed)

	if m.conn == nil {
		return nil
	}

	// Drain first
	if err := m.conn.Drain(); err != nil {
		m.conn.Close()
		return err
	}

	return nil
}

// Conn returns the underlying NATS connection.
func (m *Manager) Conn() *nats.Conn {
	return m.conn
}

// State returns the current connection state.
func (m *Manager) State() State {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.state
}

// IsConnected returns true if connected.
func (m *Manager) IsConnected() bool {
	return m.State() == StateConnected && m.conn != nil && m.conn.IsConnected()
}

// setState updates the connection state.
func (m *Manager) setState(state State) {
	m.stateMu.Lock()
	m.state = state
	m.stateMu.Unlock()
}

// recordConnect records a successful connection.
func (m *Manager) recordConnect() {
	m.metricsMu.Lock()
	m.connectCount++
	m.lastConnectTime = time.Now()
	m.metricsMu.Unlock()
}

// recordDisconnect records a disconnection.
func (m *Manager) recordDisconnect() {
	m.metricsMu.Lock()
	m.disconnectCount++
	m.metricsMu.Unlock()
}

// setLastError records the last error.
func (m *Manager) setLastError(err error) {
	if err == nil {
		return
	}
	m.metricsMu.Lock()
	m.lastError = err
	m.metricsMu.Unlock()
}

// Stats returns connection statistics.
type Stats struct {
	State           State
	ConnectCount    int
	DisconnectCount int
	LastConnectTime time.Time
	LastError       error
	RTT             time.Duration
	InMsgs          uint64
	OutMsgs         uint64
	InBytes         uint64
	OutBytes        uint64
}

// Stats returns connection statistics.
func (m *Manager) Stats() Stats {
	m.metricsMu.RLock()
	defer m.metricsMu.RUnlock()

	stats := Stats{
		State:           m.State(),
		ConnectCount:    m.connectCount,
		DisconnectCount: m.disconnectCount,
		LastConnectTime: m.lastConnectTime,
		LastError:       m.lastError,
	}

	if m.conn != nil {
		natsStats := m.conn.Stats()
		stats.InMsgs = natsStats.InMsgs
		stats.OutMsgs = natsStats.OutMsgs
		stats.InBytes = natsStats.InBytes
		stats.OutBytes = natsStats.OutBytes

		// Measure RTT
		start := time.Now()
		if err := m.conn.Flush(); err == nil {
			stats.RTT = time.Since(start)
		}
	}

	return stats
}

// WaitForConnection waits for the connection to be established.
func (m *Manager) WaitForConnection(ctx context.Context) error {
	if m.IsConnected() {
		return nil
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if m.IsConnected() {
				return nil
			}
			if m.State() == StateClosed {
				return fmt.Errorf("connection closed")
			}
		}
	}
}

// Publish publishes a message.
func (m *Manager) Publish(subject string, data []byte) error {
	if !m.IsConnected() {
		return fmt.Errorf("not connected")
	}
	return m.conn.Publish(subject, data)
}

// Request sends a request and waits for response.
func (m *Manager) Request(ctx context.Context, subject string, data []byte) (*nats.Msg, error) {
	if !m.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}
	return m.conn.RequestWithContext(ctx, subject, data)
}

// Subscribe creates a subscription.
func (m *Manager) Subscribe(subject string, handler nats.MsgHandler) (*nats.Subscription, error) {
	if !m.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}
	return m.conn.Subscribe(subject, handler)
}

// Flush flushes pending messages.
func (m *Manager) Flush() error {
	if m.conn == nil {
		return fmt.Errorf("not connected")
	}
	return m.conn.Flush()
}
