// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package nats provides a NATS client wrapper for usulnet.
package nats

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// Client wraps a NATS connection with additional functionality.
type Client struct {
	conn   *nats.Conn
	config Config
	logger *zap.Logger
	mu     sync.RWMutex

	// Callbacks
	onConnect    func()
	onDisconnect func(err error)
	onReconnect  func()
}

// Config holds NATS client configuration.
type Config struct {
	// URL is the NATS server URL (e.g., "nats://localhost:4222")
	URL string
	// Name is the client name for identification
	Name string
	// Token for authentication
	Token string
	// Username for authentication
	Username string
	// Password for authentication
	Password string
	// TLS configuration
	TLSConfig *tls.Config
	// MaxReconnects is the maximum number of reconnect attempts (-1 for infinite)
	MaxReconnects int
	// ReconnectWait is the time to wait between reconnect attempts
	ReconnectWait time.Duration
	// Timeout is the connection timeout
	Timeout time.Duration
	// PingInterval is how often to ping the server
	PingInterval time.Duration
	// MaxPingsOut is the max outstanding pings before declaring connection stale
	MaxPingsOut int
	// ReconnectBufSize is the size of the reconnect buffer in bytes
	ReconnectBufSize int

	// JetStreamEnabled controls whether JetStream is available (default true)
	JetStreamEnabled bool
	// JetStreamDomain is the JetStream domain for multi-tenant setups (empty = default)
	JetStreamDomain string
}

// DefaultConfig returns a default NATS configuration.
func DefaultConfig() Config {
	return Config{
		URL:              "nats://localhost:4222",
		Name:             "usulnet-client",
		MaxReconnects:    -1, // infinite
		ReconnectWait:    2 * time.Second,
		Timeout:          5 * time.Second,
		PingInterval:     2 * time.Minute,
		MaxPingsOut:      3,
		ReconnectBufSize: 8 * 1024 * 1024, // 8MB
		JetStreamEnabled: true,
	}
}

// NewClient creates a new NATS client.
func NewClient(config Config, logger *zap.Logger) (*Client, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	client := &Client{
		config: config,
		logger: logger.Named("nats"),
	}

	return client, nil
}

// Connect establishes a connection to the NATS server.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil && c.conn.IsConnected() {
		return nil
	}

	opts := []nats.Option{
		nats.Name(c.config.Name),
		nats.MaxReconnects(c.config.MaxReconnects),
		nats.ReconnectWait(c.config.ReconnectWait),
		nats.Timeout(c.config.Timeout),
		nats.PingInterval(c.config.PingInterval),
		nats.MaxPingsOutstanding(c.config.MaxPingsOut),
		nats.ReconnectBufSize(c.config.ReconnectBufSize),
	}

	// Authentication
	if c.config.Token != "" {
		opts = append(opts, nats.Token(c.config.Token))
	} else if c.config.Username != "" {
		opts = append(opts, nats.UserInfo(c.config.Username, c.config.Password))
	}

	// TLS
	if c.config.TLSConfig != nil {
		opts = append(opts, nats.Secure(c.config.TLSConfig))
	}

	// Callbacks
	opts = append(opts,
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			c.logger.Warn("NATS disconnected", zap.Error(err))
			if c.onDisconnect != nil {
				c.onDisconnect(err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			c.logger.Info("NATS reconnected", zap.String("url", nc.ConnectedUrl()))
			if c.onReconnect != nil {
				c.onReconnect()
			}
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			c.logger.Info("NATS connection closed")
		}),
		nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
			if sub != nil {
				c.logger.Error("NATS error", zap.String("subject", sub.Subject), zap.Error(err))
			} else {
				c.logger.Error("NATS error", zap.Error(err))
			}
		}),
	)

	conn, err := nats.Connect(c.config.URL, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}

	c.conn = conn
	c.logger.Info("Connected to NATS",
		zap.String("url", conn.ConnectedUrl()),
		zap.String("server_name", conn.ConnectedServerName()),
		zap.String("server_id", conn.ConnectedServerId()),
	)

	if c.onConnect != nil {
		c.onConnect()
	}

	return nil
}

// Close closes the NATS connection.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// Conn returns the underlying NATS connection.
func (c *Client) Conn() *nats.Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn
}

// IsConnected returns true if connected to NATS.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn != nil && c.conn.IsConnected()
}

// IsTLS returns true if the active NATS connection uses TLS.
func (c *Client) IsTLS() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.conn == nil {
		return false
	}
	_, err := c.conn.TLSConnectionState()
	return err == nil
}

// Health checks the NATS connection health.
func (c *Client) Health(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.conn == nil {
		return fmt.Errorf("NATS client not connected")
	}

	if !c.conn.IsConnected() {
		return fmt.Errorf("NATS connection is not active")
	}

	// Try to flush to verify connection
	if err := c.conn.FlushTimeout(5 * time.Second); err != nil {
		return fmt.Errorf("NATS flush failed: %w", err)
	}

	return nil
}

// Stats returns connection statistics.
func (c *Client) Stats() ConnectionStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.conn == nil {
		return ConnectionStats{}
	}

	stats := c.conn.Stats()
	return ConnectionStats{
		InMsgs:     stats.InMsgs,
		OutMsgs:    stats.OutMsgs,
		InBytes:    stats.InBytes,
		OutBytes:   stats.OutBytes,
		Reconnects: stats.Reconnects,
	}
}

// ConnectionStats holds NATS connection statistics.
type ConnectionStats struct {
	InMsgs     uint64
	OutMsgs    uint64
	InBytes    uint64
	OutBytes   uint64
	Reconnects uint64
}

// ServerInfo returns information about the connected server.
// Note: In NATS v1.39+, ServerInfo struct is not directly exposed.
// We return available information from the connection.
func (c *Client) ServerInfo() ServerInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.conn == nil {
		return ServerInfo{}
	}

	return ServerInfo{
		ServerID:    c.conn.ConnectedServerId(),
		ServerName:  c.conn.ConnectedServerName(),
		ClusterName: c.conn.ConnectedClusterName(),
		URL:         c.conn.ConnectedUrl(),
	}
}

// ServerInfo contains information about the connected NATS server.
type ServerInfo struct {
	ServerID    string
	ServerName  string
	ClusterName string
	URL         string
}

// Publish publishes a message to a subject.
func (c *Client) Publish(subject string, data []byte) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	return conn.Publish(subject, data)
}

// Request sends a request and waits for a response.
func (c *Client) Request(subject string, data []byte, timeout time.Duration) (*nats.Msg, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	return conn.Request(subject, data, timeout)
}

// Subscribe subscribes to a subject.
func (c *Client) Subscribe(subject string, handler nats.MsgHandler) (*nats.Subscription, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	return conn.Subscribe(subject, handler)
}

// QueueSubscribe subscribes to a subject with a queue group.
func (c *Client) QueueSubscribe(subject, queue string, handler nats.MsgHandler) (*nats.Subscription, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	return conn.QueueSubscribe(subject, queue, handler)
}

// Flush flushes the connection buffer.
func (c *Client) Flush() error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	return conn.Flush()
}

// FlushTimeout flushes with a timeout.
func (c *Client) FlushTimeout(timeout time.Duration) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	return conn.FlushTimeout(timeout)
}

// Callbacks
func (c *Client) OnConnect(fn func()) {
	c.onConnect = fn
}

func (c *Client) OnDisconnect(fn func(error)) {
	c.onDisconnect = fn
}

func (c *Client) OnReconnect(fn func()) {
	c.onReconnect = fn
}
