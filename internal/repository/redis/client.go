// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Options configures the Redis client
type Options struct {
	PoolSize     int
	MinIdleConns int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// TLSEnabled forces TLS even when the URL is `redis://`. When the
	// URL is already `rediss://` go-redis's ParseURL hands us a non-nil
	// *tls.Config and the flag has no further effect.
	TLSEnabled bool
	// TLSSkipVerify disables certificate-chain verification. Set this
	// when talking to a self-signed in-cluster Redis (the opt-in
	// USULNET_TLS_LOCAL_SERVICES path).
	TLSSkipVerify bool
	// TLSCAFile is an optional PEM file to populate RootCAs (verify-full
	// against an operator-supplied CA).
	TLSCAFile string
	// TLSCertFile / TLSKeyFile enable client mTLS when both are set.
	TLSCertFile string
	TLSKeyFile  string
}

// DefaultOptions returns sensible default options
func DefaultOptions() Options {
	return Options{
		PoolSize:     10,
		MinIdleConns: 5,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
}

// Client wraps redis.Client with additional functionality
type Client struct {
	rdb *redis.Client
}

// New creates a new Redis client
func New(ctx context.Context, url string, opts Options) (*Client, error) {
	options, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	// Apply options
	if opts.PoolSize > 0 {
		options.PoolSize = opts.PoolSize
	}
	if opts.MinIdleConns > 0 {
		options.MinIdleConns = opts.MinIdleConns
	}
	if opts.DialTimeout > 0 {
		options.DialTimeout = opts.DialTimeout
	}
	if opts.ReadTimeout > 0 {
		options.ReadTimeout = opts.ReadTimeout
	}
	if opts.WriteTimeout > 0 {
		options.WriteTimeout = opts.WriteTimeout
	}

	// TLS plumbing. ParseURL pre-fills options.TLSConfig with a default
	// (verify-full, no RootCAs) when the scheme is rediss://. Layer the
	// caller-provided knobs on top so an operator can mount a custom CA
	// or a client cert without having to reach into go-redis directly.
	if options.TLSConfig == nil && (opts.TLSEnabled || opts.TLSCAFile != "" || opts.TLSCertFile != "") {
		options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if options.TLSConfig != nil {
		if options.TLSConfig.MinVersion == 0 {
			options.TLSConfig.MinVersion = tls.VersionTLS12
		}
		if opts.TLSSkipVerify {
			options.TLSConfig.InsecureSkipVerify = true
		}
		if opts.TLSCAFile != "" {
			caPEM, readErr := os.ReadFile(opts.TLSCAFile)
			if readErr != nil {
				return nil, fmt.Errorf("failed to read Redis TLS CA %s: %w", opts.TLSCAFile, readErr)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("failed to parse Redis TLS CA from %s", opts.TLSCAFile)
			}
			options.TLSConfig.RootCAs = pool
		}
		if opts.TLSCertFile != "" && opts.TLSKeyFile != "" {
			cert, certErr := tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
			if certErr != nil {
				return nil, fmt.Errorf("failed to load Redis TLS client cert: %w", certErr)
			}
			options.TLSConfig.Certificates = []tls.Certificate{cert}
		}
	}

	rdb := redis.NewClient(options)

	// Test connection
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	return &Client{rdb: rdb}, nil
}

// Redis returns the underlying redis.Client
func (c *Client) Redis() *redis.Client {
	return c.rdb
}

// Close closes the Redis connection
func (c *Client) Close() error {
	return c.rdb.Close()
}

// Ping checks Redis connectivity
func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// HealthCheck performs a comprehensive health check
func (c *Client) HealthCheck(ctx context.Context) error {
	// Check connectivity
	if err := c.Ping(ctx); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	// Check pool stats
	stats := c.rdb.PoolStats()
	if stats.TotalConns == 0 {
		return fmt.Errorf("no connections available")
	}

	return nil
}

// PoolStats returns connection pool statistics
func (c *Client) PoolStats() *redis.PoolStats {
	return c.rdb.PoolStats()
}

// Info returns Redis server info
func (c *Client) Info(ctx context.Context, sections ...string) (string, error) {
	return c.rdb.Info(ctx, sections...).Result()
}

// GetVersion returns the Redis server version string by parsing INFO server.
func (c *Client) GetVersion(ctx context.Context) (string, error) {
	info, err := c.Info(ctx, "server")
	if err != nil {
		return "", fmt.Errorf("redis info: %w", err)
	}
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redis_version:") {
			return strings.TrimPrefix(line, "redis_version:"), nil
		}
	}
	return "", nil
}

// DBSize returns the number of keys in the database
func (c *Client) DBSize(ctx context.Context) (int64, error) {
	return c.rdb.DBSize(ctx).Result()
}

// FlushDB removes all keys from the current database
func (c *Client) FlushDB(ctx context.Context) error {
	return c.rdb.FlushDB(ctx).Err()
}

// Pipeline returns a new pipeline for batching commands
func (c *Client) Pipeline() redis.Pipeliner {
	return c.rdb.Pipeline()
}

// TxPipeline returns a new transactional pipeline
func (c *Client) TxPipeline() redis.Pipeliner {
	return c.rdb.TxPipeline()
}

// Watch executes a function within a WATCH transaction
func (c *Client) Watch(ctx context.Context, fn func(tx *redis.Tx) error, keys ...string) error {
	return c.rdb.Watch(ctx, fn, keys...)
}

// Key prefixing helpers

// WithPrefix creates a key with a prefix
func (c *Client) WithPrefix(prefix, key string) string {
	return fmt.Sprintf("%s:%s", prefix, key)
}

// SessionKey creates a session key
func (c *Client) SessionKey(sessionID string) string {
	return c.WithPrefix("session", sessionID)
}

// UserSessionsKey creates a key for user's sessions set
func (c *Client) UserSessionsKey(userID string) string {
	return c.WithPrefix("user_sessions", userID)
}

// CacheKey creates a cache key
func (c *Client) CacheKey(namespace, key string) string {
	return fmt.Sprintf("cache:%s:%s", namespace, key)
}

// LockKey creates a lock key
func (c *Client) LockKey(resource string) string {
	return c.WithPrefix("lock", resource)
}

// RateLimitKey creates a rate limit key
func (c *Client) RateLimitKey(identifier string) string {
	return c.WithPrefix("ratelimit", identifier)
}
