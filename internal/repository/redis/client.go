// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"fmt"
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
