// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
)

var (
	// ErrLockNotAcquired is returned when a lock cannot be acquired
	ErrLockNotAcquired = errors.New("lock not acquired")
	// ErrLockNotHeld is returned when trying to release a lock not held
	ErrLockNotHeld = errors.New("lock not held")
)

// LockKeyPrefix is the prefix for distributed lock keys
const LockKeyPrefix = "lock:"

// LockKey creates a lock key with the standard prefix
func LockKey(resource string) string {
	return LockKeyPrefix + resource
}

// Lock represents a distributed lock
type Lock struct {
	client *Client
	key    string
	value  string
	ttl    time.Duration
}

// LockOptions configures lock behavior
type LockOptions struct {
	// RetryCount is the number of times to retry acquiring the lock
	RetryCount int
	// RetryDelay is the delay between retries
	RetryDelay time.Duration
	// TTL is the lock expiration time
	TTL time.Duration
}

// DefaultLockOptions returns default lock options
func DefaultLockOptions() LockOptions {
	return LockOptions{
		RetryCount: 3,
		RetryDelay: 100 * time.Millisecond,
		TTL:        30 * time.Second,
	}
}

// NewLock creates a new distributed lock
func (c *Client) NewLock(key string, ttl time.Duration) *Lock {
	return &Lock{
		client: c,
		key:    LockKey(key),
		value:  uuid.New().String(),
		ttl:    ttl,
	}
}

// Acquire attempts to acquire the lock
func (l *Lock) Acquire(ctx context.Context) error {
	ok, err := l.client.rdb.SetNX(ctx, l.key, l.value, l.ttl).Result()
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	if !ok {
		return ErrLockNotAcquired
	}
	return nil
}

// AcquireWithRetry attempts to acquire the lock with retries
func (l *Lock) AcquireWithRetry(ctx context.Context, opts LockOptions) error {
	for i := 0; i <= opts.RetryCount; i++ {
		err := l.Acquire(ctx)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrLockNotAcquired) {
			return err
		}

		if i < opts.RetryCount {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(opts.RetryDelay):
				// Continue to next retry
			}
		}
	}
	return ErrLockNotAcquired
}

// Release releases the lock if we still hold it
func (l *Lock) Release(ctx context.Context) error {
	// Use Lua script to release lock only if we own it
	script := `
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("DEL", KEYS[1])
		else
			return 0
		end
	`
	result, err := l.client.rdb.Eval(ctx, script, []string{l.key}, l.value).Int64()
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}
	if result == 0 {
		return ErrLockNotHeld
	}
	return nil
}

// Extend extends the lock TTL if we still hold it
func (l *Lock) Extend(ctx context.Context, ttl time.Duration) error {
	script := `
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("PEXPIRE", KEYS[1], ARGV[2])
		else
			return 0
		end
	`
	result, err := l.client.rdb.Eval(ctx, script, []string{l.key}, l.value, ttl.Milliseconds()).Int64()
	if err != nil {
		return fmt.Errorf("failed to extend lock: %w", err)
	}
	if result == 0 {
		return ErrLockNotHeld
	}
	l.ttl = ttl
	return nil
}

// IsHeld checks if we still hold the lock
func (l *Lock) IsHeld(ctx context.Context) (bool, error) {
	val, err := l.client.rdb.Get(ctx, l.key).Result()
	if err != nil {
		if err == goredis.Nil {
			return false, nil
		}
		return false, err
	}
	return val == l.value, nil
}

// Key returns the lock key
func (l *Lock) Key() string {
	return l.key
}

// TTL returns the lock TTL
func (l *Lock) TTL() time.Duration {
	return l.ttl
}

// WithLock executes a function while holding the lock
func (c *Client) WithLock(ctx context.Context, key string, ttl time.Duration, fn func(context.Context) error) error {
	lock := c.NewLock(key, ttl)

	if err := lock.Acquire(ctx); err != nil {
		return err
	}
	defer func() {
		// Use background context for release to ensure it completes
		_ = lock.Release(context.Background())
	}()

	return fn(ctx)
}

// WithLockRetry executes a function while holding the lock, with retries
func (c *Client) WithLockRetry(ctx context.Context, key string, opts LockOptions, fn func(context.Context) error) error {
	lock := c.NewLock(key, opts.TTL)

	if err := lock.AcquireWithRetry(ctx, opts); err != nil {
		return err
	}
	defer func() {
		_ = lock.Release(context.Background())
	}()

	return fn(ctx)
}

// TryWithLock attempts to execute a function with a lock, returning immediately if lock is not available
func (c *Client) TryWithLock(ctx context.Context, key string, ttl time.Duration, fn func(context.Context) error) (bool, error) {
	lock := c.NewLock(key, ttl)

	if err := lock.Acquire(ctx); err != nil {
		if errors.Is(err, ErrLockNotAcquired) {
			return false, nil
		}
		return false, err
	}
	defer func() {
		_ = lock.Release(context.Background())
	}()

	return true, fn(ctx)
}

// Common lock keys for the application
func ContainerLock(containerID string) string {
	return "container:" + containerID
}

func HostLock(hostID string) string {
	return "host:" + hostID
}

func UpdateLock(containerID string) string {
	return "update:" + containerID
}

func BackupLock(containerID string) string {
	return "backup:" + containerID
}

func SecurityScanLock(containerID string) string {
	return "security_scan:" + containerID
}

func StackDeployLock(stackID string) string {
	return "stack_deploy:" + stackID
}

func ConfigSyncLock(configID string) string {
	return "config_sync:" + configID
}

// Semaphore provides a counting semaphore using Redis
type Semaphore struct {
	client   *Client
	key      string
	maxCount int64
	ttl      time.Duration
	value    string
}

// NewSemaphore creates a new semaphore
func (c *Client) NewSemaphore(key string, maxCount int64, ttl time.Duration) *Semaphore {
	return &Semaphore{
		client:   c,
		key:      "semaphore:" + key,
		maxCount: maxCount,
		ttl:      ttl,
		value:    uuid.New().String(),
	}
}

// Acquire attempts to acquire a slot in the semaphore
func (s *Semaphore) Acquire(ctx context.Context) error {
	script := `
		local current = redis.call("SCARD", KEYS[1])
		if current < tonumber(ARGV[1]) then
			redis.call("SADD", KEYS[1], ARGV[2])
			redis.call("EXPIRE", KEYS[1], ARGV[3])
			return 1
		else
			return 0
		end
	`
	result, err := s.client.rdb.Eval(ctx, script, []string{s.key}, s.maxCount, s.value, int64(s.ttl.Seconds())).Int64()
	if err != nil {
		return fmt.Errorf("failed to acquire semaphore: %w", err)
	}
	if result == 0 {
		return ErrLockNotAcquired
	}
	return nil
}

// Release releases a slot in the semaphore
func (s *Semaphore) Release(ctx context.Context) error {
	return s.client.rdb.SRem(ctx, s.key, s.value).Err()
}

// Count returns the current count of acquired slots
func (s *Semaphore) Count(ctx context.Context) (int64, error) {
	return s.client.rdb.SCard(ctx, s.key).Result()
}

// Available returns the number of available slots
func (s *Semaphore) Available(ctx context.Context) (int64, error) {
	count, err := s.Count(ctx)
	if err != nil {
		return 0, err
	}
	return s.maxCount - count, nil
}
