// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

// Get retrieves a string value
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	return c.rdb.Get(ctx, key).Result()
}

// Set stores a value with optional expiration
func (c *Client) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return c.rdb.Set(ctx, key, value, expiration).Err()
}

// SetNX sets a value only if it doesn't exist
func (c *Client) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	return c.rdb.SetNX(ctx, key, value, expiration).Result()
}

// SetXX sets a value only if it exists
func (c *Client) SetXX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	return c.rdb.SetXX(ctx, key, value, expiration).Result()
}

// Delete removes keys
func (c *Client) Delete(ctx context.Context, keys ...string) error {
	return c.rdb.Del(ctx, keys...).Err()
}

// Exists checks if a key exists
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	n, err := c.rdb.Exists(ctx, key).Result()
	return n > 0, err
}

// Expire sets expiration on a key
func (c *Client) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return c.rdb.Expire(ctx, key, expiration).Err()
}

// TTL returns the time to live of a key
func (c *Client) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.rdb.TTL(ctx, key).Result()
}

// GetJSON retrieves and unmarshals JSON
func (c *Client) GetJSON(ctx context.Context, key string, dest interface{}) error {
	data, err := c.rdb.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

// SetJSON marshals and stores JSON with optional expiration
func (c *Client) SetJSON(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, key, data, expiration).Err()
}

// GetOrSet gets a value or sets it using the provided function
func (c *Client) GetOrSet(ctx context.Context, key string, expiration time.Duration, fn func() (interface{}, error)) (string, error) {
	// Try to get existing value
	val, err := c.rdb.Get(ctx, key).Result()
	if err == nil {
		return val, nil
	}
	if err != redis.Nil {
		return "", err
	}

	// Generate new value
	newVal, err := fn()
	if err != nil {
		return "", err
	}

	// Set and return
	if err := c.rdb.Set(ctx, key, newVal, expiration).Err(); err != nil {
		return "", err
	}

	return c.rdb.Get(ctx, key).Result()
}

// GetOrSetJSON gets JSON or sets it using the provided function
func (c *Client) GetOrSetJSON(ctx context.Context, key string, dest interface{}, expiration time.Duration, fn func() (interface{}, error)) error {
	// Try to get existing value
	err := c.GetJSON(ctx, key, dest)
	if err == nil {
		return nil
	}
	if err != redis.Nil {
		return err
	}

	// Generate new value
	newVal, err := fn()
	if err != nil {
		return err
	}

	// Set new value
	if err := c.SetJSON(ctx, key, newVal, expiration); err != nil {
		return err
	}

	// Unmarshal into dest
	data, _ := json.Marshal(newVal)
	return json.Unmarshal(data, dest)
}

// Incr increments a counter
func (c *Client) Incr(ctx context.Context, key string) (int64, error) {
	return c.rdb.Incr(ctx, key).Result()
}

// IncrBy increments a counter by a specific amount
func (c *Client) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	return c.rdb.IncrBy(ctx, key, value).Result()
}

// Decr decrements a counter
func (c *Client) Decr(ctx context.Context, key string) (int64, error) {
	return c.rdb.Decr(ctx, key).Result()
}

// DecrBy decrements a counter by a specific amount
func (c *Client) DecrBy(ctx context.Context, key string, value int64) (int64, error) {
	return c.rdb.DecrBy(ctx, key, value).Result()
}

// MGet retrieves multiple values
func (c *Client) MGet(ctx context.Context, keys ...string) ([]interface{}, error) {
	return c.rdb.MGet(ctx, keys...).Result()
}

// MSet sets multiple values
func (c *Client) MSet(ctx context.Context, values ...interface{}) error {
	return c.rdb.MSet(ctx, values...).Err()
}

// Keys returns keys matching a pattern
func (c *Client) Keys(ctx context.Context, pattern string) ([]string, error) {
	return c.rdb.Keys(ctx, pattern).Result()
}

// Scan iterates over keys matching a pattern
func (c *Client) Scan(ctx context.Context, cursor uint64, match string, count int64) ([]string, uint64, error) {
	return c.rdb.Scan(ctx, cursor, match, count).Result()
}

// Hash operations

// HGet gets a hash field
func (c *Client) HGet(ctx context.Context, key, field string) (string, error) {
	return c.rdb.HGet(ctx, key, field).Result()
}

// HSet sets hash fields
func (c *Client) HSet(ctx context.Context, key string, values ...interface{}) error {
	return c.rdb.HSet(ctx, key, values...).Err()
}

// HGetAll gets all hash fields
func (c *Client) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	return c.rdb.HGetAll(ctx, key).Result()
}

// HDel deletes hash fields
func (c *Client) HDel(ctx context.Context, key string, fields ...string) error {
	return c.rdb.HDel(ctx, key, fields...).Err()
}

// HExists checks if a hash field exists
func (c *Client) HExists(ctx context.Context, key, field string) (bool, error) {
	return c.rdb.HExists(ctx, key, field).Result()
}

// HIncrBy increments a hash field
func (c *Client) HIncrBy(ctx context.Context, key, field string, incr int64) (int64, error) {
	return c.rdb.HIncrBy(ctx, key, field, incr).Result()
}

// Set operations

// SAdd adds members to a set
func (c *Client) SAdd(ctx context.Context, key string, members ...interface{}) error {
	return c.rdb.SAdd(ctx, key, members...).Err()
}

// SRem removes members from a set
func (c *Client) SRem(ctx context.Context, key string, members ...interface{}) error {
	return c.rdb.SRem(ctx, key, members...).Err()
}

// SMembers gets all set members
func (c *Client) SMembers(ctx context.Context, key string) ([]string, error) {
	return c.rdb.SMembers(ctx, key).Result()
}

// SIsMember checks if a member exists in a set
func (c *Client) SIsMember(ctx context.Context, key string, member interface{}) (bool, error) {
	return c.rdb.SIsMember(ctx, key, member).Result()
}

// SCard returns the set cardinality
func (c *Client) SCard(ctx context.Context, key string) (int64, error) {
	return c.rdb.SCard(ctx, key).Result()
}

// List operations

// LPush prepends values to a list
func (c *Client) LPush(ctx context.Context, key string, values ...interface{}) error {
	return c.rdb.LPush(ctx, key, values...).Err()
}

// RPush appends values to a list
func (c *Client) RPush(ctx context.Context, key string, values ...interface{}) error {
	return c.rdb.RPush(ctx, key, values...).Err()
}

// LPop removes and returns the first element
func (c *Client) LPop(ctx context.Context, key string) (string, error) {
	return c.rdb.LPop(ctx, key).Result()
}

// RPop removes and returns the last element
func (c *Client) RPop(ctx context.Context, key string) (string, error) {
	return c.rdb.RPop(ctx, key).Result()
}

// LRange gets a range of elements
func (c *Client) LRange(ctx context.Context, key string, start, stop int64) ([]string, error) {
	return c.rdb.LRange(ctx, key, start, stop).Result()
}

// LLen returns the list length
func (c *Client) LLen(ctx context.Context, key string) (int64, error) {
	return c.rdb.LLen(ctx, key).Result()
}

// LTrim trims a list to the specified range
func (c *Client) LTrim(ctx context.Context, key string, start, stop int64) error {
	return c.rdb.LTrim(ctx, key, start, stop).Err()
}
