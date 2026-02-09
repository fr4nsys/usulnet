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

const (
	// jwtBlacklistPrefix is the key prefix for blacklisted JWT tokens
	jwtBlacklistPrefix = "jwt:blacklist"
)

// JWTBlacklist handles JWT token blacklisting using Redis.
// Tokens are stored with their JTI (JWT ID) and automatically expire
// when the original token would have expired.
type JWTBlacklist struct {
	client *Client
}

// NewJWTBlacklist creates a new JWT blacklist repository.
func NewJWTBlacklist(client *Client) *JWTBlacklist {
	return &JWTBlacklist{client: client}
}

// BlacklistToken adds a token to the blacklist.
// The token is stored until its natural expiration time.
// jti: the unique JWT ID from the token's claims
// expiresAt: the token's expiration time (used to set TTL)
// reason: optional reason for blacklisting (e.g., "logout", "password_change")
func (b *JWTBlacklist) BlacklistToken(ctx context.Context, jti string, expiresAt time.Time, reason string) error {
	key := b.blacklistKey(jti)

	// Calculate TTL - only blacklist until the token would naturally expire
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	// Store with the reason as value (useful for debugging/auditing)
	if reason == "" {
		reason = "revoked"
	}

	err := b.client.rdb.Set(ctx, key, reason, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to blacklist token: %w", err)
	}

	return nil
}

// IsBlacklisted checks if a token is in the blacklist.
func (b *JWTBlacklist) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	key := b.blacklistKey(jti)

	exists, err := b.client.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check blacklist: %w", err)
	}

	return exists > 0, nil
}

// GetBlacklistReason returns the reason a token was blacklisted.
// Returns empty string if not blacklisted.
func (b *JWTBlacklist) GetBlacklistReason(ctx context.Context, jti string) (string, error) {
	key := b.blacklistKey(jti)

	reason, err := b.client.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get blacklist reason: %w", err)
	}

	return reason, nil
}

// RemoveFromBlacklist removes a token from the blacklist.
// This is rarely needed but available for admin operations.
func (b *JWTBlacklist) RemoveFromBlacklist(ctx context.Context, jti string) error {
	key := b.blacklistKey(jti)

	err := b.client.rdb.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to remove from blacklist: %w", err)
	}

	return nil
}

// BlacklistUserTokens blacklists all tokens for a user by storing a "user blacklist" entry.
// All tokens issued before this timestamp will be considered invalid.
// This is useful for "logout from all devices" functionality.
func (b *JWTBlacklist) BlacklistUserTokens(ctx context.Context, userID string, issuedBefore time.Time, ttl time.Duration) error {
	key := b.userBlacklistKey(userID)

	err := b.client.rdb.Set(ctx, key, issuedBefore.Unix(), ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to blacklist user tokens: %w", err)
	}

	return nil
}

// IsUserTokenBlacklisted checks if a token was issued before the user's blacklist timestamp.
// Returns true if the token should be considered invalid.
func (b *JWTBlacklist) IsUserTokenBlacklisted(ctx context.Context, userID string, issuedAt time.Time) (bool, error) {
	key := b.userBlacklistKey(userID)

	timestampStr, err := b.client.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		// No user blacklist entry, token is valid
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check user blacklist: %w", err)
	}

	var blacklistTimestamp int64
	_, err = fmt.Sscanf(timestampStr, "%d", &blacklistTimestamp)
	if err != nil {
		return false, fmt.Errorf("failed to parse blacklist timestamp: %w", err)
	}

	// Token is blacklisted if it was issued before the blacklist timestamp
	return issuedAt.Unix() < blacklistTimestamp, nil
}

// ClearUserBlacklist removes the user-level blacklist entry.
func (b *JWTBlacklist) ClearUserBlacklist(ctx context.Context, userID string) error {
	key := b.userBlacklistKey(userID)

	err := b.client.rdb.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to clear user blacklist: %w", err)
	}

	return nil
}

// GetBlacklistCount returns the number of blacklisted tokens (approximate).
func (b *JWTBlacklist) GetBlacklistCount(ctx context.Context) (int64, error) {
	pattern := fmt.Sprintf("%s:*", jwtBlacklistPrefix)

	var count int64
	var cursor uint64
	for {
		keys, nextCursor, err := b.client.rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return 0, fmt.Errorf("failed to scan blacklist: %w", err)
		}
		count += int64(len(keys))
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return count, nil
}

// blacklistKey creates the Redis key for a blacklisted token.
func (b *JWTBlacklist) blacklistKey(jti string) string {
	return fmt.Sprintf("%s:%s", jwtBlacklistPrefix, jti)
}

// userBlacklistKey creates the Redis key for a user's blacklist timestamp.
func (b *JWTBlacklist) userBlacklistKey(userID string) string {
	return fmt.Sprintf("%s:user:%s", jwtBlacklistPrefix, userID)
}

// TokenValidator contains claims needed for blacklist validation.
type TokenValidator struct {
	JTI      string
	UserID   string
	IssuedAt time.Time
}

// ValidateToken checks if a token is blacklisted (by JTI or user-level).
// Returns nil if valid, error if blacklisted.
func (b *JWTBlacklist) ValidateToken(ctx context.Context, v TokenValidator) error {
	// Check individual token blacklist
	if v.JTI != "" {
		blacklisted, err := b.IsBlacklisted(ctx, v.JTI)
		if err != nil {
			return fmt.Errorf("failed to check token blacklist: %w", err)
		}
		if blacklisted {
			return ErrTokenBlacklisted
		}
	}

	// Check user-level blacklist
	if v.UserID != "" && !v.IssuedAt.IsZero() {
		blacklisted, err := b.IsUserTokenBlacklisted(ctx, v.UserID, v.IssuedAt)
		if err != nil {
			return fmt.Errorf("failed to check user blacklist: %w", err)
		}
		if blacklisted {
			return ErrTokenBlacklisted
		}
	}

	return nil
}

// ErrTokenBlacklisted is returned when a token is found in the blacklist.
var ErrTokenBlacklisted = fmt.Errorf("token has been revoked")
