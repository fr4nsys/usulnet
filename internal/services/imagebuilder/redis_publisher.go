// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package imagebuilder

import (
	"context"

	"github.com/fr4nsys/usulnet/internal/repository/redis"
)

// RedisLogPublisher adapts *redis.PubSub onto the LogPublisher
// interface the service depends on. The build path stays free of
// pub-sub specifics so unit tests can substitute a memory channel.
type RedisLogPublisher struct {
	pub *redis.PubSub
}

// NewRedisLogPublisher returns a publisher backed by the given pub/sub
// client. Pass nil pub when Redis is not configured; the resulting
// publisher is a no-op so the build path still completes.
func NewRedisLogPublisher(pub *redis.PubSub) *RedisLogPublisher {
	return &RedisLogPublisher{pub: pub}
}

// Publish forwards raw log bytes to the named channel. A nil pub-sub
// returns nil so the build does not abort when Redis is unavailable —
// the API handler degrades to "log streaming disabled" instead.
func (p *RedisLogPublisher) Publish(ctx context.Context, channel string, payload []byte) error {
	if p == nil || p.pub == nil {
		return nil
	}
	return p.pub.PublishRaw(ctx, channel, payload)
}

// PubSub exposes the underlying pub-sub so the API handler can subscribe
// on the same instance. Returns nil when Redis is not configured.
func (p *RedisLogPublisher) PubSub() *redis.PubSub {
	if p == nil {
		return nil
	}
	return p.pub
}
