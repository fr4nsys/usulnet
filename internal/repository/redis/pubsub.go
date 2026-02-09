// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	goredis "github.com/redis/go-redis/v9"
)

// Message represents a pub/sub message
type Message struct {
	Channel string          `json:"channel"`
	Pattern string          `json:"pattern,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

// MessageHandler handles incoming messages
type MessageHandler func(ctx context.Context, msg *Message)

// PubSub manages Redis pub/sub operations
type PubSub struct {
	client       *Client
	prefix       string
	subscriptions map[string]*subscription
	mu           sync.RWMutex
}

type subscription struct {
	pubsub  *goredis.PubSub
	cancel  context.CancelFunc
	handler MessageHandler
}

// NewPubSub creates a new PubSub manager
func NewPubSub(client *Client, prefix string) *PubSub {
	return &PubSub{
		client:       client,
		prefix:       prefix,
		subscriptions: make(map[string]*subscription),
	}
}

// channelKey returns the full channel name with prefix
func (p *PubSub) channelKey(channel string) string {
	if p.prefix == "" {
		return channel
	}
	return p.prefix + channel
}

// Publish publishes a message to a channel
func (p *PubSub) Publish(ctx context.Context, channel string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	return p.client.rdb.Publish(ctx, p.channelKey(channel), data).Err()
}

// PublishRaw publishes raw data to a channel
func (p *PubSub) PublishRaw(ctx context.Context, channel string, data []byte) error {
	return p.client.rdb.Publish(ctx, p.channelKey(channel), data).Err()
}

// Subscribe subscribes to a channel
func (p *PubSub) Subscribe(ctx context.Context, channel string, handler MessageHandler) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	fullChannel := p.channelKey(channel)

	// Check if already subscribed
	if _, exists := p.subscriptions[fullChannel]; exists {
		return fmt.Errorf("already subscribed to channel: %s", channel)
	}

	// Create subscription context
	subCtx, cancel := context.WithCancel(ctx)

	// Subscribe
	pubsub := p.client.rdb.Subscribe(subCtx, fullChannel)

	// Wait for confirmation
	_, err := pubsub.Receive(subCtx)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to subscribe: %w", err)
	}

	sub := &subscription{
		pubsub:  pubsub,
		cancel:  cancel,
		handler: handler,
	}

	p.subscriptions[fullChannel] = sub

	// Start message handler goroutine
	go p.handleMessages(subCtx, sub, channel)

	return nil
}

// PSubscribe subscribes to channels matching a pattern
func (p *PubSub) PSubscribe(ctx context.Context, pattern string, handler MessageHandler) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	fullPattern := p.channelKey(pattern)

	// Check if already subscribed
	if _, exists := p.subscriptions[fullPattern]; exists {
		return fmt.Errorf("already subscribed to pattern: %s", pattern)
	}

	// Create subscription context
	subCtx, cancel := context.WithCancel(ctx)

	// Subscribe
	pubsub := p.client.rdb.PSubscribe(subCtx, fullPattern)

	// Wait for confirmation
	_, err := pubsub.Receive(subCtx)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to psubscribe: %w", err)
	}

	sub := &subscription{
		pubsub:  pubsub,
		cancel:  cancel,
		handler: handler,
	}

	p.subscriptions[fullPattern] = sub

	// Start message handler goroutine
	go p.handlePatternMessages(subCtx, sub, pattern)

	return nil
}

// Unsubscribe unsubscribes from a channel
func (p *PubSub) Unsubscribe(ctx context.Context, channel string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	fullChannel := p.channelKey(channel)

	sub, exists := p.subscriptions[fullChannel]
	if !exists {
		return nil // Not subscribed
	}

	// Cancel context to stop handler goroutine
	sub.cancel()

	// Close subscription
	if err := sub.pubsub.Close(); err != nil {
		return fmt.Errorf("failed to close subscription: %w", err)
	}

	delete(p.subscriptions, fullChannel)
	return nil
}

// PUnsubscribe unsubscribes from a pattern
func (p *PubSub) PUnsubscribe(ctx context.Context, pattern string) error {
	return p.Unsubscribe(ctx, pattern) // Same logic
}

// handleMessages processes messages for a regular subscription
func (p *PubSub) handleMessages(ctx context.Context, sub *subscription, channel string) {
	ch := sub.pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}

			message := &Message{
				Channel: channel,
				Payload: json.RawMessage(msg.Payload),
			}

			sub.handler(ctx, message)
		}
	}
}

// handlePatternMessages processes messages for a pattern subscription
func (p *PubSub) handlePatternMessages(ctx context.Context, sub *subscription, pattern string) {
	ch := sub.pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}

			// Strip prefix from channel name if present
			channelName := msg.Channel
			if p.prefix != "" && len(channelName) > len(p.prefix) {
				channelName = channelName[len(p.prefix):]
			}

			message := &Message{
				Channel: channelName,
				Pattern: pattern,
				Payload: json.RawMessage(msg.Payload),
			}

			sub.handler(ctx, message)
		}
	}
}

// Close closes all subscriptions
func (p *PubSub) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var lastErr error
	for key, sub := range p.subscriptions {
		sub.cancel()
		if err := sub.pubsub.Close(); err != nil {
			lastErr = err
		}
		delete(p.subscriptions, key)
	}

	return lastErr
}

// SubscriptionCount returns the number of active subscriptions
func (p *PubSub) SubscriptionCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.subscriptions)
}

// Channels returns a list of subscribed channels
func (p *PubSub) Channels() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	channels := make([]string, 0, len(p.subscriptions))
	for ch := range p.subscriptions {
		// Strip prefix
		if p.prefix != "" && len(ch) > len(p.prefix) {
			ch = ch[len(p.prefix):]
		}
		channels = append(channels, ch)
	}
	return channels
}

// Common channel names for the application
const (
	ChannelContainerEvents = "container:events"
	ChannelHostEvents      = "host:events"
	ChannelSecurityAlerts  = "security:alerts"
	ChannelUpdateEvents    = "update:events"
	ChannelBackupEvents    = "backup:events"
	ChannelNotifications   = "notifications"
	ChannelAuditLog        = "audit:log"
)

// Event types
type EventType string

const (
	EventCreated  EventType = "created"
	EventUpdated  EventType = "updated"
	EventDeleted  EventType = "deleted"
	EventStarted  EventType = "started"
	EventStopped  EventType = "stopped"
	EventError    EventType = "error"
	EventWarning  EventType = "warning"
	EventInfo     EventType = "info"
)

// Event represents a generic event
type Event struct {
	Type      EventType              `json:"type"`
	EntityID  string                 `json:"entity_id"`
	EntityType string                `json:"entity_type"`
	Timestamp int64                  `json:"timestamp"`
	UserID    string                 `json:"user_id,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// PublishEvent publishes a typed event
func (p *PubSub) PublishEvent(ctx context.Context, channel string, event *Event) error {
	return p.Publish(ctx, channel, event)
}
