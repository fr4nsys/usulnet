// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package nats provides subscriber functionality for NATS messaging.
package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// MessageHandler is a custom handler type that returns an error.
type MessageHandler func(msg *nats.Msg) error

// RequestHandler handles request-reply messages.
type RequestHandler func(msg *nats.Msg) ([]byte, error)

// Subscriber manages NATS subscriptions.
type Subscriber struct {
	client        *Client
	logger        *zap.Logger
	subscriptions map[string]*nats.Subscription
	mu            sync.RWMutex
}

// NewSubscriber creates a new subscriber.
func NewSubscriber(client *Client) *Subscriber {
	logger := zap.NewNop()
	if client != nil && client.logger != nil {
		logger = client.logger
	}

	return &Subscriber{
		client:        client,
		logger:        logger.Named("subscriber"),
		subscriptions: make(map[string]*nats.Subscription),
	}
}

// Subscribe subscribes to a subject with a custom MessageHandler.
// The handler's error is logged but doesn't affect message acknowledgment.
func (s *Subscriber) Subscribe(subject string, handler MessageHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn := s.client.Conn()
	if conn == nil {
		return fmt.Errorf("not connected")
	}

	// Wrap MessageHandler to nats.MsgHandler
	natsHandler := func(msg *nats.Msg) {
		if err := handler(msg); err != nil {
			s.logger.Error("message handler error",
				zap.String("subject", msg.Subject),
				zap.Error(err),
			)
		}
	}

	sub, err := conn.Subscribe(subject, natsHandler)
	if err != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", subject, err)
	}

	s.subscriptions[subject] = sub
	s.logger.Debug("Subscribed", zap.String("subject", subject))

	return nil
}

// QueueSubscribe subscribes with a queue group.
func (s *Subscriber) QueueSubscribe(subject, queue string, handler MessageHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn := s.client.Conn()
	if conn == nil {
		return fmt.Errorf("not connected")
	}

	// Wrap MessageHandler to nats.MsgHandler
	natsHandler := func(msg *nats.Msg) {
		if err := handler(msg); err != nil {
			s.logger.Error("message handler error",
				zap.String("subject", msg.Subject),
				zap.String("queue", queue),
				zap.Error(err),
			)
		}
	}

	sub, err := conn.QueueSubscribe(subject, queue, natsHandler)
	if err != nil {
		return fmt.Errorf("failed to queue subscribe to %s: %w", subject, err)
	}

	key := subject + ":" + queue
	s.subscriptions[key] = sub
	s.logger.Debug("Queue subscribed", zap.String("subject", subject), zap.String("queue", queue))

	return nil
}

// SubscribeRequest subscribes to handle request-reply pattern.
func (s *Subscriber) SubscribeRequest(subject string, handler RequestHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn := s.client.Conn()
	if conn == nil {
		return fmt.Errorf("not connected")
	}

	natsHandler := func(msg *nats.Msg) {
		response, err := handler(msg)
		if err != nil {
			s.logger.Error("request handler error",
				zap.String("subject", msg.Subject),
				zap.Error(err),
			)
			// Send error response if reply subject exists
			if msg.Reply != "" {
				errResp := map[string]string{"error": err.Error()}
				if data, _ := json.Marshal(errResp); data != nil {
					msg.Respond(data)
				}
			}
			return
		}

		if msg.Reply != "" && response != nil {
			if err := msg.Respond(response); err != nil {
				s.logger.Error("failed to send response",
					zap.String("subject", msg.Subject),
					zap.Error(err),
				)
			}
		}
	}

	sub, err := conn.Subscribe(subject, natsHandler)
	if err != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", subject, err)
	}

	s.subscriptions[subject] = sub
	s.logger.Debug("Request handler subscribed", zap.String("subject", subject))

	return nil
}

// SubscribeSync creates a synchronous subscription.
func (s *Subscriber) SubscribeSync(subject string) (*nats.Subscription, error) {
	conn := s.client.Conn()
	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	sub, err := conn.SubscribeSync(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to sync subscribe to %s: %w", subject, err)
	}

	s.mu.Lock()
	s.subscriptions[subject+"_sync"] = sub
	s.mu.Unlock()

	return sub, nil
}

// SubscribeChan subscribes and delivers messages to a channel.
func (s *Subscriber) SubscribeChan(subject string, ch chan *nats.Msg) error {
	conn := s.client.Conn()
	if conn == nil {
		return fmt.Errorf("not connected")
	}

	sub, err := conn.ChanSubscribe(subject, ch)
	if err != nil {
		return fmt.Errorf("failed to chan subscribe to %s: %w", subject, err)
	}

	s.mu.Lock()
	s.subscriptions[subject+"_chan"] = sub
	s.mu.Unlock()

	return nil
}

// Unsubscribe unsubscribes from a subject.
func (s *Subscriber) Unsubscribe(subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, ok := s.subscriptions[subject]
	if !ok {
		return fmt.Errorf("subscription not found: %s", subject)
	}

	if err := sub.Unsubscribe(); err != nil {
		return fmt.Errorf("failed to unsubscribe from %s: %w", subject, err)
	}

	delete(s.subscriptions, subject)
	s.logger.Debug("Unsubscribed", zap.String("subject", subject))

	return nil
}

// Drain drains a subscription before unsubscribing.
func (s *Subscriber) Drain(subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, ok := s.subscriptions[subject]
	if !ok {
		return fmt.Errorf("subscription not found: %s", subject)
	}

	if err := sub.Drain(); err != nil {
		return fmt.Errorf("failed to drain %s: %w", subject, err)
	}

	delete(s.subscriptions, subject)
	return nil
}

// Close unsubscribes from all subscriptions.
func (s *Subscriber) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	for subject, sub := range s.subscriptions {
		if err := sub.Unsubscribe(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", subject, err))
		}
	}

	s.subscriptions = make(map[string]*nats.Subscription)

	if len(errs) > 0 {
		return fmt.Errorf("errors closing subscriptions: %v", errs)
	}

	return nil
}

// Stats returns statistics for a subscription.
func (s *Subscriber) Stats(subject string) (*SubscriptionStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sub, ok := s.subscriptions[subject]
	if !ok {
		return nil, fmt.Errorf("subscription not found: %s", subject)
	}

	delivered, _ := sub.Delivered()
	dropped, _ := sub.Dropped()
	pending, pendingBytes, _ := sub.Pending()
	pendingLimitMsgs, pendingLimitBytes, _ := sub.PendingLimits()

	return &SubscriptionStats{
		Subject:           sub.Subject,
		Queue:             sub.Queue,
		Delivered:         uint64(delivered), // Convert int64 to uint64
		Dropped:           uint64(dropped),   // Convert int to uint64
		Pending:           pending,
		PendingBytes:      pendingBytes,
		PendingLimitMsgs:  pendingLimitMsgs,
		PendingLimitBytes: pendingLimitBytes,
		IsValid:           sub.IsValid(),
	}, nil
}

// SubscriptionStats holds subscription statistics.
type SubscriptionStats struct {
	Subject           string
	Queue             string
	Delivered         uint64
	Dropped           uint64
	Pending           int
	PendingBytes      int
	PendingLimitMsgs  int
	PendingLimitBytes int
	IsValid           bool
}

// ListSubscriptions returns all active subscription subjects.
func (s *Subscriber) ListSubscriptions() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	subjects := make([]string, 0, len(s.subscriptions))
	for subject := range s.subscriptions {
		subjects = append(subjects, subject)
	}
	return subjects
}

// SetPendingLimits sets pending message limits for a subscription.
func (s *Subscriber) SetPendingLimits(subject string, msgLimit, bytesLimit int) error {
	s.mu.RLock()
	sub, ok := s.subscriptions[subject]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("subscription not found: %s", subject)
	}

	return sub.SetPendingLimits(msgLimit, bytesLimit)
}

// TypedSubscriber handles typed message subscriptions.
type TypedSubscriber[T any] struct {
	subscriber *Subscriber
	subject    string
}

// NewTypedSubscriber creates a typed subscriber for a specific message type.
func NewTypedSubscriber[T any](subscriber *Subscriber, subject string) *TypedSubscriber[T] {
	return &TypedSubscriber[T]{
		subscriber: subscriber,
		subject:    subject,
	}
}

// Subscribe subscribes with a typed handler.
func (ts *TypedSubscriber[T]) Subscribe(handler func(msg T) error) error {
	return ts.subscriber.Subscribe(ts.subject, func(msg *nats.Msg) error {
		var typed T
		if err := json.Unmarshal(msg.Data, &typed); err != nil {
			return fmt.Errorf("failed to unmarshal message: %w", err)
		}
		return handler(typed)
	})
}

// SubscribeWithContext subscribes with context and typed handler.
func (ts *TypedSubscriber[T]) SubscribeWithContext(ctx context.Context, handler func(ctx context.Context, msg T) error) error {
	return ts.subscriber.Subscribe(ts.subject, func(msg *nats.Msg) error {
		var typed T
		if err := json.Unmarshal(msg.Data, &typed); err != nil {
			return fmt.Errorf("failed to unmarshal message: %w", err)
		}
		return handler(ctx, typed)
	})
}
