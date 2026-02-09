// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package nats provides publisher functionality for NATS messaging.
package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// Publisher handles NATS message publishing.
type Publisher struct {
	client *Client
	logger *zap.Logger
}

// NewPublisher creates a new publisher.
func NewPublisher(client *Client) *Publisher {
	logger := zap.NewNop()
	if client != nil && client.logger != nil {
		logger = client.logger
	}

	return &Publisher{
		client: client,
		logger: logger.Named("publisher"),
	}
}

// Publish publishes raw bytes to a subject.
func (p *Publisher) Publish(subject string, data []byte) error {
	conn := p.client.Conn()
	if conn == nil {
		return fmt.Errorf("not connected")
	}

	if err := conn.Publish(subject, data); err != nil {
		return fmt.Errorf("failed to publish to %s: %w", subject, err)
	}

	p.logger.Debug("Published message",
		zap.String("subject", subject),
		zap.Int("size", len(data)),
	)

	return nil
}

// PublishJSON marshals and publishes a value as JSON.
func (p *Publisher) PublishJSON(subject string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	return p.Publish(subject, data)
}

// PublishMsg publishes a NATS message.
func (p *Publisher) PublishMsg(msg *nats.Msg) error {
	conn := p.client.Conn()
	if conn == nil {
		return fmt.Errorf("not connected")
	}

	return conn.PublishMsg(msg)
}

// Request sends a request and waits for a response.
func (p *Publisher) Request(subject string, data []byte, timeout time.Duration) (*nats.Msg, error) {
	conn := p.client.Conn()
	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	return conn.Request(subject, data, timeout)
}

// RequestJSON sends a JSON request and unmarshals the response.
func (p *Publisher) RequestJSON(subject string, request interface{}, response interface{}, timeout time.Duration) error {
	data, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	msg, err := p.Request(subject, data, timeout)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	if response != nil {
		if err := json.Unmarshal(msg.Data, response); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// RequestWithContext sends a request with context for cancellation.
func (p *Publisher) RequestWithContext(ctx context.Context, subject string, data []byte) (*nats.Msg, error) {
	conn := p.client.Conn()
	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	return conn.RequestWithContext(ctx, subject, data)
}

// RequestJSONWithContext sends a JSON request with context.
func (p *Publisher) RequestJSONWithContext(ctx context.Context, subject string, request interface{}, response interface{}) error {
	data, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	msg, err := p.RequestWithContext(ctx, subject, data)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	if response != nil {
		if err := json.Unmarshal(msg.Data, response); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// Flush flushes the connection.
func (p *Publisher) Flush() error {
	return p.client.Flush()
}

// FlushTimeout flushes with a timeout.
func (p *Publisher) FlushTimeout(timeout time.Duration) error {
	return p.client.FlushTimeout(timeout)
}

// TypedPublisher handles typed message publishing.
type TypedPublisher[T any] struct {
	publisher *Publisher
	subject   string
}

// NewTypedPublisher creates a typed publisher for a specific subject.
func NewTypedPublisher[T any](publisher *Publisher, subject string) *TypedPublisher[T] {
	return &TypedPublisher[T]{
		publisher: publisher,
		subject:   subject,
	}
}

// Publish publishes a typed message.
func (tp *TypedPublisher[T]) Publish(msg T) error {
	return tp.publisher.PublishJSON(tp.subject, msg)
}

// Request sends a typed request and returns a typed response.
func (tp *TypedPublisher[T]) Request(request T, timeout time.Duration) (*nats.Msg, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	return tp.publisher.Request(tp.subject, data, timeout)
}
