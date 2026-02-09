// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package nats provides JetStream functionality for NATS messaging.
package nats

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// JetStream wraps NATS JetStream functionality.
type JetStream struct {
	client *Client
	js     nats.JetStreamContext
	logger *zap.Logger
}

// StreamConfig holds stream configuration.
type StreamConfig struct {
	Name         string
	Description  string
	Subjects     []string
	MaxAge       time.Duration
	MaxBytes     int64
	MaxMsgs      int64
	MaxMsgSize   int32
	Storage      nats.StorageType
	Replicas     int
	Retention    nats.RetentionPolicy
	Discard      nats.DiscardPolicy
	MaxConsumers int
}

// ConsumerConfig holds consumer configuration.
type ConsumerConfig struct {
	Name           string
	Durable        string
	Description    string
	FilterSubject  string
	AckPolicy      nats.AckPolicy
	AckWait        time.Duration
	MaxDeliver     int
	MaxAckPending  int
	DeliverPolicy  nats.DeliverPolicy
	DeliverSubject string
	DeliverGroup   string
}

// NewJetStream creates a new JetStream wrapper.
func NewJetStream(client *Client) (*JetStream, error) {
	if client == nil || client.Conn() == nil {
		return nil, fmt.Errorf("NATS client not connected")
	}

	js, err := client.Conn().JetStream()
	if err != nil {
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}

	logger := zap.NewNop()
	if client.logger != nil {
		logger = client.logger
	}

	return &JetStream{
		client: client,
		js:     js,
		logger: logger.Named("jetstream"),
	}, nil
}

// CreateStream creates or updates a stream.
func (j *JetStream) CreateStream(ctx context.Context, cfg StreamConfig) (*nats.StreamInfo, error) {
	streamCfg := &nats.StreamConfig{
		Name:         cfg.Name,
		Description:  cfg.Description,
		Subjects:     cfg.Subjects,
		MaxAge:       cfg.MaxAge,
		MaxBytes:     cfg.MaxBytes,
		MaxMsgs:      cfg.MaxMsgs,
		MaxMsgSize:   cfg.MaxMsgSize,
		Storage:      cfg.Storage,
		Replicas:     cfg.Replicas,
		Retention:    cfg.Retention,
		Discard:      cfg.Discard,
		MaxConsumers: cfg.MaxConsumers,
	}

	// Set defaults
	if streamCfg.Storage == 0 {
		streamCfg.Storage = nats.FileStorage
	}
	if streamCfg.Retention == 0 {
		streamCfg.Retention = nats.LimitsPolicy
	}
	if streamCfg.Discard == 0 {
		streamCfg.Discard = nats.DiscardOld
	}
	if streamCfg.Replicas == 0 {
		streamCfg.Replicas = 1
	}

	// Try to get existing stream
	info, err := j.js.StreamInfo(cfg.Name)
	if err == nil {
		// Stream exists, update it
		info, err = j.js.UpdateStream(streamCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to update stream %s: %w", cfg.Name, err)
		}
		j.logger.Debug("Updated stream", zap.String("name", cfg.Name))
		return info, nil
	}

	// Create new stream
	info, err = j.js.AddStream(streamCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream %s: %w", cfg.Name, err)
	}

	j.logger.Info("Created stream",
		zap.String("name", cfg.Name),
		zap.Strings("subjects", cfg.Subjects),
	)

	return info, nil
}

// DeleteStream deletes a stream.
func (j *JetStream) DeleteStream(ctx context.Context, name string) error {
	if err := j.js.DeleteStream(name); err != nil {
		return fmt.Errorf("failed to delete stream %s: %w", name, err)
	}

	j.logger.Info("Deleted stream", zap.String("name", name))
	return nil
}

// StreamInfo returns information about a stream.
func (j *JetStream) StreamInfo(name string) (*nats.StreamInfo, error) {
	return j.js.StreamInfo(name)
}

// ListStreams returns all streams.
func (j *JetStream) ListStreams() ([]*nats.StreamInfo, error) {
	var streams []*nats.StreamInfo

	for info := range j.js.Streams() {
		streams = append(streams, info)
	}

	return streams, nil
}

// CreateConsumer creates a consumer on a stream.
func (j *JetStream) CreateConsumer(ctx context.Context, stream string, cfg ConsumerConfig) (*nats.ConsumerInfo, error) {
	consumerCfg := &nats.ConsumerConfig{
		Durable:        cfg.Durable,
		Description:    cfg.Description,
		FilterSubject:  cfg.FilterSubject,
		AckPolicy:      cfg.AckPolicy,
		AckWait:        cfg.AckWait,
		MaxDeliver:     cfg.MaxDeliver,
		MaxAckPending:  cfg.MaxAckPending,
		DeliverPolicy:  cfg.DeliverPolicy,
		DeliverSubject: cfg.DeliverSubject,
		DeliverGroup:   cfg.DeliverGroup,
	}

	// Set defaults
	if consumerCfg.AckPolicy == 0 {
		consumerCfg.AckPolicy = nats.AckExplicitPolicy
	}
	if consumerCfg.AckWait == 0 {
		consumerCfg.AckWait = 30 * time.Second
	}
	if consumerCfg.MaxDeliver == 0 {
		consumerCfg.MaxDeliver = 5
	}

	info, err := j.js.AddConsumer(stream, consumerCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer on %s: %w", stream, err)
	}

	j.logger.Info("Created consumer",
		zap.String("stream", stream),
		zap.String("durable", cfg.Durable),
	)

	return info, nil
}

// DeleteConsumer deletes a consumer.
func (j *JetStream) DeleteConsumer(ctx context.Context, stream, consumer string) error {
	if err := j.js.DeleteConsumer(stream, consumer); err != nil {
		return fmt.Errorf("failed to delete consumer %s from %s: %w", consumer, stream, err)
	}

	j.logger.Info("Deleted consumer",
		zap.String("stream", stream),
		zap.String("consumer", consumer),
	)
	return nil
}

// ConsumerInfo returns information about a consumer.
func (j *JetStream) ConsumerInfo(stream, consumer string) (*nats.ConsumerInfo, error) {
	return j.js.ConsumerInfo(stream, consumer)
}

// Publish publishes a message to JetStream.
func (j *JetStream) Publish(subject string, data []byte, opts ...nats.PubOpt) (*nats.PubAck, error) {
	return j.js.Publish(subject, data, opts...)
}

// PublishAsync publishes asynchronously.
func (j *JetStream) PublishAsync(subject string, data []byte, opts ...nats.PubOpt) (nats.PubAckFuture, error) {
	return j.js.PublishAsync(subject, data, opts...)
}

// Subscribe creates a push subscription.
func (j *JetStream) Subscribe(subject string, handler nats.MsgHandler, opts ...nats.SubOpt) (*nats.Subscription, error) {
	return j.js.Subscribe(subject, handler, opts...)
}

// QueueSubscribe creates a queue subscription.
func (j *JetStream) QueueSubscribe(subject, queue string, handler nats.MsgHandler, opts ...nats.SubOpt) (*nats.Subscription, error) {
	return j.js.QueueSubscribe(subject, queue, handler, opts...)
}

// PullSubscribe creates a pull subscription.
func (j *JetStream) PullSubscribe(subject, durable string, opts ...nats.SubOpt) (*nats.Subscription, error) {
	return j.js.PullSubscribe(subject, durable, opts...)
}

// KeyValue returns a KeyValue store.
func (j *JetStream) KeyValue(bucket string) (nats.KeyValue, error) {
	return j.js.KeyValue(bucket)
}

// CreateKeyValue creates a KeyValue store.
func (j *JetStream) CreateKeyValue(cfg *nats.KeyValueConfig) (nats.KeyValue, error) {
	return j.js.CreateKeyValue(cfg)
}

// DeleteKeyValue deletes a KeyValue store.
func (j *JetStream) DeleteKeyValue(bucket string) error {
	return j.js.DeleteKeyValue(bucket)
}

// ObjectStore returns an ObjectStore.
func (j *JetStream) ObjectStore(bucket string) (nats.ObjectStore, error) {
	return j.js.ObjectStore(bucket)
}

// CreateObjectStore creates an ObjectStore.
func (j *JetStream) CreateObjectStore(cfg *nats.ObjectStoreConfig) (nats.ObjectStore, error) {
	return j.js.CreateObjectStore(cfg)
}

// DeleteObjectStore deletes an ObjectStore.
func (j *JetStream) DeleteObjectStore(bucket string) error {
	return j.js.DeleteObjectStore(bucket)
}

// AccountInfo returns JetStream account info.
func (j *JetStream) AccountInfo() (*nats.AccountInfo, error) {
	return j.js.AccountInfo()
}

// Context returns the underlying JetStreamContext.
func (j *JetStream) Context() nats.JetStreamContext {
	return j.js
}
