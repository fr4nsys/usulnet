// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package logger

import (
	"context"
)

// contextKey is a private type for context keys
type contextKey struct{}

// loggerKey is the key used to store/retrieve logger from context
var loggerKey = contextKey{}

// WithContext returns a new context with the logger attached
func WithContext(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// FromContext retrieves the logger from context
// Returns a no-op logger if none is found
func FromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerKey).(*Logger); ok {
		return logger
	}
	return Nop()
}

// FromContextOrDefault retrieves the logger from context or returns the provided default
func FromContextOrDefault(ctx context.Context, defaultLogger *Logger) *Logger {
	if logger, ok := ctx.Value(loggerKey).(*Logger); ok {
		return logger
	}
	return defaultLogger
}

// WithRequestID adds a request ID to the logger in context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	logger := FromContext(ctx)
	return WithContext(ctx, logger.With("request_id", requestID))
}

// WithUserID adds a user ID to the logger in context
func WithUserID(ctx context.Context, userID string) context.Context {
	logger := FromContext(ctx)
	return WithContext(ctx, logger.With("user_id", userID))
}

// WithHostID adds a host ID to the logger in context
func WithHostID(ctx context.Context, hostID string) context.Context {
	logger := FromContext(ctx)
	return WithContext(ctx, logger.With("host_id", hostID))
}

// WithContainerID adds a container ID to the logger in context
func WithContainerID(ctx context.Context, containerID string) context.Context {
	logger := FromContext(ctx)
	return WithContext(ctx, logger.With("container_id", containerID))
}

// WithOperation adds an operation name to the logger in context
func WithOperation(ctx context.Context, operation string) context.Context {
	logger := FromContext(ctx)
	return WithContext(ctx, logger.With("operation", operation))
}

// WithComponent adds a component name to the logger in context
func WithComponent(ctx context.Context, component string) context.Context {
	logger := FromContext(ctx)
	return WithContext(ctx, logger.With("component", component))
}
