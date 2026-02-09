// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package middleware provides HTTP middleware for the API server.
package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// Context keys for middleware values.
type contextKey string

const (
	// RequestIDKey is the context key for the request ID.
	RequestIDKey contextKey = "request_id"

	// RequestIDHeader is the HTTP header name for request ID.
	RequestIDHeader = "X-Request-ID"
)

// RequestID is a middleware that injects a request ID into the context of each request.
// If the incoming request has an X-Request-ID header, it will be used.
// Otherwise, a new UUID v7 (time-ordered) will be generated.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(RequestIDHeader)

		// Generate new ID if not provided or invalid
		if requestID == "" {
			// Use UUID v7 for time-ordered IDs (better for logging/sorting)
			id, err := uuid.NewV7()
			if err != nil {
				// Fallback to v4 if v7 fails
				id = uuid.New()
			}
			requestID = id.String()
		}

		// Set the request ID in the response header
		w.Header().Set(RequestIDHeader, requestID)

		// Add to context
		ctx := context.WithValue(r.Context(), RequestIDKey, requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRequestID retrieves the request ID from the context.
// Returns an empty string if no request ID is found.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(RequestIDKey).(string); ok {
		return id
	}
	return ""
}

// GetRequestIDFromRequest is a convenience function to get request ID from http.Request.
func GetRequestIDFromRequest(r *http.Request) string {
	return GetRequestID(r.Context())
}
