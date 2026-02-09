// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"net/http"
	"time"

	"github.com/go-chi/httprate"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
)

// RateLimitConfig contains rate limiting configuration.
type RateLimitConfig struct {
	// RequestLimit is the maximum number of requests allowed per window.
	RequestLimit int

	// WindowLength is the duration of the rate limit window.
	WindowLength time.Duration

	// KeyFunc extracts the rate limit key from the request.
	// If nil, defaults to IP-based limiting.
	KeyFunc func(r *http.Request) (string, error)

	// LimitHandler is called when the rate limit is exceeded.
	// If nil, a default JSON error response is sent.
	LimitHandler http.HandlerFunc

	// Headers enables rate limit headers in the response.
	// X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
	Headers bool
}

// DefaultRateLimitConfig returns a default rate limit configuration.
// 100 requests per minute per IP.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestLimit: 100,
		WindowLength: time.Minute,
		KeyFunc:      nil, // IP-based
		LimitHandler: nil, // Default JSON error
		Headers:      true,
	}
}

// RateLimit returns a rate limiting middleware with the given configuration.
func RateLimit(config RateLimitConfig) func(http.Handler) http.Handler {
	opts := []httprate.Option{
		httprate.WithLimitHandler(rateLimitHandler(config.WindowLength)),
	}

	if config.KeyFunc != nil {
		opts = append(opts, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			return config.KeyFunc(r)
		}))
	}

	// Note: httprate doesn't have a direct "Headers" option,
	// but it does set headers by default. We'll wrap it if needed.
	return httprate.Limit(config.RequestLimit, config.WindowLength, opts...)
}

// RateLimitByIP returns a rate limiting middleware that limits by IP address.
func RateLimitByIP(requestLimit int, window time.Duration) func(http.Handler) http.Handler {
	return RateLimit(RateLimitConfig{
		RequestLimit: requestLimit,
		WindowLength: window,
		Headers:      true,
	})
}

// RateLimitByUser returns a rate limiting middleware that limits by authenticated user.
// Falls back to IP if user is not authenticated.
func RateLimitByUser(requestLimit int, window time.Duration) func(http.Handler) http.Handler {
	return RateLimit(RateLimitConfig{
		RequestLimit: requestLimit,
		WindowLength: window,
		KeyFunc: func(r *http.Request) (string, error) {
			// Try to get user ID from context (set by auth middleware)
			if claims := GetUserFromContext(r.Context()); claims != nil {
				return "user:" + claims.UserID, nil
			}
			// Fallback to IP
			return "ip:" + getRealIP(r), nil
		},
		Headers: true,
	})
}

// RateLimitByAPIKey returns a rate limiting middleware that limits by API key.
// Falls back to IP if no API key is present.
func RateLimitByAPIKey(requestLimit int, window time.Duration) func(http.Handler) http.Handler {
	return RateLimit(RateLimitConfig{
		RequestLimit: requestLimit,
		WindowLength: window,
		KeyFunc: func(r *http.Request) (string, error) {
			if apiKey := r.Header.Get("X-API-KEY"); apiKey != "" {
				// Use first 16 chars of API key as identifier (don't expose full key)
				if len(apiKey) > 16 {
					apiKey = apiKey[:16]
				}
				return "apikey:" + apiKey, nil
			}
			return "ip:" + getRealIP(r), nil
		},
		Headers: true,
	})
}

// rateLimitHandler returns the handler called when rate limit is exceeded.
func rateLimitHandler(window time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		retryAfter := int(window.Seconds())
		w.Header().Set("Retry-After", string(rune(retryAfter)))

		requestID := GetRequestID(r.Context())
		apiErr := apierrors.RateLimited(retryAfter)
		apierrors.WriteErrorWithRequestID(w, apiErr, requestID)
	}
}

// ============================================================================
// Specialized rate limiters
// ============================================================================

// StrictRateLimit returns a very strict rate limiter for sensitive endpoints.
// Example: login, password reset, etc.
func StrictRateLimit() func(http.Handler) http.Handler {
	return RateLimitByIP(10, time.Minute)
}

// AuthRateLimit returns a rate limiter for authentication endpoints.
// 5 attempts per minute per IP.
func AuthRateLimit() func(http.Handler) http.Handler {
	return RateLimitByIP(5, time.Minute)
}

// APIRateLimit returns a standard rate limiter for API endpoints.
// 100 requests per minute per user/IP.
func APIRateLimit() func(http.Handler) http.Handler {
	return RateLimitByUser(100, time.Minute)
}

// BurstRateLimit returns a rate limiter that allows bursts.
// 1000 requests per minute, suitable for heavy API usage.
func BurstRateLimit() func(http.Handler) http.Handler {
	return RateLimitByUser(1000, time.Minute)
}

// WebSocketRateLimit returns a rate limiter for WebSocket connections.
// 10 connections per minute per IP.
func WebSocketRateLimit() func(http.Handler) http.Handler {
	return RateLimitByIP(10, time.Minute)
}
