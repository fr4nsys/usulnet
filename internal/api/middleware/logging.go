// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// RequestLogger is the interface that the logging middleware uses.
// Any logger from Department A should implement this interface.
type RequestLogger interface {
	Info(msg string, keysAndValues ...any)
	Warn(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
}

// LoggingConfig contains configuration for the logging middleware.
type LoggingConfig struct {
	// Logger is the logger to use
	Logger RequestLogger

	// LogRequestBody logs the request body (careful with large bodies)
	LogRequestBody bool

	// MaxBodySize is the maximum body size to log (default 1KB)
	MaxBodySize int

	// SkipPaths is a list of paths to skip logging (e.g., health checks)
	SkipPaths []string

	// LogHeaders includes request headers in the log (may contain sensitive data)
	LogHeaders bool

	// SensitiveHeaders is a list of headers to redact
	SensitiveHeaders []string
}

// DefaultLoggingConfig returns a default logging configuration.
func DefaultLoggingConfig() LoggingConfig {
	return LoggingConfig{
		Logger:         nil,
		LogRequestBody: false,
		MaxBodySize:    1024,
		SkipPaths:      []string{"/health", "/healthz", "/ready", "/metrics"},
		LogHeaders:     false,
		SensitiveHeaders: []string{
			"Authorization",
			"X-API-KEY",
			"Cookie",
			"Set-Cookie",
		},
	}
}

// responseWriter wraps http.ResponseWriter to capture status code and size.
type responseWriter struct {
	http.ResponseWriter
	status      int
	size        int
	wroteHeader bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, status: http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.wroteHeader = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}

// Unwrap returns the underlying ResponseWriter for compatibility with
// http.ResponseController and other interfaces.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// Hijack implements http.Hijacker. Required for WebSocket upgrades.
// gorilla/websocket does w.(http.Hijacker) directly, so Unwrap() alone
// is not sufficient.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("upstream ResponseWriter does not implement http.Hijacker")
}

// Flush implements http.Flusher. Required for SSE and streaming responses.
func (rw *responseWriter) Flush() {
	if fl, ok := rw.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

// Logging returns a request logging middleware.
func Logging(config LoggingConfig) func(http.Handler) http.Handler {
	if config.Logger == nil {
		// Return no-op middleware if no logger is provided
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	skipPaths := make(map[string]bool)
	for _, path := range config.SkipPaths {
		skipPaths[path] = true
	}

	sensitiveHeaders := make(map[string]bool)
	for _, h := range config.SensitiveHeaders {
		sensitiveHeaders[strings.ToLower(h)] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip certain paths
			if skipPaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			requestID := GetRequestID(r.Context())

			// Capture request body if configured
			var requestBody string
			if config.LogRequestBody && r.Body != nil {
				body, err := io.ReadAll(io.LimitReader(r.Body, int64(config.MaxBodySize)))
				if err == nil {
					requestBody = string(body)
					// Restore body for downstream handlers
					r.Body = io.NopCloser(bytes.NewReader(body))
				}
			}

			// Wrap response writer to capture status and size
			wrapped := newResponseWriter(w)

			// Process request
			next.ServeHTTP(wrapped, r)

			// Calculate duration
			duration := time.Since(start)

			// Build log fields
			fields := []any{
				"request_id", requestID,
				"method", r.Method,
				"path", r.URL.Path,
				"query", r.URL.RawQuery,
				"status", wrapped.status,
				"size", wrapped.size,
				"duration_ms", duration.Milliseconds(),
				"remote_addr", getRealIP(r),
				"user_agent", r.UserAgent(),
			}

			// Add user info if available
			if claims := GetUserFromContext(r.Context()); claims != nil {
				fields = append(fields, "user_id", claims.UserID, "username", claims.Username)
			}

			// Add request body if configured
			if requestBody != "" {
				fields = append(fields, "request_body", truncate(requestBody, config.MaxBodySize))
			}

			// Add headers if configured
			if config.LogHeaders {
				headers := make(map[string]string)
				for name, values := range r.Header {
					if sensitiveHeaders[strings.ToLower(name)] {
						headers[name] = "[REDACTED]"
					} else if len(values) > 0 {
						headers[name] = values[0]
					}
				}
				fields = append(fields, "headers", headers)
			}

			// Log based on status code
			switch {
			case wrapped.status >= 500:
				config.Logger.Error("request completed", fields...)
			case wrapped.status >= 400:
				config.Logger.Warn("request completed", fields...)
			default:
				config.Logger.Info("request completed", fields...)
			}
		})
	}
}

// SimpleLogging returns a simplified logging middleware.
func SimpleLogging(logger RequestLogger) func(http.Handler) http.Handler {
	config := DefaultLoggingConfig()
	config.Logger = logger
	return Logging(config)
}

// truncate truncates a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[truncated]"
}

// ============================================================================
// Debug logging helpers
// ============================================================================

// DebugLogging returns a verbose logging middleware for development.
func DebugLogging(logger RequestLogger) func(http.Handler) http.Handler {
	return Logging(LoggingConfig{
		Logger:         logger,
		LogRequestBody: true,
		MaxBodySize:    4096,
		SkipPaths:      nil, // Log everything
		LogHeaders:     true,
		SensitiveHeaders: []string{
			"Authorization",
			"X-API-KEY",
			"Cookie",
		},
	})
}

// ============================================================================
// Real IP middleware
// ============================================================================

// RealIP is a middleware that sets the RemoteAddr to the real client IP
// based on X-Forwarded-For or X-Real-IP headers.
func RealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rip := getRealIP(r); rip != "" {
			r.RemoteAddr = rip
		}
		next.ServeHTTP(w, r)
	})
}
