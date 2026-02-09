// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"fmt"
	"net/http"
	"runtime/debug"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
)

// Logger interface for recovery middleware.
// This allows the middleware to work with any logger implementation.
type Logger interface {
	Error(msg string, keysAndValues ...any)
}

// noopLogger is a no-op logger used when no logger is provided.
type noopLogger struct{}

func (noopLogger) Error(msg string, keysAndValues ...any) {}

// RecoveryConfig contains configuration for the recovery middleware.
type RecoveryConfig struct {
	// Logger for logging panic details
	Logger Logger

	// PrintStack determines if stack trace should be logged
	PrintStack bool

	// StackSize is the maximum size of the stack trace to capture (default 4KB)
	StackSize int

	// EnableResponseDetails includes panic details in the error response (ONLY for development)
	EnableResponseDetails bool
}

// DefaultRecoveryConfig returns a default recovery configuration.
func DefaultRecoveryConfig() RecoveryConfig {
	return RecoveryConfig{
		Logger:                nil,
		PrintStack:            true,
		StackSize:             4096,
		EnableResponseDetails: false,
	}
}

// Recovery returns a middleware that recovers from panics and returns a 500 error.
// This prevents a single panic from crashing the entire server.
func Recovery(config ...RecoveryConfig) func(http.Handler) http.Handler {
	cfg := DefaultRecoveryConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.Logger == nil {
		cfg.Logger = noopLogger{}
	}

	if cfg.StackSize == 0 {
		cfg.StackSize = 4096
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					// Get stack trace
					var stack []byte
					if cfg.PrintStack {
						stack = make([]byte, cfg.StackSize)
						stack = stack[:runtime.Stack(stack, false)]
					}

					// Get request ID for correlation
					requestID := GetRequestID(r.Context())

					// Log the panic
					cfg.Logger.Error("panic recovered",
						"error", rec,
						"request_id", requestID,
						"method", r.Method,
						"path", r.URL.Path,
						"remote_addr", r.RemoteAddr,
						"stack", string(stack),
					)

					// Build error response
					var apiErr *apierrors.APIError
					if cfg.EnableResponseDetails {
						// Include panic details (development only!)
						apiErr = apierrors.NewErrorWithDetails(
							http.StatusInternalServerError,
							apierrors.ErrCodeInternal,
							"Internal server error",
							map[string]any{
								"panic": fmt.Sprintf("%v", rec),
								"stack": string(stack),
							},
						)
					} else {
						apiErr = apierrors.Internal("")
					}

					apierrors.WriteErrorWithRequestID(w, apiErr, requestID)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// Recoverer is a simplified recovery middleware using default configuration.
// Use Recovery() for more control over the behavior.
func Recoverer(next http.Handler) http.Handler {
	return Recovery()(next)
}

// runtime.Stack wrapper to avoid importing runtime in the hot path
var runtime = struct {
	Stack func(buf []byte, all bool) int
}{
	Stack: nil,
}

// Override for runtime.Stack to use debug.Stack
func init() {
	runtime.Stack = func(buf []byte, all bool) int {
		stack := debug.Stack()
		n := copy(buf, stack)
		return n
	}
}
