// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"net/http"
	"strings"

	"github.com/go-chi/cors"
)

// CORSConfig contains CORS configuration options.
type CORSConfig struct {
	// AllowedOrigins is a list of origins a cross-domain request can be executed from.
	// If the special "*" value is present in the list, all origins will be allowed.
	// An origin may contain a wildcard (*) to replace 0 or more characters
	// (i.e.: http://*.domain.com). Usage of wildcards implies a small performance penalty.
	// Only one wildcard can be used per origin.
	AllowedOrigins []string

	// AllowedMethods is a list of methods the client is allowed to use with
	// cross-domain requests.
	AllowedMethods []string

	// AllowedHeaders is list of non simple headers the client is allowed to use with
	// cross-domain requests.
	AllowedHeaders []string

	// ExposedHeaders indicates which headers are safe to expose to the API of a CORS
	// API specification.
	ExposedHeaders []string

	// AllowCredentials indicates whether the request can include user credentials like
	// cookies, HTTP authentication or client side SSL certificates.
	AllowCredentials bool

	// MaxAge indicates how long (in seconds) the results of a preflight request
	// can be cached. Default is 300 (5 minutes).
	MaxAge int
}

// DefaultCORSConfig returns a permissive CORS configuration for development.
// WARNING: This allows all origins. Use a more restrictive config in production.
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins: []string{},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-Request-ID",
			"X-API-KEY",
		},
		ExposedHeaders: []string{
			"X-Request-ID",
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining",
			"X-RateLimit-Reset",
		},
		AllowCredentials: false,
		MaxAge:           300,
	}
}

// ProductionCORSConfig returns a more restrictive CORS configuration for production.
// You must specify the allowed origins.
func ProductionCORSConfig(allowedOrigins []string) CORSConfig {
	return CORSConfig{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-Request-ID",
			"X-API-KEY",
		},
		ExposedHeaders: []string{
			"X-Request-ID",
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining",
			"X-RateLimit-Reset",
		},
		AllowCredentials: true,
		MaxAge:           300,
	}
}

// CORS returns a CORS middleware handler with the given configuration.
func CORS(config CORSConfig) func(http.Handler) http.Handler {
	return cors.Handler(cors.Options{
		AllowedOrigins:   config.AllowedOrigins,
		AllowedMethods:   config.AllowedMethods,
		AllowedHeaders:   config.AllowedHeaders,
		ExposedHeaders:   config.ExposedHeaders,
		AllowCredentials: config.AllowCredentials,
		MaxAge:           config.MaxAge,
	})
}

// CORSFromEnv creates a CORS configuration from environment settings.
// Expects comma-separated origins in the origins parameter.
// Example: "https://app.example.com,https://admin.example.com"
func CORSFromEnv(origins string, credentials bool) CORSConfig {
	config := DefaultCORSConfig()

	if origins != "" && origins != "*" {
		originList := strings.Split(origins, ",")
		trimmedOrigins := make([]string, 0, len(originList))
		for _, o := range originList {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				trimmedOrigins = append(trimmedOrigins, trimmed)
			}
		}
		if len(trimmedOrigins) > 0 {
			config.AllowedOrigins = trimmedOrigins
		}
	}

	config.AllowCredentials = credentials
	return config
}

// AllowAll returns a CORS middleware that allows all origins.
// WARNING: Only use this for development or internal APIs.
func AllowAll() func(http.Handler) http.Handler {
	return CORS(CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"*"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"*"},
		AllowCredentials: false, // Cannot use credentials with wildcard origin
		MaxAge:           300,
	})
}
