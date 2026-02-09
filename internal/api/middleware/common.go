// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"net"
	"net/http"
	"strings"
)

// ============================================================================
// IP extraction helpers
// ============================================================================

// getRealIP extracts the real client IP from the request.
// It checks X-Forwarded-For and X-Real-IP headers before falling back to RemoteAddr.
func getRealIP(r *http.Request) string {
	// Check X-Forwarded-For header (can contain multiple IPs)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// ============================================================================
// Header constants
// ============================================================================

const (
	// HeaderRealIP is the header name for real IP (from proxy)
	HeaderRealIP = "X-Real-IP"

	// HeaderForwardedFor is the header name for forwarded IPs
	HeaderForwardedFor = "X-Forwarded-For"

	// HeaderForwardedProto is the header for forwarded protocol
	HeaderForwardedProto = "X-Forwarded-Proto"

	// HeaderAuthorization is the authorization header
	HeaderAuthorization = "Authorization"

	// HeaderContentType is the content type header
	HeaderContentType = "Content-Type"

	// HeaderAccept is the accept header
	HeaderAccept = "Accept"
)

// ============================================================================
// Response type helpers
// ============================================================================

// isJSON checks if the request accepts JSON responses
func isJSON(r *http.Request) bool {
	accept := r.Header.Get(HeaderAccept)
	return strings.Contains(accept, "application/json") || accept == "*/*" || accept == ""
}

// wantsJSON is an alias for isJSON for readability
func wantsJSON(r *http.Request) bool {
	return isJSON(r)
}
