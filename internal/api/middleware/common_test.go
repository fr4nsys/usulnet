// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ============================================================================
// getRealIP tests
// ============================================================================

func TestGetRealIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		want       string
	}{
		{
			name:       "X-Forwarded-For single IP",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.50"},
			remoteAddr: "127.0.0.1:12345",
			want:       "203.0.113.50",
		},
		{
			name:       "X-Forwarded-For multiple IPs (first used)",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.50, 70.41.3.18, 150.172.238.178"},
			remoteAddr: "127.0.0.1:12345",
			want:       "203.0.113.50",
		},
		{
			name:       "X-Forwarded-For with spaces",
			headers:    map[string]string{"X-Forwarded-For": " 10.0.0.1 "},
			remoteAddr: "127.0.0.1:12345",
			want:       "10.0.0.1",
		},
		{
			name:       "X-Real-IP used when no X-Forwarded-For",
			headers:    map[string]string{"X-Real-IP": "192.168.1.100"},
			remoteAddr: "127.0.0.1:12345",
			want:       "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For takes precedence over X-Real-IP",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1", "X-Real-IP": "10.0.0.2"},
			remoteAddr: "127.0.0.1:12345",
			want:       "10.0.0.1",
		},
		{
			name:       "fallback to RemoteAddr with port",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1:54321",
			want:       "192.168.1.1",
		},
		{
			name:       "fallback to RemoteAddr without port",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1",
			want:       "192.168.1.1",
		},
		{
			name:       "empty headers fallback to RemoteAddr",
			headers:    map[string]string{"X-Forwarded-For": "", "X-Real-IP": ""},
			remoteAddr: "10.0.0.5:8080",
			want:       "10.0.0.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			got := getRealIP(req)
			if got != tt.want {
				t.Errorf("getRealIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ============================================================================
// isJSON tests
// ============================================================================

func TestIsJSON(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   bool
	}{
		{"application/json", "application/json", true},
		{"application/json with charset", "application/json; charset=utf-8", true},
		{"wildcard accept", "*/*", true},
		{"empty accept", "", true},
		{"text/html only", "text/html", false},
		{"mixed with json", "text/html, application/json", true},
		{"text/plain", "text/plain", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}

			got := isJSON(req)
			if got != tt.want {
				t.Errorf("isJSON() with Accept=%q = %v, want %v", tt.accept, got, tt.want)
			}
		})
	}
}

func TestWantsJSON_SameAsIsJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")

	if isJSON(req) != wantsJSON(req) {
		t.Error("wantsJSON should return the same result as isJSON")
	}
}
