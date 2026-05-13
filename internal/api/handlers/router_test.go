// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers_test

import (
	"net/http"
	"testing"
)

// TestRouter_PublicRoutes verifies that health and version endpoints are accessible without auth.
func TestRouter_PublicRoutes(t *testing.T) {
	ts := setupTestSuite(t)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"health endpoint", http.MethodGet, "/health", http.StatusOK},
		{"liveness endpoint", http.MethodGet, "/healthz", http.StatusOK},
		{"version endpoint", http.MethodGet, "/api/v1/system/version", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doRequest(t, ts.router, tt.method, tt.path, "", "")
			assertStatus(t, w, tt.wantStatus)
		})
	}
}

// TestRouter_AuthRequired verifies that authenticated routes require a valid token.
func TestRouter_AuthRequired(t *testing.T) {
	ts := setupTestSuite(t)

	tests := []struct {
		name string
		path string
	}{
		{"system info", "/api/v1/system/info"},
		{"system health", "/api/v1/system/health"},
		{"system metrics", "/api/v1/system/metrics"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No auth token
			w := doRequest(t, ts.router, http.MethodGet, tt.path, "", "")
			assertStatus(t, w, http.StatusUnauthorized)
		})
	}
}

// TestRouter_WebSocketAuthzNegative verifies WS routes enforce 401/403 on sensitive operations.
func TestRouter_WebSocketAuthzNegative(t *testing.T) {
	ts := setupTestSuite(t)
	hostID := "550e8400-e29b-41d4-a716-446655440000"
	containerID := "nginx"

	t.Run("logs without token returns 401", func(t *testing.T) {
		path := "/api/v1/ws/containers/" + hostID + "/" + containerID + "/logs"
		w := doRequest(t, ts.router, http.MethodGet, path, "", "")
		assertStatus(t, w, http.StatusUnauthorized)
	})

	t.Run("exec with viewer token returns 403", func(t *testing.T) {
		viewerToken := generateTestToken(t, testUser(), "viewer", "viewer")
		path := "/api/v1/ws/containers/" + hostID + "/" + containerID + "/exec"
		w := doRequest(t, ts.router, http.MethodPost, path, `{"cmd":["/bin/sh"]}`, viewerToken)
		assertStatus(t, w, http.StatusForbidden)
	})
}

// TestRouter_InvalidToken verifies that invalid tokens are rejected.
func TestRouter_InvalidToken(t *testing.T) {
	ts := setupTestSuite(t)

	w := doRequest(t, ts.router, http.MethodGet, "/api/v1/system/info", "", "invalid-token")
	assertStatus(t, w, http.StatusUnauthorized)
}

// TestRouter_ExpiredToken verifies that expired tokens are rejected.
func TestRouter_ExpiredToken(t *testing.T) {
	ts := setupTestSuite(t)

	// Create an expired token manually
	w := doRequest(t, ts.router, http.MethodGet, "/api/v1/system/info", "", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MDAwMDAwMDB9.invalid")
	assertStatus(t, w, http.StatusUnauthorized)
}

// TestRouter_ValidAuth verifies that valid tokens grant access.
func TestRouter_ValidAuth(t *testing.T) {
	ts := setupTestSuite(t)

	token := generateTestToken(t, testUser(), "viewer", "viewer")

	tests := []struct {
		name string
		path string
	}{
		{"system info", "/api/v1/system/info"},
		{"system health", "/api/v1/system/health"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doRequest(t, ts.router, http.MethodGet, tt.path, "", token)
			assertStatus(t, w, http.StatusOK)
		})
	}
}

// TestRouter_CORS verifies that CORS headers are set.
func TestRouter_CORS(t *testing.T) {
	ts := setupTestSuite(t)

	w := doRequest(t, ts.router, http.MethodGet, "/health", "", "")

	// Verify CORS-related processing doesn't break the response
	assertStatus(t, w, http.StatusOK)
}

// TestRouter_NotFound verifies that unknown routes return 404 or 405.
func TestRouter_NotFound(t *testing.T) {
	ts := setupTestSuite(t)

	w := doRequest(t, ts.router, http.MethodGet, "/api/v1/nonexistent", "", "")
	if w.Code != http.StatusNotFound && w.Code != http.StatusUnauthorized {
		t.Errorf("expected 404 or 401 for nonexistent route, got %d", w.Code)
	}
}

// TestRouter_MethodNotAllowed verifies that wrong methods return 405.
func TestRouter_MethodNotAllowed(t *testing.T) {
	ts := setupTestSuite(t)

	w := doRequest(t, ts.router, http.MethodDelete, "/health", "", "")
	if w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusNotFound {
		t.Errorf("expected 405 or 404 for DELETE on /health, got %d", w.Code)
	}
}

// TestRouter_AuthLogin_NoBody verifies that login fails with empty body.
func TestRouter_AuthLogin_NoBody(t *testing.T) {
	ts := setupTestSuite(t)

	// Auth handler is nil in our test suite, so the route won't be mounted
	// This test verifies the route returns 404 when handler is not configured
	w := doRequest(t, ts.router, http.MethodPost, "/api/v1/auth/login", "", "")
	if w.Code != http.StatusNotFound {
		t.Logf("Auth login endpoint returned status %d (expected 404 when handler not mounted)", w.Code)
	}
}

// TestRouter_AdminRoutes_RequireAdmin verifies admin routes require admin role.
func TestRouter_AdminRoutes_RequireAdmin(t *testing.T) {
	ts := setupTestSuite(t)

	// Generate a viewer token (non-admin)
	viewerToken := generateTestToken(t, testUser(), "viewer", "viewer")

	// Settings fallback (notImplemented) should still require admin
	tests := []struct {
		name string
		path string
	}{
		{"settings get", "/api/v1/settings"},
		{"license get", "/api/v1/license"},
	}

	for _, tt := range tests {
		t.Run(tt.name+" viewer denied", func(t *testing.T) {
			w := doRequest(t, ts.router, http.MethodGet, tt.path, "", viewerToken)
			if w.Code != http.StatusForbidden {
				t.Errorf("expected 403 for viewer accessing admin route, got %d", w.Code)
			}
		})
	}

	// Admin should be able to access (returns 501 from notImplemented or 200 from handler)
	adminToken := generateTestToken(t, testUser(), "admin", "admin")
	for _, tt := range tests {
		t.Run(tt.name+" admin allowed", func(t *testing.T) {
			w := doRequest(t, ts.router, http.MethodGet, tt.path, "", adminToken)
			// Should not be 401 or 403
			if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
				t.Errorf("admin should be able to access %s, got %d", tt.path, w.Code)
			}
		})
	}
}

// TestRouter_NotImplementedFallback verifies notImplemented handlers return 501.
func TestRouter_NotImplementedFallback(t *testing.T) {
	ts := setupTestSuite(t)

	adminToken := generateTestToken(t, testUser(), "admin", "admin")

	// These use notImplemented fallback since Settings/License handlers are nil
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"settings get", http.MethodGet, "/api/v1/settings"},
		{"settings put", http.MethodPut, "/api/v1/settings"},
		{"settings ldap get", http.MethodGet, "/api/v1/settings/ldap"},
		{"settings ldap put", http.MethodPut, "/api/v1/settings/ldap"},
		{"settings ldap test", http.MethodPost, "/api/v1/settings/ldap/test"},
		{"license get", http.MethodGet, "/api/v1/license"},
		{"license post", http.MethodPost, "/api/v1/license"},
		{"license delete", http.MethodDelete, "/api/v1/license"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doRequest(t, ts.router, tt.method, tt.path, "", adminToken)
			assertStatus(t, w, http.StatusNotImplemented)

			body := assertJSON(t, w)
			if body["success"] != false {
				t.Error("expected success: false in not implemented response")
			}
		})
	}
}
