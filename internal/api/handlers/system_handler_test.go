// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
)

func TestSystemHandler_Health(t *testing.T) {
	ts := setupTestSuite(t)

	w := doRequest(t, ts.router, http.MethodGet, "/health", "", "")
	assertStatus(t, w, http.StatusOK)

	body := assertJSON(t, w)
	if body["status"] == nil {
		t.Error("expected status field in health response")
	}
}

func TestSystemHandler_Liveness(t *testing.T) {
	ts := setupTestSuite(t)

	w := doRequest(t, ts.router, http.MethodGet, "/healthz", "", "")
	assertStatus(t, w, http.StatusOK)
}

func TestSystemHandler_Readiness(t *testing.T) {
	ts := setupTestSuite(t)

	w := doRequest(t, ts.router, http.MethodGet, "/ready", "", "")
	// Readiness may return 200 or 503 depending on component status
	if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 200 or 503, got %d", w.Code)
	}
}

func TestSystemHandler_Version(t *testing.T) {
	ts := setupTestSuite(t)

	w := doRequest(t, ts.router, http.MethodGet, "/api/v1/system/version", "", "")
	assertStatus(t, w, http.StatusOK)

	body := assertJSON(t, w)
	if body["version"] != "test-version" {
		t.Errorf("expected version 'test-version', got %v", body["version"])
	}
}

func TestSystemHandler_Info_RequiresAuth(t *testing.T) {
	ts := setupTestSuite(t)

	// Without auth token - should return 401
	w := doRequest(t, ts.router, http.MethodGet, "/api/v1/system/info", "", "")
	assertStatus(t, w, http.StatusUnauthorized)
}

func TestSystemHandler_Info_WithAuth(t *testing.T) {
	ts := setupTestSuite(t)

	token := generateTestToken(t, testUser(), "admin", "admin")
	w := doRequest(t, ts.router, http.MethodGet, "/api/v1/system/info", "", token)
	assertStatus(t, w, http.StatusOK)

	body := assertJSON(t, w)
	if body["version"] == nil {
		t.Error("expected version field in info response")
	}
}

func TestSystemHandler_Health_WithChecker(t *testing.T) {
	handler := handlers.NewSystemHandler("1.0.0", "abc123", "2026-01-01", nil)

	handler.RegisterHealthChecker("test-db", func(ctx context.Context) *handlers.HealthStatus {
		return &handlers.HealthStatus{
			Status:  "up",
			Latency: 1,
		}
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.Health(w, r)

	assertStatus(t, w, http.StatusOK)

	var resp handlers.HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse health response: %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("expected healthy status, got %s", resp.Status)
	}

	if resp.Components["test-db"] == nil {
		t.Error("expected test-db component in health response")
	}

	if resp.Components["test-db"].Status != "up" {
		t.Errorf("expected test-db status 'up', got %s", resp.Components["test-db"].Status)
	}
}

func TestSystemHandler_Readiness_WithComponents(t *testing.T) {
	handler := handlers.NewSystemHandler("1.0.0", "abc123", "2026-01-01", nil)

	handler.RegisterHealthChecker("db", func(ctx context.Context) *handlers.HealthStatus {
		return &handlers.HealthStatus{Status: "healthy"}
	})
	handler.RegisterHealthChecker("cache", func(ctx context.Context) *handlers.HealthStatus {
		return &handlers.HealthStatus{Status: "healthy"}
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	handler.Readiness(w, r)

	assertStatus(t, w, http.StatusOK)

	var resp handlers.ReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse readiness response: %v", err)
	}

	if resp.Status != "ready" {
		t.Errorf("expected status 'ready', got %q", resp.Status)
	}
	if len(resp.Components) != 2 {
		t.Errorf("expected 2 components, got %d", len(resp.Components))
	}
	for name, cs := range resp.Components {
		if cs.CheckedAt == "" {
			t.Errorf("component %q missing checked_at", name)
		}
	}
}

func TestSystemHandler_Readiness_UnhealthyComponent(t *testing.T) {
	handler := handlers.NewSystemHandler("1.0.0", "abc123", "2026-01-01", nil)

	handler.RegisterHealthChecker("db", func(ctx context.Context) *handlers.HealthStatus {
		return &handlers.HealthStatus{Status: "healthy"}
	})
	handler.RegisterHealthChecker("cache", func(ctx context.Context) *handlers.HealthStatus {
		return &handlers.HealthStatus{Status: "unhealthy", Message: "connection refused"}
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	handler.Readiness(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}

	var resp handlers.ReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse readiness response: %v", err)
	}

	if resp.Status != "not_ready" {
		t.Errorf("expected status 'not_ready', got %q", resp.Status)
	}
	if resp.Components["cache"] == nil {
		t.Fatal("expected cache component in response")
	}
	if resp.Components["cache"].Status != "unhealthy" {
		t.Errorf("expected cache unhealthy, got %q", resp.Components["cache"].Status)
	}
}

func TestSystemHandler_Health_DegradedChecker(t *testing.T) {
	handler := handlers.NewSystemHandler("1.0.0", "abc123", "2026-01-01", nil)

	handler.RegisterHealthChecker("healthy-svc", func(ctx context.Context) *handlers.HealthStatus {
		return &handlers.HealthStatus{Status: "up", Latency: 1}
	})
	handler.RegisterHealthChecker("degraded-svc", func(ctx context.Context) *handlers.HealthStatus {
		return &handlers.HealthStatus{Status: "unhealthy", Latency: 5000, Message: "connection refused"}
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.Health(w, r)

	var resp handlers.HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse health response: %v", err)
	}

	// Should report unhealthy when a component is unhealthy
	if resp.Status == "healthy" {
		t.Error("expected non-healthy status when a component is unhealthy")
	}
}
