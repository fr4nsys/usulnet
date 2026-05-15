// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fr4nsys/usulnet/internal/license"
)

// ============================================================================
// Mock LicenseProvider
// ============================================================================

type mockLicenseProvider struct {
	info *license.Info
}

func (m *mockLicenseProvider) GetLicense(_ context.Context) (*license.Info, error) {
	return m.info, nil
}

func (m *mockLicenseProvider) HasFeature(_ context.Context, feature license.Feature) bool {
	return m.info.HasFeature(feature)
}

func (m *mockLicenseProvider) IsValid(_ context.Context) bool {
	return m.info != nil && m.info.Valid && !m.info.IsExpired()
}

func (m *mockLicenseProvider) GetLimits() license.Limits {
	if m.info != nil {
		return m.info.Limits
	}
	return license.OpenLimits()
}

func openProvider() *mockLicenseProvider {
	return &mockLicenseProvider{info: license.NewOpenInfo()}
}

// ============================================================================
// License middleware (context injection)
// ============================================================================

func TestLicense_AddsToContext(t *testing.T) {
	provider := openProvider()
	mw := License(LicenseConfig{
		Provider:     provider,
		AddToContext: true,
	})

	var gotInfo *license.Info
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotInfo = GetLicenseFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if gotInfo == nil {
		t.Fatal("license info not found in context")
	}
	if gotInfo.Edition != license.CE {
		t.Errorf("context edition = %q, want %q", gotInfo.Edition, license.CE)
	}
}

func TestLicense_SkipsContextWhenDisabled(t *testing.T) {
	provider := openProvider()
	mw := License(LicenseConfig{
		Provider:     provider,
		AddToContext: false,
	})

	var gotInfo *license.Info
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotInfo = GetLicenseFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if gotInfo != nil {
		t.Error("license info should not be in context when AddToContext=false")
	}
}

func TestLicense_NilProvider(t *testing.T) {
	mw := License(LicenseConfig{
		Provider:     nil,
		AddToContext: true,
	})

	called := false
	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler was not called with nil provider")
	}
}

// ============================================================================
// GetLicenseFromContext
// ============================================================================

func TestGetLicenseFromContext(t *testing.T) {
	t.Run("with info", func(t *testing.T) {
		info := license.NewOpenInfo()
		ctx := context.WithValue(context.Background(), LicenseContextKey, info)
		got := GetLicenseFromContext(ctx)
		if got == nil {
			t.Fatal("GetLicenseFromContext() returned nil")
		}
		if got.Edition != license.CE {
			t.Errorf("edition = %q, want %q", got.Edition, license.CE)
		}
	})

	t.Run("without info", func(t *testing.T) {
		got := GetLicenseFromContext(context.Background())
		if got != nil {
			t.Error("GetLicenseFromContext() should return nil for empty context")
		}
	})
}

// ============================================================================
// LicenseProvider interface compliance
// ============================================================================

func TestMockLicenseProvider_SatisfiesInterface(t *testing.T) {
	var _ LicenseProvider = (*mockLicenseProvider)(nil)
}
