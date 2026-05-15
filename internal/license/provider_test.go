// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"context"
	"sync"
	"testing"
)

// ============================================================================
// Test logger mock
// ============================================================================

type testLogger struct {
	mu       sync.Mutex
	messages []string
}

func (l *testLogger) Info(msg string, _ ...any)  { l.record(msg) }
func (l *testLogger) Warn(msg string, _ ...any)  { l.record(msg) }
func (l *testLogger) Error(msg string, _ ...any) { l.record(msg) }

func (l *testLogger) record(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, msg)
}

// ============================================================================
// NewProvider
// ============================================================================

func TestNewProvider(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	if p == nil {
		t.Fatal("NewProvider() returned nil")
	}
}

func TestNewProvider_DefaultsCE(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	info := p.GetInfo()
	if info.Edition != CE {
		t.Errorf("default edition = %q, want %q", info.Edition, CE)
	}
	if !info.Valid {
		t.Error("default info.Valid = false, want true")
	}
	if info.Limits != OpenLimits() {
		t.Errorf("default limits = %+v, want %+v", info.Limits, OpenLimits())
	}
}

func TestNewProvider_GeneratesInstanceID(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	id := p.InstanceID()
	if id == "" {
		t.Error("InstanceID() is empty")
	}
	if len(id) != 32 && id != "unknown" {
		t.Errorf("InstanceID() length = %d, want 32", len(id))
	}
}

// ============================================================================
// GetInfo returns a copy (prevents mutation)
// ============================================================================

func TestProvider_GetInfoReturnsCopy(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	info1 := p.GetInfo()
	info2 := p.GetInfo()

	// Mutating one copy should not affect the other
	info1.Edition = Enterprise
	if info2.Edition == Enterprise {
		t.Error("GetInfo() returned a reference instead of a copy")
	}
}

// ============================================================================
// GetLicense (context-aware wrapper)
// ============================================================================

func TestProvider_GetLicense(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	info, err := p.GetLicense(context.Background())
	if err != nil {
		t.Fatalf("GetLicense() error: %v", err)
	}
	if info == nil {
		t.Fatal("GetLicense() returned nil info")
	}
	if info.Edition != CE {
		t.Errorf("GetLicense() edition = %q, want %q", info.Edition, CE)
	}
}

// ============================================================================
// HasFeature
// ============================================================================

func TestProvider_HasFeature_OpenEdition(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	ctx := context.Background()

	// The AGPL build unlocks every implemented feature unconditionally.
	for _, f := range AllFeatures() {
		if !p.HasFeature(ctx, f) {
			t.Errorf("open edition HasFeature(%q) = false, want true", f)
		}
	}
}

// ============================================================================
// IsValid
// ============================================================================

func TestProvider_IsValid_CE(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	// CE is always valid (no expiration)
	if !p.IsValid(context.Background()) {
		t.Error("CE IsValid() = false, want true")
	}
}

// ============================================================================
// GetLimits
// ============================================================================

func TestProvider_GetLimits_OpenEdition(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	if got := p.GetLimits(); got != OpenLimits() {
		t.Errorf("open GetLimits() = %+v, want %+v", got, OpenLimits())
	}
}

// ============================================================================
// Edition
// ============================================================================

func TestProvider_Edition_CE(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	if p.Edition() != CE {
		t.Errorf("Edition() = %q, want %q", p.Edition(), CE)
	}
}

// ============================================================================
// RawJWT
// ============================================================================

func TestProvider_RawJWT_CE(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	// CE has no JWT
	if raw := p.RawJWT(); raw != "" {
		t.Errorf("CE RawJWT() = %q, want empty", raw)
	}
}

// ============================================================================
// Deactivate
// ============================================================================

func TestProvider_Deactivate(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	// Deactivate should revert to CE
	if err := p.Deactivate(); err != nil {
		t.Fatalf("Deactivate() error: %v", err)
	}

	info := p.GetInfo()
	if info.Edition != CE {
		t.Errorf("after Deactivate() Edition = %q, want %q", info.Edition, CE)
	}
	if !info.Valid {
		t.Error("after Deactivate() Valid = false, want true")
	}
	if p.RawJWT() != "" {
		t.Error("after Deactivate() RawJWT() should be empty")
	}
}

func TestProvider_Deactivate_RemovesStoredFile(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	// Save a fake JWT to disk to verify it gets removed
	store := NewStore(dir)
	if err := store.Save("test-jwt"); err != nil {
		t.Fatalf("store.Save() error: %v", err)
	}

	if err := p.Deactivate(); err != nil {
		t.Fatalf("Deactivate() error: %v", err)
	}

	// Stored file should be removed
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load() error: %v", err)
	}
	if loaded != "" {
		t.Error("stored JWT should be removed after Deactivate()")
	}
}

// ============================================================================
// Activate with invalid JWT
// ============================================================================

func TestProvider_Activate_InvalidJWT(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	// Invalid JWT should fail
	err = p.Activate("not-a-valid-jwt")
	if err == nil {
		t.Error("Activate(invalid) should error")
	}

	// Should still be CE after failed activation
	if p.Edition() != CE {
		t.Errorf("after failed Activate, Edition = %q, want CE", p.Edition())
	}
}

func TestProvider_Activate_EmptyJWT(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	err = p.Activate("")
	if err == nil {
		t.Error("Activate('') should error")
	}
}

// ============================================================================
// Concurrent access safety
// ============================================================================

func TestProvider_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	ctx := context.Background()
	var wg sync.WaitGroup

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.GetInfo()
			_ = p.GetLimits()
			_ = p.Edition()
			_ = p.RawJWT()
			_ = p.InstanceID()
			_, _ = p.GetLicense(ctx)
			_ = p.HasFeature(ctx, FeatureAPIKeys)
			_ = p.IsValid(ctx)
		}()
	}

	// Concurrent deactivate/read interleaving
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.Deactivate()
		}()
	}

	// Concurrent invalid activations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.Activate("invalid-jwt")
		}()
	}

	wg.Wait()

	// After all concurrent operations, should still be in a valid state
	info := p.GetInfo()
	if info == nil {
		t.Fatal("GetInfo() returned nil after concurrent access")
	}
}

// ============================================================================
// Stop
// ============================================================================

func TestProvider_Stop(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}

	// Should not panic
	p.Stop()

	// Provider should still return data after Stop (just no background validation)
	info := p.GetInfo()
	if info == nil {
		t.Fatal("GetInfo() returned nil after Stop()")
	}
}

// ============================================================================
// LoadStoredLicense on start
// ============================================================================

func TestProvider_LoadsStoredLicense(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	// Store an invalid JWT - provider should fall back to CE
	store := NewStore(dir)
	if err := store.Save("invalid-jwt-token"); err != nil {
		t.Fatalf("store.Save() error: %v", err)
	}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	// Invalid stored JWT should result in CE fallback
	if p.Edition() != CE {
		t.Errorf("with invalid stored JWT, Edition = %q, want CE", p.Edition())
	}
}

func TestProvider_NoStoredLicense(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	// No stored license = CE
	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	if p.Edition() != CE {
		t.Errorf("no stored license, Edition = %q, want CE", p.Edition())
	}
}

// ============================================================================
// LimitProvider interface compliance
// ============================================================================

func TestProvider_SatisfiesLimitProvider(t *testing.T) {
	dir := t.TempDir()
	logger := &testLogger{}

	p, err := NewProvider(dir, logger)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	defer p.Stop()

	// Provider should satisfy LimitProvider interface
	var lp LimitProvider = p
	limits := lp.GetLimits()
	if limits != OpenLimits() {
		t.Errorf("GetLimits() via LimitProvider = %+v, want %+v", limits, OpenLimits())
	}
}

// ============================================================================
// Logger interface
// ============================================================================

func TestLogger_InterfaceCompliance(t *testing.T) {
	// Verify testLogger satisfies Logger interface
	var _ Logger = (*testLogger)(nil)
}
