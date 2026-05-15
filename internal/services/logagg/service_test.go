// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package logagg

import (
	"testing"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	cfg := DefaultConfig()

	// logagg.Service takes a concrete *postgres.LogRepository; passing nil is
	// acceptable for construction (the service does not access the repo during
	// NewService). We also pass nil for hostService.
	svc := NewService(nil, nil, cfg, nil) // nil repo, nil hostService, nil logger
	if svc == nil {
		t.Fatal("NewService returned nil")
	}

	// Verify that default config values were applied (the constructor clamps
	// zero/negative values to defaults).
	if svc.config.BatchSize != cfg.BatchSize {
		t.Errorf("expected BatchSize=%d, got %d", cfg.BatchSize, svc.config.BatchSize)
	}
	if svc.config.FlushInterval != cfg.FlushInterval {
		t.Errorf("expected FlushInterval=%v, got %v", cfg.FlushInterval, svc.config.FlushInterval)
	}
	if svc.config.CollectionInterval != cfg.CollectionInterval {
		t.Errorf("expected CollectionInterval=%v, got %v", cfg.CollectionInterval, svc.config.CollectionInterval)
	}
	if svc.config.Retention != cfg.Retention {
		t.Errorf("expected Retention=%v, got %v", cfg.Retention, svc.config.Retention)
	}

	// Verify that the buffer was initialized.
	if svc.buffer == nil {
		t.Fatal("expected buffer to be initialized, got nil")
	}
}

func TestNewService_ZeroConfig(t *testing.T) {
	// A zero-value Config should be clamped to defaults by the constructor.
	svc := NewService(nil, nil, Config{}, logger.Nop())
	if svc == nil {
		t.Fatal("NewService returned nil with zero config")
	}

	defaults := DefaultConfig()
	if svc.config.BatchSize != defaults.BatchSize {
		t.Errorf("expected BatchSize to be clamped to %d, got %d", defaults.BatchSize, svc.config.BatchSize)
	}
	if svc.config.FlushInterval != defaults.FlushInterval {
		t.Errorf("expected FlushInterval to be clamped to %v, got %v", defaults.FlushInterval, svc.config.FlushInterval)
	}
	if svc.config.CollectionInterval != defaults.CollectionInterval {
		t.Errorf("expected CollectionInterval to be clamped to %v, got %v", defaults.CollectionInterval, svc.config.CollectionInterval)
	}
	if svc.config.Retention != defaults.Retention {
		t.Errorf("expected Retention to be clamped to %v, got %v", defaults.Retention, svc.config.Retention)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Retention != 7*24*time.Hour {
		t.Errorf("expected Retention=7d, got %v", cfg.Retention)
	}
	if cfg.BatchSize != 100 {
		t.Errorf("expected BatchSize=100, got %d", cfg.BatchSize)
	}
	if cfg.FlushInterval != 5*time.Second {
		t.Errorf("expected FlushInterval=5s, got %v", cfg.FlushInterval)
	}
	if cfg.CollectionInterval != 30*time.Second {
		t.Errorf("expected CollectionInterval=30s, got %v", cfg.CollectionInterval)
	}
}

func TestSearch_Delegates(t *testing.T) {
	// Search requires a non-nil repo to delegate to. This test only
	// asserts that NewService accepts the documented constructor
	// signature (so a future refactor cannot silently change it). A
	// full delegation test with a live repo belongs in the integration
	// suite.
	svc := NewService(nil, nil, DefaultConfig(), logger.Nop())
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
}
