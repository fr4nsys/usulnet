// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package onboarding owns the v26.5.2 first-run wizard: a one-time
// flow that an operator passes through after the bootstrap admin
// logs in for the first time. The wizard's mandatory step is a
// password change; everything else is informational.
//
// The package is intentionally narrow — it only tracks the binary
// "has onboarding completed?" flag in system_state. The wizard itself
// (UI + handlers) lives in internal/web because it composes with the
// existing auth/session middleware.
package onboarding

import (
	"context"
	"sync/atomic"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// SystemStateRepo is the narrow contract the service needs from the
// repository layer. Defined here so tests can supply an in-memory
// fake without depending on pgx.
type SystemStateRepo interface {
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string) error
}

// stateKey is the only key onboarding writes to. Centralised so the
// migration seed and the runtime lookup cannot drift.
const stateKey = "onboarding_completed"

// Service exposes the onboarding flag to handlers and middleware.
//
// IsCompleted is hot-path (middleware checks it on every request), so
// the service caches the value in memory and refreshes only after
// MarkComplete is called. The cache is invalidated, not mutated under
// lock, so reads are wait-free.
type Service struct {
	repo      SystemStateRepo
	completed atomic.Bool
	logger    *logger.Logger
}

// NewService wires a Service. The constructor performs the initial DB
// read so the cached flag matches reality from the first request
// onwards. A read error is non-fatal — the service starts with
// completed=false, which fails closed (the wizard fires) and avoids a
// bricked install if the DB hiccups during boot.
func NewService(ctx context.Context, repo SystemStateRepo, log *logger.Logger) *Service {
	s := &Service{repo: repo, logger: log}
	val, ok, err := repo.Get(ctx, stateKey)
	if err != nil {
		log.Warn("onboarding: failed to read state, defaulting to not-completed",
			"error", err.Error())
		return s
	}
	if ok && val == "true" {
		s.completed.Store(true)
	}
	return s
}

// IsCompleted reports whether the onboarding wizard has been finished.
// Returns true on every request after the operator clicks "Finish",
// false until then. Cheap enough to call per request — no DB hit.
func (s *Service) IsCompleted() bool {
	return s.completed.Load()
}

// MarkComplete writes the flag and updates the in-memory cache. After
// it returns, subsequent IsCompleted calls observe true without
// needing the DB.
func (s *Service) MarkComplete(ctx context.Context) error {
	if err := s.repo.Set(ctx, stateKey, "true"); err != nil {
		return err
	}
	s.completed.Store(true)
	s.logger.Info("onboarding: marked complete")
	return nil
}
