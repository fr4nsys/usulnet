// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package onboarding

import (
	"context"
	"errors"
	"testing"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// fakeRepo is a tiny in-memory SystemStateRepo. Tests use it so the
// service logic stays isolated from pgx.
type fakeRepo struct {
	store  map[string]string
	getErr error
	setErr error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{store: map[string]string{}}
}

func (f *fakeRepo) Get(_ context.Context, key string) (string, bool, error) {
	if f.getErr != nil {
		return "", false, f.getErr
	}
	v, ok := f.store[key]
	return v, ok, nil
}

func (f *fakeRepo) Set(_ context.Context, key, value string) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.store[key] = value
	return nil
}

// testLogger returns a discarding logger for unit tests.
func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	l, err := logger.New("error", "json")
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	return l
}

func TestService_IsCompleted_DefaultsFalseOnFreshInstall(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(context.Background(), repo, testLogger(t))
	if svc.IsCompleted() {
		t.Error("fresh install must report onboarding incomplete so the wizard fires")
	}
}

func TestService_IsCompleted_ReadsSeededTrue(t *testing.T) {
	repo := newFakeRepo()
	repo.store[stateKey] = "true"
	svc := NewService(context.Background(), repo, testLogger(t))
	if !svc.IsCompleted() {
		t.Error("seeded true must be observed on the very first IsCompleted call")
	}
}

func TestService_IsCompleted_FailsClosedOnDBError(t *testing.T) {
	repo := newFakeRepo()
	repo.getErr = errors.New("boom")
	svc := NewService(context.Background(), repo, testLogger(t))
	// Fail-closed: if the DB is broken on boot we keep the wizard
	// firing rather than skipping it — security over availability.
	if svc.IsCompleted() {
		t.Error("DB read error must default to incomplete (fail closed)")
	}
}

func TestService_MarkComplete_UpdatesCacheAndStore(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(context.Background(), repo, testLogger(t))

	if err := svc.MarkComplete(context.Background()); err != nil {
		t.Fatalf("MarkComplete: %v", err)
	}
	if !svc.IsCompleted() {
		t.Error("MarkComplete must flip the in-memory cache without a re-read")
	}
	if got := repo.store[stateKey]; got != "true" {
		t.Errorf("MarkComplete wrote %q to store, want %q", got, "true")
	}
}

func TestService_MarkComplete_DoesNotPoisonCacheOnDBFailure(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(context.Background(), repo, testLogger(t))

	repo.setErr = errors.New("disk full")
	if err := svc.MarkComplete(context.Background()); err == nil {
		t.Fatal("MarkComplete must propagate Set errors so the handler can re-display the form")
	}
	if svc.IsCompleted() {
		t.Error("a failed Set must NOT flip the cache — the wizard should fire again on the next request")
	}
}
