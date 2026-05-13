// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package audit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------
//
// The mock is shared between the test goroutine and the LogAsync
// goroutines spawned by Service. Every read and write must take the
// mutex, otherwise -race trips on the entries slice.

type mockAuditRepo struct {
	mu         sync.Mutex
	entries    []*models.AuditLogEntry
	createErr  error
	createCall atomic.Int32
}

func (r *mockAuditRepo) snapshot() []*models.AuditLogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*models.AuditLogEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

// seed appends a pre-built entry under the lock so test setup is
// race-safe alongside any concurrently running LogAsync goroutines.
func (r *mockAuditRepo) seed(e *models.AuditLogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, e)
}

func (r *mockAuditRepo) Create(_ context.Context, input *postgres.CreateAuditLogInput) error {
	r.createCall.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.createErr != nil {
		return r.createErr
	}
	entry := &models.AuditLogEntry{
		Action:     input.Action,
		EntityType: input.ResourceType,
		UserID:     input.UserID,
		CreatedAt:  time.Now(),
	}
	r.entries = append(r.entries, entry)
	return nil
}

func (r *mockAuditRepo) List(_ context.Context, opts postgres.AuditLogListOptions) ([]*models.AuditLogEntry, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []*models.AuditLogEntry
	for _, e := range r.entries {
		if opts.Action != nil && e.Action != *opts.Action {
			continue
		}
		if opts.ResourceType != nil && e.EntityType != *opts.ResourceType {
			continue
		}
		result = append(result, e)
	}
	return result, len(result), nil
}

func (r *mockAuditRepo) GetByUser(_ context.Context, userID uuid.UUID, limit int) ([]*models.AuditLogEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []*models.AuditLogEntry
	for _, e := range r.entries {
		if e.UserID != nil && *e.UserID == userID {
			result = append(result, e)
			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func (r *mockAuditRepo) GetByResource(_ context.Context, resourceType, _ string, limit int) ([]*models.AuditLogEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []*models.AuditLogEntry
	for _, e := range r.entries {
		if e.EntityType == resourceType {
			result = append(result, e)
			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func (r *mockAuditRepo) GetRecent(_ context.Context, limit int) ([]*models.AuditLogEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limit <= 0 || limit > len(r.entries) {
		limit = len(r.entries)
	}
	return r.entries[:limit], nil
}

func (r *mockAuditRepo) GetStats(_ context.Context, _ time.Time) (map[string]int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stats := make(map[string]int)
	for _, e := range r.entries {
		stats[e.Action]++
	}
	return stats, nil
}

func (r *mockAuditRepo) DeleteOlderThan(_ context.Context, before time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var kept []*models.AuditLogEntry
	var deleted int64
	for _, e := range r.entries {
		if e.CreatedAt.Before(before) {
			deleted++
		} else {
			kept = append(kept, e)
		}
	}
	r.entries = kept
	return deleted, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testEntry() LogEntry {
	userID := uuid.New()
	username := "admin"
	return LogEntry{
		UserID:       &userID,
		Username:     &username,
		Action:       "login",
		ResourceType: ResourceTypeSession,
		Success:      true,
	}
}

// ---------------------------------------------------------------------------
// Tests: Log
// ---------------------------------------------------------------------------

func TestLog_HappyPath(t *testing.T) {
	repo := &mockAuditRepo{}
	svc := NewService(repo, logger.Nop(), DefaultConfig())

	err := svc.Log(context.Background(), testEntry())
	if err != nil {
		t.Fatalf("Log() error: %v", err)
	}
	entries := repo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("repo has %d entries, want 1", len(entries))
	}
	if entries[0].Action != "login" {
		t.Errorf("Action = %q, want %q", entries[0].Action, "login")
	}
}

func TestLog_DisabledConfig_NoWrite(t *testing.T) {
	repo := &mockAuditRepo{}
	cfg := DefaultConfig()
	cfg.Enabled = false
	svc := NewService(repo, logger.Nop(), cfg)

	err := svc.Log(context.Background(), testEntry())
	if err != nil {
		t.Fatalf("Log() error: %v", err)
	}
	if entries := repo.snapshot(); len(entries) != 0 {
		t.Errorf("repo has %d entries, want 0 (disabled)", len(entries))
	}
}

func TestLog_RepoError_SwallowedNotReturned(t *testing.T) {
	repo := &mockAuditRepo{createErr: errors.New("db unavailable")}
	svc := NewService(repo, logger.Nop(), DefaultConfig())

	// The key property: audit Log never returns an error, even on repo failure
	err := svc.Log(context.Background(), testEntry())
	if err != nil {
		t.Fatalf("Log() should never return error, got: %v", err)
	}
	if repo.createCall.Load() != 1 {
		t.Errorf("Create was called %d times, want 1", repo.createCall.Load())
	}
}

// ---------------------------------------------------------------------------
// Tests: LogAsync
// ---------------------------------------------------------------------------

func TestLogAsync_FireAndForget(t *testing.T) {
	repo := &mockAuditRepo{}
	svc := NewService(repo, logger.Nop(), DefaultConfig())

	svc.LogAsync(context.Background(), testEntry())

	// Give goroutine time to execute
	time.Sleep(50 * time.Millisecond)

	if repo.createCall.Load() != 1 {
		t.Errorf("Create was called %d times, want 1 (async)", repo.createCall.Load())
	}
}

// ---------------------------------------------------------------------------
// Tests: Query methods
// ---------------------------------------------------------------------------

func TestList_ReturnsFilteredResults(t *testing.T) {
	repo := &mockAuditRepo{}
	svc := NewService(repo, logger.Nop(), DefaultConfig())
	ctx := context.Background()

	// Log entries of different types
	entry1 := testEntry()
	entry1.Action = "login"
	_ = svc.Log(ctx, entry1)

	entry2 := testEntry()
	entry2.Action = "create_user"
	_ = svc.Log(ctx, entry2)

	action := "login"
	entries, count, err := svc.List(ctx, postgres.AuditLogListOptions{Action: &action})
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if len(entries) != 1 || entries[0].Action != "login" {
		t.Errorf("expected 1 login entry, got %d entries", len(entries))
	}
}

func TestGetRecent_RespectsLimit(t *testing.T) {
	repo := &mockAuditRepo{}
	svc := NewService(repo, logger.Nop(), DefaultConfig())
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_ = svc.Log(ctx, testEntry())
	}

	entries, err := svc.GetRecent(ctx, 3)
	if err != nil {
		t.Fatalf("GetRecent() error: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("GetRecent(3) returned %d entries, want 3", len(entries))
	}
}

// ---------------------------------------------------------------------------
// Tests: Convenience loggers
// ---------------------------------------------------------------------------

func TestLogLogin(t *testing.T) {
	repo := &mockAuditRepo{}
	svc := NewService(repo, logger.Nop(), DefaultConfig())

	userID := uuid.New()
	svc.LogLogin(context.Background(), &userID, "admin", "127.0.0.1", "curl/7.0", true, nil)

	// LogLogin dispatches via LogAsync; let the goroutine complete.
	time.Sleep(50 * time.Millisecond)

	entries := repo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Action != "login" {
		t.Errorf("Action = %q, want %q", entries[0].Action, "login")
	}
}

func TestLogResourceAction(t *testing.T) {
	repo := &mockAuditRepo{}
	svc := NewService(repo, logger.Nop(), DefaultConfig())

	userID := uuid.New()
	svc.LogResourceAction(context.Background(), userID, "admin", "start", ResourceTypeContainer, "abc123", "my-container", "127.0.0.1", "curl/7.0", true, nil)

	// LogResourceAction dispatches via LogAsync; let the goroutine complete.
	time.Sleep(50 * time.Millisecond)

	if entries := repo.snapshot(); len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

// ---------------------------------------------------------------------------
// Tests: Cleanup
// ---------------------------------------------------------------------------

func TestStartCleanupWorker_DeletesOldEntries(t *testing.T) {
	repo := &mockAuditRepo{}
	cfg := DefaultConfig()
	cfg.RetentionDays = 1
	cfg.CleanupInterval = 50 * time.Millisecond
	svc := NewService(repo, logger.Nop(), cfg)
	ctx := context.Background()

	// Create an entry with old timestamp
	repo.seed(&models.AuditLogEntry{
		Action:    "old-action",
		CreatedAt: time.Now().Add(-48 * time.Hour), // 2 days old
	})

	// Create a recent entry
	repo.seed(&models.AuditLogEntry{
		Action:    "recent-action",
		CreatedAt: time.Now(),
	})

	cancelCtx, cancel := context.WithCancel(ctx)
	svc.StartCleanupWorker(cancelCtx)
	time.Sleep(200 * time.Millisecond)
	cancel()

	entries := repo.snapshot()
	if len(entries) != 1 {
		t.Errorf("expected 1 entry after cleanup, got %d", len(entries))
	}
	if len(entries) > 0 && entries[0].Action != "recent-action" {
		t.Errorf("wrong entry survived cleanup: %q", entries[0].Action)
	}
}
