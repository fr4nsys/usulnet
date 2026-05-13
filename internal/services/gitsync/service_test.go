// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package gitsync_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/gitsync"
)

// ============================================================================
// Mock Repository
// ============================================================================

type mockRepo struct {
	mu        sync.Mutex
	configs   map[uuid.UUID]*models.GitSyncConfig
	events    map[uuid.UUID][]*models.GitSyncEvent
	conflicts map[uuid.UUID]*models.GitSyncConflict
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		configs:   make(map[uuid.UUID]*models.GitSyncConfig),
		events:    make(map[uuid.UUID][]*models.GitSyncEvent),
		conflicts: make(map[uuid.UUID]*models.GitSyncConflict),
	}
}

func (m *mockRepo) CreateConfig(_ context.Context, cfg *models.GitSyncConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[cfg.ID] = cfg
	return nil
}

func (m *mockRepo) GetConfig(_ context.Context, id uuid.UUID) (*models.GitSyncConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, ok := m.configs[id]
	if !ok {
		return nil, fmt.Errorf("config %s not found", id)
	}
	return cfg, nil
}

func (m *mockRepo) ListConfigs(_ context.Context) ([]*models.GitSyncConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*models.GitSyncConfig, 0, len(m.configs))
	for _, c := range m.configs {
		out = append(out, c)
	}
	return out, nil
}

func (m *mockRepo) ListConfigsByConnection(_ context.Context, connID uuid.UUID) ([]*models.GitSyncConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.GitSyncConfig
	for _, c := range m.configs {
		if c.ConnectionID == connID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *mockRepo) UpdateConfig(_ context.Context, cfg *models.GitSyncConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[cfg.ID] = cfg
	return nil
}

func (m *mockRepo) DeleteConfig(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.configs[id]; !ok {
		return fmt.Errorf("config %s not found", id)
	}
	delete(m.configs, id)
	return nil
}

func (m *mockRepo) UpdateSyncStatus(_ context.Context, id uuid.UUID, status, syncErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, ok := m.configs[id]
	if !ok {
		return fmt.Errorf("config %s not found", id)
	}
	cfg.LastSyncStatus = status
	cfg.LastSyncError = syncErr
	return nil
}

func (m *mockRepo) ToggleConfig(_ context.Context, id uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, ok := m.configs[id]
	if !ok {
		return false, fmt.Errorf("config %s not found", id)
	}
	cfg.IsEnabled = !cfg.IsEnabled
	return cfg.IsEnabled, nil
}

func (m *mockRepo) CreateEvent(_ context.Context, evt *models.GitSyncEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[evt.ConfigID] = append(m.events[evt.ConfigID], evt)
	return nil
}

func (m *mockRepo) ListEvents(_ context.Context, configID uuid.UUID, limit int) ([]*models.GitSyncEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	evts := m.events[configID]
	if limit > 0 && len(evts) > limit {
		evts = evts[:limit]
	}
	return evts, nil
}

func (m *mockRepo) CreateConflict(_ context.Context, c *models.GitSyncConflict) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conflicts[c.ID] = c
	return nil
}

func (m *mockRepo) ListConflicts(_ context.Context, configID uuid.UUID, resolution string) ([]*models.GitSyncConflict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.GitSyncConflict
	for _, c := range m.conflicts {
		if c.ConfigID == configID && (resolution == "" || string(c.Resolution) == resolution) {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *mockRepo) ResolveConflict(_ context.Context, id uuid.UUID, resolution string, resolvedBy uuid.UUID, mergedContent *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.conflicts[id]
	if !ok {
		return fmt.Errorf("conflict %s not found", id)
	}
	c.Resolution = models.ConflictResolution(resolution)
	c.ResolvedBy = &resolvedBy
	c.MergedContent = mergedContent
	return nil
}

func (m *mockRepo) GetConflict(_ context.Context, id uuid.UUID) (*models.GitSyncConflict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.conflicts[id]
	if !ok {
		return nil, fmt.Errorf("conflict %s not found", id)
	}
	return c, nil
}

// ============================================================================
// Tests
// ============================================================================

func newService() (*gitsync.Service, *mockRepo) {
	repo := newMockRepo()
	svc := gitsync.NewService(repo, gitsync.DefaultConfig(), nil)
	return svc, repo
}

func validInput() gitsync.CreateSyncInput {
	return gitsync.CreateSyncInput{
		ConnectionID:  uuid.New(),
		RepositoryID:  uuid.New(),
		RepoFullName:  "owner/repo",
		Name:          "my-sync",
		SyncDirection: models.SyncDirectionToGit,
		StackName:     "web-stack",
	}
}

func TestCreateSyncConfig(t *testing.T) {
	svc, repo := newService()
	ctx := context.Background()

	input := validInput()
	cfg, err := svc.CreateSyncConfig(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Name != "my-sync" {
		t.Errorf("Name = %q, want %q", cfg.Name, "my-sync")
	}
	if cfg.Branch != "main" {
		t.Errorf("Branch default = %q, want %q", cfg.Branch, "main")
	}
	if cfg.FilePattern != "docker-compose.yml" {
		t.Errorf("FilePattern default = %q, want %q", cfg.FilePattern, "docker-compose.yml")
	}
	if !cfg.IsEnabled {
		t.Error("expected IsEnabled to be true")
	}
	if cfg.LastSyncStatus != "pending" {
		t.Errorf("LastSyncStatus = %q, want %q", cfg.LastSyncStatus, "pending")
	}

	// Verify stored in repo.
	stored, err := repo.GetConfig(ctx, cfg.ID)
	if err != nil {
		t.Fatalf("config not found in repo: %v", err)
	}
	if stored.Name != cfg.Name {
		t.Errorf("stored Name = %q, want %q", stored.Name, cfg.Name)
	}
}

func TestCreateSyncConfig_Validation(t *testing.T) {
	svc, _ := newService()
	ctx := context.Background()

	tests := []struct {
		name  string
		input gitsync.CreateSyncInput
	}{
		{"empty name", gitsync.CreateSyncInput{ConnectionID: uuid.New(), RepositoryID: uuid.New(), SyncDirection: models.SyncDirectionToGit}},
		{"nil connection", gitsync.CreateSyncInput{Name: "x", RepositoryID: uuid.New(), SyncDirection: models.SyncDirectionToGit}},
		{"nil repository", gitsync.CreateSyncInput{Name: "x", ConnectionID: uuid.New(), SyncDirection: models.SyncDirectionToGit}},
		{"bad direction", gitsync.CreateSyncInput{Name: "x", ConnectionID: uuid.New(), RepositoryID: uuid.New(), SyncDirection: "invalid"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateSyncConfig(ctx, tc.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestListConfigs(t *testing.T) {
	svc, _ := newService()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		input := validInput()
		input.Name = fmt.Sprintf("sync-%d", i)
		if _, err := svc.CreateSyncConfig(ctx, input); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}

	configs, err := svc.ListConfigs(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 3 {
		t.Errorf("len = %d, want 3", len(configs))
	}
}

func TestDeleteConfig(t *testing.T) {
	svc, _ := newService()
	ctx := context.Background()

	cfg, err := svc.CreateSyncConfig(ctx, validInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := svc.DeleteConfig(ctx, cfg.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err = svc.GetConfig(ctx, cfg.ID)
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}

func TestToggleConfig(t *testing.T) {
	svc, _ := newService()
	ctx := context.Background()

	cfg, err := svc.CreateSyncConfig(ctx, validInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !cfg.IsEnabled {
		t.Fatal("expected initially enabled")
	}

	enabled, err := svc.ToggleConfig(ctx, cfg.ID)
	if err != nil {
		t.Fatalf("toggle: %v", err)
	}
	if enabled {
		t.Error("expected disabled after first toggle")
	}

	enabled, err = svc.ToggleConfig(ctx, cfg.ID)
	if err != nil {
		t.Fatalf("toggle back: %v", err)
	}
	if !enabled {
		t.Error("expected enabled after second toggle")
	}
}

func TestResolveConflict(t *testing.T) {
	svc, repo := newService()
	ctx := context.Background()

	conflictID := uuid.New()
	repo.conflicts[conflictID] = &models.GitSyncConflict{
		ID:         conflictID,
		ConfigID:   uuid.New(),
		Resolution: models.ConflictResolutionPending,
	}

	// Valid resolution: use_git
	err := svc.ResolveConflict(ctx, conflictID, models.ConflictResolutionUseGit, uuid.New(), nil)
	if err != nil {
		t.Fatalf("resolve use_git: %v", err)
	}

	// Merged without content should fail
	repo.conflicts[conflictID].Resolution = models.ConflictResolutionPending
	err = svc.ResolveConflict(ctx, conflictID, models.ConflictResolutionMerged, uuid.New(), nil)
	if err == nil {
		t.Fatal("expected error for merged without content")
	}

	// Merged with content should succeed
	content := "merged content"
	err = svc.ResolveConflict(ctx, conflictID, models.ConflictResolutionMerged, uuid.New(), &content)
	if err != nil {
		t.Fatalf("resolve merged: %v", err)
	}

	// Invalid resolution
	err = svc.ResolveConflict(ctx, conflictID, "bad_value", uuid.New(), nil)
	if err == nil {
		t.Fatal("expected error for invalid resolution")
	}
}

func TestGetSyncStats(t *testing.T) {
	svc, repo := newService()
	ctx := context.Background()

	// Create two configs: one enabled with sync count 5, one disabled with sync count 3.
	id1, id2 := uuid.New(), uuid.New()
	repo.configs[id1] = &models.GitSyncConfig{ID: id1, IsEnabled: true, SyncCount: 5}
	repo.configs[id2] = &models.GitSyncConfig{ID: id2, IsEnabled: false, SyncCount: 3}

	// Add a pending conflict for id1.
	repo.conflicts[uuid.New()] = &models.GitSyncConflict{
		ID: uuid.New(), ConfigID: id1, Resolution: models.ConflictResolutionPending,
	}

	stats, err := svc.GetSyncStats(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.TotalConfigs != 2 {
		t.Errorf("TotalConfigs = %d, want 2", stats.TotalConfigs)
	}
	if stats.ActiveConfigs != 1 {
		t.Errorf("ActiveConfigs = %d, want 1", stats.ActiveConfigs)
	}
	if stats.TotalSyncs != 8 {
		t.Errorf("TotalSyncs = %d, want 8", stats.TotalSyncs)
	}
	if stats.PendingConflicts != 1 {
		t.Errorf("PendingConflicts = %d, want 1", stats.PendingConflicts)
	}
}
