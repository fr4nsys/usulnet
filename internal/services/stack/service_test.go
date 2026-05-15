// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package stack

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// ---------------------------------------------------------------------------
// Mock: StackRepository
// ---------------------------------------------------------------------------

type testStackRepo struct {
	stacks    map[uuid.UUID]*models.Stack
	byName    map[string]*models.Stack
	createErr error
	updateErr error
	deleteErr error
	deleted   []uuid.UUID
	statuses  map[uuid.UUID]models.StackStatus
	counts    map[uuid.UUID][2]int // [serviceCount, runningCount]
}

func newTestStackRepo() *testStackRepo {
	return &testStackRepo{
		stacks:   make(map[uuid.UUID]*models.Stack),
		byName:   make(map[string]*models.Stack),
		statuses: make(map[uuid.UUID]models.StackStatus),
		counts:   make(map[uuid.UUID][2]int),
	}
}

func (r *testStackRepo) addStack(s *models.Stack) {
	r.stacks[s.ID] = s
	key := s.HostID.String() + "/" + s.Name
	r.byName[key] = s
}

func (r *testStackRepo) Create(_ context.Context, s *models.Stack) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.stacks[s.ID] = s
	key := s.HostID.String() + "/" + s.Name
	r.byName[key] = s
	return nil
}

func (r *testStackRepo) GetByID(_ context.Context, id uuid.UUID) (*models.Stack, error) {
	if s, ok := r.stacks[id]; ok {
		return s, nil
	}
	return nil, errors.New("stack not found")
}

func (r *testStackRepo) GetByName(_ context.Context, hostID uuid.UUID, name string) (*models.Stack, error) {
	key := hostID.String() + "/" + name
	if s, ok := r.byName[key]; ok {
		return s, nil
	}
	return nil, errors.New("stack not found")
}

func (r *testStackRepo) Update(_ context.Context, s *models.Stack) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	r.stacks[s.ID] = s
	return nil
}

func (r *testStackRepo) Delete(_ context.Context, id uuid.UUID) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	r.deleted = append(r.deleted, id)
	delete(r.stacks, id)
	return nil
}

func (r *testStackRepo) ExistsByName(_ context.Context, hostID uuid.UUID, name string) (bool, error) {
	key := hostID.String() + "/" + name
	_, ok := r.byName[key]
	return ok, nil
}

func (r *testStackRepo) List(_ context.Context, _ postgres.StackListOptions) ([]*models.Stack, int64, error) {
	var result []*models.Stack
	for _, s := range r.stacks {
		result = append(result, s)
	}
	return result, int64(len(result)), nil
}

func (r *testStackRepo) ListByHost(_ context.Context, hostID uuid.UUID) ([]*models.Stack, error) {
	var result []*models.Stack
	for _, s := range r.stacks {
		if s.HostID == hostID {
			result = append(result, s)
		}
	}
	return result, nil
}

func (r *testStackRepo) UpdateStatus(_ context.Context, id uuid.UUID, status models.StackStatus) error {
	r.statuses[id] = status
	return nil
}

func (r *testStackRepo) UpdateCounts(_ context.Context, id uuid.UUID, serviceCount, runningCount int) error {
	r.counts[id] = [2]int{serviceCount, runningCount}
	return nil
}

// ---------------------------------------------------------------------------
// Mock: HostService
// ---------------------------------------------------------------------------

type testHostSvc struct {
	hosts   map[uuid.UUID]*models.Host
	clients map[uuid.UUID]docker.ClientAPI
}

func newTestHostSvc() *testHostSvc {
	return &testHostSvc{
		hosts:   make(map[uuid.UUID]*models.Host),
		clients: make(map[uuid.UUID]docker.ClientAPI),
	}
}

func (h *testHostSvc) Get(_ context.Context, id uuid.UUID) (*models.Host, error) {
	if host, ok := h.hosts[id]; ok {
		return host, nil
	}
	return nil, errors.New("host not found")
}

func (h *testHostSvc) GetClient(_ context.Context, hostID uuid.UUID) (docker.ClientAPI, error) {
	if c, ok := h.clients[hostID]; ok {
		return c, nil
	}
	return nil, errors.New("host not found")
}

// ---------------------------------------------------------------------------
// Mock: ContainerService
// ---------------------------------------------------------------------------

type testContainerSvc struct {
	containers map[string][]*models.Container
}

func newTestContainerSvc() *testContainerSvc {
	return &testContainerSvc{
		containers: make(map[string][]*models.Container),
	}
}

func (c *testContainerSvc) ListByLabel(_ context.Context, hostID uuid.UUID, key, value string) ([]*models.Container, error) {
	mapKey := hostID.String() + "/" + key + "=" + value
	return c.containers[mapKey], nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestStackService(t *testing.T) (*Service, *testStackRepo, *testHostSvc, *testContainerSvc) {
	t.Helper()
	repo := newTestStackRepo()
	hostSvc := newTestHostSvc()
	containerSvc := newTestContainerSvc()
	log := logger.Nop()

	cfg := ServiceConfig{
		StacksDir:      t.TempDir(),
		ComposeCommand: "docker compose",
	}

	svc := NewService(repo, hostSvc, containerSvc, cfg, log)
	return svc, repo, hostSvc, containerSvc
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	svc, _, _, _ := newTestStackService(t)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestNewService_NilLogger(t *testing.T) {
	repo := newTestStackRepo()
	cfg := ServiceConfig{StacksDir: t.TempDir()}
	svc := NewService(repo, newTestHostSvc(), newTestContainerSvc(), cfg, nil)
	if svc.logger == nil {
		t.Error("expected non-nil logger even with nil input")
	}
}

func TestNewService_CreatesStacksDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deep", "nested", "stacks")
	cfg := ServiceConfig{StacksDir: dir}
	NewService(newTestStackRepo(), newTestHostSvc(), newTestContainerSvc(), cfg, logger.Nop())

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("expected stacks dir to be created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected a directory")
	}
}

func TestCreate_Success(t *testing.T) {
	svc, repo, _, _ := newTestStackService(t)
	ctx := context.Background()
	hostID := uuid.New()

	composeContent := "version: '3'\nservices:\n  web:\n    image: nginx\n"
	stack, err := svc.Create(ctx, hostID, &models.CreateStackInput{
		Name:        "test-stack",
		ComposeFile: composeContent,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if stack.Name != "test-stack" {
		t.Errorf("expected name test-stack, got %s", stack.Name)
	}
	if stack.HostID != hostID {
		t.Error("expected correct host ID")
	}
	if stack.Status != models.StackStatusInactive {
		t.Errorf("expected status inactive, got %s", stack.Status)
	}
	// Check repo has the stack
	if _, ok := repo.stacks[stack.ID]; !ok {
		t.Error("expected stack saved in repo")
	}
	// Check compose file written to disk
	composePath := filepath.Join(svc.config.StacksDir, stack.ID.String(), "docker-compose.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("compose file not found on disk: %v", err)
	}
	if string(data) != composeContent {
		t.Error("compose file content mismatch")
	}
}

func TestCreate_EmptyName(t *testing.T) {
	svc, _, _, _ := newTestStackService(t)
	ctx := context.Background()

	_, err := svc.Create(ctx, uuid.New(), &models.CreateStackInput{
		Name:        "",
		ComposeFile: "version: '3'\nservices:\n  web:\n    image: nginx\n",
	})
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestCreate_EmptyComposeFile(t *testing.T) {
	svc, _, _, _ := newTestStackService(t)
	ctx := context.Background()

	_, err := svc.Create(ctx, uuid.New(), &models.CreateStackInput{
		Name:        "test",
		ComposeFile: "",
	})
	if err == nil {
		t.Error("expected error for empty compose file")
	}
}

func TestCreate_DuplicateName(t *testing.T) {
	svc, repo, _, _ := newTestStackService(t)
	ctx := context.Background()
	hostID := uuid.New()

	repo.addStack(&models.Stack{ID: uuid.New(), HostID: hostID, Name: "existing"})

	_, err := svc.Create(ctx, hostID, &models.CreateStackInput{
		Name:        "existing",
		ComposeFile: "version: '3'\nservices:\n  web:\n    image: nginx\n",
	})
	if err == nil {
		t.Error("expected error for duplicate name")
	}
}

func TestCreate_WithEnvFile(t *testing.T) {
	svc, _, _, _ := newTestStackService(t)
	ctx := context.Background()
	hostID := uuid.New()

	envContent := "DB_HOST=localhost\nDB_PORT=5432"
	stack, err := svc.Create(ctx, hostID, &models.CreateStackInput{
		Name:        "with-env",
		ComposeFile: "version: '3'\nservices:\n  web:\n    image: nginx\n",
		EnvFile:     &envContent,
	})
	if err != nil {
		t.Fatalf("Create with env failed: %v", err)
	}

	envPath := filepath.Join(svc.config.StacksDir, stack.ID.String(), ".env")
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("env file not found: %v", err)
	}
	if string(data) != envContent {
		t.Error("env file content mismatch")
	}
}

func TestGet(t *testing.T) {
	svc, repo, _, _ := newTestStackService(t)
	ctx := context.Background()

	id := uuid.New()
	repo.addStack(&models.Stack{ID: id, Name: "my-stack"})

	stack, err := svc.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if stack.Name != "my-stack" {
		t.Errorf("expected name my-stack, got %s", stack.Name)
	}
}

func TestGet_NotFound(t *testing.T) {
	svc, _, _, _ := newTestStackService(t)
	ctx := context.Background()

	_, err := svc.Get(ctx, uuid.New())
	if err == nil {
		t.Error("expected error for non-existent stack")
	}
}

func TestGetByName(t *testing.T) {
	svc, repo, _, _ := newTestStackService(t)
	ctx := context.Background()

	hostID := uuid.New()
	repo.addStack(&models.Stack{ID: uuid.New(), HostID: hostID, Name: "prod-stack"})

	stack, err := svc.GetByName(ctx, hostID, "prod-stack")
	if err != nil {
		t.Fatalf("GetByName failed: %v", err)
	}
	if stack.Name != "prod-stack" {
		t.Errorf("expected name prod-stack, got %s", stack.Name)
	}
}

func TestList(t *testing.T) {
	svc, repo, _, _ := newTestStackService(t)
	ctx := context.Background()

	repo.addStack(&models.Stack{ID: uuid.New(), Name: "s1"})
	repo.addStack(&models.Stack{ID: uuid.New(), Name: "s2"})

	stacks, total, err := svc.List(ctx, postgres.StackListOptions{})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
	if len(stacks) != 2 {
		t.Errorf("expected 2 stacks, got %d", len(stacks))
	}
}

func TestListByHost(t *testing.T) {
	svc, repo, _, _ := newTestStackService(t)
	ctx := context.Background()

	hostID := uuid.New()
	otherHost := uuid.New()
	repo.addStack(&models.Stack{ID: uuid.New(), HostID: hostID, Name: "s1"})
	repo.addStack(&models.Stack{ID: uuid.New(), HostID: hostID, Name: "s2"})
	repo.addStack(&models.Stack{ID: uuid.New(), HostID: otherHost, Name: "s3"})

	stacks, err := svc.ListByHost(ctx, hostID)
	if err != nil {
		t.Fatalf("ListByHost failed: %v", err)
	}
	if len(stacks) != 2 {
		t.Errorf("expected 2 stacks for host, got %d", len(stacks))
	}
}

func TestUpdate(t *testing.T) {
	svc, repo, _, _ := newTestStackService(t)
	ctx := context.Background()

	id := uuid.New()
	hostID := uuid.New()
	repo.addStack(&models.Stack{ID: id, HostID: hostID, Name: "test"})

	// Create the stack directory so WriteFile succeeds
	os.MkdirAll(filepath.Join(svc.config.StacksDir, id.String()), 0755)

	newCompose := "version: '3'\nservices:\n  api:\n    image: node\n"
	updated, err := svc.Update(ctx, id, &models.UpdateStackInput{
		ComposeFile: &newCompose,
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.ComposeFile != newCompose {
		t.Error("expected compose file to be updated")
	}
}

func TestUpdate_NotFound(t *testing.T) {
	svc, _, _, _ := newTestStackService(t)
	ctx := context.Background()

	compose := "version: '3'\nservices:\n  web:\n    image: nginx\n"
	_, err := svc.Update(ctx, uuid.New(), &models.UpdateStackInput{
		ComposeFile: &compose,
	})
	if err == nil {
		t.Error("expected error for non-existent stack")
	}
}

func TestDelete(t *testing.T) {
	svc, repo, _, _ := newTestStackService(t)
	ctx := context.Background()

	id := uuid.New()
	repo.addStack(&models.Stack{ID: id, Name: "doomed", Status: models.StackStatusInactive})

	// Create stack dir
	stackDir := filepath.Join(svc.config.StacksDir, id.String())
	os.MkdirAll(stackDir, 0755)
	os.WriteFile(filepath.Join(stackDir, "docker-compose.yml"), []byte("test"), 0644)

	err := svc.Delete(ctx, id, false)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Stack should be removed from repo
	if len(repo.deleted) != 1 || repo.deleted[0] != id {
		t.Error("expected stack to be deleted from repo")
	}

	// Directory should be removed
	if _, err := os.Stat(stackDir); !os.IsNotExist(err) {
		t.Error("expected stack directory to be removed")
	}
}

func TestDelete_NotFound(t *testing.T) {
	svc, _, _, _ := newTestStackService(t)
	ctx := context.Background()

	err := svc.Delete(ctx, uuid.New(), false)
	if err == nil {
		t.Error("expected error for non-existent stack")
	}
}

func TestCreate_InvalidComposeContent(t *testing.T) {
	svc, _, _, _ := newTestStackService(t)
	ctx := context.Background()

	_, err := svc.Create(ctx, uuid.New(), &models.CreateStackInput{
		Name:        "bad-compose",
		ComposeFile: "this is not valid yaml: [",
	})
	if err == nil {
		t.Error("expected error for invalid compose content")
	}
}

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.StacksDir != "/data/stacks" {
		t.Errorf("expected /data/stacks, got %s", cfg.StacksDir)
	}
	if cfg.ComposeCommand != "docker compose" {
		t.Errorf("expected docker compose, got %s", cfg.ComposeCommand)
	}
	if !cfg.PullBeforeDeploy {
		t.Error("expected PullBeforeDeploy true by default")
	}
}
