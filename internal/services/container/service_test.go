// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package container

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// ---------------------------------------------------------------------------
// Mock: ContainerRepository
// ---------------------------------------------------------------------------

type testContainerRepo struct {
	// mu guards every map / slice below. The parallel reconciliation
	// worker (syncAllHosts) writes from multiple goroutines, so the
	// test repo must be safe against concurrent Upsert / Delete /
	// GetContainerIDs calls — otherwise -race would flag the map writes.
	mu            sync.Mutex
	containers    map[string]*models.Container
	byHost        map[uuid.UUID][]*models.Container
	stateUpdates  map[string]models.ContainerState
	batchUpserted []*models.Container
	deleted       []string
	stats         *postgres.ContainerStats
	statsHistory  []*models.ContainerStats
	deletedStats  int64
	deletedLogs   int64
	containerIDs  []string
	securityInfos map[string]int
	listErr       error
}

func newTestContainerRepo() *testContainerRepo {
	return &testContainerRepo{
		containers:    make(map[string]*models.Container),
		byHost:        make(map[uuid.UUID][]*models.Container),
		stateUpdates:  make(map[string]models.ContainerState),
		securityInfos: make(map[string]int),
	}
}

func (r *testContainerRepo) addContainer(c *models.Container) {
	r.containers[c.ID] = c
	r.byHost[c.HostID] = append(r.byHost[c.HostID], c)
}

func (r *testContainerRepo) Upsert(_ context.Context, c *models.Container) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.containers[c.ID] = c
	return nil
}

func (r *testContainerRepo) UpsertBatch(_ context.Context, containers []*models.Container) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batchUpserted = append(r.batchUpserted, containers...)
	for _, c := range containers {
		r.containers[c.ID] = c
	}
	return nil
}

func (r *testContainerRepo) GetByHostAndID(_ context.Context, hostID uuid.UUID, containerID string) (*models.Container, error) {
	if c, ok := r.containers[containerID]; ok && c.HostID == hostID {
		return c, nil
	}
	return nil, errors.New("container not found")
}

func (r *testContainerRepo) GetByName(_ context.Context, hostID uuid.UUID, name string) (*models.Container, error) {
	for _, c := range r.containers {
		if c.HostID == hostID && c.Name == name {
			return c, nil
		}
	}
	return nil, errors.New("container not found")
}

func (r *testContainerRepo) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleted = append(r.deleted, id)
	delete(r.containers, id)
	return nil
}

func (r *testContainerRepo) List(_ context.Context, _ postgres.ContainerListOptions) ([]*models.Container, int64, error) {
	if r.listErr != nil {
		return nil, 0, r.listErr
	}
	var result []*models.Container
	for _, c := range r.containers {
		result = append(result, c)
	}
	return result, int64(len(result)), nil
}

func (r *testContainerRepo) ListByHost(_ context.Context, hostID uuid.UUID) ([]*models.Container, error) {
	return r.byHost[hostID], nil
}

func (r *testContainerRepo) ListWithUpdatesAvailable(_ context.Context, _ *uuid.UUID) ([]*models.Container, error) {
	var result []*models.Container
	for _, c := range r.containers {
		if c.UpdateAvailable {
			result = append(result, c)
		}
	}
	return result, nil
}

func (r *testContainerRepo) ListBySecurityGrade(_ context.Context, grade string, _ *uuid.UUID) ([]*models.Container, error) {
	var result []*models.Container
	for _, c := range r.containers {
		if c.SecurityGrade == grade {
			result = append(result, c)
		}
	}
	return result, nil
}

func (r *testContainerRepo) UpdateState(_ context.Context, id string, state models.ContainerState, _ string) error {
	r.stateUpdates[id] = state
	return nil
}

func (r *testContainerRepo) UpdateSecurityInfo(_ context.Context, id string, score int, grade string) error {
	r.securityInfos[id] = score
	if c, ok := r.containers[id]; ok {
		c.SecurityScore = score
		c.SecurityGrade = grade
	}
	return nil
}

func (r *testContainerRepo) GetContainerIDs(_ context.Context, _ uuid.UUID) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Return a copy so the caller can iterate without holding the lock.
	out := make([]string, len(r.containerIDs))
	copy(out, r.containerIDs)
	return out, nil
}

func (r *testContainerRepo) GetStats(_ context.Context, _ *uuid.UUID) (*postgres.ContainerStats, error) {
	if r.stats != nil {
		return r.stats, nil
	}
	return &postgres.ContainerStats{}, nil
}

func (r *testContainerRepo) GetStatsHistory(_ context.Context, _ string, _ time.Time, _ int) ([]*models.ContainerStats, error) {
	return r.statsHistory, nil
}

func (r *testContainerRepo) DeleteOldStats(_ context.Context, _ time.Duration) (int64, error) {
	return r.deletedStats, nil
}

func (r *testContainerRepo) DeleteOldLogs(_ context.Context, _ time.Duration) (int64, error) {
	return r.deletedLogs, nil
}

// ---------------------------------------------------------------------------
// Mock: HostService
// ---------------------------------------------------------------------------

type testHostService struct {
	clients  map[uuid.UUID]docker.ClientAPI
	hosts    []*models.Host
	clientFn func(uuid.UUID) (docker.ClientAPI, error)
}

func newTestHostService() *testHostService {
	return &testHostService{
		clients: make(map[uuid.UUID]docker.ClientAPI),
	}
}

func (h *testHostService) GetClient(_ context.Context, hostID uuid.UUID) (docker.ClientAPI, error) {
	if h.clientFn != nil {
		return h.clientFn(hostID)
	}
	if c, ok := h.clients[hostID]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("host %s not found", hostID)
}

func (h *testHostService) List(_ context.Context, _ postgres.HostListOptions) ([]*models.Host, int64, error) {
	return h.hosts, int64(len(h.hosts)), nil
}

// ---------------------------------------------------------------------------
// Mock: Docker ClientAPI (minimal, using embedding)
// ---------------------------------------------------------------------------

type testDockerClientForService struct {
	docker.ClientAPI
	containers    map[string]*docker.ContainerDetails
	containerList []docker.Container
	startErr      error
	stopErr       error
	restartErr    error
	started       []string
	stopped       []string
	restarted     []string
	killed        []string
}

func newTestDockerClientForService() *testDockerClientForService {
	return &testDockerClientForService{
		containers: make(map[string]*docker.ContainerDetails),
	}
}

func (c *testDockerClientForService) ContainerGet(_ context.Context, containerID string) (*docker.ContainerDetails, error) {
	if d, ok := c.containers[containerID]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("container %s not found", containerID)
}

func (c *testDockerClientForService) ContainerList(_ context.Context, _ docker.ContainerListOptions) ([]docker.Container, error) {
	return c.containerList, nil
}

func (c *testDockerClientForService) ContainerStart(_ context.Context, containerID string) error {
	if c.startErr != nil {
		return c.startErr
	}
	c.started = append(c.started, containerID)
	return nil
}

func (c *testDockerClientForService) ContainerStop(_ context.Context, containerID string, _ *int) error {
	if c.stopErr != nil {
		return c.stopErr
	}
	c.stopped = append(c.stopped, containerID)
	return nil
}

func (c *testDockerClientForService) ContainerRestart(_ context.Context, containerID string, _ *int) error {
	if c.restartErr != nil {
		return c.restartErr
	}
	c.restarted = append(c.restarted, containerID)
	return nil
}

func (c *testDockerClientForService) ContainerKill(_ context.Context, containerID string, _ string) error {
	c.killed = append(c.killed, containerID)
	return nil
}

func (c *testDockerClientForService) ContainerPause(_ context.Context, _ string) error { return nil }
func (c *testDockerClientForService) ContainerUnpause(_ context.Context, _ string) error {
	return nil
}
func (c *testDockerClientForService) ContainerRemove(_ context.Context, _ string, _, _ bool) error {
	return nil
}
func (c *testDockerClientForService) ContainerRename(_ context.Context, _, _ string) error {
	return nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestContainerService(t *testing.T) (*Service, *testContainerRepo, *testHostService) {
	t.Helper()
	repo := newTestContainerRepo()
	hostSvc := newTestHostService()
	cfg := DefaultConfig()
	log := logger.Nop()

	svc := NewService(repo, hostSvc, cfg, log)
	return svc, repo, hostSvc
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	svc, _, _ := newTestContainerService(t)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.repo == nil {
		t.Error("expected repo to be set")
	}
	if svc.hostService == nil {
		t.Error("expected hostService to be set")
	}
}

func TestNewService_NilLogger(t *testing.T) {
	repo := newTestContainerRepo()
	hostSvc := newTestHostService()
	svc := NewService(repo, hostSvc, DefaultConfig(), nil)
	if svc.logger == nil {
		t.Error("expected non-nil logger even with nil input")
	}
}

func TestList(t *testing.T) {
	svc, repo, _ := newTestContainerService(t)
	ctx := context.Background()

	hostID := uuid.New()
	repo.addContainer(&models.Container{ID: "c1", Name: "web", HostID: hostID})
	repo.addContainer(&models.Container{ID: "c2", Name: "db", HostID: hostID})

	containers, total, err := svc.List(ctx, postgres.ContainerListOptions{})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
	if len(containers) != 2 {
		t.Errorf("expected 2 containers, got %d", len(containers))
	}
}

func TestList_Error(t *testing.T) {
	svc, repo, _ := newTestContainerService(t)
	ctx := context.Background()

	repo.listErr = errors.New("database error")

	_, _, err := svc.List(ctx, postgres.ContainerListOptions{})
	if err == nil {
		t.Error("expected error from List")
	}
}

func TestListByHost(t *testing.T) {
	svc, repo, _ := newTestContainerService(t)
	ctx := context.Background()

	hostID := uuid.New()
	otherHost := uuid.New()
	repo.addContainer(&models.Container{ID: "c1", Name: "web", HostID: hostID})
	repo.addContainer(&models.Container{ID: "c2", Name: "db", HostID: hostID})
	repo.addContainer(&models.Container{ID: "c3", Name: "other", HostID: otherHost})

	containers, err := svc.ListByHost(ctx, hostID)
	if err != nil {
		t.Fatalf("ListByHost failed: %v", err)
	}
	if len(containers) != 2 {
		t.Errorf("expected 2 containers for host, got %d", len(containers))
	}
}

func TestGet(t *testing.T) {
	svc, repo, _ := newTestContainerService(t)
	ctx := context.Background()

	hostID := uuid.New()
	repo.addContainer(&models.Container{ID: "c1", Name: "web", HostID: hostID})

	c, err := svc.Get(ctx, hostID, "c1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if c.Name != "web" {
		t.Errorf("expected name web, got %s", c.Name)
	}
}

func TestGet_NotFound(t *testing.T) {
	svc, _, _ := newTestContainerService(t)
	ctx := context.Background()

	_, err := svc.Get(ctx, uuid.New(), "nonexistent")
	if err == nil {
		t.Error("expected error for non-existent container")
	}
}

func TestGetByName(t *testing.T) {
	svc, repo, _ := newTestContainerService(t)
	ctx := context.Background()

	hostID := uuid.New()
	repo.addContainer(&models.Container{ID: "c1", Name: "my-app", HostID: hostID})

	c, err := svc.GetByName(ctx, hostID, "my-app")
	if err != nil {
		t.Fatalf("GetByName failed: %v", err)
	}
	if c.ID != "c1" {
		t.Errorf("expected ID c1, got %s", c.ID)
	}
}

func TestGetContainerStats(t *testing.T) {
	svc, repo, _ := newTestContainerService(t)
	ctx := context.Background()

	repo.stats = &postgres.ContainerStats{
		Total:   10,
		Running: 7,
		Stopped: 3,
	}

	stats, err := svc.GetContainerStats(ctx, nil)
	if err != nil {
		t.Fatalf("GetContainerStats failed: %v", err)
	}
	if stats.Total != 10 {
		t.Errorf("expected total 10, got %d", stats.Total)
	}
	if stats.Running != 7 {
		t.Errorf("expected running 7, got %d", stats.Running)
	}
}

func TestGetStatsHistory(t *testing.T) {
	svc, repo, _ := newTestContainerService(t)
	ctx := context.Background()

	now := time.Now()
	repo.statsHistory = []*models.ContainerStats{
		{ContainerID: "c1", CPUPercent: 50.0, CollectedAt: now},
		{ContainerID: "c1", CPUPercent: 60.0, CollectedAt: now.Add(-time.Minute)},
	}

	history, err := svc.GetStatsHistory(ctx, "c1", now.Add(-time.Hour), 100)
	if err != nil {
		t.Fatalf("GetStatsHistory failed: %v", err)
	}
	if len(history) != 2 {
		t.Errorf("expected 2 stats, got %d", len(history))
	}
}

func TestListWithUpdates(t *testing.T) {
	svc, repo, _ := newTestContainerService(t)
	ctx := context.Background()

	hostID := uuid.New()
	repo.addContainer(&models.Container{ID: "c1", Name: "outdated", HostID: hostID, UpdateAvailable: true})
	repo.addContainer(&models.Container{ID: "c2", Name: "current", HostID: hostID, UpdateAvailable: false})

	containers, err := svc.ListWithUpdates(ctx, nil)
	if err != nil {
		t.Fatalf("ListWithUpdates failed: %v", err)
	}
	if len(containers) != 1 {
		t.Errorf("expected 1 container with updates, got %d", len(containers))
	}
}

func TestListBySecurityGrade(t *testing.T) {
	svc, repo, _ := newTestContainerService(t)
	ctx := context.Background()

	hostID := uuid.New()
	repo.addContainer(&models.Container{ID: "c1", Name: "secure", HostID: hostID, SecurityGrade: "A"})
	repo.addContainer(&models.Container{ID: "c2", Name: "risky", HostID: hostID, SecurityGrade: "F"})

	containers, err := svc.ListBySecurityGrade(ctx, "A", nil)
	if err != nil {
		t.Fatalf("ListBySecurityGrade failed: %v", err)
	}
	if len(containers) != 1 {
		t.Errorf("expected 1 grade-A container, got %d", len(containers))
	}
}

func TestUpdateSecurityInfo(t *testing.T) {
	svc, repo, _ := newTestContainerService(t)
	ctx := context.Background()

	repo.addContainer(&models.Container{ID: "c1", Name: "web"})

	err := svc.UpdateSecurityInfo(ctx, "c1", 85, "B")
	if err != nil {
		t.Fatalf("UpdateSecurityInfo failed: %v", err)
	}
	if repo.securityInfos["c1"] != 85 {
		t.Errorf("expected security score 85, got %d", repo.securityInfos["c1"])
	}
}

func TestStartContainer(t *testing.T) {
	svc, repo, hostSvc := newTestContainerService(t)
	ctx := context.Background()

	hostID := uuid.New()
	containerID := "c1"
	repo.addContainer(&models.Container{ID: containerID, Name: "web", HostID: hostID})

	dockerClient := newTestDockerClientForService()
	hostSvc.clients[hostID] = dockerClient

	err := svc.StartContainer(ctx, hostID, containerID)
	if err != nil {
		t.Fatalf("StartContainer failed: %v", err)
	}
	if len(dockerClient.started) != 1 || dockerClient.started[0] != containerID {
		t.Error("expected container to be started via docker client")
	}
	if state, ok := repo.stateUpdates[containerID]; !ok || state != models.ContainerStateRunning {
		t.Error("expected container state updated to running")
	}
}

func TestStopContainer(t *testing.T) {
	svc, repo, hostSvc := newTestContainerService(t)
	ctx := context.Background()

	hostID := uuid.New()
	containerID := "c1"
	repo.addContainer(&models.Container{ID: containerID, Name: "web", HostID: hostID})

	dockerClient := newTestDockerClientForService()
	hostSvc.clients[hostID] = dockerClient

	err := svc.StopContainer(ctx, hostID, containerID)
	if err != nil {
		t.Fatalf("StopContainer failed: %v", err)
	}
	if len(dockerClient.stopped) != 1 || dockerClient.stopped[0] != containerID {
		t.Error("expected container to be stopped via docker client")
	}
	if state, ok := repo.stateUpdates[containerID]; !ok || state != models.ContainerStateExited {
		t.Error("expected container state updated to exited")
	}
}

func TestRestartContainer(t *testing.T) {
	svc, repo, hostSvc := newTestContainerService(t)
	ctx := context.Background()

	hostID := uuid.New()
	containerID := "c1"
	repo.addContainer(&models.Container{ID: containerID, Name: "web", HostID: hostID})

	dockerClient := newTestDockerClientForService()
	hostSvc.clients[hostID] = dockerClient

	err := svc.Restart(ctx, hostID, containerID)
	if err != nil {
		t.Fatalf("Restart failed: %v", err)
	}
	if len(dockerClient.restarted) != 1 || dockerClient.restarted[0] != containerID {
		t.Error("expected container to be restarted via docker client")
	}
	if state, ok := repo.stateUpdates[containerID]; !ok || state != models.ContainerStateRunning {
		t.Error("expected container state updated to running")
	}
}

func TestStartContainer_HostNotFound(t *testing.T) {
	svc, _, _ := newTestContainerService(t)
	ctx := context.Background()

	err := svc.StartContainer(ctx, uuid.New(), "c1")
	if err == nil {
		t.Error("expected error when host not found")
	}
}

func TestKillContainer(t *testing.T) {
	svc, repo, hostSvc := newTestContainerService(t)
	ctx := context.Background()

	hostID := uuid.New()
	containerID := "c1"
	repo.addContainer(&models.Container{ID: containerID, Name: "web", HostID: hostID})

	dockerClient := newTestDockerClientForService()
	hostSvc.clients[hostID] = dockerClient

	err := svc.Kill(ctx, hostID, containerID, "SIGKILL")
	if err != nil {
		t.Fatalf("Kill failed: %v", err)
	}
	if len(dockerClient.killed) != 1 || dockerClient.killed[0] != containerID {
		t.Error("expected container to be killed via docker client")
	}
}

func TestGetDockerClient(t *testing.T) {
	svc, _, hostSvc := newTestContainerService(t)
	ctx := context.Background()

	hostID := uuid.New()
	expected := newTestDockerClientForService()
	hostSvc.clients[hostID] = expected

	client, err := svc.GetDockerClient(ctx, hostID)
	if err != nil {
		t.Fatalf("GetDockerClient failed: %v", err)
	}
	if client != expected {
		t.Error("expected same client instance")
	}
}

// TestSyncAllHosts_NoHosts pins the early-return path: zero online
// hosts produces no goroutines, no work, and no panic.
func TestSyncAllHosts_NoHosts(t *testing.T) {
	svc, _, _ := newTestContainerService(t)
	// hostSvc.hosts is empty by default.
	done := make(chan struct{})
	go func() {
		svc.syncAllHosts(context.Background())
		close(done)
	}()
	select {
	case <-done:
		// Pass.
	case <-time.After(2 * time.Second):
		t.Fatal("syncAllHosts blocked on empty hosts list")
	}
}

// TestSyncAllHosts_FansOutAcrossHosts pins the parallel reconciliation
// path: every online host's container set should land in the repo by
// the time syncAllHosts returns, regardless of how the goroutine pool
// schedules them. Uses more hosts than the containerSyncFanoutCap so
// the semaphore path runs at least one wait.
func TestSyncAllHosts_FansOutAcrossHosts(t *testing.T) {
	svc, repo, hostSvc := newTestContainerService(t)

	const numHosts = containerSyncFanoutCap + 4 // 12 hosts on a cap of 8
	type fixture struct {
		hostID      uuid.UUID
		containerID string
	}
	fixtures := make([]fixture, 0, numHosts)
	for i := 0; i < numHosts; i++ {
		hostID := uuid.New()
		containerID := fmt.Sprintf("c-%d", i)
		fixtures = append(fixtures, fixture{hostID: hostID, containerID: containerID})

		hostSvc.hosts = append(hostSvc.hosts, &models.Host{
			ID:     hostID,
			Status: models.HostStatusOnline,
		})

		client := newTestDockerClientForService()
		client.containerList = []docker.Container{{ID: containerID}}
		// containerInspectFromContainer keeps the inspect lookup simple — every
		// container has only itself.
		client.containers[containerID] = &docker.ContainerDetails{
			Container: docker.Container{
				ID:   containerID,
				Name: "/svc-" + containerID,
			},
		}
		hostSvc.clients[hostID] = client
	}

	done := make(chan struct{})
	go func() {
		svc.syncAllHosts(context.Background())
		close(done)
	}()
	select {
	case <-done:
		// Pass.
	case <-time.After(5 * time.Second):
		t.Fatal("syncAllHosts blocked — fan-out semaphore or WaitGroup deadlock?")
	}

	// Every host's container should now be in the repo. Holding the test
	// repo's mutex while reading keeps the assertion safe against any
	// in-flight goroutine that the WaitGroup might somehow have missed.
	repo.mu.Lock()
	defer repo.mu.Unlock()
	for _, f := range fixtures {
		if _, ok := repo.containers[f.containerID]; !ok {
			t.Errorf("host %s: container %q not Upserted into repo", f.hostID, f.containerID)
		}
	}
}

func TestSyncInventory(t *testing.T) {
	svc, repo, _ := newTestContainerService(t)
	ctx := context.Background()

	hostID := uuid.New()

	// Pre-populate existing containers for this host
	repo.addContainer(&models.Container{ID: "c1", Name: "web", HostID: hostID})
	repo.addContainer(&models.Container{ID: "c2", Name: "old-db", HostID: hostID})
	repo.addContainer(&models.Container{ID: "c3", Name: "old-cache", HostID: hostID})

	// Sync with only c1 and c4 (c2 and c3 should be deleted as stale)
	newContainers := []*models.Container{
		{ID: "c1", Name: "web", HostID: hostID},
		{ID: "c4", Name: "new-svc", HostID: hostID},
	}

	err := svc.SyncInventory(ctx, hostID, newContainers)
	if err != nil {
		t.Fatalf("SyncInventory failed: %v", err)
	}

	// Should have upserted the synced containers
	if len(repo.batchUpserted) != 2 {
		t.Errorf("expected 2 upserted, got %d", len(repo.batchUpserted))
	}

	// Should have deleted stale containers (c2 and c3)
	if len(repo.deleted) != 2 {
		t.Errorf("expected 2 deleted, got %d", len(repo.deleted))
	}
}

func TestStop(t *testing.T) {
	svc := &Service{
		logger:         logger.Nop().Named("test"),
		config:         DefaultConfig(),
		stopCh:         make(chan struct{}),
		activeWatchers: make(map[uuid.UUID]context.CancelFunc),
	}

	err := svc.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Calling Stop again should not panic (already stopped)
	err = svc.Stop()
	if err != nil {
		t.Fatalf("second Stop failed: %v", err)
	}
}
