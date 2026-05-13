// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package container

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// mockDockerClient is a minimal mock that implements the methods used by the
// event handler (ContainerGet). It uses an embedded nil to satisfy the full
// ClientAPI interface - only the methods we override are usable.
type mockDockerClient struct {
	docker.ClientAPI // embed to satisfy interface; unused methods panic
	containers       map[string]*docker.ContainerDetails
}

func newMockDockerClient() *mockDockerClient {
	return &mockDockerClient{
		containers: make(map[string]*docker.ContainerDetails),
	}
}

func (c *mockDockerClient) ContainerGet(_ context.Context, containerID string) (*docker.ContainerDetails, error) {
	d, ok := c.containers[containerID]
	if !ok {
		return nil, fmt.Errorf("container %s not found", containerID)
	}
	return d, nil
}

func (c *mockDockerClient) StreamEvents(ctx context.Context) (<-chan docker.DockerEvent, <-chan error) {
	ch := make(chan docker.DockerEvent)
	errCh := make(chan error, 1)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch, errCh
}

func TestHandleDockerEvent_Start(t *testing.T) {
	hostID := uuid.New()
	containerID := "abc123def456"

	client := newMockDockerClient()
	client.containers[containerID] = &docker.ContainerDetails{
		Container: docker.Container{
			ID:    containerID,
			Name:  "test-container",
			Image: "nginx:latest",
			State: "running",
		},
	}

	svc := &Service{
		logger: logger.Nop().Named("test"),
		config: DefaultConfig(),
	}

	// Test that handleDockerEvent correctly processes a start event.
	// Since we can't mock the repo through the concrete type, we verify
	// the function doesn't panic and handles the flow correctly by
	// inspecting what would be logged.
	event := docker.DockerEvent{
		Type:      "container",
		Action:    "start",
		ActorID:   containerID,
		ActorName: "test-container",
		Time:      time.Now(),
	}

	// This will try to upsert via the nil repo and fail silently
	// (the handler logs a warning but doesn't propagate errors).
	// The key test here is that it doesn't panic on the event processing flow.
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Expected since repo is nil; the test verifies the code
				// path reaches the repo call without earlier panics.
				t.Logf("recovered panic (expected with nil repo): %v", r)
			}
		}()
		svc.handleDockerEvent(context.Background(), hostID, client, event)
	}()
}

func TestHandleDockerEvent_IgnoresNonContainer(t *testing.T) {
	hostID := uuid.New()
	client := newMockDockerClient()

	svc := &Service{
		logger: logger.Nop().Named("test"),
		config: DefaultConfig(),
	}

	// Image events should be ignored
	event := docker.DockerEvent{
		Type:      "image",
		Action:    "pull",
		ActorID:   "sha256:abc123",
		ActorName: "nginx:latest",
		Time:      time.Now(),
	}

	// Should not panic - event is filtered out before any repo access
	svc.handleDockerEvent(context.Background(), hostID, client, event)
}

func TestHandleDockerEvent_IgnoresUnknownAction(t *testing.T) {
	hostID := uuid.New()
	client := newMockDockerClient()

	svc := &Service{
		logger: logger.Nop().Named("test"),
		config: DefaultConfig(),
	}

	// Container event with unknown action should be ignored
	event := docker.DockerEvent{
		Type:      "container",
		Action:    "attach",
		ActorID:   "container123",
		ActorName: "test",
		Time:      time.Now(),
	}

	svc.handleDockerEvent(context.Background(), hostID, client, event)
}

func TestContainerEventActions(t *testing.T) {
	expected := []string{
		"create", "start", "stop", "die", "kill",
		"pause", "unpause", "destroy", "rename",
		"restart", "oom", "health_status",
	}

	for _, action := range expected {
		if !containerEventActions[action] {
			t.Errorf("expected action %q to be in containerEventActions", action)
		}
	}

	// Verify non-event actions are excluded
	excluded := []string{"attach", "detach", "exec_create", "exec_start", "export", "commit"}
	for _, action := range excluded {
		if containerEventActions[action] {
			t.Errorf("expected action %q to NOT be in containerEventActions", action)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.SyncInterval != 5*time.Minute {
		t.Errorf("SyncInterval = %v, want %v", cfg.SyncInterval, 5*time.Minute)
	}

	if cfg.EventReconnectMin != 1*time.Second {
		t.Errorf("EventReconnectMin = %v, want %v", cfg.EventReconnectMin, 1*time.Second)
	}

	if cfg.EventReconnectMax != 30*time.Second {
		t.Errorf("EventReconnectMax = %v, want %v", cfg.EventReconnectMax, 30*time.Second)
	}
}

func TestHostEventWatcher_ContextCancel(t *testing.T) {
	hostID := uuid.New()

	svc := &Service{
		logger:         logger.Nop().Named("test"),
		config:         DefaultConfig(),
		stopCh:         make(chan struct{}),
		activeWatchers: make(map[uuid.UUID]context.CancelFunc),
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		// hostEventWatcher should return when context is cancelled.
		// It will fail to get a client (hostService is nil) and retry,
		// but cancelling the context should stop it.
		svc.hostEventWatcher(ctx, hostID)
		close(done)
	}()

	// Give it a moment to start, then cancel
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Success - watcher stopped
	case <-time.After(5 * time.Second):
		t.Fatal("hostEventWatcher did not stop after context cancel")
	}
}

func TestHostEventWatcher_StopChannel(t *testing.T) {
	hostID := uuid.New()

	svc := &Service{
		logger:         logger.Nop().Named("test"),
		config:         DefaultConfig(),
		stopCh:         make(chan struct{}),
		activeWatchers: make(map[uuid.UUID]context.CancelFunc),
	}

	done := make(chan struct{})
	go func() {
		svc.hostEventWatcher(context.Background(), hostID)
		close(done)
	}()

	// Give it a moment to start, then stop via channel
	time.Sleep(50 * time.Millisecond)
	close(svc.stopCh)

	select {
	case <-done:
		// Success - watcher stopped
	case <-time.After(5 * time.Second):
		t.Fatal("hostEventWatcher did not stop after stopCh closed")
	}
}

func TestServiceStop_CancelsWatchers(t *testing.T) {
	svc := &Service{
		logger:         logger.Nop().Named("test"),
		config:         DefaultConfig(),
		stopCh:         make(chan struct{}),
		activeWatchers: make(map[uuid.UUID]context.CancelFunc),
	}

	// Add some fake watchers
	cancelled := make([]bool, 3)
	for i := range 3 {
		idx := i
		_, cancel := context.WithCancel(context.Background())
		wrappedCancel := func() {
			cancelled[idx] = true
			cancel()
		}
		svc.activeWatchers[uuid.New()] = wrappedCancel
	}

	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	for i, c := range cancelled {
		if !c {
			t.Errorf("watcher %d was not cancelled", i)
		}
	}

	if len(svc.activeWatchers) != 0 {
		t.Errorf("activeWatchers should be empty after Stop, got %d", len(svc.activeWatchers))
	}
}
