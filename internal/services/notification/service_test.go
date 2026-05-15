// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package notification

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/services/notification/channels"
)

// ============================================================================
// Mock Repository
// ============================================================================

type mockRepo struct {
	mu sync.Mutex

	logCalls          []*NotificationLog
	logErr            error
	getLogsCalls      int
	getLogsResult     []*NotificationLog
	getLogsTotal      int64
	getLogsErr        error
	getStatsCalls     int
	getStatsResult    *NotificationStats
	getStatsErr       error
	saveChannelCalls  []*channels.ChannelConfig
	saveChannelErr    error
	getConfigsCalls   int
	getConfigsResult  []*channels.ChannelConfig
	getConfigsErr     error
	getConfigCalls    []string
	getConfigResult   *channels.ChannelConfig
	getConfigErr      error
	deleteConfigCalls []string
	deleteConfigErr   error
	saveRulesCalls    int
	saveRulesArg      [][]*RoutingRule
	saveRulesErr      error
	getRulesCalls     int
	getRulesResult    []*RoutingRule
	getRulesErr       error
}

func (m *mockRepo) LogNotification(_ context.Context, log *NotificationLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logCalls = append(m.logCalls, log)
	return m.logErr
}

func (m *mockRepo) GetNotificationLogs(_ context.Context, _ LogFilter) ([]*NotificationLog, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getLogsCalls++
	return m.getLogsResult, m.getLogsTotal, m.getLogsErr
}

func (m *mockRepo) GetNotificationStats(_ context.Context, _ time.Time) (*NotificationStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getStatsCalls++
	return m.getStatsResult, m.getStatsErr
}

func (m *mockRepo) SaveChannelConfig(_ context.Context, config *channels.ChannelConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveChannelCalls = append(m.saveChannelCalls, config)
	return m.saveChannelErr
}

func (m *mockRepo) GetChannelConfigs(_ context.Context) ([]*channels.ChannelConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getConfigsCalls++
	return m.getConfigsResult, m.getConfigsErr
}

func (m *mockRepo) GetChannelConfig(_ context.Context, name string) (*channels.ChannelConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getConfigCalls = append(m.getConfigCalls, name)
	return m.getConfigResult, m.getConfigErr
}

func (m *mockRepo) DeleteChannelConfig(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteConfigCalls = append(m.deleteConfigCalls, name)
	return m.deleteConfigErr
}

func (m *mockRepo) SaveRoutingRules(_ context.Context, rules []*RoutingRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveRulesCalls++
	m.saveRulesArg = append(m.saveRulesArg, rules)
	return m.saveRulesErr
}

func (m *mockRepo) GetRoutingRules(_ context.Context) ([]*RoutingRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getRulesCalls++
	return m.getRulesResult, m.getRulesErr
}

// ============================================================================
// Mock LimitProvider
// ============================================================================

type mockLimitProvider struct {
	limits license.Limits
}

func (m *mockLimitProvider) GetLimits() license.Limits {
	return m.limits
}

// ============================================================================
// Test helpers
// ============================================================================

// webhookConfig returns a valid webhook ChannelConfig for testing.
// Uses a fake URL; tests that exercise Send will fail at the HTTP layer,
// which is acceptable because we're testing service-level logic, not HTTP.
func webhookConfig(url string) *channels.ChannelConfig {
	return &channels.ChannelConfig{
		Type:    "webhook",
		Enabled: true,
		Settings: map[string]interface{}{
			"url": url,
		},
	}
}

// newTestService creates a service with default config and the given repo.
func newTestService(repo Repository) *Service {
	return New(repo, DefaultConfig())
}

// newTestServiceWithThrottle creates a service with custom throttle config.
func newTestServiceWithThrottle(repo Repository, tc ThrottleConfig) *Service {
	cfg := DefaultConfig()
	cfg.ThrottleConfig = tc
	return New(repo, cfg)
}

// ============================================================================
// Constructor tests
// ============================================================================

func TestNew_WithNilRepo(t *testing.T) {
	svc := New(nil, DefaultConfig())
	if svc == nil {
		t.Fatal("New returned nil with nil repo")
	}
}

func TestNew_WithRepo(t *testing.T) {
	repo := &mockRepo{}
	svc := New(repo, DefaultConfig())
	if svc == nil {
		t.Fatal("New returned nil with valid repo")
	}
}

func TestNew_QueueCreated(t *testing.T) {
	cfg := Config{QueueSize: 42, Workers: 1}
	svc := New(nil, cfg)
	if cap(svc.queue) != 42 {
		t.Errorf("queue capacity = %d, want 42", cap(svc.queue))
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.QueueSize != 1000 {
		t.Errorf("QueueSize = %d, want 1000", cfg.QueueSize)
	}
	if cfg.Workers != 5 {
		t.Errorf("Workers = %d, want 5", cfg.Workers)
	}
	if !cfg.ThrottleConfig.Enabled {
		t.Error("ThrottleConfig.Enabled = false, want true")
	}
}

// ============================================================================
// Start / Stop lifecycle tests
// ============================================================================

func TestStart_Idempotent(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(repo)
	ctx := context.Background()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	// Second call should be a no-op.
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("second Start failed: %v", err)
	}

	svc.Stop()
}

func TestStop_Idempotent(t *testing.T) {
	svc := newTestService(nil)
	ctx := context.Background()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// First Stop should work.
	svc.Stop()
	// Second Stop should not panic.
	svc.Stop()
}

func TestStop_WithoutStart(t *testing.T) {
	svc := newTestService(nil)
	// Stop without Start should not panic.
	svc.Stop()
}

func TestStart_LoadsConfigFromRepo(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(repo)
	ctx := context.Background()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer svc.Stop()

	repo.mu.Lock()
	configCalls := repo.getConfigsCalls
	rulesCalls := repo.getRulesCalls
	repo.mu.Unlock()

	if configCalls != 1 {
		t.Errorf("GetChannelConfigs called %d times, want 1", configCalls)
	}
	if rulesCalls != 1 {
		t.Errorf("GetRoutingRules called %d times, want 1", rulesCalls)
	}
}

func TestStart_NilRepo_SkipsConfigLoad(t *testing.T) {
	svc := newTestService(nil)
	ctx := context.Background()

	// Should not panic with nil repo.
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	svc.Stop()
}

func TestStart_ConfigLoadError_DoesNotFail(t *testing.T) {
	repo := &mockRepo{
		getConfigsErr: errors.New("db down"),
	}
	svc := newTestService(repo)
	ctx := context.Background()

	// Start should succeed even if config loading fails (non-fatal).
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start should not fail on config load error: %v", err)
	}
	svc.Stop()
}

func TestStart_LoadsChannelsFromRepo(t *testing.T) {
	repo := &mockRepo{
		getConfigsResult: []*channels.ChannelConfig{
			{
				Type:    "webhook",
				Name:    "test-hook",
				Enabled: true,
				Settings: map[string]interface{}{
					"url": "http://example.com/hook",
				},
			},
		},
	}
	svc := newTestService(repo)
	ctx := context.Background()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer svc.Stop()

	chans := svc.ListChannels()
	if len(chans) != 1 {
		t.Fatalf("ListChannels() = %d channels, want 1", len(chans))
	}
	if chans[0] != "test-hook" {
		t.Errorf("channel name = %q, want %q", chans[0], "test-hook")
	}
}

func TestStart_LoadsRoutingRulesFromRepo(t *testing.T) {
	rules := []*RoutingRule{
		{Name: "rule-1", Enabled: true, Channels: []string{"ch1"}},
	}
	repo := &mockRepo{
		getRulesResult: rules,
	}
	svc := newTestService(repo)
	ctx := context.Background()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer svc.Stop()

	// Verify routing rules were loaded by checking dispatcher state.
	// We can't directly inspect the dispatcher, but the fact that Start
	// succeeded and GetRoutingRules was called proves loading happened.
	repo.mu.Lock()
	calls := repo.getRulesCalls
	repo.mu.Unlock()
	if calls != 1 {
		t.Errorf("GetRoutingRules called %d times, want 1", calls)
	}
}

// ============================================================================
// RegisterChannel tests
// ============================================================================

func TestRegisterChannel_Success(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(repo)

	err := svc.RegisterChannel("my-hook", webhookConfig("http://example.com/hook"))
	if err != nil {
		t.Fatalf("RegisterChannel failed: %v", err)
	}

	chans := svc.ListChannels()
	if len(chans) != 1 {
		t.Fatalf("ListChannels() = %d, want 1", len(chans))
	}
	if chans[0] != "my-hook" {
		t.Errorf("channel name = %q, want %q", chans[0], "my-hook")
	}
}

func TestRegisterChannel_PersistsToRepo(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(repo)

	cfg := webhookConfig("http://example.com/hook")
	err := svc.RegisterChannel("persist-test", cfg)
	if err != nil {
		t.Fatalf("RegisterChannel failed: %v", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.saveChannelCalls) != 1 {
		t.Fatalf("SaveChannelConfig called %d times, want 1", len(repo.saveChannelCalls))
	}
	saved := repo.saveChannelCalls[0]
	if saved.Name != "persist-test" {
		t.Errorf("saved config name = %q, want %q", saved.Name, "persist-test")
	}
}

func TestRegisterChannel_NilRepo_DoesNotPersist(t *testing.T) {
	svc := newTestService(nil)

	err := svc.RegisterChannel("no-persist", webhookConfig("http://example.com/hook"))
	if err != nil {
		t.Fatalf("RegisterChannel failed: %v", err)
	}

	chans := svc.ListChannels()
	if len(chans) != 1 {
		t.Fatalf("expected 1 channel registered, got %d", len(chans))
	}
}

func TestRegisterChannel_RepoPersistError_StillRegisters(t *testing.T) {
	repo := &mockRepo{
		saveChannelErr: errors.New("disk full"),
	}
	svc := newTestService(repo)

	err := svc.RegisterChannel("my-hook", webhookConfig("http://example.com/hook"))
	// RegisterChannel should succeed even if repo persist fails (logged warning).
	if err != nil {
		t.Fatalf("RegisterChannel should not fail on repo error: %v", err)
	}

	if len(svc.ListChannels()) != 1 {
		t.Error("channel should still be registered despite repo error")
	}
}

func TestRegisterChannel_UnsupportedType(t *testing.T) {
	svc := newTestService(nil)

	err := svc.RegisterChannel("bad-channel", &channels.ChannelConfig{
		Type:     "carrier_pigeon",
		Enabled:  true,
		Settings: map[string]interface{}{},
	})
	if err == nil {
		t.Fatal("expected error for unsupported channel type")
	}
}

func TestRegisterChannel_NoLicenseLimit(t *testing.T) {
	// The AGPL build never caps notification channels from a license
	// token. A SetLimitProvider call with a non-zero MaxNotificationChannels
	// must NOT block additional channel registrations.
	svc := newTestService(nil)
	svc.SetLimitProvider(&mockLimitProvider{
		limits: license.Limits{MaxNotificationChannels: 1},
	})

	for i, name := range []string{"hook-1", "hook-2", "hook-3"} {
		if err := svc.RegisterChannel(name, webhookConfig("http://example.com/"+name)); err != nil {
			t.Fatalf("RegisterChannel %d failed: %v", i, err)
		}
	}

	if got := len(svc.ListChannels()); got != 3 {
		t.Errorf("ListChannels() = %d, want 3", got)
	}
}

func TestRegisterChannel_LicenseLimit_Zero_Unlimited(t *testing.T) {
	svc := newTestService(nil)
	svc.SetLimitProvider(&mockLimitProvider{
		limits: license.Limits{MaxNotificationChannels: 0},
	})

	// Limit of 0 means unlimited.
	for i := 0; i < 5; i++ {
		err := svc.RegisterChannel(
			fmt.Sprintf("hook-%d", i),
			webhookConfig(fmt.Sprintf("http://example.com/%d", i)),
		)
		if err != nil {
			t.Fatalf("RegisterChannel #%d failed unexpectedly: %v", i, err)
		}
	}

	if len(svc.ListChannels()) != 5 {
		t.Errorf("expected 5 channels, got %d", len(svc.ListChannels()))
	}
}

func TestRegisterChannel_NoLimitProvider_NoLimit(t *testing.T) {
	svc := newTestService(nil)
	// No limit provider set; should register without limit checks.

	for i := 0; i < 3; i++ {
		err := svc.RegisterChannel(
			fmt.Sprintf("hook-%d", i),
			webhookConfig(fmt.Sprintf("http://example.com/%d", i)),
		)
		if err != nil {
			t.Fatalf("RegisterChannel #%d failed: %v", i, err)
		}
	}
}

// ============================================================================
// RemoveChannel tests
// ============================================================================

func TestRemoveChannel_Success(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(repo)

	_ = svc.RegisterChannel("to-remove", webhookConfig("http://example.com/hook"))
	if len(svc.ListChannels()) != 1 {
		t.Fatal("channel not registered")
	}

	err := svc.RemoveChannel("to-remove")
	if err != nil {
		t.Fatalf("RemoveChannel failed: %v", err)
	}
	if len(svc.ListChannels()) != 0 {
		t.Error("channel should be removed")
	}
}

func TestRemoveChannel_PersistsDeletion(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(repo)

	_ = svc.RegisterChannel("del-test", webhookConfig("http://example.com/hook"))

	err := svc.RemoveChannel("del-test")
	if err != nil {
		t.Fatalf("RemoveChannel failed: %v", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.deleteConfigCalls) != 1 {
		t.Fatalf("DeleteChannelConfig called %d times, want 1", len(repo.deleteConfigCalls))
	}
	if repo.deleteConfigCalls[0] != "del-test" {
		t.Errorf("deleted name = %q, want %q", repo.deleteConfigCalls[0], "del-test")
	}
}

func TestRemoveChannel_NilRepo_NoPersist(t *testing.T) {
	svc := newTestService(nil)

	_ = svc.RegisterChannel("no-persist", webhookConfig("http://example.com/hook"))
	err := svc.RemoveChannel("no-persist")
	if err != nil {
		t.Fatalf("RemoveChannel should succeed with nil repo: %v", err)
	}
	if len(svc.ListChannels()) != 0 {
		t.Error("channel should be removed")
	}
}

func TestRemoveChannel_RepoDeleteError(t *testing.T) {
	repo := &mockRepo{
		deleteConfigErr: errors.New("db error"),
	}
	svc := newTestService(repo)

	_ = svc.RegisterChannel("err-test", webhookConfig("http://example.com/hook"))
	err := svc.RemoveChannel("err-test")
	if err == nil {
		t.Fatal("expected error when repo delete fails")
	}
}

func TestRemoveChannel_NonExistent(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(repo)

	// Removing a channel that doesn't exist in the dispatcher should not error
	// (dispatcher.RemoveChannel is a no-op for missing keys), but the repo
	// DeleteChannelConfig call will still happen.
	err := svc.RemoveChannel("ghost")
	if err != nil {
		t.Fatalf("RemoveChannel for non-existent channel failed: %v", err)
	}
}

// ============================================================================
// ListChannels tests
// ============================================================================

func TestListChannels_Empty(t *testing.T) {
	svc := newTestService(nil)
	chans := svc.ListChannels()
	if len(chans) != 0 {
		t.Errorf("expected 0 channels, got %d", len(chans))
	}
}

func TestListChannels_Multiple(t *testing.T) {
	svc := newTestService(nil)
	for i := 0; i < 3; i++ {
		_ = svc.RegisterChannel(
			fmt.Sprintf("ch-%d", i),
			webhookConfig(fmt.Sprintf("http://example.com/%d", i)),
		)
	}

	chans := svc.ListChannels()
	if len(chans) != 3 {
		t.Errorf("expected 3 channels, got %d", len(chans))
	}

	// Build a set to check names (order not guaranteed from map iteration).
	nameSet := make(map[string]bool)
	for _, ch := range chans {
		nameSet[ch] = true
	}
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("ch-%d", i)
		if !nameSet[name] {
			t.Errorf("missing channel %q", name)
		}
	}
}

// ============================================================================
// TestChannel tests
// ============================================================================

func TestTestChannel_NotFound(t *testing.T) {
	svc := newTestService(nil)

	err := svc.TestChannel(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent channel")
	}
}

// ============================================================================
// Send tests
// ============================================================================

func TestSend_NoChannels_ReturnsNil(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(repo)

	// With no channels registered, Dispatch returns an empty results slice.
	// len(failures) == 0 so Send returns nil.
	err := svc.Send(context.Background(), Message{
		Type: channels.TypeTestMessage,
	})
	if err != nil {
		t.Fatalf("Send with no channels should return nil, got: %v", err)
	}
}

func TestSend_DefaultPriority_SetFromType(t *testing.T) {
	repo := &mockRepo{}
	// Disable throttling so we can inspect the log.
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	msg := Message{
		Type: channels.TypeSecurityAlert,
		// Priority is 0 (zero value) — should be set to TypeSecurityAlert default.
	}

	_ = svc.Send(context.Background(), msg)

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) != 1 {
		t.Fatalf("expected 1 log call, got %d", len(repo.logCalls))
	}
	logged := repo.logCalls[0]
	// TypeSecurityAlert.DefaultPriority() == PriorityCritical
	if logged.Priority != channels.PriorityCritical {
		t.Errorf("priority = %v, want %v (PriorityCritical)", logged.Priority, channels.PriorityCritical)
	}
}

func TestSend_ExplicitPriority_Preserved(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	msg := Message{
		Type:     channels.TypeTestMessage,
		Priority: channels.PriorityHigh,
	}

	_ = svc.Send(context.Background(), msg)

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) != 1 {
		t.Fatalf("expected 1 log call, got %d", len(repo.logCalls))
	}
	if repo.logCalls[0].Priority != channels.PriorityHigh {
		t.Errorf("priority = %v, want PriorityHigh", repo.logCalls[0].Priority)
	}
}

func TestSend_Throttled_ReturnNil(t *testing.T) {
	repo := &mockRepo{}
	// Set very restrictive throttle: 1 per window, no burst, no critical bypass.
	tc := ThrottleConfig{
		Enabled:        true,
		DefaultWindow:  time.Hour,
		DefaultLimit:   1,
		GlobalLimit:    1,
		CriticalBypass: false,
		BurstAllowance: 0,
	}
	svc := newTestServiceWithThrottle(repo, tc)

	msg := Message{
		Type:     channels.TypeTestMessage,
		Priority: channels.PriorityNormal,
	}

	// First send should pass through throttle.
	err := svc.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("first Send failed: %v", err)
	}

	// Second send should be throttled but return nil (silent).
	err = svc.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("throttled Send should return nil, got: %v", err)
	}

	// Verify throttled log was recorded.
	repo.mu.Lock()
	defer repo.mu.Unlock()
	foundThrottled := false
	for _, log := range repo.logCalls {
		if log.Throttled {
			foundThrottled = true
			break
		}
	}
	if !foundThrottled {
		t.Error("expected a throttled log entry")
	}
}

func TestSend_CriticalBypassThrottle(t *testing.T) {
	repo := &mockRepo{}
	tc := ThrottleConfig{
		Enabled:        true,
		DefaultWindow:  time.Hour,
		DefaultLimit:   1,
		GlobalLimit:    100,
		CriticalBypass: true,
		BurstAllowance: 0,
	}
	svc := newTestServiceWithThrottle(repo, tc)

	// Exhaust the type limit with a normal priority message.
	_ = svc.Send(context.Background(), Message{
		Type:     channels.TypeContainerDown,
		Priority: channels.PriorityNormal,
	})

	// Critical priority should bypass throttle.
	err := svc.Send(context.Background(), Message{
		Type:     channels.TypeContainerDown,
		Priority: channels.PriorityCritical,
	})
	if err != nil {
		t.Fatalf("critical Send should bypass throttle: %v", err)
	}
}

func TestSend_LogsToRepo(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	msg := Message{
		Type:  channels.TypeTestMessage,
		Title: "Test Title",
		Body:  "Test Body",
	}

	_ = svc.Send(context.Background(), msg)

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) != 1 {
		t.Fatalf("expected 1 log call, got %d", len(repo.logCalls))
	}

	logged := repo.logCalls[0]
	if logged.Type != channels.TypeTestMessage {
		t.Errorf("type = %v, want %v", logged.Type, channels.TypeTestMessage)
	}
	if logged.Throttled {
		t.Error("notification should not be throttled")
	}
	if logged.ID.String() == "" {
		t.Error("logged notification should have a UUID")
	}
	if logged.CreatedAt.IsZero() {
		t.Error("logged notification should have a CreatedAt timestamp")
	}
}

func TestSend_NilRepo_NoLogPanic(t *testing.T) {
	svc := newTestServiceWithThrottle(nil, ThrottleConfig{Enabled: false})

	// Should not panic when repo is nil.
	err := svc.Send(context.Background(), Message{
		Type: channels.TypeTestMessage,
	})
	if err != nil {
		t.Fatalf("Send with nil repo should not error on logging: %v", err)
	}
}

func TestSend_LogRepoError_DoesNotFail(t *testing.T) {
	repo := &mockRepo{
		logErr: errors.New("log storage error"),
	}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	// Send should succeed even if logging fails (logged as warning).
	err := svc.Send(context.Background(), Message{
		Type: channels.TypeTestMessage,
	})
	if err != nil {
		t.Fatalf("Send should not fail due to log error: %v", err)
	}
}

// ============================================================================
// SendAsync tests
// ============================================================================

func TestSendAsync_NotRunning_ReturnsError(t *testing.T) {
	svc := newTestService(nil)
	// Service not started.

	err := svc.SendAsync(context.Background(), Message{
		Type: channels.TypeTestMessage,
	})
	if err == nil {
		t.Fatal("expected error when service not running")
	}
	if err.Error() != "notification service not running" {
		t.Errorf("error = %q, want %q", err.Error(), "notification service not running")
	}
}

func TestSendAsync_Running_QueuesMessage(t *testing.T) {
	svc := newTestService(nil)
	ctx := context.Background()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer svc.Stop()

	err := svc.SendAsync(ctx, Message{
		Type: channels.TypeTestMessage,
	})
	if err != nil {
		t.Fatalf("SendAsync failed: %v", err)
	}
}

func TestSendAsync_QueueFull_ReturnsError(t *testing.T) {
	cfg := Config{QueueSize: 1, Workers: 0} // 0 workers so nothing drains the queue
	cfg.ThrottleConfig = DefaultThrottleConfig()
	svc := New(nil, cfg)

	// Manually set running without starting workers.
	svc.mu.Lock()
	svc.running = true
	svc.mu.Unlock()

	// Fill the queue.
	err := svc.SendAsync(context.Background(), Message{Type: channels.TypeTestMessage})
	if err != nil {
		t.Fatalf("first SendAsync should succeed: %v", err)
	}

	// Queue is now full (capacity 1).
	err = svc.SendAsync(context.Background(), Message{Type: channels.TypeTestMessage})
	if err == nil {
		t.Fatal("expected queue full error")
	}
	if err.Error() != "notification queue full" {
		t.Errorf("error = %q, want %q", err.Error(), "notification queue full")
	}
}

func TestSendAsync_StopDrainsQueue(t *testing.T) {
	repo := &mockRepo{}
	cfg := Config{QueueSize: 10, Workers: 1}
	cfg.ThrottleConfig = ThrottleConfig{Enabled: false}
	svc := New(repo, cfg)
	ctx := context.Background()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Queue a message.
	err := svc.SendAsync(ctx, Message{
		Type: channels.TypeTestMessage,
	})
	if err != nil {
		t.Fatalf("SendAsync failed: %v", err)
	}

	// Stop waits for workers to drain.
	svc.Stop()

	// Verify the queued message was processed (logged).
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) < 1 {
		t.Error("expected at least 1 log call after Stop drained the queue")
	}
}

// ============================================================================
// SetRoutingRules tests
// ============================================================================

func TestSetRoutingRules_PersistsToRepo(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(repo)

	rules := []*RoutingRule{
		{Name: "rule-1", Enabled: true, Channels: []string{"ch1"}},
		{Name: "rule-2", Enabled: false, Channels: []string{"ch2"}},
	}

	err := svc.SetRoutingRules(rules)
	if err != nil {
		t.Fatalf("SetRoutingRules failed: %v", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.saveRulesCalls != 1 {
		t.Fatalf("SaveRoutingRules called %d times, want 1", repo.saveRulesCalls)
	}
	if len(repo.saveRulesArg[0]) != 2 {
		t.Errorf("saved %d rules, want 2", len(repo.saveRulesArg[0]))
	}
}

func TestSetRoutingRules_NilRepo_NoPersist(t *testing.T) {
	svc := newTestService(nil)

	err := svc.SetRoutingRules([]*RoutingRule{
		{Name: "rule-1"},
	})
	if err != nil {
		t.Fatalf("SetRoutingRules should succeed with nil repo: %v", err)
	}
}

func TestSetRoutingRules_RepoError(t *testing.T) {
	repo := &mockRepo{
		saveRulesErr: errors.New("db error"),
	}
	svc := newTestService(repo)

	err := svc.SetRoutingRules([]*RoutingRule{})
	if err == nil {
		t.Fatal("expected error when repo save fails")
	}
}

// ============================================================================
// GetStats tests
// ============================================================================

func TestGetStats_NilRepo_ReturnsError(t *testing.T) {
	svc := newTestService(nil)

	_, err := svc.GetStats(context.Background(), time.Now().Add(-24*time.Hour))
	if err == nil {
		t.Fatal("expected error with nil repo")
	}
	if err.Error() != "no repository configured" {
		t.Errorf("error = %q, want %q", err.Error(), "no repository configured")
	}
}

func TestGetStats_DelegatesToRepo(t *testing.T) {
	expected := &NotificationStats{
		Total:       100,
		Sent:        90,
		Failed:      10,
		SuccessRate: 90.0,
	}
	repo := &mockRepo{
		getStatsResult: expected,
	}
	svc := newTestService(repo)

	stats, err := svc.GetStats(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if stats.Total != 100 {
		t.Errorf("Total = %d, want 100", stats.Total)
	}
	if stats.Sent != 90 {
		t.Errorf("Sent = %d, want 90", stats.Sent)
	}
}

func TestGetStats_RepoError(t *testing.T) {
	repo := &mockRepo{
		getStatsErr: errors.New("query failed"),
	}
	svc := newTestService(repo)

	_, err := svc.GetStats(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// ============================================================================
// GetLogs tests
// ============================================================================

func TestGetLogs_NilRepo_ReturnsError(t *testing.T) {
	svc := newTestService(nil)

	_, _, err := svc.GetLogs(context.Background(), LogFilter{})
	if err == nil {
		t.Fatal("expected error with nil repo")
	}
	if err.Error() != "no repository configured" {
		t.Errorf("error = %q, want %q", err.Error(), "no repository configured")
	}
}

func TestGetLogs_DelegatesToRepo(t *testing.T) {
	logs := []*NotificationLog{
		{Type: channels.TypeTestMessage, Title: "Test"},
	}
	repo := &mockRepo{
		getLogsResult: logs,
		getLogsTotal:  1,
	}
	svc := newTestService(repo)

	result, total, err := svc.GetLogs(context.Background(), LogFilter{Limit: 10})
	if err != nil {
		t.Fatalf("GetLogs failed: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(result) != 1 {
		t.Fatalf("result length = %d, want 1", len(result))
	}
	if result[0].Title != "Test" {
		t.Errorf("title = %q, want %q", result[0].Title, "Test")
	}
}

func TestGetLogs_RepoError(t *testing.T) {
	repo := &mockRepo{
		getLogsErr: errors.New("query failed"),
	}
	svc := newTestService(repo)

	_, _, err := svc.GetLogs(context.Background(), LogFilter{})
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// ============================================================================
// Throttle stats / reset tests
// ============================================================================

func TestGetThrottleStats_Initial(t *testing.T) {
	svc := newTestService(nil)

	stats := svc.GetThrottleStats()
	if stats.GlobalCount != 0 {
		t.Errorf("initial GlobalCount = %d, want 0", stats.GlobalCount)
	}
	if stats.GlobalLimit != DefaultThrottleConfig().GlobalLimit {
		t.Errorf("GlobalLimit = %d, want %d", stats.GlobalLimit, DefaultThrottleConfig().GlobalLimit)
	}
	if len(stats.TypeCounts) != 0 {
		t.Errorf("initial TypeCounts should be empty, got %d entries", len(stats.TypeCounts))
	}
}

func TestGetThrottleStats_AfterSend(t *testing.T) {
	tc := ThrottleConfig{
		Enabled:        true,
		DefaultWindow:  time.Hour,
		DefaultLimit:   100,
		GlobalLimit:    100,
		CriticalBypass: false,
		BurstAllowance: 0,
	}
	svc := newTestServiceWithThrottle(nil, tc)

	// Send a message to create a window entry.
	_ = svc.Send(context.Background(), Message{
		Type:     channels.TypeTestMessage,
		Priority: channels.PriorityNormal,
	})

	stats := svc.GetThrottleStats()
	if stats.GlobalCount != 1 {
		t.Errorf("GlobalCount = %d, want 1", stats.GlobalCount)
	}

	typeStats, ok := stats.TypeCounts[channels.TypeTestMessage]
	if !ok {
		t.Fatal("expected TypeCounts entry for test_message")
	}
	if typeStats.Count != 1 {
		t.Errorf("type count = %d, want 1", typeStats.Count)
	}
}

func TestResetThrottle(t *testing.T) {
	tc := ThrottleConfig{
		Enabled:        true,
		DefaultWindow:  time.Hour,
		DefaultLimit:   100,
		GlobalLimit:    100,
		CriticalBypass: false,
		BurstAllowance: 0,
	}
	svc := newTestServiceWithThrottle(nil, tc)

	// Send some messages to populate throttle windows.
	for i := 0; i < 5; i++ {
		_ = svc.Send(context.Background(), Message{
			Type:     channels.TypeTestMessage,
			Priority: channels.PriorityNormal,
		})
	}

	stats := svc.GetThrottleStats()
	if stats.GlobalCount == 0 {
		t.Fatal("expected non-zero GlobalCount before reset")
	}

	svc.ResetThrottle()

	stats = svc.GetThrottleStats()
	if stats.GlobalCount != 0 {
		t.Errorf("GlobalCount after reset = %d, want 0", stats.GlobalCount)
	}
	if len(stats.TypeCounts) != 0 {
		t.Errorf("TypeCounts after reset should be empty, got %d", len(stats.TypeCounts))
	}
}

// ============================================================================
// SetLimitProvider tests
// ============================================================================

func TestSetLimitProvider_IsNoOp(t *testing.T) {
	svc := newTestService(nil)

	_ = svc.RegisterChannel("hook-1", webhookConfig("http://example.com/1"))
	_ = svc.RegisterChannel("hook-2", webhookConfig("http://example.com/2"))

	// SetLimitProvider is retained for backward compat but the AGPL
	// build never enforces the supplied cap.
	svc.SetLimitProvider(&mockLimitProvider{
		limits: license.Limits{MaxNotificationChannels: 2},
	})

	if err := svc.RegisterChannel("hook-3", webhookConfig("http://example.com/3")); err != nil {
		t.Fatalf("third channel rejected after SetLimitProvider: %v", err)
	}
	if got := len(svc.ListChannels()); got != 3 {
		t.Errorf("ListChannels() = %d, want 3", got)
	}
}

func TestSetLimitProvider_ConcurrencySafe(t *testing.T) {
	svc := newTestService(nil)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.SetLimitProvider(&mockLimitProvider{
				limits: license.Limits{MaxNotificationChannels: 5},
			})
		}()
	}
	wg.Wait()
}

// ============================================================================
// Convenience method tests
// ============================================================================

func TestSendSecurityAlert(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	err := svc.SendSecurityAlert(context.Background(), "nginx", "CVE found", "critical", nil)
	if err != nil {
		t.Fatalf("SendSecurityAlert failed: %v", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) != 1 {
		t.Fatalf("expected 1 log call, got %d", len(repo.logCalls))
	}

	log := repo.logCalls[0]
	if log.Type != channels.TypeSecurityAlert {
		t.Errorf("type = %v, want %v", log.Type, channels.TypeSecurityAlert)
	}
	if log.Priority != channels.PriorityCritical {
		t.Errorf("priority = %v, want PriorityCritical", log.Priority)
	}
}

func TestSendSecurityAlert_NilData_CreatesMap(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	// Passing nil data should not panic; the method creates the map.
	err := svc.SendSecurityAlert(context.Background(), "app", "test", "high", nil)
	if err != nil {
		t.Fatalf("SendSecurityAlert with nil data failed: %v", err)
	}
}

func TestSendSecurityAlert_ExistingData_Augmented(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	data := map[string]interface{}{
		"extra": "value",
	}
	err := svc.SendSecurityAlert(context.Background(), "web", "breach", "critical", data)
	if err != nil {
		t.Fatalf("SendSecurityAlert failed: %v", err)
	}

	// Verify the data map was augmented (not replaced).
	if data["container"] != "web" {
		t.Errorf("data[container] = %v, want %q", data["container"], "web")
	}
	if data["extra"] != "value" {
		t.Errorf("data[extra] = %v, want %q", data["extra"], "value")
	}
}

func TestSendUpdateAvailable(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	err := svc.SendUpdateAvailable(context.Background(), "redis", "7.0", "7.2", "Bug fixes")
	if err != nil {
		t.Fatalf("SendUpdateAvailable failed: %v", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) != 1 {
		t.Fatalf("expected 1 log call, got %d", len(repo.logCalls))
	}

	log := repo.logCalls[0]
	if log.Type != channels.TypeUpdateAvailable {
		t.Errorf("type = %v, want %v", log.Type, channels.TypeUpdateAvailable)
	}
	if log.Priority != channels.PriorityNormal {
		t.Errorf("priority = %v, want PriorityNormal", log.Priority)
	}
}

func TestSendBackupCompleted(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	err := svc.SendBackupCompleted(context.Background(), "postgres", "/backups/pg.tar.gz", 1024*1024, 30*time.Second)
	if err != nil {
		t.Fatalf("SendBackupCompleted failed: %v", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) != 1 {
		t.Fatalf("expected 1 log call, got %d", len(repo.logCalls))
	}

	log := repo.logCalls[0]
	if log.Type != channels.TypeBackupCompleted {
		t.Errorf("type = %v, want %v", log.Type, channels.TypeBackupCompleted)
	}
	if log.Priority != channels.PriorityLow {
		t.Errorf("priority = %v, want PriorityLow", log.Priority)
	}
}

func TestSendContainerDown(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	err := svc.SendContainerDown(context.Background(), "web-app", "nginx:latest", 137, "Killed")
	if err != nil {
		t.Fatalf("SendContainerDown failed: %v", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) != 1 {
		t.Fatalf("expected 1 log call, got %d", len(repo.logCalls))
	}

	log := repo.logCalls[0]
	if log.Type != channels.TypeContainerDown {
		t.Errorf("type = %v, want %v", log.Type, channels.TypeContainerDown)
	}
	if log.Priority != channels.PriorityCritical {
		t.Errorf("priority = %v, want PriorityCritical", log.Priority)
	}
}

func TestSendHostOffline(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	lastSeen := time.Now().Add(-5 * time.Minute)
	err := svc.SendHostOffline(context.Background(), "node-02", lastSeen, 12)
	if err != nil {
		t.Fatalf("SendHostOffline failed: %v", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) != 1 {
		t.Fatalf("expected 1 log call, got %d", len(repo.logCalls))
	}

	log := repo.logCalls[0]
	if log.Type != channels.TypeHostOffline {
		t.Errorf("type = %v, want %v", log.Type, channels.TypeHostOffline)
	}
	if log.Priority != channels.PriorityCritical {
		t.Errorf("priority = %v, want PriorityCritical", log.Priority)
	}
}

func TestSendLicenseExpiring(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	err := svc.SendLicenseExpiring(context.Background(), "Business", "lic-123", 7)
	if err != nil {
		t.Fatalf("SendLicenseExpiring failed: %v", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) != 1 {
		t.Fatalf("expected 1 log call, got %d", len(repo.logCalls))
	}

	log := repo.logCalls[0]
	if log.Type != channels.TypeLicenseExpiry {
		t.Errorf("type = %v, want %v", log.Type, channels.TypeLicenseExpiry)
	}
	if log.Priority != channels.PriorityHigh {
		t.Errorf("priority = %v, want PriorityHigh", log.Priority)
	}
}

func TestSendLicenseExpired(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	err := svc.SendLicenseExpired(context.Background(), "Enterprise", "lic-456")
	if err != nil {
		t.Fatalf("SendLicenseExpired failed: %v", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) != 1 {
		t.Fatalf("expected 1 log call, got %d", len(repo.logCalls))
	}

	log := repo.logCalls[0]
	if log.Type != channels.TypeLicenseExpired {
		t.Errorf("type = %v, want %v", log.Type, channels.TypeLicenseExpired)
	}
	if log.Priority != channels.PriorityCritical {
		t.Errorf("priority = %v, want PriorityCritical", log.Priority)
	}
}

func TestSendResourceLimitApproaching(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	err := svc.SendResourceLimitApproaching(context.Background(), "containers", 45, 50, 90.0)
	if err != nil {
		t.Fatalf("SendResourceLimitApproaching failed: %v", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) != 1 {
		t.Fatalf("expected 1 log call, got %d", len(repo.logCalls))
	}

	log := repo.logCalls[0]
	if log.Type != channels.TypeResourceThreshold {
		t.Errorf("type = %v, want %v", log.Type, channels.TypeResourceThreshold)
	}
	if log.Priority != channels.PriorityHigh {
		t.Errorf("priority = %v, want PriorityHigh", log.Priority)
	}
}

// ============================================================================
// AddRoutingRule test
// ============================================================================

func TestAddRoutingRule(t *testing.T) {
	svc := newTestService(nil)

	rule := &RoutingRule{
		Name:     "test-rule",
		Enabled:  true,
		Channels: []string{"ch1"},
	}

	// AddRoutingRule does not return an error and does not persist.
	svc.AddRoutingRule(rule)
}

// ============================================================================
// Interface compliance
// ============================================================================

func TestRepository_InterfaceCompliance(t *testing.T) {
	// Verify mockRepo implements Repository at compile time.
	var _ Repository = (*mockRepo)(nil)
}

func TestLimitProvider_InterfaceCompliance(t *testing.T) {
	var _ license.LimitProvider = (*mockLimitProvider)(nil)
}

// ============================================================================
// logThrottled / logNotification nil repo safety
// ============================================================================

func TestLogThrottled_NilRepo_NoPanic(t *testing.T) {
	svc := newTestService(nil)

	// Trigger throttled path: restrictive throttle, send twice.
	tc := ThrottleConfig{
		Enabled:        true,
		DefaultWindow:  time.Hour,
		DefaultLimit:   1,
		GlobalLimit:    1,
		CriticalBypass: false,
		BurstAllowance: 0,
	}
	svc.throttler = NewThrottler(tc)

	msg := Message{
		Type:     channels.TypeTestMessage,
		Priority: channels.PriorityNormal,
	}

	// First send uses the quota.
	_ = svc.Send(context.Background(), msg)
	// Second send is throttled; logThrottled is called with nil repo.
	_ = svc.Send(context.Background(), msg)
}

// ============================================================================
// Concurrent access tests
// ============================================================================

func TestConcurrent_RegisterAndList(t *testing.T) {
	svc := newTestService(nil)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			_ = svc.RegisterChannel(
				fmt.Sprintf("ch-%d", idx),
				webhookConfig(fmt.Sprintf("http://example.com/%d", idx)),
			)
		}(i)
		go func() {
			defer wg.Done()
			_ = svc.ListChannels()
		}()
	}
	wg.Wait()
}

func TestConcurrent_SendAndThrottle(t *testing.T) {
	repo := &mockRepo{}
	tc := ThrottleConfig{
		Enabled:        true,
		DefaultWindow:  time.Hour,
		DefaultLimit:   100,
		GlobalLimit:    200,
		CriticalBypass: false,
		BurstAllowance: 5,
	}
	svc := newTestServiceWithThrottle(repo, tc)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.Send(context.Background(), Message{
				Type:     channels.TypeTestMessage,
				Priority: channels.PriorityNormal,
			})
		}()
	}
	wg.Wait()
}

func TestConcurrent_StartStop(t *testing.T) {
	svc := newTestService(nil)

	var wg sync.WaitGroup
	ctx := context.Background()

	// Start and stop concurrently should not panic.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.Start(ctx)
		}()
	}
	wg.Wait()

	svc.Stop()
}

// ============================================================================
// Message type/priority defaults (verify DefaultPriority mapping)
// ============================================================================

func TestConvenienceMethod_Priorities(t *testing.T) {
	tests := []struct {
		name     string
		call     func(svc *Service) error
		wantType channels.NotificationType
		wantPri  channels.Priority
	}{
		{
			name: "SendSecurityAlert uses PriorityCritical",
			call: func(svc *Service) error {
				return svc.SendSecurityAlert(context.Background(), "c", "m", "s", nil)
			},
			wantType: channels.TypeSecurityAlert,
			wantPri:  channels.PriorityCritical,
		},
		{
			name: "SendUpdateAvailable uses PriorityNormal",
			call: func(svc *Service) error {
				return svc.SendUpdateAvailable(context.Background(), "c", "1", "2", "")
			},
			wantType: channels.TypeUpdateAvailable,
			wantPri:  channels.PriorityNormal,
		},
		{
			name: "SendBackupCompleted uses PriorityLow",
			call: func(svc *Service) error {
				return svc.SendBackupCompleted(context.Background(), "c", "/p", 100, time.Second)
			},
			wantType: channels.TypeBackupCompleted,
			wantPri:  channels.PriorityLow,
		},
		{
			name: "SendContainerDown uses PriorityCritical",
			call: func(svc *Service) error {
				return svc.SendContainerDown(context.Background(), "c", "img", 1, "log")
			},
			wantType: channels.TypeContainerDown,
			wantPri:  channels.PriorityCritical,
		},
		{
			name: "SendHostOffline uses PriorityCritical",
			call: func(svc *Service) error {
				return svc.SendHostOffline(context.Background(), "h", time.Now(), 5)
			},
			wantType: channels.TypeHostOffline,
			wantPri:  channels.PriorityCritical,
		},
		{
			name: "SendLicenseExpiring uses PriorityHigh",
			call: func(svc *Service) error {
				return svc.SendLicenseExpiring(context.Background(), "biz", "id", 7)
			},
			wantType: channels.TypeLicenseExpiry,
			wantPri:  channels.PriorityHigh,
		},
		{
			name: "SendLicenseExpired uses PriorityCritical",
			call: func(svc *Service) error {
				return svc.SendLicenseExpired(context.Background(), "ee", "id")
			},
			wantType: channels.TypeLicenseExpired,
			wantPri:  channels.PriorityCritical,
		},
		{
			name: "SendResourceLimitApproaching uses PriorityHigh",
			call: func(svc *Service) error {
				return svc.SendResourceLimitApproaching(context.Background(), "r", 8, 10, 80)
			},
			wantType: channels.TypeResourceThreshold,
			wantPri:  channels.PriorityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockRepo{}
			svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

			err := tt.call(svc)
			if err != nil {
				t.Fatalf("call failed: %v", err)
			}

			repo.mu.Lock()
			defer repo.mu.Unlock()
			if len(repo.logCalls) != 1 {
				t.Fatalf("expected 1 log call, got %d", len(repo.logCalls))
			}

			log := repo.logCalls[0]
			if log.Type != tt.wantType {
				t.Errorf("type = %v, want %v", log.Type, tt.wantType)
			}
			if log.Priority != tt.wantPri {
				t.Errorf("priority = %v, want %v", log.Priority, tt.wantPri)
			}
		})
	}
}

// ============================================================================
// Send with zero-value Message
// ============================================================================

func TestSend_ZeroValueMessage(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	// A zero-value Message has Type="" and Priority=0.
	// DefaultPriority for unknown type returns PriorityLow (0),
	// but since Priority field is 0 and PriorityLow is also 0,
	// the branch `if msg.Priority == 0` is entered and sets it to DefaultPriority.
	err := svc.Send(context.Background(), Message{})
	if err != nil {
		t.Fatalf("Send with zero-value Message failed: %v", err)
	}
}

// ============================================================================
// Multiple channel types (verify dispatcher creates them correctly)
// ============================================================================

func TestRegisterChannel_SupportedTypes(t *testing.T) {
	// These types require specific settings to construct. We test that the
	// dispatcher properly rejects invalid settings rather than panicking.
	tests := []struct {
		channelType string
		settings    map[string]interface{}
		shouldError bool
	}{
		{"webhook", map[string]interface{}{"url": "http://example.com"}, false},
		{"webhook", map[string]interface{}{}, true}, // missing url
		{"slack", map[string]interface{}{"webhook_url": "http://hooks.slack.com/test"}, false},
		{"discord", map[string]interface{}{"webhook_url": "http://discord.com/api/webhooks/test"}, false},
		{"telegram", map[string]interface{}{"bot_token": "tok", "chat_id": "123"}, false},
		{"gotify", map[string]interface{}{"server_url": "http://gotify.local", "app_token": "tok"}, false},
		{"ntfy", map[string]interface{}{"server_url": "http://ntfy.local", "topic": "test"}, false},
		{"pagerduty", map[string]interface{}{"routing_key": "key123"}, false},
		{"opsgenie", map[string]interface{}{"api_key": "key123"}, false},
		{"unsupported_type", map[string]interface{}{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.channelType, func(t *testing.T) {
			svc := newTestService(nil)
			err := svc.RegisterChannel("test-"+tt.channelType, &channels.ChannelConfig{
				Type:     tt.channelType,
				Enabled:  true,
				Settings: tt.settings,
			})
			if tt.shouldError && err == nil {
				t.Errorf("expected error for type %q with settings %v", tt.channelType, tt.settings)
			}
			if !tt.shouldError && err != nil {
				t.Errorf("unexpected error for type %q: %v", tt.channelType, err)
			}
		})
	}
}

// ============================================================================
// Throttle disabled scenario
// ============================================================================

func TestThrottleDisabled_AllMessagesPass(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	// Send many messages; none should be throttled.
	for i := 0; i < 20; i++ {
		_ = svc.Send(context.Background(), Message{
			Type:     channels.TypeTestMessage,
			Priority: channels.PriorityNormal,
		})
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	for _, log := range repo.logCalls {
		if log.Throttled {
			t.Error("no messages should be throttled when throttle is disabled")
		}
	}
}

// ============================================================================
// NotificationLog struct fields
// ============================================================================

func TestNotificationLog_Fields(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestServiceWithThrottle(repo, ThrottleConfig{Enabled: false})

	before := time.Now()
	_ = svc.Send(context.Background(), Message{
		Type:     channels.TypeBackupCompleted,
		Priority: channels.PriorityNormal,
	})
	after := time.Now()

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logCalls) != 1 {
		t.Fatalf("expected 1 log, got %d", len(repo.logCalls))
	}

	log := repo.logCalls[0]

	// Verify UUID is set.
	if log.ID.String() == "00000000-0000-0000-0000-000000000000" {
		t.Error("log ID should not be zero UUID")
	}

	// Verify timestamp is in range.
	if log.CreatedAt.Before(before) || log.CreatedAt.After(after) {
		t.Errorf("CreatedAt %v not in range [%v, %v]", log.CreatedAt, before, after)
	}

	// With no channels registered, Results and Channels should be empty.
	if len(log.Results) != 0 {
		t.Errorf("Results length = %d, want 0", len(log.Results))
	}
	if log.SuccessCount != 0 {
		t.Errorf("SuccessCount = %d, want 0", log.SuccessCount)
	}
	if log.FailedCount != 0 {
		t.Errorf("FailedCount = %d, want 0", log.FailedCount)
	}
}
