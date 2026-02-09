// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package notification provides the notification service for USULNET.
// Department L: Notifications
package notification

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/services/notification/channels"
)

// Service is the main notification service that coordinates
// message rendering, throttling, and multi-channel delivery.
type Service struct {
	dispatcher    *Dispatcher
	throttler     *Throttler
	templates     *TemplateEngine
	repository    Repository
	limitProvider license.LimitProvider

	mu       sync.RWMutex
	running  bool
	queue    chan queuedMessage
	wg       sync.WaitGroup
}

// SetLimitProvider sets the license limit provider for resource cap enforcement.
func (s *Service) SetLimitProvider(lp license.LimitProvider) {
	s.limitProvider = lp
}

// Repository interface for notification persistence.
// Implementation should be in internal/repository/postgres/notification_log_repo.go
type Repository interface {
	// LogNotification stores a notification record.
	LogNotification(ctx context.Context, log *NotificationLog) error
	
	// GetNotificationLogs retrieves notification history.
	GetNotificationLogs(ctx context.Context, filter LogFilter) ([]*NotificationLog, error)
	
	// GetNotificationStats returns aggregated statistics.
	GetNotificationStats(ctx context.Context, since time.Time) (*NotificationStats, error)
	
	// SaveChannelConfig persists channel configuration.
	SaveChannelConfig(ctx context.Context, config *channels.ChannelConfig) error
	
	// GetChannelConfigs loads all channel configurations.
	GetChannelConfigs(ctx context.Context) ([]*channels.ChannelConfig, error)

	// GetChannelConfig loads a single channel configuration.
	GetChannelConfig(ctx context.Context, name string) (*channels.ChannelConfig, error)
	
	// DeleteChannelConfig removes a channel configuration.
	DeleteChannelConfig(ctx context.Context, name string) error
	
	// SaveRoutingRules persists routing rules.
	SaveRoutingRules(ctx context.Context, rules []*RoutingRule) error
	
	// GetRoutingRules loads routing rules.
	GetRoutingRules(ctx context.Context) ([]*RoutingRule, error)
}

// NotificationLog represents a stored notification record.
type NotificationLog struct {
	ID           uuid.UUID                 `json:"id"`
	Type         channels.NotificationType `json:"type"`
	Priority     channels.Priority         `json:"priority"`
	Title        string                    `json:"title"`
	Body         string                    `json:"body"`
	Channels     []string                  `json:"channels"`
	Results      []channels.DeliveryResult `json:"results"`
	Throttled    bool                      `json:"throttled"`
	SuccessCount int                       `json:"success_count"`
	FailedCount  int                       `json:"failed_count"`
	CreatedAt    time.Time                 `json:"created_at"`
}

// LogFilter for querying notification history.
type LogFilter struct {
	Types      []channels.NotificationType
	Priorities []channels.Priority
	Channels   []string
	Since      *time.Time
	Until      *time.Time
	Limit      int
	Offset     int
	OnlyFailed bool
}

// NotificationStats contains aggregated statistics.
type NotificationStats struct {
	Total       int64            `json:"total"`
	Sent        int64            `json:"sent"`
	Failed      int64            `json:"failed"`
	Throttled   int64            `json:"throttled"`
	ByType      map[string]int64 `json:"by_type"`
	ByChannel   map[string]int64 `json:"by_channel"`
	SuccessRate float64          `json:"success_rate"`
}

// RoutingRule defines when notifications go to specific channels.
type RoutingRule struct {
	ID                uuid.UUID                   `json:"id"`
	Name              string                      `json:"name"`
	Enabled           bool                        `json:"enabled"`
	NotificationTypes []channels.NotificationType `json:"notification_types"`
	MinPriority       channels.Priority           `json:"min_priority"`
	Categories        []string                    `json:"categories"`
	Channels          []string                    `json:"channels"`
	ExcludeChannels   []string                    `json:"exclude_channels"`
	TimeWindow        *TimeWindow                 `json:"time_window,omitempty"`
	Position          int                         `json:"position"`
}

// TimeWindow restricts when a rule is active.
type TimeWindow struct {
	Days      []time.Weekday `json:"days"`
	StartHour int            `json:"start_hour"`
	EndHour   int            `json:"end_hour"`
	Timezone  string         `json:"timezone"`
}

// Message represents a notification to be sent.
type Message struct {
	// Type categorizes the notification.
	Type channels.NotificationType

	// Title is the notification subject (optional, templates provide defaults).
	Title string

	// Body is the main content (optional, templates provide defaults).
	Body string

	// Priority indicates urgency (optional, defaults based on type).
	Priority channels.Priority

	// Data contains additional context for templates.
	Data map[string]interface{}

	// Channels specifies target channels (empty = use routing rules).
	Channels []string
}

// queuedMessage is an internal wrapper for async processing.
type queuedMessage struct {
	msg Message
	ctx context.Context
}

// Config holds service configuration.
type Config struct {
	// QueueSize is the async message queue capacity.
	QueueSize int

	// Workers is the number of concurrent message processors.
	Workers int

	// ThrottleConfig for rate limiting.
	ThrottleConfig ThrottleConfig
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		QueueSize:      1000,
		Workers:        5,
		ThrottleConfig: DefaultThrottleConfig(),
	}
}

// New creates a new notification service.
func New(repo Repository, config Config) *Service {
	return &Service{
		dispatcher: NewDispatcher(),
		throttler:  NewThrottler(config.ThrottleConfig),
		templates:  NewTemplateEngine(),
		repository: repo,
		queue:      make(chan queuedMessage, config.QueueSize),
	}
}

// Start initializes the notification service.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	// Load configuration from repository
	if s.repository != nil {
		if err := s.loadConfiguration(ctx); err != nil {
			// Log but don't fail - can work without persisted config
			fmt.Printf("warning: failed to load notification config: %v\n", err)
		}
	}

	// Start message processors
	config := DefaultConfig()
	for i := 0; i < config.Workers; i++ {
		s.wg.Add(1)
		go s.processQueue(ctx)
	}

	return nil
}

// Stop gracefully shuts down the notification service.
func (s *Service) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	s.mu.Unlock()

	close(s.queue)
	s.wg.Wait()
}

// Send sends a notification synchronously.
func (s *Service) Send(ctx context.Context, msg Message) error {
	// Set default priority if not specified
	if msg.Priority == 0 {
		msg.Priority = msg.Type.DefaultPriority()
	}

	// Check throttling
	if !s.throttler.Allow(msg.Type, msg.Priority) {
		s.logThrottled(ctx, msg)
		return nil // Silently throttled
	}

	// Render message
	rendered, err := s.templates.Render(msg)
	if err != nil {
		return fmt.Errorf("failed to render notification: %w", err)
	}

	// Dispatch to channels
	results := s.dispatcher.Dispatch(ctx, rendered, msg.Channels)

	// Log notification
	s.logNotification(ctx, msg, rendered, results, false)

	// Check for failures
	var failures []string
	for _, r := range results {
		if !r.Success {
			failures = append(failures, fmt.Sprintf("%s: %s", r.ChannelName, r.Error))
		}
	}

	if len(failures) > 0 && len(failures) == len(results) {
		return fmt.Errorf("all channels failed: %v", failures)
	}

	return nil
}

// SendAsync queues a notification for asynchronous delivery.
func (s *Service) SendAsync(ctx context.Context, msg Message) error {
	s.mu.RLock()
	if !s.running {
		s.mu.RUnlock()
		return fmt.Errorf("notification service not running")
	}
	s.mu.RUnlock()

	select {
	case s.queue <- queuedMessage{msg: msg, ctx: ctx}:
		return nil
	default:
		return fmt.Errorf("notification queue full")
	}
}

// processQueue handles async message delivery.
func (s *Service) processQueue(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case qm, ok := <-s.queue:
			if !ok {
				return
			}
			// Use a timeout context for processing
			processCtx, cancel := context.WithTimeout(qm.ctx, 30*time.Second)
			_ = s.Send(processCtx, qm.msg)
			cancel()
		}
	}
}

// RegisterChannel adds a notification channel.
func (s *Service) RegisterChannel(name string, config *channels.ChannelConfig) error {
	// Enforce license notification channel limit
	if s.limitProvider != nil {
		limit := s.limitProvider.GetLimits().MaxNotificationChannels
		if limit > 0 {
			current := len(s.ListChannels())
			if current >= limit {
				return fmt.Errorf("notification channel limit reached (%d/%d), upgrade your license for more", current, limit)
			}
		}
	}

	if err := s.dispatcher.RegisterChannel(name, config); err != nil {
		return err
	}

	// Persist configuration
	if s.repository != nil {
		config.Name = name
		if err := s.repository.SaveChannelConfig(context.Background(), config); err != nil {
			// Log but don't fail
			fmt.Printf("warning: failed to persist channel config: %v\n", err)
		}
	}

	return nil
}

// RemoveChannel removes a notification channel.
func (s *Service) RemoveChannel(name string) error {
	s.dispatcher.RemoveChannel(name)

	if s.repository != nil {
		return s.repository.DeleteChannelConfig(context.Background(), name)
	}

	return nil
}

// TestChannel sends a test notification to a specific channel.
func (s *Service) TestChannel(ctx context.Context, name string) error {
	return s.dispatcher.TestChannel(ctx, name)
}

// ListChannels returns all registered channels.
func (s *Service) ListChannels() []string {
	return s.dispatcher.ListChannels()
}

// SetRoutingRules configures notification routing.
func (s *Service) SetRoutingRules(rules []*RoutingRule) error {
	s.dispatcher.SetRoutingRules(rules)

	if s.repository != nil {
		return s.repository.SaveRoutingRules(context.Background(), rules)
	}

	return nil
}

// AddRoutingRule adds a single routing rule.
func (s *Service) AddRoutingRule(rule *RoutingRule) {
	s.dispatcher.AddRoutingRule(rule)
}

// GetThrottleStats returns current throttling statistics.
func (s *Service) GetThrottleStats() ThrottleStats {
	return s.throttler.Stats()
}

// ResetThrottle clears all throttle windows.
func (s *Service) ResetThrottle() {
	s.throttler.Reset()
}

// GetStats returns notification statistics.
func (s *Service) GetStats(ctx context.Context, since time.Time) (*NotificationStats, error) {
	if s.repository == nil {
		return nil, fmt.Errorf("no repository configured")
	}
	return s.repository.GetNotificationStats(ctx, since)
}

// GetLogs retrieves notification history.
func (s *Service) GetLogs(ctx context.Context, filter LogFilter) ([]*NotificationLog, error) {
	if s.repository == nil {
		return nil, fmt.Errorf("no repository configured")
	}
	return s.repository.GetNotificationLogs(ctx, filter)
}

// loadConfiguration loads channels and routing rules from repository.
func (s *Service) loadConfiguration(ctx context.Context) error {
	// Load channel configurations
	configs, err := s.repository.GetChannelConfigs(ctx)
	if err != nil {
		return fmt.Errorf("failed to load channel configs: %w", err)
	}

	for _, cfg := range configs {
		if err := s.dispatcher.RegisterChannel(cfg.Name, cfg); err != nil {
			fmt.Printf("warning: failed to register channel %s: %v\n", cfg.Name, err)
		}
	}

	// Load routing rules
	rules, err := s.repository.GetRoutingRules(ctx)
	if err != nil {
		return fmt.Errorf("failed to load routing rules: %w", err)
	}

	s.dispatcher.SetRoutingRules(rules)

	return nil
}

// logNotification persists a notification record.
func (s *Service) logNotification(ctx context.Context, msg Message, rendered channels.RenderedMessage, results []channels.DeliveryResult, throttled bool) {
	if s.repository == nil {
		return
	}

	channelNames := make([]string, len(results))
	var successCount, failedCount int
	for i, r := range results {
		channelNames[i] = r.ChannelName
		if r.Success {
			successCount++
		} else {
			failedCount++
		}
	}

	log := &NotificationLog{
		ID:           uuid.New(),
		Type:         msg.Type,
		Priority:     msg.Priority,
		Title:        rendered.Title,
		Body:         rendered.BodyPlain,
		Channels:     channelNames,
		Results:      results,
		Throttled:    throttled,
		SuccessCount: successCount,
		FailedCount:  failedCount,
		CreatedAt:    time.Now(),
	}

	if err := s.repository.LogNotification(ctx, log); err != nil {
		// Log but don't fail
		fmt.Printf("warning: failed to log notification: %v\n", err)
	}
}

// logThrottled logs a throttled notification.
func (s *Service) logThrottled(ctx context.Context, msg Message) {
	if s.repository == nil {
		return
	}

	log := &NotificationLog{
		ID:        uuid.New(),
		Type:      msg.Type,
		Priority:  msg.Priority,
		Title:     msg.Title,
		Body:      msg.Body,
		Throttled: true,
		CreatedAt: time.Now(),
	}

	if err := s.repository.LogNotification(ctx, log); err != nil {
		fmt.Printf("warning: failed to log throttled notification: %v\n", err)
	}
}

// Helper functions for common notifications

// SendSecurityAlert sends a security alert notification.
func (s *Service) SendSecurityAlert(ctx context.Context, container, message, severity string, data map[string]interface{}) error {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["container"] = container
	data["message"] = message
	data["severity"] = severity

	return s.Send(ctx, Message{
		Type:     channels.TypeSecurityAlert,
		Priority: channels.PriorityCritical,
		Data:     data,
	})
}

// SendUpdateAvailable sends an update available notification.
func (s *Service) SendUpdateAvailable(ctx context.Context, container, currentVersion, newVersion, changelog string) error {
	return s.Send(ctx, Message{
		Type:     channels.TypeUpdateAvailable,
		Priority: channels.PriorityNormal,
		Data: map[string]interface{}{
			"container":       container,
			"current_version": currentVersion,
			"new_version":     newVersion,
			"changelog":       changelog,
		},
	})
}

// SendBackupCompleted sends a backup completion notification.
func (s *Service) SendBackupCompleted(ctx context.Context, container, path string, sizeBytes int64, duration time.Duration) error {
	return s.Send(ctx, Message{
		Type:     channels.TypeBackupCompleted,
		Priority: channels.PriorityLow,
		Data: map[string]interface{}{
			"container": container,
			"path":      path,
			"size":      sizeBytes,
			"duration":  int64(duration.Seconds()),
		},
	})
}

// SendContainerDown sends a container down notification.
func (s *Service) SendContainerDown(ctx context.Context, container, image string, exitCode int, lastLog string) error {
	return s.Send(ctx, Message{
		Type:     channels.TypeContainerDown,
		Priority: channels.PriorityCritical,
		Data: map[string]interface{}{
			"container": container,
			"image":     image,
			"exit_code": exitCode,
			"last_log":  lastLog,
		},
	})
}

// SendHostOffline sends a host offline notification.
func (s *Service) SendHostOffline(ctx context.Context, host string, lastSeen time.Time, containerCount int) error {
	return s.Send(ctx, Message{
		Type:     channels.TypeHostOffline,
		Priority: channels.PriorityCritical,
		Data: map[string]interface{}{
			"host":       host,
			"last_seen":  lastSeen,
			"containers": containerCount,
		},
	})
}
