// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package monitoring provides monitoring and alerting services.
package monitoring

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// AlertRepository defines the interface for alert storage.
type AlertRepository interface {
	// Rules
	CreateRule(ctx context.Context, rule *models.AlertRule) error
	GetRule(ctx context.Context, id uuid.UUID) (*models.AlertRule, error)
	UpdateRule(ctx context.Context, rule *models.AlertRule) error
	DeleteRule(ctx context.Context, id uuid.UUID) error
	ListRules(ctx context.Context, opts models.AlertListOptions) ([]*models.AlertRule, int64, error)
	ListEnabledRules(ctx context.Context) ([]*models.AlertRule, error)

	// Events
	CreateEvent(ctx context.Context, event *models.AlertEvent) error
	GetEvent(ctx context.Context, id uuid.UUID) (*models.AlertEvent, error)
	UpdateEvent(ctx context.Context, event *models.AlertEvent) error
	ListEvents(ctx context.Context, opts models.AlertEventListOptions) ([]*models.AlertEvent, int64, error)
	GetActiveEvents(ctx context.Context) ([]*models.AlertEvent, error)

	// Silences
	CreateSilence(ctx context.Context, silence *models.AlertSilence) error
	GetSilence(ctx context.Context, id uuid.UUID) (*models.AlertSilence, error)
	DeleteSilence(ctx context.Context, id uuid.UUID) error
	ListSilences(ctx context.Context) ([]*models.AlertSilence, error)
	GetActiveSilences(ctx context.Context) ([]*models.AlertSilence, error)

	// Stats
	GetStats(ctx context.Context) (*models.AlertStats, error)
}

// MetricsProvider provides current metrics values.
type MetricsProvider interface {
	// GetHostMetric retrieves the current value for a host metric.
	GetHostMetric(ctx context.Context, hostID uuid.UUID, metric models.AlertMetric) (float64, error)

	// GetContainerMetric retrieves the current value for a container metric.
	GetContainerMetric(ctx context.Context, hostID uuid.UUID, containerID string, metric models.AlertMetric) (float64, error)

	// ListHosts returns all monitored hosts.
	ListHosts(ctx context.Context) ([]uuid.UUID, error)

	// ListContainers returns all containers for a host.
	ListContainers(ctx context.Context, hostID uuid.UUID) ([]string, error)
}

// NotificationSender sends notifications for alerts.
type NotificationSender interface {
	SendAlert(ctx context.Context, rule *models.AlertRule, event *models.AlertEvent) error
}

// AlertServiceConfig contains configuration for the alert service.
type AlertServiceConfig struct {
	// DefaultEvalInterval is the default interval between rule evaluations.
	DefaultEvalInterval time.Duration

	// MaxConcurrentEvaluations limits concurrent rule evaluations.
	MaxConcurrentEvaluations int

	// EnableAutoResolve automatically resolves alerts when condition clears.
	EnableAutoResolve bool
}

// DefaultAlertConfig returns default alert service configuration.
func DefaultAlertConfig() AlertServiceConfig {
	return AlertServiceConfig{
		DefaultEvalInterval:      30 * time.Second,
		MaxConcurrentEvaluations: 10,
		EnableAutoResolve:        true,
	}
}

// AlertService manages monitoring alerts.
type AlertService struct {
	repo         AlertRepository
	metrics      MetricsProvider
	notifier     NotificationSender
	config       AlertServiceConfig
	logger       *logger.Logger

	// State tracking
	ruleStates   map[uuid.UUID]*ruleState
	ruleStatesMu sync.RWMutex

	// Lifecycle
	stopCh  chan struct{}
	stopped atomic.Bool
	wg      sync.WaitGroup
}

// ruleState tracks the evaluation state of a rule.
type ruleState struct {
	pendingSince *time.Time // When condition first became true
	lastFired    time.Time  // Last time alert fired
	lastValue    float64    // Last evaluated value
}

// NewAlertService creates a new alert service.
func NewAlertService(
	repo AlertRepository,
	metrics MetricsProvider,
	notifier NotificationSender,
	config AlertServiceConfig,
	log *logger.Logger,
) *AlertService {
	if log == nil {
		log = logger.Nop()
	}

	return &AlertService{
		repo:       repo,
		metrics:    metrics,
		notifier:   notifier,
		config:     config,
		logger:     log.Named("alerts"),
		ruleStates: make(map[uuid.UUID]*ruleState),
		stopCh:     make(chan struct{}),
	}
}

// Start starts the alert evaluation loop.
func (s *AlertService) Start(ctx context.Context) error {
	s.logger.Info("starting alert service",
		"eval_interval", s.config.DefaultEvalInterval,
	)

	s.wg.Add(1)
	go s.evaluationLoop(ctx)

	return nil
}

// Stop stops the alert service.
func (s *AlertService) Stop() error {
	if !s.stopped.CompareAndSwap(false, true) {
		return nil
	}

	close(s.stopCh)

	// Wait for workers
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		s.logger.Warn("timeout waiting for alert workers to stop")
	}

	s.logger.Info("alert service stopped")
	return nil
}

// evaluationLoop runs the periodic alert evaluation.
func (s *AlertService) evaluationLoop(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.DefaultEvalInterval)
	defer ticker.Stop()

	// Run initial evaluation
	s.evaluateAllRules(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.evaluateAllRules(ctx)
		}
	}
}

// evaluateAllRules evaluates all enabled alert rules.
func (s *AlertService) evaluateAllRules(ctx context.Context) {
	rules, err := s.repo.ListEnabledRules(ctx)
	if err != nil {
		s.logger.Error("failed to list enabled rules", "error", err)
		return
	}

	// Get active silences
	silences, _ := s.repo.GetActiveSilences(ctx)

	// Evaluate rules concurrently with limit
	sem := make(chan struct{}, s.config.MaxConcurrentEvaluations)
	var wg sync.WaitGroup

	for _, rule := range rules {
		if s.isSilenced(rule, silences) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(r *models.AlertRule) {
			defer wg.Done()
			defer func() { <-sem }()

			s.evaluateRule(ctx, r)
		}(rule)
	}

	wg.Wait()
}

// evaluateRule evaluates a single alert rule.
func (s *AlertService) evaluateRule(ctx context.Context, rule *models.AlertRule) {
	log := s.logger.With(
		"rule_id", rule.ID,
		"rule_name", rule.Name,
		"metric", rule.Metric,
	)

	// Get current metric value
	value, err := s.getMetricValue(ctx, rule)
	if err != nil {
		log.Debug("failed to get metric value", "error", err)
		return
	}

	// Check if condition is met
	conditionMet := rule.MatchesValue(value)

	// Get or create rule state
	s.ruleStatesMu.Lock()
	state, ok := s.ruleStates[rule.ID]
	if !ok {
		state = &ruleState{}
		s.ruleStates[rule.ID] = state
	}
	state.lastValue = value
	s.ruleStatesMu.Unlock()

	now := time.Now()

	if conditionMet {
		s.handleConditionMet(ctx, rule, state, value, now, log)
	} else {
		s.handleConditionCleared(ctx, rule, state, now, log)
	}

	// Update last evaluated time
	rule.LastEvaluated = &now
	s.repo.UpdateRule(ctx, rule)
}

// handleConditionMet handles when an alert condition is met.
func (s *AlertService) handleConditionMet(
	ctx context.Context,
	rule *models.AlertRule,
	state *ruleState,
	value float64,
	now time.Time,
	log *logger.Logger,
) {
	// Start pending timer if not already
	if state.pendingSince == nil {
		state.pendingSince = &now
		log.Debug("alert condition met, starting pending timer", "value", value)
	}

	// Check if duration requirement is met
	pendingDuration := now.Sub(*state.pendingSince)
	requiredDuration := time.Duration(rule.Duration) * time.Second

	if pendingDuration < requiredDuration {
		// Still in pending state
		if rule.State != models.AlertStatePending {
			rule.State = models.AlertStatePending
			rule.StateChangedAt = &now
			s.repo.UpdateRule(ctx, rule)
		}
		return
	}

	// Check cooldown
	cooldown := time.Duration(rule.Cooldown) * time.Second
	if cooldown > 0 && !state.lastFired.IsZero() && now.Sub(state.lastFired) < cooldown {
		log.Debug("alert in cooldown", "cooldown_remaining", cooldown-now.Sub(state.lastFired))
		return
	}

	// Fire the alert
	s.fireAlert(ctx, rule, state, value, now, log)
}

// handleConditionCleared handles when an alert condition is no longer met.
func (s *AlertService) handleConditionCleared(
	ctx context.Context,
	rule *models.AlertRule,
	state *ruleState,
	now time.Time,
	log *logger.Logger,
) {
	// Reset pending state
	state.pendingSince = nil

	// Auto-resolve if enabled and rule was firing
	if s.config.EnableAutoResolve && rule.State == models.AlertStateFiring {
		log.Info("alert condition cleared, resolving")

		rule.State = models.AlertStateResolved
		rule.StateChangedAt = &now
		s.repo.UpdateRule(ctx, rule)

		// Resolve any active events
		s.resolveActiveEvents(ctx, rule.ID, now)
	} else if rule.State == models.AlertStatePending {
		// Clear pending state
		rule.State = models.AlertStateOK
		rule.StateChangedAt = &now
		s.repo.UpdateRule(ctx, rule)
	}
}

// fireAlert fires an alert and creates an event.
func (s *AlertService) fireAlert(
	ctx context.Context,
	rule *models.AlertRule,
	state *ruleState,
	value float64,
	now time.Time,
	log *logger.Logger,
) {
	log.Warn("alert firing",
		"value", value,
		"threshold", rule.Threshold,
		"severity", rule.Severity,
	)

	// Update rule state
	rule.State = models.AlertStateFiring
	rule.StateChangedAt = &now
	rule.LastFiredAt = &now
	rule.FiringValue = &value
	s.repo.UpdateRule(ctx, rule)

	// Update local state
	state.lastFired = now

	// Create event
	event := &models.AlertEvent{
		ID:        uuid.New(),
		AlertID:   rule.ID,
		HostID:    s.getHostIDForRule(rule),
		ContainerID: rule.ContainerID,
		State:     models.AlertStateFiring,
		Value:     value,
		Threshold: rule.Threshold,
		Message:   s.formatAlertMessage(rule, value),
		Labels:    rule.Labels,
		FiredAt:   now,
		CreatedAt: now,
	}

	if err := s.repo.CreateEvent(ctx, event); err != nil {
		log.Error("failed to create alert event", "error", err)
		return
	}

	// Send notification
	if s.notifier != nil {
		if err := s.notifier.SendAlert(ctx, rule, event); err != nil {
			log.Error("failed to send alert notification", "error", err)
		}
	}
}

// resolveActiveEvents resolves all active events for a rule.
func (s *AlertService) resolveActiveEvents(ctx context.Context, ruleID uuid.UUID, resolvedAt time.Time) {
	events, _, _ := s.repo.ListEvents(ctx, models.AlertEventListOptions{
		AlertID: &ruleID,
		State:   ptr(models.AlertStateFiring),
	})

	for _, event := range events {
		event.State = models.AlertStateResolved
		event.ResolvedAt = &resolvedAt
		s.repo.UpdateEvent(ctx, event)
	}
}

// getMetricValue retrieves the current metric value for a rule.
func (s *AlertService) getMetricValue(ctx context.Context, rule *models.AlertRule) (float64, error) {
	if s.metrics == nil {
		return 0, fmt.Errorf("metrics provider not configured")
	}

	hostID := s.getHostIDForRule(rule)

	if rule.ContainerID != nil {
		return s.metrics.GetContainerMetric(ctx, hostID, *rule.ContainerID, rule.Metric)
	}

	return s.metrics.GetHostMetric(ctx, hostID, rule.Metric)
}

// getHostIDForRule returns the host ID for a rule.
func (s *AlertService) getHostIDForRule(rule *models.AlertRule) uuid.UUID {
	if rule.HostID != nil {
		return *rule.HostID
	}
	// Return a nil UUID for global rules
	return uuid.Nil
}

// isSilenced checks if a rule is currently silenced.
func (s *AlertService) isSilenced(rule *models.AlertRule, silences []*models.AlertSilence) bool {
	for _, silence := range silences {
		if !silence.IsActive() {
			continue
		}

		// Check if silence applies to this rule
		if silence.AlertID != nil && *silence.AlertID == rule.ID {
			return true
		}
		if silence.HostID != nil && rule.HostID != nil && *silence.HostID == *rule.HostID {
			return true
		}
		// Global silence (no specific alert or host)
		if silence.AlertID == nil && silence.HostID == nil {
			return true
		}
	}

	return false
}

// formatAlertMessage formats the alert message.
func (s *AlertService) formatAlertMessage(rule *models.AlertRule, value float64) string {
	operatorStr := map[models.AlertOperator]string{
		models.AlertOperatorGreater:      ">",
		models.AlertOperatorGreaterEqual: ">=",
		models.AlertOperatorLess:         "<",
		models.AlertOperatorLessEqual:    "<=",
		models.AlertOperatorEqual:        "==",
		models.AlertOperatorNotEqual:     "!=",
	}[rule.Operator]

	return fmt.Sprintf("%s: %s is %.2f (threshold: %s %.2f)",
		rule.Name, rule.Metric, value, operatorStr, rule.Threshold)
}

// ============================================================================
// CRUD Operations
// ============================================================================

// CreateRule creates a new alert rule.
func (s *AlertService) CreateRule(ctx context.Context, input models.CreateAlertRuleInput, createdBy *uuid.UUID) (*models.AlertRule, error) {
	rule := &models.AlertRule{
		ID:           uuid.New(),
		HostID:       input.HostID,
		ContainerID:  input.ContainerID,
		Name:         input.Name,
		Description:  input.Description,
		Metric:       input.Metric,
		Operator:     input.Operator,
		Threshold:    input.Threshold,
		Severity:     input.Severity,
		Duration:     input.DurationSeconds,
		Cooldown:     input.CooldownSeconds,
		EvalInterval: input.EvalInterval,
		State:        models.AlertStateOK,
		NotifyChannels: input.NotifyChannels,
		Labels:       input.Labels,
		IsEnabled:    input.IsEnabled,
		CreatedBy:    createdBy,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Apply defaults
	if rule.EvalInterval == 0 {
		rule.EvalInterval = int(s.config.DefaultEvalInterval.Seconds())
	}
	if rule.Cooldown == 0 {
		rule.Cooldown = 300 // 5 minutes default
	}

	if err := s.repo.CreateRule(ctx, rule); err != nil {
		return nil, err
	}

	s.logger.Info("alert rule created",
		"id", rule.ID,
		"name", rule.Name,
		"metric", rule.Metric,
	)

	return rule, nil
}

// GetRule retrieves an alert rule by ID.
func (s *AlertService) GetRule(ctx context.Context, id uuid.UUID) (*models.AlertRule, error) {
	return s.repo.GetRule(ctx, id)
}

// UpdateRule updates an alert rule.
func (s *AlertService) UpdateRule(ctx context.Context, id uuid.UUID, input models.UpdateAlertRuleInput) (*models.AlertRule, error) {
	rule, err := s.repo.GetRule(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if input.Name != nil {
		rule.Name = *input.Name
	}
	if input.Description != nil {
		rule.Description = *input.Description
	}
	if input.Threshold != nil {
		rule.Threshold = *input.Threshold
	}
	if input.Severity != nil {
		rule.Severity = *input.Severity
	}
	if input.DurationSeconds != nil {
		rule.Duration = *input.DurationSeconds
	}
	if input.CooldownSeconds != nil {
		rule.Cooldown = *input.CooldownSeconds
	}
	if input.NotifyChannels != nil {
		rule.NotifyChannels = input.NotifyChannels
	}
	if input.Labels != nil {
		rule.Labels = input.Labels
	}
	if input.IsEnabled != nil {
		rule.IsEnabled = *input.IsEnabled
	}

	rule.UpdatedAt = time.Now()

	if err := s.repo.UpdateRule(ctx, rule); err != nil {
		return nil, err
	}

	return rule, nil
}

// DeleteRule deletes an alert rule.
func (s *AlertService) DeleteRule(ctx context.Context, id uuid.UUID) error {
	// Clean up state
	s.ruleStatesMu.Lock()
	delete(s.ruleStates, id)
	s.ruleStatesMu.Unlock()

	return s.repo.DeleteRule(ctx, id)
}

// ListRules lists alert rules with filtering.
func (s *AlertService) ListRules(ctx context.Context, opts models.AlertListOptions) ([]*models.AlertRule, int64, error) {
	return s.repo.ListRules(ctx, opts)
}

// ListEvents lists alert events with filtering.
func (s *AlertService) ListEvents(ctx context.Context, opts models.AlertEventListOptions) ([]*models.AlertEvent, int64, error) {
	return s.repo.ListEvents(ctx, opts)
}

// GetStats retrieves alert statistics.
func (s *AlertService) GetStats(ctx context.Context) (*models.AlertStats, error) {
	return s.repo.GetStats(ctx)
}

// ============================================================================
// Silence Operations
// ============================================================================

// CreateSilence creates a new alert silence.
func (s *AlertService) CreateSilence(ctx context.Context, input models.CreateAlertSilenceInput, createdBy *uuid.UUID) (*models.AlertSilence, error) {
	silence := &models.AlertSilence{
		ID:        uuid.New(),
		AlertID:   input.AlertID,
		HostID:    input.HostID,
		Reason:    input.Reason,
		StartsAt:  input.StartsAt,
		EndsAt:    input.EndsAt,
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
	}

	if err := s.repo.CreateSilence(ctx, silence); err != nil {
		return nil, err
	}

	s.logger.Info("alert silence created",
		"id", silence.ID,
		"starts_at", silence.StartsAt,
		"ends_at", silence.EndsAt,
	)

	return silence, nil
}

// DeleteSilence deletes an alert silence.
func (s *AlertService) DeleteSilence(ctx context.Context, id uuid.UUID) error {
	return s.repo.DeleteSilence(ctx, id)
}

// ListSilences lists all alert silences.
func (s *AlertService) ListSilences(ctx context.Context) ([]*models.AlertSilence, error) {
	return s.repo.ListSilences(ctx)
}

// ============================================================================
// Event Operations
// ============================================================================

// AcknowledgeEvent acknowledges an alert event.
func (s *AlertService) AcknowledgeEvent(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	event, err := s.repo.GetEvent(ctx, id)
	if err != nil {
		return err
	}

	now := time.Now()
	event.AcknowledgedAt = &now
	event.AcknowledgedBy = &userID

	return s.repo.UpdateEvent(ctx, event)
}

// InitializeDefaults creates default alert rules if none exist.
func (s *AlertService) InitializeDefaults(ctx context.Context, createdBy *uuid.UUID) error {
	rules, _, err := s.repo.ListRules(ctx, models.AlertListOptions{Limit: 1})
	if err != nil {
		return err
	}

	// Only create defaults if no rules exist
	if len(rules) > 0 {
		return nil
	}

	s.logger.Info("initializing default alert rules")

	for _, input := range models.DefaultAlertRules() {
		if _, err := s.CreateRule(ctx, input, createdBy); err != nil {
			s.logger.Warn("failed to create default rule",
				"name", input.Name,
				"error", err,
			)
		}
	}

	return nil
}

// EvaluateNow triggers immediate evaluation of all rules.
func (s *AlertService) EvaluateNow(ctx context.Context) {
	s.evaluateAllRules(ctx)
}

// Helper function for pointer to AlertState
func ptr[T any](v T) *T {
	return &v
}
