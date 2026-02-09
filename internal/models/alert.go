// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AlertSeverity represents the severity level of an alert.
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertMetric represents the metric type being monitored.
type AlertMetric string

const (
	// Host metrics
	AlertMetricHostCPU     AlertMetric = "host_cpu"
	AlertMetricHostMemory  AlertMetric = "host_memory"
	AlertMetricHostDisk    AlertMetric = "host_disk"
	AlertMetricHostNetwork AlertMetric = "host_network"

	// Container metrics
	AlertMetricContainerCPU     AlertMetric = "container_cpu"
	AlertMetricContainerMemory  AlertMetric = "container_memory"
	AlertMetricContainerNetwork AlertMetric = "container_network"
	AlertMetricContainerStatus  AlertMetric = "container_status"
	AlertMetricContainerHealth  AlertMetric = "container_health"
)

// AlertOperator represents the comparison operator.
type AlertOperator string

const (
	AlertOperatorGreater      AlertOperator = "gt"  // >
	AlertOperatorGreaterEqual AlertOperator = "gte" // >=
	AlertOperatorLess         AlertOperator = "lt"  // <
	AlertOperatorLessEqual    AlertOperator = "lte" // <=
	AlertOperatorEqual        AlertOperator = "eq"  // ==
	AlertOperatorNotEqual     AlertOperator = "neq" // !=
)

// AlertState represents the current state of an alert rule.
type AlertState string

const (
	AlertStateOK       AlertState = "ok"
	AlertStatePending  AlertState = "pending"
	AlertStateFiring   AlertState = "firing"
	AlertStateResolved AlertState = "resolved"
)

// AlertRule represents a monitoring alert rule with thresholds.
type AlertRule struct {
	ID          uuid.UUID     `json:"id" db:"id"`
	HostID      *uuid.UUID    `json:"host_id,omitempty" db:"host_id"` // nil = all hosts
	ContainerID *string       `json:"container_id,omitempty" db:"container_id"`
	Name        string        `json:"name" db:"name"`
	Description string        `json:"description,omitempty" db:"description"`
	Metric      AlertMetric   `json:"metric" db:"metric"`
	Operator    AlertOperator `json:"operator" db:"operator"`
	Threshold   float64       `json:"threshold" db:"threshold"`
	Severity    AlertSeverity `json:"severity" db:"severity"`

	// Timing configuration
	Duration    int `json:"duration_seconds" db:"duration_seconds"` // How long condition must be true before firing
	Cooldown    int `json:"cooldown_seconds" db:"cooldown_seconds"` // Minimum time between repeated alerts
	EvalInterval int `json:"eval_interval_seconds" db:"eval_interval_seconds"` // How often to evaluate

	// Current state
	State         AlertState `json:"state" db:"state"`
	StateChangedAt *time.Time `json:"state_changed_at,omitempty" db:"state_changed_at"`
	LastEvaluated *time.Time `json:"last_evaluated,omitempty" db:"last_evaluated"`
	LastFiredAt   *time.Time `json:"last_fired_at,omitempty" db:"last_fired_at"`
	FiringValue   *float64   `json:"firing_value,omitempty" db:"firing_value"` // Value when alert fired

	// Actions
	NotifyChannels []string `json:"notify_channels,omitempty" db:"notify_channels"` // Channel IDs
	AutoActions    json.RawMessage `json:"auto_actions,omitempty" db:"auto_actions"` // Automated responses

	IsEnabled bool `json:"is_enabled" db:"is_enabled"`

	// Labels for grouping/filtering
	Labels map[string]string `json:"labels,omitempty" db:"labels"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
}

// MatchesValue checks if the given value triggers this alert rule.
func (r *AlertRule) MatchesValue(value float64) bool {
	switch r.Operator {
	case AlertOperatorGreater:
		return value > r.Threshold
	case AlertOperatorGreaterEqual:
		return value >= r.Threshold
	case AlertOperatorLess:
		return value < r.Threshold
	case AlertOperatorLessEqual:
		return value <= r.Threshold
	case AlertOperatorEqual:
		return value == r.Threshold
	case AlertOperatorNotEqual:
		return value != r.Threshold
	default:
		return false
	}
}

// AlertEvent represents an alert firing or resolution.
type AlertEvent struct {
	ID         uuid.UUID     `json:"id" db:"id"`
	AlertID    uuid.UUID     `json:"alert_id" db:"alert_id"`
	HostID     uuid.UUID     `json:"host_id" db:"host_id"`
	ContainerID *string      `json:"container_id,omitempty" db:"container_id"`
	State      AlertState    `json:"state" db:"state"`
	Value      float64       `json:"value" db:"value"`
	Threshold  float64       `json:"threshold" db:"threshold"`
	Message    string        `json:"message" db:"message"`
	Labels     map[string]string `json:"labels,omitempty" db:"labels"`
	FiredAt    time.Time     `json:"fired_at" db:"fired_at"`
	ResolvedAt *time.Time    `json:"resolved_at,omitempty" db:"resolved_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty" db:"acknowledged_at"`
	AcknowledgedBy *uuid.UUID `json:"acknowledged_by,omitempty" db:"acknowledged_by"`
	CreatedAt  time.Time     `json:"created_at" db:"created_at"`
}

// AlertSilence represents a period during which alerts are muted.
type AlertSilence struct {
	ID        uuid.UUID `json:"id" db:"id"`
	AlertID   *uuid.UUID `json:"alert_id,omitempty" db:"alert_id"` // nil = all alerts
	HostID    *uuid.UUID `json:"host_id,omitempty" db:"host_id"`   // nil = all hosts
	Reason    string    `json:"reason" db:"reason"`
	StartsAt  time.Time `json:"starts_at" db:"starts_at"`
	EndsAt    time.Time `json:"ends_at" db:"ends_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// IsActive checks if the silence is currently active.
func (s *AlertSilence) IsActive() bool {
	now := time.Now()
	return now.After(s.StartsAt) && now.Before(s.EndsAt)
}

// CreateAlertRuleInput represents input for creating an alert rule.
type CreateAlertRuleInput struct {
	Name           string        `json:"name" validate:"required,min=1,max=255"`
	Description    string        `json:"description,omitempty" validate:"max=1000"`
	HostID         *uuid.UUID    `json:"host_id,omitempty"`
	ContainerID    *string       `json:"container_id,omitempty"`
	Metric         AlertMetric   `json:"metric" validate:"required"`
	Operator       AlertOperator `json:"operator" validate:"required"`
	Threshold      float64       `json:"threshold" validate:"required"`
	Severity       AlertSeverity `json:"severity" validate:"required,oneof=info warning critical"`
	DurationSeconds int          `json:"duration_seconds,omitempty" validate:"min=0,max=3600"`
	CooldownSeconds int          `json:"cooldown_seconds,omitempty" validate:"min=0,max=86400"`
	EvalInterval    int          `json:"eval_interval_seconds,omitempty" validate:"min=10,max=3600"`
	NotifyChannels []string      `json:"notify_channels,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	IsEnabled      bool          `json:"is_enabled"`
}

// UpdateAlertRuleInput represents input for updating an alert rule.
type UpdateAlertRuleInput struct {
	Name           *string        `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Description    *string        `json:"description,omitempty" validate:"omitempty,max=1000"`
	Threshold      *float64       `json:"threshold,omitempty"`
	Severity       *AlertSeverity `json:"severity,omitempty" validate:"omitempty,oneof=info warning critical"`
	DurationSeconds *int          `json:"duration_seconds,omitempty" validate:"omitempty,min=0,max=3600"`
	CooldownSeconds *int          `json:"cooldown_seconds,omitempty" validate:"omitempty,min=0,max=86400"`
	NotifyChannels []string       `json:"notify_channels,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	IsEnabled      *bool          `json:"is_enabled,omitempty"`
}

// CreateAlertSilenceInput represents input for creating an alert silence.
type CreateAlertSilenceInput struct {
	AlertID  *uuid.UUID `json:"alert_id,omitempty"`
	HostID   *uuid.UUID `json:"host_id,omitempty"`
	Reason   string     `json:"reason" validate:"required,min=1,max=500"`
	StartsAt time.Time  `json:"starts_at" validate:"required"`
	EndsAt   time.Time  `json:"ends_at" validate:"required,gtfield=StartsAt"`
}

// AlertListOptions represents options for listing alerts.
type AlertListOptions struct {
	HostID      *uuid.UUID     `json:"host_id,omitempty"`
	ContainerID *string        `json:"container_id,omitempty"`
	Metric      *AlertMetric   `json:"metric,omitempty"`
	Severity    *AlertSeverity `json:"severity,omitempty"`
	State       *AlertState    `json:"state,omitempty"`
	IsEnabled   *bool          `json:"is_enabled,omitempty"`
	Limit       int            `json:"limit,omitempty"`
	Offset      int            `json:"offset,omitempty"`
}

// AlertEventListOptions represents options for listing alert events.
type AlertEventListOptions struct {
	AlertID     *uuid.UUID  `json:"alert_id,omitempty"`
	HostID      *uuid.UUID  `json:"host_id,omitempty"`
	ContainerID *string     `json:"container_id,omitempty"`
	State       *AlertState `json:"state,omitempty"`
	From        *time.Time  `json:"from,omitempty"`
	To          *time.Time  `json:"to,omitempty"`
	Limit       int         `json:"limit,omitempty"`
	Offset      int         `json:"offset,omitempty"`
}

// AlertStats represents alert statistics.
type AlertStats struct {
	TotalRules    int64            `json:"total_rules"`
	EnabledRules  int64            `json:"enabled_rules"`
	FiringCount   int64            `json:"firing_count"`
	BySeverity    map[string]int64 `json:"by_severity"`
	ByState       map[string]int64 `json:"by_state"`
	EventsToday   int64            `json:"events_today"`
	EventsWeek    int64            `json:"events_week"`
}

// DefaultAlertRules returns a set of recommended default alert rules.
func DefaultAlertRules() []CreateAlertRuleInput {
	return []CreateAlertRuleInput{
		{
			Name:        "High Host CPU Usage",
			Description: "Alerts when host CPU usage exceeds 90%",
			Metric:      AlertMetricHostCPU,
			Operator:    AlertOperatorGreater,
			Threshold:   90,
			Severity:    AlertSeverityWarning,
			DurationSeconds: 300, // 5 minutes
			CooldownSeconds: 900, // 15 minutes
			IsEnabled:  true,
		},
		{
			Name:        "Critical Host CPU Usage",
			Description: "Alerts when host CPU usage exceeds 95%",
			Metric:      AlertMetricHostCPU,
			Operator:    AlertOperatorGreater,
			Threshold:   95,
			Severity:    AlertSeverityCritical,
			DurationSeconds: 60, // 1 minute
			CooldownSeconds: 300, // 5 minutes
			IsEnabled:  true,
		},
		{
			Name:        "High Host Memory Usage",
			Description: "Alerts when host memory usage exceeds 85%",
			Metric:      AlertMetricHostMemory,
			Operator:    AlertOperatorGreater,
			Threshold:   85,
			Severity:    AlertSeverityWarning,
			DurationSeconds: 300,
			CooldownSeconds: 900,
			IsEnabled:  true,
		},
		{
			Name:        "Critical Host Memory Usage",
			Description: "Alerts when host memory usage exceeds 95%",
			Metric:      AlertMetricHostMemory,
			Operator:    AlertOperatorGreater,
			Threshold:   95,
			Severity:    AlertSeverityCritical,
			DurationSeconds: 60,
			CooldownSeconds: 300,
			IsEnabled:  true,
		},
		{
			Name:        "High Host Disk Usage",
			Description: "Alerts when host disk usage exceeds 80%",
			Metric:      AlertMetricHostDisk,
			Operator:    AlertOperatorGreater,
			Threshold:   80,
			Severity:    AlertSeverityWarning,
			DurationSeconds: 0, // Immediate
			CooldownSeconds: 3600, // 1 hour
			IsEnabled:  true,
		},
		{
			Name:        "Critical Host Disk Usage",
			Description: "Alerts when host disk usage exceeds 90%",
			Metric:      AlertMetricHostDisk,
			Operator:    AlertOperatorGreater,
			Threshold:   90,
			Severity:    AlertSeverityCritical,
			DurationSeconds: 0,
			CooldownSeconds: 1800, // 30 minutes
			IsEnabled:  true,
		},
		{
			Name:        "High Container Memory Usage",
			Description: "Alerts when container memory usage exceeds 90%",
			Metric:      AlertMetricContainerMemory,
			Operator:    AlertOperatorGreater,
			Threshold:   90,
			Severity:    AlertSeverityWarning,
			DurationSeconds: 180, // 3 minutes
			CooldownSeconds: 600, // 10 minutes
			IsEnabled:  true,
		},
		{
			Name:        "Container Unhealthy",
			Description: "Alerts when a container reports unhealthy status",
			Metric:      AlertMetricContainerHealth,
			Operator:    AlertOperatorEqual,
			Threshold:   0, // 0 = unhealthy
			Severity:    AlertSeverityCritical,
			DurationSeconds: 60,
			CooldownSeconds: 300,
			IsEnabled:  true,
		},
	}
}
