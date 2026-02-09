// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package postgres provides PostgreSQL repository implementations.
// Department L: Notifications - Configuration Repository
package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/services/notification"
	"github.com/fr4nsys/usulnet/internal/services/notification/channels"
)

// NotificationConfigRepository handles notification configuration persistence.
type NotificationConfigRepository struct {
	db *DB
}

// NewNotificationConfigRepository creates a new notification config repository.
func NewNotificationConfigRepository(db *DB) *NotificationConfigRepository {
	return &NotificationConfigRepository{db: db}
}

// SaveChannelConfig persists a channel configuration.
func (r *NotificationConfigRepository) SaveChannelConfig(ctx context.Context, config *channels.ChannelConfig) error {
	settingsJSON, err := json.Marshal(config.Settings)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to marshal settings")
	}

	typesJSON, err := json.Marshal(config.NotificationTypes)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to marshal notification types")
	}

	query := `
		INSERT INTO notification_channels (
			name, type, enabled, settings, notification_types, min_priority, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (name) DO UPDATE SET
			type = EXCLUDED.type,
			enabled = EXCLUDED.enabled,
			settings = EXCLUDED.settings,
			notification_types = EXCLUDED.notification_types,
			min_priority = EXCLUDED.min_priority,
			updated_at = EXCLUDED.updated_at
	`

	_, err = r.db.Pool().Exec(ctx, query,
		config.Name,
		config.Type,
		config.Enabled,
		settingsJSON,
		typesJSON,
		int(config.MinPriority),
		time.Now(),
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to save channel config")
	}

	return nil
}

// GetChannelConfigs retrieves all channel configurations.
func (r *NotificationConfigRepository) GetChannelConfigs(ctx context.Context) ([]*channels.ChannelConfig, error) {
	query := `
		SELECT name, type, enabled, settings, notification_types, min_priority
		FROM notification_channels
		ORDER BY name
	`

	rows, err := r.db.Pool().Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query channel configs")
	}
	defer rows.Close()

	var configs []*channels.ChannelConfig
	for rows.Next() {
		var (
			cfg           channels.ChannelConfig
			settingsJSON  []byte
			typesJSON     []byte
			minPriorityInt int
		)

		if err := rows.Scan(
			&cfg.Name,
			&cfg.Type,
			&cfg.Enabled,
			&settingsJSON,
			&typesJSON,
			&minPriorityInt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan channel config")
		}

		if err := json.Unmarshal(settingsJSON, &cfg.Settings); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to unmarshal settings")
		}

		if len(typesJSON) > 0 {
			if err := json.Unmarshal(typesJSON, &cfg.NotificationTypes); err != nil {
				return nil, errors.Wrap(err, errors.CodeInternal, "failed to unmarshal notification types")
			}
		}

		cfg.MinPriority = channels.Priority(minPriorityInt)
		configs = append(configs, &cfg)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "row iteration error")
	}

	return configs, nil
}

// GetChannelConfig retrieves a single channel configuration by name.
func (r *NotificationConfigRepository) GetChannelConfig(ctx context.Context, name string) (*channels.ChannelConfig, error) {
	query := `
		SELECT name, type, enabled, settings, notification_types, min_priority
		FROM notification_channels
		WHERE name = $1
	`

	var (
		cfg           channels.ChannelConfig
		settingsJSON  []byte
		typesJSON     []byte
		minPriorityInt int
	)

	err := r.db.Pool().QueryRow(ctx, query, name).Scan(
		&cfg.Name,
		&cfg.Type,
		&cfg.Enabled,
		&settingsJSON,
		&typesJSON,
		&minPriorityInt,
	)

	if err == pgx.ErrNoRows {
		return nil, errors.NotFound("channel config")
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query channel config")
	}

	if err := json.Unmarshal(settingsJSON, &cfg.Settings); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to unmarshal settings")
	}

	if len(typesJSON) > 0 {
		if err := json.Unmarshal(typesJSON, &cfg.NotificationTypes); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to unmarshal notification types")
		}
	}

	cfg.MinPriority = channels.Priority(minPriorityInt)
	return &cfg, nil
}

// DeleteChannelConfig removes a channel configuration.
func (r *NotificationConfigRepository) DeleteChannelConfig(ctx context.Context, name string) error {
	query := `DELETE FROM notification_channels WHERE name = $1`

	result, err := r.db.Pool().Exec(ctx, query, name)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete channel config")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFound("channel config")
	}

	return nil
}

// SaveRoutingRules persists all routing rules.
func (r *NotificationConfigRepository) SaveRoutingRules(ctx context.Context, rules []*notification.RoutingRule) error {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to begin transaction")
	}
	defer tx.Rollback(ctx)

	// Clear existing rules
	if _, err := tx.Exec(ctx, `DELETE FROM notification_routing_rules`); err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to clear routing rules")
	}

	// Insert new rules
	query := `
		INSERT INTO notification_routing_rules (
			name, enabled, notification_types, min_priority, categories,
			channels, exclude_channels, time_window, position
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	for i, rule := range rules {
		typesJSON, _ := json.Marshal(rule.NotificationTypes)
		categoriesJSON, _ := json.Marshal(rule.Categories)
		channelsJSON, _ := json.Marshal(rule.Channels)
		excludeJSON, _ := json.Marshal(rule.ExcludeChannels)
		
		var timeWindowJSON []byte
		if rule.TimeWindow != nil {
			timeWindowJSON, _ = json.Marshal(rule.TimeWindow)
		}

		_, err := tx.Exec(ctx, query,
			rule.Name,
			rule.Enabled,
			typesJSON,
			int(rule.MinPriority),
			categoriesJSON,
			channelsJSON,
			excludeJSON,
			timeWindowJSON,
			i, // position for ordering
		)
		if err != nil {
			return errors.Wrap(err, errors.CodeDatabaseError, "failed to insert routing rule")
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to commit transaction")
	}

	return nil
}

// GetRoutingRules retrieves all routing rules in order.
func (r *NotificationConfigRepository) GetRoutingRules(ctx context.Context) ([]*notification.RoutingRule, error) {
	query := `
		SELECT name, enabled, notification_types, min_priority, categories,
		       channels, exclude_channels, time_window
		FROM notification_routing_rules
		ORDER BY position
	`

	rows, err := r.db.Pool().Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query routing rules")
	}
	defer rows.Close()

	var rules []*notification.RoutingRule
	for rows.Next() {
		var (
			rule           notification.RoutingRule
			typesJSON      []byte
			categoriesJSON []byte
			channelsJSON   []byte
			excludeJSON    []byte
			timeWindowJSON []byte
			minPriorityInt int
		)

		if err := rows.Scan(
			&rule.Name,
			&rule.Enabled,
			&typesJSON,
			&minPriorityInt,
			&categoriesJSON,
			&channelsJSON,
			&excludeJSON,
			&timeWindowJSON,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan routing rule")
		}

		if len(typesJSON) > 0 {
			json.Unmarshal(typesJSON, &rule.NotificationTypes)
		}
		if len(categoriesJSON) > 0 {
			json.Unmarshal(categoriesJSON, &rule.Categories)
		}
		if len(channelsJSON) > 0 {
			json.Unmarshal(channelsJSON, &rule.Channels)
		}
		if len(excludeJSON) > 0 {
			json.Unmarshal(excludeJSON, &rule.ExcludeChannels)
		}
		if len(timeWindowJSON) > 0 {
			rule.TimeWindow = &notification.TimeWindow{}
			json.Unmarshal(timeWindowJSON, rule.TimeWindow)
		}

		rule.MinPriority = channels.Priority(minPriorityInt)
		rules = append(rules, &rule)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "row iteration error")
	}

	return rules, nil
}
