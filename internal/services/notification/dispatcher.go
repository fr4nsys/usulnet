// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package notification provides the notification service for USULNET.
// Department L: Notifications
package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/fr4nsys/usulnet/internal/services/notification/channels"
)

// Dispatcher manages multiple notification channels and routes messages.
type Dispatcher struct {
	mu           sync.RWMutex
	channels     map[string]channels.Channel
	configs      map[string]*channels.ChannelConfig
	routingRules []*RoutingRule
}

// IsActive checks if the current time falls within the window.
func (tw *TimeWindow) IsActive() bool {
	if tw == nil {
		return true
	}

	loc := time.UTC
	if tw.Timezone != "" {
		if l, err := time.LoadLocation(tw.Timezone); err == nil {
			loc = l
		}
	}

	now := time.Now().In(loc)

	// Check day of week
	if len(tw.Days) > 0 {
		dayMatch := false
		currentDay := now.Weekday()
		for _, d := range tw.Days {
			if d == currentDay {
				dayMatch = true
				break
			}
		}
		if !dayMatch {
			return false
		}
	}

	// Check hour
	currentHour := now.Hour()
	if tw.StartHour <= tw.EndHour {
		// Simple range (e.g., 9-17)
		return currentHour >= tw.StartHour && currentHour < tw.EndHour
	}
	// Overnight range (e.g., 22-6)
	return currentHour >= tw.StartHour || currentHour < tw.EndHour
}

// NewDispatcher creates a new notification dispatcher.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		channels:     make(map[string]channels.Channel),
		configs:      make(map[string]*channels.ChannelConfig),
		routingRules: []*RoutingRule{},
	}
}

// RegisterChannel adds a new notification channel.
func (d *Dispatcher) RegisterChannel(name string, config *channels.ChannelConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ch, err := d.createChannel(config)
	if err != nil {
		return fmt.Errorf("failed to create channel %s: %w", name, err)
	}

	d.channels[name] = ch
	d.configs[name] = config
	return nil
}

// RemoveChannel removes a notification channel.
func (d *Dispatcher) RemoveChannel(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.channels, name)
	delete(d.configs, name)
}

// GetChannel returns a channel by name.
func (d *Dispatcher) GetChannel(name string) (channels.Channel, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ch, ok := d.channels[name]
	return ch, ok
}

// ListChannels returns all registered channel names.
func (d *Dispatcher) ListChannels() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	names := make([]string, 0, len(d.channels))
	for name := range d.channels {
		names = append(names, name)
	}
	return names
}

// AddRoutingRule adds a routing rule.
func (d *Dispatcher) AddRoutingRule(rule *RoutingRule) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.routingRules = append(d.routingRules, rule)
}

// SetRoutingRules replaces all routing rules.
func (d *Dispatcher) SetRoutingRules(rules []*RoutingRule) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.routingRules = rules
}

// Dispatch sends a rendered message to appropriate channels.
func (d *Dispatcher) Dispatch(ctx context.Context, msg channels.RenderedMessage, targetChannels []string) []channels.DeliveryResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Determine which channels to use
	channelNames := targetChannels
	if len(channelNames) == 0 {
		channelNames = d.resolveChannels(msg)
	}

	// Send to all resolved channels concurrently
	results := make([]channels.DeliveryResult, len(channelNames))
	var wg sync.WaitGroup

	for i, name := range channelNames {
		wg.Add(1)
		go func(idx int, channelName string) {
			defer wg.Done()

			result := channels.DeliveryResult{
				ChannelName: channelName,
				Timestamp:   time.Now(),
			}

			ch, ok := d.channels[channelName]
			if !ok {
				result.Error = "channel not found"
				results[idx] = result
				return
			}

			// Check if channel config allows this notification
			cfg, ok := d.configs[channelName]
			if ok && !cfg.ShouldSend(msg.Type, msg.Priority) {
				result.Error = "filtered by channel config"
				results[idx] = result
				return
			}

			start := time.Now()
			err := ch.Send(ctx, msg)
			result.Duration = time.Since(start)

			if err != nil {
				result.Error = err.Error()
			} else {
				result.Success = true
			}

			results[idx] = result
		}(i, name)
	}

	wg.Wait()
	return results
}

// TestChannel sends a test notification to a specific channel.
func (d *Dispatcher) TestChannel(ctx context.Context, name string) error {
	d.mu.RLock()
	ch, ok := d.channels[name]
	d.mu.RUnlock()

	if !ok {
		return fmt.Errorf("channel %s not found", name)
	}

	return ch.Test(ctx)
}

// resolveChannels determines which channels should receive a notification.
func (d *Dispatcher) resolveChannels(msg channels.RenderedMessage) []string {
	channelSet := make(map[string]bool)
	excludeSet := make(map[string]bool)

	// Evaluate routing rules
	for _, rule := range d.routingRules {
		if !rule.Enabled {
			continue
		}

		if !d.ruleMatches(rule, msg) {
			continue
		}

		// Check time window
		if rule.TimeWindow != nil && !rule.TimeWindow.IsActive() {
			continue
		}

		// Add channels from this rule
		for _, ch := range rule.Channels {
			channelSet[ch] = true
		}

		// Add exclusions
		for _, ch := range rule.ExcludeChannels {
			excludeSet[ch] = true
		}
	}

	// If no rules matched, use all enabled channels that accept this notification
	if len(channelSet) == 0 {
		for name, cfg := range d.configs {
			if cfg.ShouldSend(msg.Type, msg.Priority) {
				channelSet[name] = true
			}
		}
	}

	// Apply exclusions and build result
	result := make([]string, 0, len(channelSet))
	for name := range channelSet {
		if !excludeSet[name] {
			result = append(result, name)
		}
	}

	return result
}

// ruleMatches checks if a routing rule matches a notification.
func (d *Dispatcher) ruleMatches(rule *RoutingRule, msg channels.RenderedMessage) bool {
	// Check priority
	if msg.Priority < rule.MinPriority {
		return false
	}

	// Check notification type
	if len(rule.NotificationTypes) > 0 {
		typeMatch := false
		for _, t := range rule.NotificationTypes {
			if t == msg.Type {
				typeMatch = true
				break
			}
		}
		if !typeMatch {
			return false
		}
	}

	// Check category
	if len(rule.Categories) > 0 {
		categoryMatch := false
		msgCategory := msg.Type.Category()
		for _, c := range rule.Categories {
			if c == msgCategory {
				categoryMatch = true
				break
			}
		}
		if !categoryMatch {
			return false
		}
	}

	return true
}

// createChannel creates a channel instance from config.
func (d *Dispatcher) createChannel(config *channels.ChannelConfig) (channels.Channel, error) {
	switch config.Type {
	case "email":
		return channels.NewEmailChannelFromSettings(config.Settings)
	case "slack":
		return channels.NewSlackChannelFromSettings(config.Settings)
	case "discord":
		return channels.NewDiscordChannelFromSettings(config.Settings)
	case "telegram":
		return channels.NewTelegramChannelFromSettings(config.Settings)
	case "webhook":
		return channels.NewWebhookChannelFromSettings(config.Settings)
	case "gotify":
		return channels.NewGotifyChannelFromSettings(config.Settings)
	case "ntfy":
		return channels.NewNtfyChannelFromSettings(config.Settings)
	case "pagerduty":
		return channels.NewPagerDutyChannelFromSettings(config.Settings)
	case "opsgenie":
		return channels.NewOpsgenieChannelFromSettings(config.Settings)
	default:
		return nil, fmt.Errorf("unsupported channel type: %s", config.Type)
	}
}

// LoadChannelsFromJSON loads channel configurations from JSON.
func (d *Dispatcher) LoadChannelsFromJSON(data []byte) error {
	var configs []*channels.ChannelConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return fmt.Errorf("failed to parse channel configs: %w", err)
	}

	for _, cfg := range configs {
		if err := d.RegisterChannel(cfg.Name, cfg); err != nil {
			return fmt.Errorf("failed to register channel %s: %w", cfg.Name, err)
		}
	}

	return nil
}

// LoadRoutingRulesFromJSON loads routing rules from JSON.
func (d *Dispatcher) LoadRoutingRulesFromJSON(data []byte) error {
	var rules []*RoutingRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("failed to parse routing rules: %w", err)
	}

	d.SetRoutingRules(rules)
	return nil
}

// ExportChannelsToJSON exports channel configurations to JSON.
func (d *Dispatcher) ExportChannelsToJSON() ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	configs := make([]*channels.ChannelConfig, 0, len(d.configs))
	for _, cfg := range d.configs {
		configs = append(configs, cfg)
	}

	return json.MarshalIndent(configs, "", "  ")
}

// ExportRoutingRulesToJSON exports routing rules to JSON.
func (d *Dispatcher) ExportRoutingRulesToJSON() ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return json.MarshalIndent(d.routingRules, "", "  ")
}
