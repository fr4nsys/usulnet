// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package gateway provides event handling and processing for the gateway.
package gateway

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// EventProcessor processes events from agents.
type EventProcessor struct {
	server    *Server
	log       *logger.Logger
	handlers  map[protocol.EventType][]EventHandler
	mu        sync.RWMutex

	// Event buffer for batch processing
	buffer    chan *protocol.Event
	batchSize int
	flushInterval time.Duration
}

// EventHandler processes a specific event.
type EventHandler func(ctx context.Context, event *protocol.Event) error

// EventProcessorConfig configures the event processor.
type EventProcessorConfig struct {
	BufferSize    int
	BatchSize     int
	FlushInterval time.Duration
}

// DefaultEventProcessorConfig returns default configuration.
func DefaultEventProcessorConfig() EventProcessorConfig {
	return EventProcessorConfig{
		BufferSize:    10000,
		BatchSize:     100,
		FlushInterval: 5 * time.Second,
	}
}

// NewEventProcessor creates a new event processor.
func NewEventProcessor(server *Server, cfg EventProcessorConfig, log *logger.Logger) *EventProcessor {
	return &EventProcessor{
		server:        server,
		log:           log.Named("event-processor"),
		handlers:      make(map[protocol.EventType][]EventHandler),
		buffer:        make(chan *protocol.Event, cfg.BufferSize),
		batchSize:     cfg.BatchSize,
		flushInterval: cfg.FlushInterval,
	}
}

// RegisterHandler registers a handler for an event type.
func (p *EventProcessor) RegisterHandler(eventType protocol.EventType, handler EventHandler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handlers[eventType] = append(p.handlers[eventType], handler)
}

// Start starts the event processor.
func (p *EventProcessor) Start(ctx context.Context) {
	go p.processLoop(ctx)
}

// Submit submits an event for processing.
func (p *EventProcessor) Submit(event *protocol.Event) {
	select {
	case p.buffer <- event:
	default:
		p.log.Warn("Event buffer full, dropping event",
			"event_id", event.ID,
			"event_type", event.Type,
		)
	}
}

// processLoop processes events from the buffer.
func (p *EventProcessor) processLoop(ctx context.Context) {
	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()

	batch := make([]*protocol.Event, 0, p.batchSize)

	for {
		select {
		case <-ctx.Done():
			// Process remaining events
			if len(batch) > 0 {
				p.processBatch(ctx, batch)
			}
			return

		case event := <-p.buffer:
			batch = append(batch, event)
			if len(batch) >= p.batchSize {
				p.processBatch(ctx, batch)
				batch = make([]*protocol.Event, 0, p.batchSize)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				p.processBatch(ctx, batch)
				batch = make([]*protocol.Event, 0, p.batchSize)
			}
		}
	}
}

// processBatch processes a batch of events.
func (p *EventProcessor) processBatch(ctx context.Context, events []*protocol.Event) {
	p.log.Debug("Processing event batch", "count", len(events))

	for _, event := range events {
		p.processEvent(ctx, event)
	}
}

// processEvent processes a single event.
func (p *EventProcessor) processEvent(ctx context.Context, event *protocol.Event) {
	p.mu.RLock()
	handlers := p.handlers[event.Type]
	p.mu.RUnlock()

	if len(handlers) == 0 {
		p.log.Debug("No handlers for event type", "type", event.Type)
		return
	}

	for _, handler := range handlers {
		if err := handler(ctx, event); err != nil {
			p.log.Warn("Event handler failed",
				"event_id", event.ID,
				"event_type", event.Type,
				"error", err,
			)
		}
	}
}

// ProcessSync processes an event synchronously.
func (p *EventProcessor) ProcessSync(ctx context.Context, event *protocol.Event) error {
	p.mu.RLock()
	handlers := p.handlers[event.Type]
	p.mu.RUnlock()

	for _, handler := range handlers {
		if err := handler(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

// ============================================================================
// Event Collectors (from server)
// ============================================================================

// EventCollector collects events from the gateway server.
type EventCollector struct {
	processor *EventProcessor
	server    *Server
	log       *logger.Logger
}

// NewEventCollector creates a new event collector.
func NewEventCollector(server *Server, processor *EventProcessor, log *logger.Logger) *EventCollector {
	return &EventCollector{
		processor: processor,
		server:    server,
		log:       log.Named("event-collector"),
	}
}

// HandleRawEvent handles a raw event message.
func (c *EventCollector) HandleRawEvent(data []byte) {
	var event protocol.Event
	if err := json.Unmarshal(data, &event); err != nil {
		c.log.Warn("Invalid event data", "error", err)
		return
	}

	// Validate event
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Severity == "" {
		event.Severity = protocol.GetSeverity(event.Type)
	}

	c.processor.Submit(&event)
}

// ============================================================================
// Event Store Interface
// ============================================================================

// EventStore defines the interface for event persistence.
type EventStore interface {
	// Save persists an event
	Save(ctx context.Context, event *protocol.Event) error
	// GetByID retrieves an event by ID
	GetByID(ctx context.Context, id string) (*protocol.Event, error)
	// List retrieves events with filters
	List(ctx context.Context, opts EventListOptions) ([]*protocol.Event, int64, error)
	// DeleteOlderThan deletes events older than a duration
	DeleteOlderThan(ctx context.Context, duration time.Duration) (int64, error)
}

// EventListOptions contains options for listing events.
type EventListOptions struct {
	HostID    *uuid.UUID
	AgentID   string
	Type      *protocol.EventType
	Severity  *protocol.EventSeverity
	Since     *time.Time
	Until     *time.Time
	Page      int
	PerPage   int
	SortDesc  bool
}

// ============================================================================
// Built-in Event Handlers
// ============================================================================

// LoggingHandler logs all events.
func LoggingHandler(log *logger.Logger) EventHandler {
	return func(ctx context.Context, event *protocol.Event) error {
		log.Info("Event received",
			"event_id", event.ID,
			"type", event.Type,
			"severity", event.Severity,
			"agent_id", event.AgentID,
			"host_id", event.HostID,
		)
		return nil
	}
}

// PersistenceHandler persists events to storage.
func PersistenceHandler(store EventStore) EventHandler {
	return func(ctx context.Context, event *protocol.Event) error {
		if !protocol.ShouldPersist(event.Type) {
			return nil
		}
		return store.Save(ctx, event)
	}
}

// NotificationHandler sends notifications for critical events.
type NotificationHandler struct {
	// notificationService would be injected here
	log *logger.Logger
}

func NewNotificationHandler(log *logger.Logger) *NotificationHandler {
	return &NotificationHandler{log: log}
}

func (h *NotificationHandler) Handle(ctx context.Context, event *protocol.Event) error {
	if !protocol.ShouldNotify(event.Type) {
		return nil
	}

	h.log.Info("Would send notification",
		"event_type", event.Type,
		"severity", event.Severity,
	)

	// TODO: Integrate with notification service
	return nil
}

// MetricsHandler updates metrics based on events.
type MetricsHandler struct {
	// metrics would be injected here
	containerEvents int64
	imageEvents     int64
	securityEvents  int64
	mu              sync.Mutex
}

func NewMetricsHandler() *MetricsHandler {
	return &MetricsHandler{}
}

func (h *MetricsHandler) Handle(ctx context.Context, event *protocol.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	switch {
	case isContainerEvent(event.Type):
		h.containerEvents++
	case isImageEvent(event.Type):
		h.imageEvents++
	case isSecurityEvent(event.Type):
		h.securityEvents++
	}

	return nil
}

func isContainerEvent(t protocol.EventType) bool {
	switch t {
	case protocol.EventContainerCreate, protocol.EventContainerStart,
		protocol.EventContainerStop, protocol.EventContainerDie,
		protocol.EventContainerKill, protocol.EventContainerPause,
		protocol.EventContainerUnpause, protocol.EventContainerDestroy,
		protocol.EventContainerRename, protocol.EventContainerRestart,
		protocol.EventContainerOOM, protocol.EventContainerHealth:
		return true
	}
	return false
}

func isImageEvent(t protocol.EventType) bool {
	switch t {
	case protocol.EventImagePull, protocol.EventImagePush,
		protocol.EventImageTag, protocol.EventImageUntag,
		protocol.EventImageDelete:
		return true
	}
	return false
}

func isSecurityEvent(t protocol.EventType) bool {
	switch t {
	case protocol.EventSecurityScanStarted, protocol.EventSecurityScanCompleted,
		protocol.EventSecurityVulnFound, protocol.EventSecurityScoreChanged:
		return true
	}
	return false
}

// ============================================================================
// Event Aggregator
// ============================================================================

// EventAggregator aggregates events for reporting.
type EventAggregator struct {
	counts   map[protocol.EventType]int64
	byHost   map[uuid.UUID]int64
	bySeverity map[protocol.EventSeverity]int64
	window   time.Duration
	lastReset time.Time
	mu       sync.RWMutex
}

// NewEventAggregator creates a new event aggregator.
func NewEventAggregator(window time.Duration) *EventAggregator {
	return &EventAggregator{
		counts:     make(map[protocol.EventType]int64),
		byHost:     make(map[uuid.UUID]int64),
		bySeverity: make(map[protocol.EventSeverity]int64),
		window:     window,
		lastReset:  time.Now(),
	}
}

// Record records an event.
func (a *EventAggregator) Record(event *protocol.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if we need to reset
	if time.Since(a.lastReset) > a.window {
		a.counts = make(map[protocol.EventType]int64)
		a.byHost = make(map[uuid.UUID]int64)
		a.bySeverity = make(map[protocol.EventSeverity]int64)
		a.lastReset = time.Now()
	}

	a.counts[event.Type]++
	a.bySeverity[event.Severity]++

	if event.HostID != "" {
		hostID, _ := uuid.Parse(event.HostID)
		a.byHost[hostID]++
	}
}

// EventSummary contains aggregated event statistics.
type EventSummary struct {
	WindowStart   time.Time                           `json:"window_start"`
	WindowEnd     time.Time                           `json:"window_end"`
	TotalEvents   int64                               `json:"total_events"`
	ByType        map[protocol.EventType]int64        `json:"by_type"`
	BySeverity    map[protocol.EventSeverity]int64    `json:"by_severity"`
	ByHost        map[string]int64                    `json:"by_host"`
}

// Summary returns aggregated statistics.
func (a *EventAggregator) Summary() EventSummary {
	a.mu.RLock()
	defer a.mu.RUnlock()

	summary := EventSummary{
		WindowStart: a.lastReset,
		WindowEnd:   time.Now(),
		ByType:      make(map[protocol.EventType]int64),
		BySeverity:  make(map[protocol.EventSeverity]int64),
		ByHost:      make(map[string]int64),
	}

	for t, count := range a.counts {
		summary.ByType[t] = count
		summary.TotalEvents += count
	}

	for s, count := range a.bySeverity {
		summary.BySeverity[s] = count
	}

	for h, count := range a.byHost {
		summary.ByHost[h.String()] = count
	}

	return summary
}
