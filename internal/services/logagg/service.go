// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package logagg provides log aggregation services for collecting, searching,
// and managing container logs across hosts.
package logagg

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/services/host"
)

// Config contains log aggregation service configuration.
type Config struct {
	// Retention is how long to keep log entries before cleanup.
	Retention time.Duration

	// BatchSize is the maximum number of logs to buffer before flushing to the database.
	BatchSize int

	// FlushInterval is how often to flush buffered logs to the database.
	FlushInterval time.Duration

	// CollectionInterval is how often to collect logs from containers.
	CollectionInterval time.Duration
}

// DefaultConfig returns default log aggregation configuration.
func DefaultConfig() Config {
	return Config{
		Retention:          7 * 24 * time.Hour, // 7 days
		BatchSize:          100,
		FlushInterval:      5 * time.Second,
		CollectionInterval: 30 * time.Second,
	}
}

// Service manages log aggregation, collection, and search.
type Service struct {
	repo        *postgres.LogRepository
	hostService *host.Service
	config      Config
	logger      *logger.Logger

	// buffer holds pending logs before they are flushed to the database.
	buffer []*models.AggregatedLog
	mu     sync.Mutex

	stopCh  chan struct{}
	running bool
	runMu   sync.Mutex
}

// NewService creates a new log aggregation service.
func NewService(
	repo *postgres.LogRepository,
	hostService *host.Service,
	config Config,
	log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.Nop()
	}

	if config.BatchSize <= 0 {
		config.BatchSize = DefaultConfig().BatchSize
	}
	if config.FlushInterval <= 0 {
		config.FlushInterval = DefaultConfig().FlushInterval
	}
	if config.CollectionInterval <= 0 {
		config.CollectionInterval = DefaultConfig().CollectionInterval
	}
	if config.Retention <= 0 {
		config.Retention = DefaultConfig().Retention
	}

	return &Service{
		repo:        repo,
		hostService: hostService,
		config:      config,
		logger:      log.Named("logagg"),
		buffer:      make([]*models.AggregatedLog, 0, config.BatchSize),
		stopCh:      make(chan struct{}),
	}
}

// Start starts the background log collection and cleanup workers.
func (s *Service) Start(ctx context.Context) error {
	s.runMu.Lock()
	if s.running {
		s.runMu.Unlock()
		return nil
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.runMu.Unlock()

	s.logger.Info("starting log aggregation service",
		"retention", s.config.Retention,
		"batch_size", s.config.BatchSize,
		"flush_interval", s.config.FlushInterval,
		"collection_interval", s.config.CollectionInterval,
	)

	// Start the flush worker
	go s.flushWorker(ctx)

	// Start the collection worker
	go s.collectionWorker(ctx)

	// Start the cleanup worker
	go s.cleanupWorker(ctx)

	return nil
}

// Stop stops all background workers and flushes remaining logs.
func (s *Service) Stop() error {
	s.runMu.Lock()
	defer s.runMu.Unlock()

	if !s.running {
		return nil
	}

	close(s.stopCh)
	s.running = false

	// Flush any remaining buffered logs
	s.mu.Lock()
	remaining := s.buffer
	s.buffer = make([]*models.AggregatedLog, 0, s.config.BatchSize)
	s.mu.Unlock()

	if len(remaining) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.repo.InsertLogBatch(ctx, remaining); err != nil {
			s.logger.Error("failed to flush remaining logs on shutdown", "error", err, "count", len(remaining))
		} else {
			s.logger.Info("flushed remaining logs on shutdown", "count", len(remaining))
		}
	}

	s.logger.Info("log aggregation service stopped")
	return nil
}

// IngestContainerLogs reads recent logs from a specific container and ingests them.
func (s *Service) IngestContainerLogs(ctx context.Context, hostID uuid.UUID, containerID string) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return fmt.Errorf("get docker client for host %s: %w", hostID, err)
	}

	// Get container details for the name
	containerName := containerID
	details, err := client.ContainerGet(ctx, containerID)
	if err == nil && details.Name != "" {
		containerName = strings.TrimPrefix(details.Name, "/")
	}

	// Read recent logs
	reader, err := client.ContainerLogs(ctx, containerID, docker.LogOptions{
		Tail:       "100",
		Timestamps: true,
		Stdout:     true,
		Stderr:     true,
	})
	if err != nil {
		return fmt.Errorf("get container logs for %s: %w", containerID, err)
	}
	defer reader.Close()

	// Determine if the container uses TTY (no multiplexing)
	isTTY := details != nil && details.Config != nil && details.Config.Tty

	var logs []*models.AggregatedLog

	if isTTY {
		logs = s.parseTTYLogs(reader, &hostID, containerID, containerName)
	} else {
		logs = s.parseMultiplexedLogs(reader, &hostID, containerID, containerName)
	}

	if len(logs) == 0 {
		return nil
	}

	// Buffer the logs for batch insertion
	s.bufferLogs(logs)

	return nil
}

// IngestAllContainerLogs ingests logs from all running containers on a host.
func (s *Service) IngestAllContainerLogs(ctx context.Context, hostID uuid.UUID) error {
	client, err := s.hostService.GetClient(ctx, hostID)
	if err != nil {
		return fmt.Errorf("get docker client for host %s: %w", hostID, err)
	}

	containers, err := client.ContainerList(ctx, docker.ContainerListOptions{
		All:     false, // Only running containers
		Filters: map[string][]string{"status": {"running"}},
	})
	if err != nil {
		return fmt.Errorf("list containers on host %s: %w", hostID, err)
	}

	var lastErr error
	ingested := 0

	for _, c := range containers {
		if err := s.IngestContainerLogs(ctx, hostID, c.ID); err != nil {
			s.logger.Warn("failed to ingest logs for container",
				"host_id", hostID,
				"container_id", c.ID,
				"container_name", c.Name,
				"error", err,
			)
			lastErr = err
			continue
		}
		ingested++
	}

	s.logger.Debug("ingested container logs",
		"host_id", hostID,
		"containers_ingested", ingested,
		"containers_total", len(containers),
	)

	return lastErr
}

// Search delegates to the repository to search aggregated logs.
func (s *Service) Search(ctx context.Context, opts models.AggregatedLogSearchOptions) ([]*models.AggregatedLog, int64, error) {
	return s.repo.SearchLogs(ctx, opts)
}

// GetStats delegates to the repository to retrieve log statistics.
func (s *Service) GetStats(ctx context.Context, since time.Time) (*postgres.LogStats, error) {
	return s.repo.GetLogStats(ctx, since)
}

// ============================================================================
// Log Parsing
// ============================================================================

// detectSeverity determines the severity level from a log message.
func detectSeverity(message string) string {
	upper := strings.ToUpper(message)

	// Check for error-level patterns first (most critical)
	for _, pattern := range []string{"PANIC", "FATAL"} {
		if strings.Contains(upper, pattern) {
			return models.LogSeverityFatal
		}
	}

	if strings.Contains(upper, "ERROR") {
		return string(models.LogSeverityError)
	}

	// Warning patterns
	for _, pattern := range []string{"WARN", "WARNING"} {
		if strings.Contains(upper, pattern) {
			return models.LogSeverityWarn
		}
	}

	// Debug patterns
	for _, pattern := range []string{"DEBUG", "TRACE"} {
		if strings.Contains(upper, pattern) {
			return string(models.LogSeverityDebug)
		}
	}

	return string(models.LogSeverityInfo)
}

// parseTimestampAndMessage extracts a timestamp and message from a Docker log line.
// Docker timestamps are in RFC3339Nano format followed by a space.
func parseTimestampAndMessage(line string) (time.Time, string) {
	if len(line) > 30 {
		spaceIdx := strings.Index(line, " ")
		if spaceIdx > 0 && spaceIdx < 35 {
			timeStr := line[:spaceIdx]
			if t, err := time.Parse(time.RFC3339Nano, timeStr); err == nil {
				return t, line[spaceIdx+1:]
			}
		}
	}
	return time.Now().UTC(), line
}

// parseTTYLogs reads logs from a TTY container (no multiplexing).
func (s *Service) parseTTYLogs(reader io.Reader, hostID *uuid.UUID, containerID, containerName string) []*models.AggregatedLog {
	var logs []*models.AggregatedLog

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		ts, message := parseTimestampAndMessage(line)
		severity := detectSeverity(message)

		logs = append(logs, &models.AggregatedLog{
			HostID:        hostID,
			ContainerID:   containerID,
			ContainerName: containerName,
			Source:        models.LogSourceDocker,
			Stream:        "stdout",
			Severity:      severity,
			Message:       message,
			Timestamp:     ts,
			IngestedAt:    time.Now().UTC(),
		})
	}

	if err := scanner.Err(); err != nil {
		s.logger.Debug("TTY log stream ended", "container_id", containerID, "error", err)
	}

	return logs
}

// parseMultiplexedLogs reads multiplexed Docker logs (stdout/stderr with 8-byte header).
func (s *Service) parseMultiplexedLogs(reader io.Reader, hostID *uuid.UUID, containerID, containerName string) []*models.AggregatedLog {
	var logs []*models.AggregatedLog
	header := make([]byte, 8)

	for {
		_, err := io.ReadFull(reader, header)
		if err != nil {
			if err != io.EOF {
				s.logger.Debug("multiplexed log stream ended", "container_id", containerID, "error", err)
			}
			break
		}

		// Parse stream type: 1 = stdout, 2 = stderr
		stream := "stdout"
		if header[0] == 2 {
			stream = "stderr"
		}

		// Parse message size (big-endian uint32)
		size := binary.BigEndian.Uint32(header[4:8])
		if size == 0 {
			continue
		}

		message := make([]byte, size)
		_, err = io.ReadFull(reader, message)
		if err != nil {
			if err != io.EOF {
				s.logger.Debug("failed to read log message", "container_id", containerID, "error", err)
			}
			break
		}

		line := strings.TrimSuffix(string(message), "\n")
		if line == "" {
			continue
		}

		ts, msg := parseTimestampAndMessage(line)
		severity := detectSeverity(msg)

		logs = append(logs, &models.AggregatedLog{
			HostID:        hostID,
			ContainerID:   containerID,
			ContainerName: containerName,
			Source:        models.LogSourceDocker,
			Stream:        stream,
			Severity:      severity,
			Message:       msg,
			Timestamp:     ts,
			IngestedAt:    time.Now().UTC(),
		})
	}

	return logs
}

// ============================================================================
// Buffering
// ============================================================================

// bufferLogs adds logs to the internal buffer and flushes when the batch size is reached.
func (s *Service) bufferLogs(logs []*models.AggregatedLog) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.buffer = append(s.buffer, logs...)

	if len(s.buffer) >= s.config.BatchSize {
		batch := s.buffer
		s.buffer = make([]*models.AggregatedLog, 0, s.config.BatchSize)

		// Flush in a goroutine to avoid holding the lock during DB write
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := s.repo.InsertLogBatch(ctx, batch); err != nil {
				s.logger.Error("failed to flush log batch", "error", err, "count", len(batch))
			}
		}()
	}
}

// ============================================================================
// Background Workers
// ============================================================================

// flushWorker periodically flushes buffered logs to the database.
func (s *Service) flushWorker(ctx context.Context) {
	ticker := time.NewTicker(s.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.flush(ctx)
		}
	}
}

// flush writes all buffered logs to the database.
func (s *Service) flush(ctx context.Context) {
	s.mu.Lock()
	if len(s.buffer) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.buffer
	s.buffer = make([]*models.AggregatedLog, 0, s.config.BatchSize)
	s.mu.Unlock()

	if err := s.repo.InsertLogBatch(ctx, batch); err != nil {
		s.logger.Error("failed to flush log buffer", "error", err, "count", len(batch))
		// Put logs back in the buffer for retry
		s.mu.Lock()
		s.buffer = append(batch, s.buffer...)
		// Prevent unbounded growth: drop oldest if too large
		maxBuffer := s.config.BatchSize * 10
		if len(s.buffer) > maxBuffer {
			dropped := len(s.buffer) - maxBuffer
			s.buffer = s.buffer[dropped:]
			s.logger.Warn("dropped old buffered logs to prevent unbounded growth", "dropped", dropped)
		}
		s.mu.Unlock()
	}
}

// collectionWorker periodically collects logs from all running containers on all online hosts.
func (s *Service) collectionWorker(ctx context.Context) {
	ticker := time.NewTicker(s.config.CollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.collectAllLogs(ctx)
		}
	}
}

// collectAllLogs collects logs from all containers on all online hosts.
func (s *Service) collectAllLogs(ctx context.Context) {
	hostIDs := s.hostService.GetOnlineHosts()
	if len(hostIDs) == 0 {
		return
	}

	for _, hostIDStr := range hostIDs {
		hostID, err := uuid.Parse(hostIDStr)
		if err != nil {
			s.logger.Warn("invalid host ID in online hosts", "host_id", hostIDStr)
			continue
		}

		if err := s.IngestAllContainerLogs(ctx, hostID); err != nil {
			s.logger.Warn("failed to ingest logs from host",
				"host_id", hostID,
				"error", err,
			)
		}
	}
}

// cleanupWorker periodically removes old log entries based on the retention policy.
func (s *Service) cleanupWorker(ctx context.Context) {
	// Run cleanup once per hour
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			count, err := s.repo.DeleteOldLogs(ctx, s.config.Retention)
			if err != nil {
				s.logger.Error("failed to delete old logs", "error", err)
			} else if count > 0 {
				s.logger.Info("cleaned up old aggregated logs",
					"count", count,
					"retention", s.config.Retention,
				)
			}
		}
	}
}
