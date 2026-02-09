// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// MetricType represents the type of metrics snapshot.
type MetricType string

const (
	MetricTypeHost      MetricType = "host"
	MetricTypeContainer MetricType = "container"
)

// MetricsSnapshot represents a single metrics measurement stored in the DB.
// Maps to table: metrics_snapshots (migration 021).
type MetricsSnapshot struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	HostID     uuid.UUID  `json:"host_id" db:"host_id"`
	MetricType MetricType `json:"metric_type" db:"metric_type"`

	// Container-specific (NULL for host metrics)
	ContainerID   *string `json:"container_id,omitempty" db:"container_id"`
	ContainerName *string `json:"container_name,omitempty" db:"container_name"`

	// Common metrics
	CPUPercent    *float64 `json:"cpu_percent,omitempty" db:"cpu_percent"`
	MemoryUsed    *int64   `json:"memory_used,omitempty" db:"memory_used"`
	MemoryTotal   *int64   `json:"memory_total,omitempty" db:"memory_total"`
	MemoryPercent *float64 `json:"memory_percent,omitempty" db:"memory_percent"`

	// Network I/O
	NetworkRxBytes *int64 `json:"network_rx_bytes,omitempty" db:"network_rx_bytes"`
	NetworkTxBytes *int64 `json:"network_tx_bytes,omitempty" db:"network_tx_bytes"`

	// Disk / Block I/O
	DiskUsed    *int64   `json:"disk_used,omitempty" db:"disk_used"`
	DiskTotal   *int64   `json:"disk_total,omitempty" db:"disk_total"`
	DiskPercent *float64 `json:"disk_percent,omitempty" db:"disk_percent"`
	BlockRead   *int64   `json:"block_read,omitempty" db:"block_read"`
	BlockWrite  *int64   `json:"block_write,omitempty" db:"block_write"`

	// Container-specific
	PIDs          *int    `json:"pids,omitempty" db:"pids"`
	State         *string `json:"state,omitempty" db:"state"`
	Health        *string `json:"health,omitempty" db:"health"`
	UptimeSeconds *int64  `json:"uptime_seconds,omitempty" db:"uptime_seconds"`

	// Host-specific
	ContainersTotal   *int `json:"containers_total,omitempty" db:"containers_total"`
	ContainersRunning *int `json:"containers_running,omitempty" db:"containers_running"`
	ContainersStopped *int `json:"containers_stopped,omitempty" db:"containers_stopped"`
	ImagesTotal       *int `json:"images_total,omitempty" db:"images_total"`
	VolumesTotal      *int `json:"volumes_total,omitempty" db:"volumes_total"`

	// Extra metadata
	Labels map[string]string `json:"labels,omitempty" db:"labels"`

	// Timestamp
	CollectedAt time.Time `json:"collected_at" db:"collected_at"`
}

// MetricsQueryOptions holds filters for querying metrics history.
type MetricsQueryOptions struct {
	HostID      uuid.UUID
	MetricType  MetricType
	ContainerID string // optional, filter by container
	From        time.Time
	To          time.Time
	Interval    string // "1m", "5m", "1h", "1d" for aggregation
	Limit       int
}
