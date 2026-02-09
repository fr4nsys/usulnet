// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CaptureStatus represents the status of a packet capture session.
type CaptureStatus string

const (
	CaptureStatusRunning   CaptureStatus = "running"
	CaptureStatusStopped   CaptureStatus = "stopped"
	CaptureStatusCompleted CaptureStatus = "completed"
	CaptureStatusError     CaptureStatus = "error"
)

// PacketCapture represents a packet capture session.
type PacketCapture struct {
	ID          uuid.UUID     `json:"id" db:"id"`
	UserID      uuid.UUID     `json:"user_id" db:"user_id"`
	Name        string        `json:"name" db:"name"`
	Interface   string        `json:"interface" db:"interface"`
	Filter      string        `json:"filter" db:"filter"`
	Status      CaptureStatus `json:"status" db:"status"`
	StatusMsg   string        `json:"status_message" db:"status_message"`
	PacketCount int64         `json:"packet_count" db:"packet_count"`
	FileSize    int64         `json:"file_size" db:"file_size"`
	FilePath    string        `json:"file_path" db:"file_path"`
	MaxPackets  int           `json:"max_packets" db:"max_packets"`
	MaxDuration int           `json:"max_duration" db:"max_duration"` // seconds
	PID         int           `json:"pid" db:"pid"`                  // tcpdump process ID
	StartedAt   time.Time     `json:"started_at" db:"started_at"`
	StoppedAt   *time.Time    `json:"stopped_at,omitempty" db:"stopped_at"`
	CreatedAt   time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at" db:"updated_at"`
}

// CreateCaptureInput is the input for creating a new capture.
type CreateCaptureInput struct {
	Name        string `json:"name"`
	Interface   string `json:"interface"`
	Filter      string `json:"filter"`
	MaxPackets  int    `json:"max_packets"`
	MaxDuration int    `json:"max_duration"` // seconds
}

// Duration returns the elapsed time of the capture.
func (c *PacketCapture) Duration() time.Duration {
	if c.StoppedAt != nil {
		return c.StoppedAt.Sub(c.StartedAt)
	}
	if c.Status == CaptureStatusRunning {
		return time.Since(c.StartedAt)
	}
	return 0
}

// FileSizeHuman returns a human-readable file size.
func (c *PacketCapture) FileSizeHuman() string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case c.FileSize >= GB:
		return formatFloat(float64(c.FileSize)/float64(GB)) + " GB"
	case c.FileSize >= MB:
		return formatFloat(float64(c.FileSize)/float64(MB)) + " MB"
	case c.FileSize >= KB:
		return formatFloat(float64(c.FileSize)/float64(KB)) + " KB"
	default:
		return formatInt(c.FileSize) + " B"
	}
}

func formatFloat(v float64) string {
	if v == float64(int64(v)) {
		return formatInt(int64(v))
	}
	// Simple 1 decimal place
	return fmt.Sprintf("%.1f", v)
}

func formatInt(v int64) string {
	return fmt.Sprintf("%d", v)
}
