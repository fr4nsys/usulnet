// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// VerificationStatus represents the lifecycle status of a backup verification.
type VerificationStatus string

const (
	VerificationStatusPending VerificationStatus = "pending"
	VerificationStatusRunning VerificationStatus = "running"
	VerificationStatusPassed  VerificationStatus = "passed"
	VerificationStatusFailed  VerificationStatus = "failed"
)

// VerificationMethod is how a backup is verified.
//
//   - extract:   decompress the archive and confirm the files are readable.
//   - container: extract + spin up a sandbox container against the data.
//   - database:  extract + restore the dump into an isolated database.
type VerificationMethod string

const (
	VerificationMethodExtract   VerificationMethod = "extract"
	VerificationMethodContainer VerificationMethod = "container"
	VerificationMethodDatabase  VerificationMethod = "database"
)

// IsValid reports whether m is a known verification method.
func (m VerificationMethod) IsValid() bool {
	switch m {
	case VerificationMethodExtract, VerificationMethodContainer, VerificationMethodDatabase:
		return true
	}
	return false
}

// BackupVerification is a single verification run against a stored backup.
type BackupVerification struct {
	ID            uuid.UUID          `json:"id" db:"id"`
	BackupID      uuid.UUID          `json:"backup_id" db:"backup_id"`
	HostID        uuid.UUID          `json:"host_id" db:"host_id"`
	Status        VerificationStatus `json:"status" db:"status"`
	Method        VerificationMethod `json:"method" db:"method"`
	ChecksumValid *bool              `json:"checksum_valid,omitempty" db:"checksum_valid"`
	FilesReadable *bool              `json:"files_readable,omitempty" db:"files_readable"`
	ContainerTest *bool              `json:"container_test,omitempty" db:"container_test"`
	DataValid     *bool              `json:"data_valid,omitempty" db:"data_valid"`
	FileCount     int                `json:"file_count" db:"file_count"`
	SizeBytes     int64              `json:"size_bytes" db:"size_bytes"`
	DurationMs    int                `json:"duration_ms" db:"duration_ms"`
	ErrorMessage  string             `json:"error_message" db:"error_message"`
	Details       json.RawMessage    `json:"details" db:"details"`
	VerifiedBy    *uuid.UUID         `json:"verified_by,omitempty" db:"verified_by"`
	StartedAt     *time.Time         `json:"started_at,omitempty" db:"started_at"`
	CompletedAt   *time.Time         `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt     time.Time          `json:"created_at" db:"created_at"`
}

// BackupVerificationSchedule is a cron-triggered verification policy applied
// to a host's most recent backups.
type BackupVerificationSchedule struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	HostID        uuid.UUID  `json:"host_id" db:"host_id"`
	Schedule      string     `json:"schedule" db:"schedule"`
	Method        string     `json:"method" db:"method"`
	MaxBackups    int        `json:"max_backups" db:"max_backups"`
	Enabled       bool       `json:"enabled" db:"enabled"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty" db:"last_run_at"`
	LastRunStatus string     `json:"last_run_status,omitempty" db:"last_run_status"`
	NextRunAt     *time.Time `json:"next_run_at,omitempty" db:"next_run_at"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
}

// BackupVerificationStats summarizes verifications for a host.
type BackupVerificationStats struct {
	TotalVerified int     `json:"total_verified"`
	PassRate      float64 `json:"pass_rate"`
	LastVerified  string  `json:"last_verified"`
	Passed        int     `json:"passed"`
	Failed        int     `json:"failed"`
}
