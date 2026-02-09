// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// StorageConnectionStatus represents the status of a storage connection.
type StorageConnectionStatus string

const (
	StorageConnectionActive       StorageConnectionStatus = "active"
	StorageConnectionInactive     StorageConnectionStatus = "inactive"
	StorageConnectionError        StorageConnectionStatus = "error"
	StorageConnectionPending      StorageConnectionStatus = "pending"
)

// StorageConnection represents a connection to an S3-compatible storage service.
type StorageConnection struct {
	ID           uuid.UUID               `db:"id" json:"id"`
	HostID       uuid.UUID               `db:"host_id" json:"host_id"`
	Name         string                  `db:"name" json:"name"`
	Endpoint     string                  `db:"endpoint" json:"endpoint"`
	Region       string                  `db:"region" json:"region"`
	AccessKey    string                  `db:"access_key" json:"-"`
	SecretKey    string                  `db:"secret_key" json:"-"`
	UsePathStyle bool                    `db:"use_path_style" json:"use_path_style"`
	UseSSL       bool                    `db:"use_ssl" json:"use_ssl"`
	IsDefault    bool                    `db:"is_default" json:"is_default"`
	Status       StorageConnectionStatus `db:"status" json:"status"`
	StatusMsg    string                  `db:"status_message" json:"status_message,omitempty"`
	CreatedAt    time.Time               `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time               `db:"updated_at" json:"updated_at"`
	CreatedBy    string                  `db:"created_by" json:"created_by"`
	LastChecked  *time.Time              `db:"last_checked" json:"last_checked,omitempty"`
}

// StorageBucket represents a tracked S3 bucket.
type StorageBucket struct {
	ID           uuid.UUID `db:"id" json:"id"`
	ConnectionID uuid.UUID `db:"connection_id" json:"connection_id"`
	Name         string    `db:"name" json:"name"`
	Region       string    `db:"region" json:"region"`
	SizeBytes    int64     `db:"size_bytes" json:"size_bytes"`
	ObjectCount  int64     `db:"object_count" json:"object_count"`
	IsPublic     bool      `db:"is_public" json:"is_public"`
	Versioning   bool      `db:"versioning" json:"versioning"`
	Tags         string    `db:"tags" json:"tags,omitempty"` // JSON
	CreatedAt    time.Time `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time `db:"updated_at" json:"updated_at"`
	LastSynced   *time.Time `db:"last_synced" json:"last_synced,omitempty"`
}

// StorageObject represents an object in a bucket (not persisted, fetched from S3).
type StorageObject struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
	ETag         string    `json:"etag"`
	ContentType  string    `json:"content_type"`
	StorageClass string    `json:"storage_class"`
	IsDir        bool      `json:"is_dir"`
}

// StorageAuditLog represents an audit entry for storage operations.
type StorageAuditLog struct {
	ID           uuid.UUID `db:"id" json:"id"`
	ConnectionID uuid.UUID `db:"connection_id" json:"connection_id"`
	Action       string    `db:"action" json:"action"` // create_bucket, delete_bucket, upload, delete, etc.
	ResourceType string    `db:"resource_type" json:"resource_type"` // connection, bucket, object
	ResourceName string    `db:"resource_name" json:"resource_name"`
	Details      string    `db:"details" json:"details,omitempty"` // JSON
	UserID       string    `db:"user_id" json:"user_id"`
	CreatedAt    time.Time `db:"created_at" json:"created_at"`
}

// CreateStorageConnectionInput is the input for creating a connection.
type CreateStorageConnectionInput struct {
	Name         string `json:"name" validate:"required,max=100"`
	Endpoint     string `json:"endpoint" validate:"required"`
	Region       string `json:"region"`
	AccessKey    string `json:"access_key" validate:"required"`
	SecretKey    string `json:"secret_key" validate:"required"`
	UsePathStyle bool   `json:"use_path_style"`
	UseSSL       bool   `json:"use_ssl"`
	IsDefault    bool   `json:"is_default"`
}

// UpdateStorageConnectionInput is the input for updating a connection.
type UpdateStorageConnectionInput struct {
	Name         *string `json:"name,omitempty"`
	Endpoint     *string `json:"endpoint,omitempty"`
	Region       *string `json:"region,omitempty"`
	AccessKey    *string `json:"access_key,omitempty"`
	SecretKey    *string `json:"secret_key,omitempty"`
	UsePathStyle *bool   `json:"use_path_style,omitempty"`
	UseSSL       *bool   `json:"use_ssl,omitempty"`
	IsDefault    *bool   `json:"is_default,omitempty"`
}

// CreateBucketInput is the input for creating a bucket.
type CreateBucketInput struct {
	Name       string `json:"name" validate:"required,min=3,max=63"`
	Region     string `json:"region"`
	IsPublic   bool   `json:"is_public"`
	Versioning bool   `json:"versioning"`
}

// PresignedURLRequest is the input for generating a presigned URL.
type PresignedURLRequest struct {
	BucketName string        `json:"bucket_name" validate:"required"`
	ObjectKey  string        `json:"object_key" validate:"required"`
	Expiry     time.Duration `json:"expiry"` // defaults to 1h
	Operation  string        `json:"operation"` // "get" or "put"
}

// StorageStats holds stats for a storage connection.
type StorageStats struct {
	TotalBuckets int64 `json:"total_buckets"`
	TotalSize    int64 `json:"total_size"`
	TotalObjects int64 `json:"total_objects"`
}
