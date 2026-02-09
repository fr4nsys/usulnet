// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package storage

import (
	"context"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ConnectionRepository persists storage connection metadata.
type ConnectionRepository interface {
	Create(ctx context.Context, conn *models.StorageConnection) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.StorageConnection, error)
	List(ctx context.Context, hostID uuid.UUID) ([]*models.StorageConnection, error)
	Update(ctx context.Context, conn *models.StorageConnection) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.StorageConnectionStatus, msg string) error
	GetDefault(ctx context.Context, hostID uuid.UUID) (*models.StorageConnection, error)
}

// BucketRepository persists tracked bucket metadata.
type BucketRepository interface {
	Upsert(ctx context.Context, bucket *models.StorageBucket) error
	ListByConnection(ctx context.Context, connID uuid.UUID) ([]*models.StorageBucket, error)
	GetByName(ctx context.Context, connID uuid.UUID, name string) (*models.StorageBucket, error)
	Delete(ctx context.Context, connID uuid.UUID, name string) error
	DeleteByConnection(ctx context.Context, connID uuid.UUID) error
	GetStats(ctx context.Context, connID uuid.UUID) (*models.StorageStats, error)
}

// AuditRepository persists storage audit entries.
type AuditRepository interface {
	Create(ctx context.Context, entry *models.StorageAuditLog) error
	List(ctx context.Context, connID uuid.UUID, limit, offset int) ([]*models.StorageAuditLog, int64, error)
}

// Encryptor encrypts/decrypts sensitive fields.
type Encryptor interface {
	EncryptString(plaintext string) (string, error)
	DecryptString(ciphertext string) (string, error)
}

// S3Client abstracts S3-compatible operations.
type S3Client interface {
	Healthy(ctx context.Context) bool
	ListBuckets(ctx context.Context) ([]BucketInfo, error)
	CreateBucket(ctx context.Context, name, region string) error
	DeleteBucket(ctx context.Context, name string) error
	BucketExists(ctx context.Context, name string) (bool, error)
	GetBucketVersioning(ctx context.Context, name string) (bool, error)
	SetBucketVersioning(ctx context.Context, name string, enabled bool) error
	ListObjects(ctx context.Context, bucket, prefix, delimiter string, maxKeys int) (*ListObjectsResult, error)
	GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, *ObjectMeta, error)
	PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, contentType string) error
	DeleteObject(ctx context.Context, bucket, key string) error
	DeleteObjects(ctx context.Context, bucket string, keys []string) error
	CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error
	PresignGetObject(ctx context.Context, bucket, key string, expiry time.Duration) (string, error)
	PresignPutObject(ctx context.Context, bucket, key string, expiry time.Duration) (string, error)
}

// BucketInfo is returned by ListBuckets.
type BucketInfo struct {
	Name      string
	CreatedAt time.Time
}

// ObjectMeta holds metadata returned with GetObject.
type ObjectMeta struct {
	Key           string
	ContentType   string
	ContentLength int64
	ETag          string
	LastModified  time.Time
}

// ListObjectsResult holds the result of listing objects.
type ListObjectsResult struct {
	Objects        []models.StorageObject
	CommonPrefixes []string
	IsTruncated    bool
	NextMarker     string
}
