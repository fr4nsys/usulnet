// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Config holds storage service configuration.
type Config struct {
	DefaultHostID uuid.UUID
}

// Service manages S3-compatible storage connections and operations.
type Service struct {
	connRepo      ConnectionRepository
	bucketRepo    BucketRepository
	auditRepo     AuditRepository
	encryptor     Encryptor
	config        Config
	logger        *logger.Logger
	limitMu       sync.RWMutex
	limitProvider license.LimitProvider

	mu      sync.RWMutex
	clients map[uuid.UUID]S3Client
}

// SetLimitProvider sets the license limit provider for enforcing MaxS3Connections.
// Thread-safe: may be called while goroutines read limitProvider.
func (s *Service) SetLimitProvider(lp license.LimitProvider) {
	s.limitMu.Lock()
	s.limitProvider = lp
	s.limitMu.Unlock()
}

// NewService creates a new storage service.
func NewService(
	connRepo ConnectionRepository,
	bucketRepo BucketRepository,
	auditRepo AuditRepository,
	encryptor Encryptor,
	cfg Config,
	log *logger.Logger,
) *Service {
	return &Service{
		connRepo:   connRepo,
		bucketRepo: bucketRepo,
		auditRepo:  auditRepo,
		encryptor:  encryptor,
		config:     cfg,
		logger:     log.Named("storage"),
		clients:    make(map[uuid.UUID]S3Client),
	}
}

// ============================================================================
// Connection CRUD
// ============================================================================

// CreateConnection creates, encrypts credentials, and tests a storage connection.
func (s *Service) CreateConnection(ctx context.Context, input models.CreateStorageConnectionInput, userID string) (*models.StorageConnection, error) {
	// Enforce MaxS3Connections license limit
	s.limitMu.RLock()
	lp := s.limitProvider
	s.limitMu.RUnlock()
	if lp != nil {
		limit := lp.GetLimits().MaxS3Connections
		if limit > 0 {
			existing, err := s.connRepo.List(ctx, s.config.DefaultHostID)
			if err == nil && len(existing) >= limit {
				return nil, errors.NewWithStatus(errors.CodeLimitExceeded,
					fmt.Sprintf("storage connection limit reached (%d/%d), upgrade your license for more", len(existing), limit), 402)
			}
		}
	}

	encAccess, err := s.encryptor.EncryptString(input.AccessKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt access key")
	}
	encSecret, err := s.encryptor.EncryptString(input.SecretKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt secret key")
	}

	region := input.Region
	if region == "" {
		region = "us-east-1"
	}

	conn := &models.StorageConnection{
		HostID:       s.config.DefaultHostID,
		Name:         input.Name,
		Endpoint:     input.Endpoint,
		Region:       region,
		AccessKey:    encAccess,
		SecretKey:    encSecret,
		UsePathStyle: input.UsePathStyle,
		UseSSL:       input.UseSSL,
		IsDefault:    input.IsDefault,
		Status:       models.StorageConnectionPending,
		CreatedBy:    userID,
	}

	if err := s.connRepo.Create(ctx, conn); err != nil {
		return nil, err
	}

	// Test connectivity
	client, err := s.buildClient(ctx, conn, input.AccessKey, input.SecretKey)
	if err != nil {
		_ = s.connRepo.UpdateStatus(ctx, conn.ID, models.StorageConnectionError, err.Error())
		conn.Status = models.StorageConnectionError
		conn.StatusMsg = err.Error()
	} else if !client.Healthy(ctx) {
		_ = s.connRepo.UpdateStatus(ctx, conn.ID, models.StorageConnectionError, "connection test failed")
		conn.Status = models.StorageConnectionError
		conn.StatusMsg = "connection test failed"
	} else {
		_ = s.connRepo.UpdateStatus(ctx, conn.ID, models.StorageConnectionActive, "")
		conn.Status = models.StorageConnectionActive
	}

	s.audit(ctx, conn.ID, "create", "connection", conn.Name, userID, nil)
	return conn, nil
}

// GetConnection retrieves a connection by ID.
func (s *Service) GetConnection(ctx context.Context, id uuid.UUID) (*models.StorageConnection, error) {
	return s.connRepo.GetByID(ctx, id)
}

// ListConnections returns all connections for the default host.
func (s *Service) ListConnections(ctx context.Context) ([]*models.StorageConnection, error) {
	return s.connRepo.List(ctx, s.config.DefaultHostID)
}

// UpdateConnection updates a connection and invalidates cached client.
func (s *Service) UpdateConnection(ctx context.Context, id uuid.UUID, input models.UpdateStorageConnectionInput, userID string) (*models.StorageConnection, error) {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		conn.Name = *input.Name
	}
	if input.Endpoint != nil {
		conn.Endpoint = *input.Endpoint
	}
	if input.Region != nil {
		conn.Region = *input.Region
	}
	if input.UsePathStyle != nil {
		conn.UsePathStyle = *input.UsePathStyle
	}
	if input.UseSSL != nil {
		conn.UseSSL = *input.UseSSL
	}
	if input.IsDefault != nil {
		conn.IsDefault = *input.IsDefault
	}
	if input.AccessKey != nil {
		enc, err := s.encryptor.EncryptString(*input.AccessKey)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt access key")
		}
		conn.AccessKey = enc
	}
	if input.SecretKey != nil {
		enc, err := s.encryptor.EncryptString(*input.SecretKey)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeEncryptionFailed, "failed to encrypt secret key")
		}
		conn.SecretKey = enc
	}

	if err := s.connRepo.Update(ctx, conn); err != nil {
		return nil, err
	}

	// Invalidate cached client
	s.mu.Lock()
	delete(s.clients, id)
	s.mu.Unlock()

	s.audit(ctx, id, "update", "connection", conn.Name, userID, nil)
	return conn, nil
}

// DeleteConnection removes a connection and associated data.
func (s *Service) DeleteConnection(ctx context.Context, id uuid.UUID, userID string) error {
	conn, err := s.connRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	_ = s.bucketRepo.DeleteByConnection(ctx, id)

	if err := s.connRepo.Delete(ctx, id); err != nil {
		return err
	}

	s.mu.Lock()
	delete(s.clients, id)
	s.mu.Unlock()

	s.audit(ctx, id, "delete", "connection", conn.Name, userID, nil)
	return nil
}

// TestConnection verifies connectivity and updates status.
func (s *Service) TestConnection(ctx context.Context, id uuid.UUID) error {
	client, err := s.clientFor(ctx, id)
	if err != nil {
		_ = s.connRepo.UpdateStatus(ctx, id, models.StorageConnectionError, err.Error())
		return err
	}
	if !client.Healthy(ctx) {
		msg := "connection test failed"
		_ = s.connRepo.UpdateStatus(ctx, id, models.StorageConnectionError, msg)
		return errors.New(errors.CodeStorageError, msg)
	}
	_ = s.connRepo.UpdateStatus(ctx, id, models.StorageConnectionActive, "")
	return nil
}

// ============================================================================
// Bucket Operations
// ============================================================================

// ListBuckets lists buckets from S3 and syncs metadata to DB.
func (s *Service) ListBuckets(ctx context.Context, connID uuid.UUID) ([]*models.StorageBucket, error) {
	client, err := s.clientFor(ctx, connID)
	if err != nil {
		return s.bucketRepo.ListByConnection(ctx, connID)
	}

	infos, err := client.ListBuckets(ctx)
	if err != nil {
		s.logger.Warn("S3 list failed, using cache", "error", err)
		return s.bucketRepo.ListByConnection(ctx, connID)
	}

	now := time.Now()
	for _, bi := range infos {
		bucket := &models.StorageBucket{
			ID:           uuid.New(),
			ConnectionID: connID,
			Name:         bi.Name,
			CreatedAt:    bi.CreatedAt,
			LastSynced:   &now,
			Tags:         "{}",
		}
		if v, err := client.GetBucketVersioning(ctx, bi.Name); err == nil {
			bucket.Versioning = v
		}
		_ = s.bucketRepo.Upsert(ctx, bucket)
	}

	return s.bucketRepo.ListByConnection(ctx, connID)
}

// CreateBucket creates a bucket on S3 and tracks it.
func (s *Service) CreateBucket(ctx context.Context, connID uuid.UUID, input models.CreateBucketInput, userID string) error {
	client, err := s.clientFor(ctx, connID)
	if err != nil {
		return err
	}

	conn, err := s.connRepo.GetByID(ctx, connID)
	if err != nil {
		return err
	}
	region := input.Region
	if region == "" {
		region = conn.Region
	}

	if err := client.CreateBucket(ctx, input.Name, region); err != nil {
		return err
	}

	if input.Versioning {
		if err := client.SetBucketVersioning(ctx, input.Name, true); err != nil {
			s.logger.Warn("bucket created but versioning failed", "bucket", input.Name, "error", err)
		}
	}

	now := time.Now()
	_ = s.bucketRepo.Upsert(ctx, &models.StorageBucket{
		ID:           uuid.New(),
		ConnectionID: connID,
		Name:         input.Name,
		Region:       region,
		IsPublic:     input.IsPublic,
		Versioning:   input.Versioning,
		Tags:         "{}",
		CreatedAt:    now,
		LastSynced:   &now,
	})

	s.audit(ctx, connID, "create_bucket", "bucket", input.Name, userID, nil)
	return nil
}

// DeleteBucket deletes a bucket from S3 and removes tracking.
func (s *Service) DeleteBucket(ctx context.Context, connID uuid.UUID, name, userID string) error {
	client, err := s.clientFor(ctx, connID)
	if err != nil {
		return err
	}
	if err := client.DeleteBucket(ctx, name); err != nil {
		return err
	}
	_ = s.bucketRepo.Delete(ctx, connID, name)
	s.audit(ctx, connID, "delete_bucket", "bucket", name, userID, nil)
	return nil
}

// GetBucketStats retrieves aggregate stats.
func (s *Service) GetBucketStats(ctx context.Context, connID uuid.UUID) (*models.StorageStats, error) {
	return s.bucketRepo.GetStats(ctx, connID)
}

// ============================================================================
// Object Operations
// ============================================================================

// ListObjects lists objects with directory-style navigation.
func (s *Service) ListObjects(ctx context.Context, connID uuid.UUID, bucket, prefix string) (*ListObjectsResult, error) {
	client, err := s.clientFor(ctx, connID)
	if err != nil {
		return nil, err
	}
	return client.ListObjects(ctx, bucket, prefix, "/", 1000)
}

// GetObject returns an object's content and metadata.
func (s *Service) GetObject(ctx context.Context, connID uuid.UUID, bucket, key string) (io.ReadCloser, *ObjectMeta, error) {
	client, err := s.clientFor(ctx, connID)
	if err != nil {
		return nil, nil, err
	}
	return client.GetObject(ctx, bucket, key)
}

// UploadObject uploads a file to a bucket.
func (s *Service) UploadObject(ctx context.Context, connID uuid.UUID, bucket, key string, reader io.Reader, size int64, contentType, userID string) error {
	client, err := s.clientFor(ctx, connID)
	if err != nil {
		return err
	}
	if err := client.PutObject(ctx, bucket, key, reader, size, contentType); err != nil {
		return err
	}
	s.audit(ctx, connID, "upload", "object", bucket+"/"+key, userID, map[string]interface{}{
		"size": size, "content_type": contentType,
	})
	return nil
}

// DeleteObject removes a single object.
func (s *Service) DeleteObject(ctx context.Context, connID uuid.UUID, bucket, key, userID string) error {
	client, err := s.clientFor(ctx, connID)
	if err != nil {
		return err
	}
	if err := client.DeleteObject(ctx, bucket, key); err != nil {
		return err
	}
	s.audit(ctx, connID, "delete", "object", bucket+"/"+key, userID, nil)
	return nil
}

// DeleteObjects removes multiple objects in batch.
func (s *Service) DeleteObjects(ctx context.Context, connID uuid.UUID, bucket string, keys []string, userID string) error {
	client, err := s.clientFor(ctx, connID)
	if err != nil {
		return err
	}
	if err := client.DeleteObjects(ctx, bucket, keys); err != nil {
		return err
	}
	s.audit(ctx, connID, "delete_batch", "object", fmt.Sprintf("%s (%d objects)", bucket, len(keys)), userID, nil)
	return nil
}

// CreateFolder creates a folder marker.
func (s *Service) CreateFolder(ctx context.Context, connID uuid.UUID, bucket, prefix, userID string) error {
	client, err := s.clientFor(ctx, connID)
	if err != nil {
		return err
	}
	if err := CreateFolder(ctx, client, bucket, prefix); err != nil {
		return err
	}
	s.audit(ctx, connID, "create_folder", "object", bucket+"/"+prefix, userID, nil)
	return nil
}

// PresignDownload generates a time-limited download URL.
func (s *Service) PresignDownload(ctx context.Context, connID uuid.UUID, bucket, key string, expiry time.Duration) (string, error) {
	client, err := s.clientFor(ctx, connID)
	if err != nil {
		return "", err
	}
	return client.PresignGetObject(ctx, bucket, key, expiry)
}

// PresignUpload generates a time-limited upload URL.
func (s *Service) PresignUpload(ctx context.Context, connID uuid.UUID, bucket, key string, expiry time.Duration) (string, error) {
	client, err := s.clientFor(ctx, connID)
	if err != nil {
		return "", err
	}
	return client.PresignPutObject(ctx, bucket, key, expiry)
}

// ============================================================================
// Audit
// ============================================================================

// ListAuditLogs retrieves audit entries for a connection.
func (s *Service) ListAuditLogs(ctx context.Context, connID uuid.UUID, limit, offset int) ([]*models.StorageAuditLog, int64, error) {
	return s.auditRepo.List(ctx, connID, limit, offset)
}

// ============================================================================
// Internal
// ============================================================================

func (s *Service) clientFor(ctx context.Context, connID uuid.UUID) (S3Client, error) {
	s.mu.RLock()
	if c, ok := s.clients[connID]; ok {
		s.mu.RUnlock()
		return c, nil
	}
	s.mu.RUnlock()

	conn, err := s.connRepo.GetByID(ctx, connID)
	if err != nil {
		return nil, err
	}

	accessKey, err := s.encryptor.DecryptString(conn.AccessKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDecryptionFailed, "failed to decrypt access key")
	}
	secretKey, err := s.encryptor.DecryptString(conn.SecretKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDecryptionFailed, "failed to decrypt secret key")
	}

	return s.buildClient(ctx, conn, accessKey, secretKey)
}

func (s *Service) buildClient(ctx context.Context, conn *models.StorageConnection, accessKey, secretKey string) (S3Client, error) {
	client, err := NewS3Client(ctx, S3ClientConfig{
		Endpoint:     conn.Endpoint,
		Region:       conn.Region,
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		UsePathStyle: conn.UsePathStyle,
		UseSSL:       conn.UseSSL,
	})
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.clients[conn.ID] = client
	s.mu.Unlock()

	return client, nil
}

func (s *Service) audit(ctx context.Context, connID uuid.UUID, action, resourceType, resourceName, userID string, details map[string]interface{}) {
	detailsJSON := "{}"
	if details != nil {
		if b, err := json.Marshal(details); err == nil {
			detailsJSON = string(b)
		}
	}
	entry := &models.StorageAuditLog{
		ConnectionID: connID,
		Action:       action,
		ResourceType: resourceType,
		ResourceName: resourceName,
		Details:      detailsJSON,
		UserID:       userID,
	}
	if err := s.auditRepo.Create(ctx, entry); err != nil {
		s.logger.Warn("audit log failed", "action", action, "error", err)
	}
}
