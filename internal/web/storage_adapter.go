// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	storagesvc "github.com/fr4nsys/usulnet/internal/services/storage"
)

// storageAdapter bridges storage.Service to the web StorageService interface.
type storageAdapter struct {
	svc *storagesvc.Service
}

func (a *storageAdapter) ListConnections(ctx context.Context) ([]StorageConnectionView, error) {
	conns, err := a.svc.ListConnections(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]StorageConnectionView, 0, len(conns))
	for _, c := range conns {
		v := connToView(c)
		// Fetch stats
		if stats, err := a.svc.GetBucketStats(ctx, c.ID); err == nil {
			v.BucketCount = stats.TotalBuckets
			v.TotalSize = stats.TotalSize
			v.TotalObjects = stats.TotalObjects
		}
		views = append(views, v)
	}
	return views, nil
}

func (a *storageAdapter) GetConnection(connID string) (*StorageConnectionView, error) {
	id, err := uuid.Parse(connID)
	if err != nil {
		return nil, fmt.Errorf("invalid connection ID: %s", connID)
	}
	ctx := context.Background()
	c, err := a.svc.GetConnection(ctx, id)
	if err != nil {
		return nil, err
	}
	v := connToView(c)
	if stats, err := a.svc.GetBucketStats(ctx, c.ID); err == nil {
		v.BucketCount = stats.TotalBuckets
		v.TotalSize = stats.TotalSize
		v.TotalObjects = stats.TotalObjects
	}
	return &v, nil
}

func (a *storageAdapter) CreateConnection(ctx context.Context, name, endpoint, region, accessKey, secretKey string, usePathStyle, useSSL, isDefault bool, userID string) (*StorageConnectionView, error) {
	input := models.CreateStorageConnectionInput{
		Name:         name,
		Endpoint:     endpoint,
		Region:       region,
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		UsePathStyle: usePathStyle,
		UseSSL:       useSSL,
		IsDefault:    isDefault,
	}
	conn, err := a.svc.CreateConnection(ctx, input, userID)
	if err != nil {
		return nil, err
	}
	v := connToView(conn)
	return &v, nil
}

func (a *storageAdapter) UpdateConnection(ctx context.Context, connID string, name, endpoint, region, accessKey, secretKey *string, usePathStyle, useSSL, isDefault *bool, userID string) error {
	id, err := uuid.Parse(connID)
	if err != nil {
		return fmt.Errorf("invalid connection ID: %s", connID)
	}
	input := models.UpdateStorageConnectionInput{
		Name:         name,
		Endpoint:     endpoint,
		Region:       region,
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		UsePathStyle: usePathStyle,
		UseSSL:       useSSL,
		IsDefault:    isDefault,
	}
	_, err = a.svc.UpdateConnection(ctx, id, input, userID)
	return err
}

func (a *storageAdapter) DeleteConnection(ctx context.Context, connID, userID string) error {
	id, err := uuid.Parse(connID)
	if err != nil {
		return fmt.Errorf("invalid connection ID: %s", connID)
	}
	return a.svc.DeleteConnection(ctx, id, userID)
}

func (a *storageAdapter) TestConnection(ctx context.Context, connID string) error {
	id, err := uuid.Parse(connID)
	if err != nil {
		return fmt.Errorf("invalid connection ID: %s", connID)
	}
	return a.svc.TestConnection(ctx, id)
}

func (a *storageAdapter) ListBuckets(ctx context.Context, connID string) ([]StorageBucketView, error) {
	id, err := uuid.Parse(connID)
	if err != nil {
		return nil, fmt.Errorf("invalid connection ID: %s", connID)
	}
	buckets, err := a.svc.ListBuckets(ctx, id)
	if err != nil {
		return nil, err
	}
	views := make([]StorageBucketView, 0, len(buckets))
	for _, b := range buckets {
		views = append(views, bucketToView(b))
	}
	return views, nil
}

func (a *storageAdapter) CreateBucket(ctx context.Context, connID, name, region string, isPublic, versioning bool, userID string) error {
	id, err := uuid.Parse(connID)
	if err != nil {
		return fmt.Errorf("invalid connection ID: %s", connID)
	}
	return a.svc.CreateBucket(ctx, id, models.CreateBucketInput{
		Name:       name,
		Region:     region,
		IsPublic:   isPublic,
		Versioning: versioning,
	}, userID)
}

func (a *storageAdapter) DeleteBucket(ctx context.Context, connID, name, userID string) error {
	id, err := uuid.Parse(connID)
	if err != nil {
		return fmt.Errorf("invalid connection ID: %s", connID)
	}
	return a.svc.DeleteBucket(ctx, id, name, userID)
}

func (a *storageAdapter) ListObjects(ctx context.Context, connID, bucket, prefix string) ([]StorageObjectView, error) {
	id, err := uuid.Parse(connID)
	if err != nil {
		return nil, fmt.Errorf("invalid connection ID: %s", connID)
	}
	result, err := a.svc.ListObjects(ctx, id, bucket, prefix)
	if err != nil {
		return nil, err
	}

	views := make([]StorageObjectView, 0, len(result.CommonPrefixes)+len(result.Objects))

	// Folders first
	for _, cp := range result.CommonPrefixes {
		name := cp
		if prefix != "" {
			name = strings.TrimPrefix(cp, prefix)
		}
		name = strings.TrimSuffix(name, "/")
		views = append(views, StorageObjectView{
			Key:   cp,
			Name:  name,
			IsDir: true,
		})
	}

	// Files
	for _, obj := range result.Objects {
		// Skip the prefix itself (folder marker)
		if obj.Key == prefix {
			continue
		}
		name := path.Base(obj.Key)
		views = append(views, StorageObjectView{
			Key:          obj.Key,
			Name:         name,
			Size:         obj.Size,
			SizeHuman:    humanizeBytes(obj.Size),
			LastModified: obj.LastModified.Format("2006-01-02 15:04"),
			ETag:         obj.ETag,
			ContentType:  obj.ContentType,
			StorageClass: obj.StorageClass,
			IsDir:        false,
		})
	}

	return views, nil
}

func (a *storageAdapter) UploadObject(ctx context.Context, connID, bucket, key string, reader io.Reader, size int64, contentType, userID string) error {
	id, err := uuid.Parse(connID)
	if err != nil {
		return fmt.Errorf("invalid connection ID: %s", connID)
	}
	return a.svc.UploadObject(ctx, id, bucket, key, reader, size, contentType, userID)
}

func (a *storageAdapter) DeleteObject(ctx context.Context, connID, bucket, key, userID string) error {
	id, err := uuid.Parse(connID)
	if err != nil {
		return fmt.Errorf("invalid connection ID: %s", connID)
	}
	return a.svc.DeleteObject(ctx, id, bucket, key, userID)
}

func (a *storageAdapter) CreateFolder(ctx context.Context, connID, bucket, prefix, userID string) error {
	id, err := uuid.Parse(connID)
	if err != nil {
		return fmt.Errorf("invalid connection ID: %s", connID)
	}
	return a.svc.CreateFolder(ctx, id, bucket, prefix, userID)
}

func (a *storageAdapter) PresignDownload(ctx context.Context, connID, bucket, key string) (string, error) {
	id, err := uuid.Parse(connID)
	if err != nil {
		return "", fmt.Errorf("invalid connection ID: %s", connID)
	}
	return a.svc.PresignDownload(ctx, id, bucket, key, time.Hour)
}

func (a *storageAdapter) PresignUpload(ctx context.Context, connID, bucket, key string) (string, error) {
	id, err := uuid.Parse(connID)
	if err != nil {
		return "", fmt.Errorf("invalid connection ID: %s", connID)
	}
	return a.svc.PresignUpload(ctx, id, bucket, key, time.Hour)
}

func (a *storageAdapter) ListAuditLogs(ctx context.Context, connID string, limit, offset int) ([]StorageAuditView, int64, error) {
	id, err := uuid.Parse(connID)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid connection ID: %s", connID)
	}
	entries, total, err := a.svc.ListAuditLogs(ctx, id, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	views := make([]StorageAuditView, 0, len(entries))
	for _, e := range entries {
		views = append(views, StorageAuditView{
			Action:       e.Action,
			ResourceType: e.ResourceType,
			ResourceName: e.ResourceName,
			UserID:       e.UserID,
			CreatedAt:    e.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return views, total, nil
}

// ============================================================================
// Helpers
// ============================================================================

func connToView(c *models.StorageConnection) StorageConnectionView {
	v := StorageConnectionView{
		ID:           c.ID.String(),
		Name:         c.Name,
		Endpoint:     c.Endpoint,
		Region:       c.Region,
		UsePathStyle: c.UsePathStyle,
		UseSSL:       c.UseSSL,
		IsDefault:    c.IsDefault,
		Status:       string(c.Status),
		StatusMsg:    c.StatusMsg,
		CreatedAt:    c.CreatedAt.Format("2006-01-02 15:04"),
	}
	if c.LastChecked != nil {
		v.LastChecked = c.LastChecked.Format("2006-01-02 15:04")
	}
	return v
}

func bucketToView(b *models.StorageBucket) StorageBucketView {
	v := StorageBucketView{
		Name:        b.Name,
		Region:      b.Region,
		SizeBytes:   b.SizeBytes,
		SizeHuman:   humanizeBytes(b.SizeBytes),
		ObjectCount: b.ObjectCount,
		IsPublic:    b.IsPublic,
		Versioning:  b.Versioning,
		CreatedAt:   b.CreatedAt.Format("2006-01-02 15:04"),
	}
	if b.LastSynced != nil {
		v.LastSynced = b.LastSynced.Format("2006-01-02 15:04")
	}
	return v
}

func humanizeBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
