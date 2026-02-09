// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

//go:build gcs

package storage

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/services/backup"
)

// GCSStorage implements backup.Storage for Google Cloud Storage.
type GCSStorage struct {
	client     *storage.Client
	bucket     *storage.BucketHandle
	bucketName string
	prefix     string
}

// GCSConfig contains Google Cloud Storage configuration.
type GCSConfig struct {
	// CredentialsJSON is the JSON content of the service account credentials
	CredentialsJSON string

	// CredentialsFile is the path to the service account credentials file
	CredentialsFile string

	// ProjectID is the GCP project ID (optional if using credentials file)
	ProjectID string

	// Bucket is the GCS bucket name
	Bucket string

	// Prefix is the object prefix for all backups
	Prefix string

	// Endpoint is the custom endpoint URL (optional, for emulators)
	Endpoint string
}

// NewGCSStorage creates a new Google Cloud Storage backend.
func NewGCSStorage(ctx context.Context, cfg GCSConfig) (*GCSStorage, error) {
	if cfg.Bucket == "" {
		return nil, errors.New(errors.CodeStorageError, "GCS bucket is required")
	}

	var opts []option.ClientOption

	// Add credentials
	if cfg.CredentialsJSON != "" {
		opts = append(opts, option.WithCredentialsJSON([]byte(cfg.CredentialsJSON)))
	} else if cfg.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(cfg.CredentialsFile))
	}
	// If neither is provided, it will use Application Default Credentials

	// Custom endpoint (for emulators)
	if cfg.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(cfg.Endpoint))
	}

	// Create client
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to create GCS client")
	}

	// Get bucket handle
	bucket := client.Bucket(cfg.Bucket)

	// Verify bucket exists and we have access
	_, err = bucket.Attrs(ctx)
	if err != nil {
		if err == storage.ErrBucketNotExist {
			return nil, errors.New(errors.CodeStorageError, fmt.Sprintf("GCS bucket %s does not exist", cfg.Bucket))
		}
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to access GCS bucket")
	}

	return &GCSStorage{
		client:     client,
		bucket:     bucket,
		bucketName: cfg.Bucket,
		prefix:     strings.TrimPrefix(cfg.Prefix, "/"),
	}, nil
}

// Type returns the storage type identifier.
func (s *GCSStorage) Type() string {
	return "gcs"
}

// Write writes data to GCS.
func (s *GCSStorage) Write(ctx context.Context, path string, reader io.Reader, size int64) error {
	objectName := s.fullObjectName(path)
	obj := s.bucket.Object(objectName)

	// Create writer
	writer := obj.NewWriter(ctx)
	writer.ContentType = "application/octet-stream"

	// Set chunk size for resumable uploads (8MB default is fine for most cases)
	// For very large files, GCS automatically handles resumable uploads

	// Copy data
	written, err := copyWithContext(ctx, writer, reader)
	if err != nil {
		writer.Close()
		return errors.Wrap(err, errors.CodeStorageError, "failed to write backup data")
	}

	// Close writer to finalize upload
	if err := writer.Close(); err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to finalize GCS upload")
	}

	// Verify size if provided
	if size > 0 && written != size {
		// Delete the uploaded object since size doesn't match
		s.bucket.Object(objectName).Delete(ctx)
		return errors.New(errors.CodeStorageError,
			fmt.Sprintf("size mismatch: expected %d, got %d", size, written))
	}

	return nil
}

// Read returns a reader for the backup at path.
func (s *GCSStorage) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	objectName := s.fullObjectName(path)
	obj := s.bucket.Object(objectName)

	reader, err := obj.NewReader(ctx)
	if err != nil {
		if err == storage.ErrObjectNotExist {
			return nil, errors.NotFound("backup")
		}
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to get backup from GCS")
	}

	return reader, nil
}

// Delete removes a backup from GCS.
func (s *GCSStorage) Delete(ctx context.Context, path string) error {
	objectName := s.fullObjectName(path)
	obj := s.bucket.Object(objectName)

	err := obj.Delete(ctx)
	if err != nil {
		if err == storage.ErrObjectNotExist {
			return nil // Already deleted
		}
		return errors.Wrap(err, errors.CodeStorageError, "failed to delete backup from GCS")
	}

	return nil
}

// Exists checks if a backup exists.
func (s *GCSStorage) Exists(ctx context.Context, path string) (bool, error) {
	objectName := s.fullObjectName(path)
	obj := s.bucket.Object(objectName)

	_, err := obj.Attrs(ctx)
	if err != nil {
		if err == storage.ErrObjectNotExist {
			return false, nil
		}
		return false, errors.Wrap(err, errors.CodeStorageError, "failed to check backup existence")
	}

	return true, nil
}

// Size returns the size of a backup in bytes.
func (s *GCSStorage) Size(ctx context.Context, path string) (int64, error) {
	objectName := s.fullObjectName(path)
	obj := s.bucket.Object(objectName)

	attrs, err := obj.Attrs(ctx)
	if err != nil {
		if err == storage.ErrObjectNotExist {
			return 0, errors.NotFound("backup")
		}
		return 0, errors.Wrap(err, errors.CodeStorageError, "failed to get backup size from GCS")
	}

	return attrs.Size, nil
}

// List lists backups with optional prefix.
func (s *GCSStorage) List(ctx context.Context, prefix string) ([]backup.StorageEntry, error) {
	searchPrefix := s.prefix
	if prefix != "" {
		if searchPrefix != "" {
			searchPrefix = searchPrefix + "/" + prefix
		} else {
			searchPrefix = prefix
		}
	}

	var entries []backup.StorageEntry

	query := &storage.Query{
		Prefix: searchPrefix,
	}

	it := s.bucket.Objects(ctx, query)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeStorageError, "failed to list backups from GCS")
		}

		// Get relative path (remove our prefix)
		path := attrs.Name
		if s.prefix != "" {
			path = strings.TrimPrefix(path, s.prefix+"/")
		}

		entries = append(entries, backup.StorageEntry{
			Path:         path,
			Size:         attrs.Size,
			ModTime:      attrs.Updated,
			ETag:         attrs.Etag,
			StorageClass: attrs.StorageClass,
		})
	}

	return entries, nil
}

// Stats returns storage statistics.
func (s *GCSStorage) Stats(ctx context.Context) (*backup.StorageStats, error) {
	var totalSize int64
	var backupCount int64

	query := &storage.Query{
		Prefix: s.prefix,
	}

	it := s.bucket.Objects(ctx, query)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeStorageError, "failed to get GCS stats")
		}

		totalSize += attrs.Size
		backupCount++
	}

	return &backup.StorageStats{
		TotalSpace:     -1, // Unknown for GCS
		UsedSpace:      totalSize,
		AvailableSpace: -1, // Unknown for GCS
		FileCount:      backupCount,
	}, nil
}

// Close releases any resources.
func (s *GCSStorage) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// BucketName returns the GCS bucket name.
func (s *GCSStorage) BucketName() string {
	return s.bucketName
}

// Prefix returns the object prefix.
func (s *GCSStorage) Prefix() string {
	return s.prefix
}

// fullObjectName returns the full GCS object name for a path.
func (s *GCSStorage) fullObjectName(path string) string {
	if s.prefix == "" {
		return path
	}
	return s.prefix + "/" + strings.TrimPrefix(path, "/")
}

// GenerateSignedURL generates a signed URL for downloading a backup.
func (s *GCSStorage) GenerateSignedURL(ctx context.Context, path string, expiry time.Duration) (string, error) {
	objectName := s.fullObjectName(path)

	opts := &storage.SignedURLOptions{
		Method:  "GET",
		Expires: time.Now().Add(expiry),
	}

	// In newer versions of the GCS library, SignedURL is a method on BucketHandle
	url, err := s.bucket.SignedURL(objectName, opts)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeStorageError, "failed to generate signed URL")
	}

	return url, nil
}

// CopyObject copies an object within GCS.
func (s *GCSStorage) CopyObject(ctx context.Context, srcPath, dstPath string) error {
	srcObjectName := s.fullObjectName(srcPath)
	dstObjectName := s.fullObjectName(dstPath)

	src := s.bucket.Object(srcObjectName)
	dst := s.bucket.Object(dstObjectName)

	copier := dst.CopierFrom(src)
	_, err := copier.Run(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to copy GCS object")
	}

	return nil
}

// SetStorageClass changes the storage class of an object.
func (s *GCSStorage) SetStorageClass(ctx context.Context, path string, storageClass string) error {
	objectName := s.fullObjectName(path)
	obj := s.bucket.Object(objectName)

	// Copy object to itself with new storage class
	copier := obj.CopierFrom(obj)
	copier.StorageClass = storageClass

	_, err := copier.Run(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to change storage class")
	}

	return nil
}

// GetObjectMetadata returns metadata for an object.
func (s *GCSStorage) GetObjectMetadata(ctx context.Context, path string) (map[string]string, error) {
	objectName := s.fullObjectName(path)
	obj := s.bucket.Object(objectName)

	attrs, err := obj.Attrs(ctx)
	if err != nil {
		if err == storage.ErrObjectNotExist {
			return nil, errors.NotFound("backup")
		}
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to get object metadata")
	}

	return attrs.Metadata, nil
}

// SetObjectMetadata sets custom metadata for an object.
func (s *GCSStorage) SetObjectMetadata(ctx context.Context, path string, metadata map[string]string) error {
	objectName := s.fullObjectName(path)
	obj := s.bucket.Object(objectName)

	_, err := obj.Update(ctx, storage.ObjectAttrsToUpdate{
		Metadata: metadata,
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to set object metadata")
	}

	return nil
}
