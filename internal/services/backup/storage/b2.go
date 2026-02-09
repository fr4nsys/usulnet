// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/services/backup"
)

// B2Storage implements backup.Storage for Backblaze B2 storage using S3-compatible API.
type B2Storage struct {
	client *s3.Client
	bucket string
	prefix string
}

// B2Config contains B2 storage configuration.
type B2Config struct {
	// KeyID is the Backblaze B2 Application Key ID
	KeyID string

	// ApplicationKey is the Backblaze B2 Application Key
	ApplicationKey string

	// Bucket is the B2 bucket name
	Bucket string

	// Region is the B2 region (e.g., "us-west-002", "eu-central-003")
	Region string

	// Prefix is the key prefix for all backups
	Prefix string
}

// NewB2Storage creates a new Backblaze B2 storage backend.
func NewB2Storage(ctx context.Context, cfg B2Config) (*B2Storage, error) {
	if cfg.KeyID == "" {
		return nil, errors.New(errors.CodeStorageError, "B2 Key ID is required")
	}
	if cfg.ApplicationKey == "" {
		return nil, errors.New(errors.CodeStorageError, "B2 Application Key is required")
	}
	if cfg.Bucket == "" {
		return nil, errors.New(errors.CodeStorageError, "B2 bucket is required")
	}
	if cfg.Region == "" {
		return nil, errors.New(errors.CodeStorageError, "B2 region is required")
	}

	// Build the S3-compatible endpoint for B2
	// Format: https://s3.<region>.backblazeb2.com
	endpoint := fmt.Sprintf("https://s3.%s.backblazeb2.com", cfg.Region)

	// Build AWS config options
	var opts []func(*config.LoadOptions) error
	opts = append(opts, config.WithRegion(cfg.Region))
	opts = append(opts, config.WithCredentialsProvider(
		credentials.NewStaticCredentialsProvider(cfg.KeyID, cfg.ApplicationKey, ""),
	))

	// Load AWS config
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to load B2 config")
	}

	// Create S3 client with B2 endpoint
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true // B2 requires path-style
	})

	// Verify bucket exists and we have access
	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(cfg.Bucket),
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to access B2 bucket")
	}

	return &B2Storage{
		client: client,
		bucket: cfg.Bucket,
		prefix: strings.TrimPrefix(cfg.Prefix, "/"),
	}, nil
}

// Type returns the storage type identifier.
func (s *B2Storage) Type() string {
	return "b2"
}

// Write writes data to B2 storage.
func (s *B2Storage) Write(ctx context.Context, path string, reader io.Reader, size int64) error {
	key := s.fullKey(path)

	// B2 recommends larger part sizes for multipart uploads
	const multipartThreshold = 100 * 1024 * 1024 // 100MB

	if size > 0 && size < multipartThreshold {
		// Read all data into memory for single-part upload
		data, err := io.ReadAll(reader)
		if err != nil {
			return errors.Wrap(err, errors.CodeStorageError, "failed to read backup data")
		}

		_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(s.bucket),
			Key:           aws.String(key),
			Body:          bytes.NewReader(data),
			ContentLength: aws.Int64(int64(len(data))),
			ContentType:   aws.String("application/octet-stream"),
		})
		if err != nil {
			return errors.Wrap(err, errors.CodeStorageError, "failed to upload backup to B2")
		}

		return nil
	}

	// Use multipart upload for large files or unknown size
	return s.multipartUpload(ctx, key, reader)
}

// multipartUpload handles large file uploads to B2.
func (s *B2Storage) multipartUpload(ctx context.Context, key string, reader io.Reader) error {
	// B2 recommends 100MB parts for optimal performance
	const partSize = 100 * 1024 * 1024 // 100MB parts

	// Start multipart upload
	createResp, err := s.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to start multipart upload")
	}

	uploadID := *createResp.UploadId
	var completedParts []types.CompletedPart
	partNumber := int32(1)

	// Clean up on failure
	defer func() {
		if len(completedParts) == 0 || completedParts[len(completedParts)-1].ETag == nil {
			s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   aws.String(s.bucket),
				Key:      aws.String(key),
				UploadId: aws.String(uploadID),
			})
		}
	}()

	buf := make([]byte, partSize)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := io.ReadFull(reader, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return errors.Wrap(err, errors.CodeStorageError, "failed to read backup data")
		}

		if n == 0 {
			break
		}

		// Upload part
		uploadResp, err := s.client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        aws.String(s.bucket),
			Key:           aws.String(key),
			UploadId:      aws.String(uploadID),
			PartNumber:    aws.Int32(partNumber),
			Body:          bytes.NewReader(buf[:n]),
			ContentLength: aws.Int64(int64(n)),
		})
		if err != nil {
			return errors.Wrap(err, errors.CodeStorageError, "failed to upload part")
		}

		completedParts = append(completedParts, types.CompletedPart{
			ETag:       uploadResp.ETag,
			PartNumber: aws.Int32(partNumber),
		})

		partNumber++

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	// Complete multipart upload
	_, err = s.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(s.bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to complete multipart upload")
	}

	return nil
}

// Read returns a reader for the backup at path.
func (s *B2Storage) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	key := s.fullKey(path)

	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, errors.NotFound("backup")
		}
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to get backup from B2")
	}

	return resp.Body, nil
}

// Delete removes a backup from B2.
func (s *B2Storage) Delete(ctx context.Context, path string) error {
	key := s.fullKey(path)

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to delete backup from B2")
	}

	return nil
}

// Exists checks if a backup exists.
func (s *B2Storage) Exists(ctx context.Context, path string) (bool, error) {
	key := s.fullKey(path)

	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		var notFound *types.NotFound
		if errors.As(err, &nsk) || errors.As(err, &notFound) {
			return false, nil
		}
		return false, errors.Wrap(err, errors.CodeStorageError, "failed to check backup existence")
	}

	return true, nil
}

// Size returns the size of a backup in bytes.
func (s *B2Storage) Size(ctx context.Context, path string) (int64, error) {
	key := s.fullKey(path)

	resp, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return 0, errors.NotFound("backup")
		}
		return 0, errors.Wrap(err, errors.CodeStorageError, "failed to get backup size from B2")
	}

	if resp.ContentLength != nil {
		return *resp.ContentLength, nil
	}
	return 0, nil
}

// List lists backups with optional prefix.
func (s *B2Storage) List(ctx context.Context, prefix string) ([]backup.StorageEntry, error) {
	searchPrefix := s.prefix
	if prefix != "" {
		if searchPrefix != "" {
			searchPrefix = searchPrefix + "/" + prefix
		} else {
			searchPrefix = prefix
		}
	}

	var entries []backup.StorageEntry

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(searchPrefix),
	})

	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeStorageError, "failed to list backups from B2")
		}

		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}

			// Get relative path (remove our prefix)
			path := *obj.Key
			if s.prefix != "" {
				path = strings.TrimPrefix(path, s.prefix+"/")
			}

			var size int64
			if obj.Size != nil {
				size = *obj.Size
			}

			var modTime time.Time
			if obj.LastModified != nil {
				modTime = *obj.LastModified
			}

			entries = append(entries, backup.StorageEntry{
				Path:    path,
				Size:    size,
				ModTime: modTime,
			})
		}
	}

	return entries, nil
}

// Stats returns storage statistics.
func (s *B2Storage) Stats(ctx context.Context) (*backup.StorageStats, error) {
	var totalSize int64
	var backupCount int64

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(s.prefix),
	})

	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeStorageError, "failed to get B2 stats")
		}

		for _, obj := range page.Contents {
			if obj.Size != nil {
				totalSize += *obj.Size
			}
			backupCount++
		}
	}

	return &backup.StorageStats{
		TotalSpace:     -1, // Unknown for B2
		UsedSpace:      totalSize,
		AvailableSpace: -1, // Unknown for B2
		FileCount:      backupCount,
	}, nil
}

// Close releases any resources.
func (s *B2Storage) Close() error {
	return nil
}

// Bucket returns the B2 bucket name.
func (s *B2Storage) Bucket() string {
	return s.bucket
}

// Prefix returns the key prefix.
func (s *B2Storage) Prefix() string {
	return s.prefix
}

// fullKey returns the full B2 key for a path.
func (s *B2Storage) fullKey(path string) string {
	if s.prefix == "" {
		return path
	}
	return s.prefix + "/" + strings.TrimPrefix(path, "/")
}

// GeneratePresignedURL generates a presigned URL for downloading a backup.
func (s *B2Storage) GeneratePresignedURL(ctx context.Context, path string, expiry time.Duration) (string, error) {
	key := s.fullKey(path)

	presignClient := s3.NewPresignClient(s.client)
	req, err := presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = expiry
	})
	if err != nil {
		return "", errors.Wrap(err, errors.CodeStorageError, "failed to generate presigned URL")
	}

	return req.URL, nil
}

// CopyObject copies an object within B2.
func (s *B2Storage) CopyObject(ctx context.Context, srcPath, dstPath string) error {
	srcKey := s.fullKey(srcPath)
	dstKey := s.fullKey(dstPath)

	_, err := s.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(s.bucket),
		CopySource: aws.String(fmt.Sprintf("%s/%s", s.bucket, srcKey)),
		Key:        aws.String(dstKey),
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to copy B2 object")
	}

	return nil
}
