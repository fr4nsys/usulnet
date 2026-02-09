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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/services/backup"
)

// AzureBlobStorage implements backup.Storage for Azure Blob storage.
type AzureBlobStorage struct {
	client          *azblob.Client
	containerClient *container.Client
	containerName   string
	prefix          string
}

// AzureBlobConfig contains Azure Blob storage configuration.
type AzureBlobConfig struct {
	// AccountName is the Azure storage account name
	AccountName string

	// AccountKey is the Azure storage account key
	AccountKey string

	// ConnectionString is the full connection string (alternative to AccountName/Key)
	ConnectionString string

	// ContainerName is the Azure blob container name
	ContainerName string

	// Prefix is the blob prefix for all backups
	Prefix string

	// Endpoint is the custom endpoint URL (optional, for government/China clouds)
	Endpoint string
}

// NewAzureBlobStorage creates a new Azure Blob storage backend.
func NewAzureBlobStorage(ctx context.Context, cfg AzureBlobConfig) (*AzureBlobStorage, error) {
	if cfg.ContainerName == "" {
		return nil, errors.New(errors.CodeStorageError, "Azure container name is required")
	}

	var client *azblob.Client
	var err error

	if cfg.ConnectionString != "" {
		// Use connection string
		client, err = azblob.NewClientFromConnectionString(cfg.ConnectionString, nil)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeStorageError, "failed to create Azure client from connection string")
		}
	} else if cfg.AccountName != "" && cfg.AccountKey != "" {
		// Use account name and key
		cred, err := azblob.NewSharedKeyCredential(cfg.AccountName, cfg.AccountKey)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeStorageError, "failed to create Azure credentials")
		}

		// Build service URL
		serviceURL := cfg.Endpoint
		if serviceURL == "" {
			serviceURL = fmt.Sprintf("https://%s.blob.core.windows.net/", cfg.AccountName)
		}

		client, err = azblob.NewClientWithSharedKeyCredential(serviceURL, cred, nil)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeStorageError, "failed to create Azure client")
		}
	} else {
		return nil, errors.New(errors.CodeStorageError, "Azure connection string or account credentials required")
	}

	// Get container client
	containerClient := client.ServiceClient().NewContainerClient(cfg.ContainerName)

	// Check if container exists, create if not
	_, err = containerClient.GetProperties(ctx, nil)
	if err != nil {
		// Try to create the container
		_, err = containerClient.Create(ctx, nil)
		if err != nil {
			// Check if it's just a conflict (container already exists)
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == 409 {
				// Container exists, that's fine
			} else {
				return nil, errors.Wrap(err, errors.CodeStorageError, "failed to create Azure container")
			}
		}
	}

	return &AzureBlobStorage{
		client:          client,
		containerClient: containerClient,
		containerName:   cfg.ContainerName,
		prefix:          strings.TrimPrefix(cfg.Prefix, "/"),
	}, nil
}

// Type returns the storage type identifier.
func (s *AzureBlobStorage) Type() string {
	return "azure"
}

// Write writes data to Azure Blob storage.
func (s *AzureBlobStorage) Write(ctx context.Context, path string, reader io.Reader, size int64) error {
	blobName := s.fullBlobName(path)
	blobClient := s.containerClient.NewBlockBlobClient(blobName)

	// For small files, use simple upload
	const blockUploadThreshold = 256 * 1024 * 1024 // 256MB (Azure max for single upload)

	if size > 0 && size < blockUploadThreshold {
		// Read all data into memory for single upload
		data, err := io.ReadAll(reader)
		if err != nil {
			return errors.Wrap(err, errors.CodeStorageError, "failed to read backup data")
		}

		_, err = blobClient.Upload(ctx, streaming.NopCloser(bytes.NewReader(data)), &blockblob.UploadOptions{
			HTTPHeaders: &blob.HTTPHeaders{
				BlobContentType: ptrString("application/octet-stream"),
			},
		})
		if err != nil {
			return errors.Wrap(err, errors.CodeStorageError, "failed to upload backup to Azure")
		}

		return nil
	}

	// Use block upload for large files or unknown size
	return s.blockUpload(ctx, blobClient, reader)
}

// blockUpload handles large file uploads using Azure's block blob mechanism.
func (s *AzureBlobStorage) blockUpload(ctx context.Context, blobClient *blockblob.Client, reader io.Reader) error {
	// Azure supports up to 100MB per block, 50000 blocks per blob
	const blockSize = 100 * 1024 * 1024 // 100MB blocks

	var blockIDs []string
	blockNum := 0
	buf := make([]byte, blockSize)

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

		// Generate block ID (must be base64 encoded and consistent length)
		blockID := fmt.Sprintf("%06d", blockNum)

		// Stage block
		_, err = blobClient.StageBlock(ctx, blockID, streaming.NopCloser(bytes.NewReader(buf[:n])), nil)
		if err != nil {
			return errors.Wrap(err, errors.CodeStorageError, "failed to stage block")
		}

		blockIDs = append(blockIDs, blockID)
		blockNum++

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	// Commit block list
	_, err := blobClient.CommitBlockList(ctx, blockIDs, &blockblob.CommitBlockListOptions{
		HTTPHeaders: &blob.HTTPHeaders{
			BlobContentType: ptrString("application/octet-stream"),
		},
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to commit block list")
	}

	return nil
}

// Read returns a reader for the backup at path.
func (s *AzureBlobStorage) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	blobName := s.fullBlobName(path)
	blobClient := s.containerClient.NewBlobClient(blobName)

	resp, err := blobClient.DownloadStream(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == 404 {
			return nil, errors.NotFound("backup")
		}
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to get backup from Azure")
	}

	return resp.Body, nil
}

// Delete removes a backup from Azure Blob storage.
func (s *AzureBlobStorage) Delete(ctx context.Context, path string) error {
	blobName := s.fullBlobName(path)
	blobClient := s.containerClient.NewBlobClient(blobName)

	_, err := blobClient.Delete(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == 404 {
			return nil // Already deleted
		}
		return errors.Wrap(err, errors.CodeStorageError, "failed to delete backup from Azure")
	}

	return nil
}

// Exists checks if a backup exists.
func (s *AzureBlobStorage) Exists(ctx context.Context, path string) (bool, error) {
	blobName := s.fullBlobName(path)
	blobClient := s.containerClient.NewBlobClient(blobName)

	_, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == 404 {
			return false, nil
		}
		return false, errors.Wrap(err, errors.CodeStorageError, "failed to check backup existence")
	}

	return true, nil
}

// Size returns the size of a backup in bytes.
func (s *AzureBlobStorage) Size(ctx context.Context, path string) (int64, error) {
	blobName := s.fullBlobName(path)
	blobClient := s.containerClient.NewBlobClient(blobName)

	props, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == 404 {
			return 0, errors.NotFound("backup")
		}
		return 0, errors.Wrap(err, errors.CodeStorageError, "failed to get backup size from Azure")
	}

	if props.ContentLength != nil {
		return *props.ContentLength, nil
	}
	return 0, nil
}

// List lists backups with optional prefix.
func (s *AzureBlobStorage) List(ctx context.Context, prefix string) ([]backup.StorageEntry, error) {
	searchPrefix := s.prefix
	if prefix != "" {
		if searchPrefix != "" {
			searchPrefix = searchPrefix + "/" + prefix
		} else {
			searchPrefix = prefix
		}
	}

	var entries []backup.StorageEntry

	pager := s.containerClient.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{
		Prefix: &searchPrefix,
	})

	for pager.More() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeStorageError, "failed to list backups from Azure")
		}

		for _, blobItem := range page.Segment.BlobItems {
			if blobItem.Name == nil {
				continue
			}

			// Get relative path (remove our prefix)
			path := *blobItem.Name
			if s.prefix != "" {
				path = strings.TrimPrefix(path, s.prefix+"/")
			}

			var size int64
			if blobItem.Properties != nil && blobItem.Properties.ContentLength != nil {
				size = *blobItem.Properties.ContentLength
			}

			var modTime time.Time
			if blobItem.Properties != nil && blobItem.Properties.LastModified != nil {
				modTime = *blobItem.Properties.LastModified
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
func (s *AzureBlobStorage) Stats(ctx context.Context) (*backup.StorageStats, error) {
	var totalSize int64
	var backupCount int64

	pager := s.containerClient.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{
		Prefix: &s.prefix,
	})

	for pager.More() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeStorageError, "failed to get Azure stats")
		}

		for _, blobItem := range page.Segment.BlobItems {
			if blobItem.Properties != nil && blobItem.Properties.ContentLength != nil {
				totalSize += *blobItem.Properties.ContentLength
			}
			backupCount++
		}
	}

	return &backup.StorageStats{
		TotalSpace:     -1, // Unknown for Azure
		UsedSpace:      totalSize,
		AvailableSpace: -1, // Unknown for Azure
		FileCount:      backupCount,
	}, nil
}

// Close releases any resources.
func (s *AzureBlobStorage) Close() error {
	return nil
}

// ContainerName returns the Azure container name.
func (s *AzureBlobStorage) ContainerName() string {
	return s.containerName
}

// Prefix returns the blob prefix.
func (s *AzureBlobStorage) Prefix() string {
	return s.prefix
}

// fullBlobName returns the full blob name for a path.
func (s *AzureBlobStorage) fullBlobName(path string) string {
	if s.prefix == "" {
		return path
	}
	return s.prefix + "/" + strings.TrimPrefix(path, "/")
}

// GenerateSASURL generates a SAS URL for downloading a backup.
func (s *AzureBlobStorage) GenerateSASURL(ctx context.Context, path string, expiry time.Duration) (string, error) {
	blobName := s.fullBlobName(path)
	blobClient := s.containerClient.NewBlobClient(blobName)

	// Note: To generate SAS URLs, the storage account key is required
	// The SDK requires additional setup for SAS generation
	// For now, return the blob URL (requires public access or Azure AD auth)
	return blobClient.URL(), nil
}

// CopyBlob copies a blob within Azure storage.
func (s *AzureBlobStorage) CopyBlob(ctx context.Context, srcPath, dstPath string) error {
	srcBlobName := s.fullBlobName(srcPath)
	dstBlobName := s.fullBlobName(dstPath)

	srcClient := s.containerClient.NewBlobClient(srcBlobName)
	dstClient := s.containerClient.NewBlobClient(dstBlobName)

	// Start copy operation
	_, err := dstClient.StartCopyFromURL(ctx, srcClient.URL(), nil)
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to copy Azure blob")
	}

	return nil
}

// ptrString returns a pointer to a string.
func ptrString(s string) *string {
	return &s
}
