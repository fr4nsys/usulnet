// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/services/backup"
)

// LocalStorage implements backup.Storage for local filesystem storage.
type LocalStorage struct {
	basePath string
}

// NewLocalStorage creates a new local storage backend.
func NewLocalStorage(basePath string) (*LocalStorage, error) {
	// Ensure base path is absolute
	absPath, err := filepath.Abs(basePath)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "invalid storage path")
	}

	// Create base directory if it doesn't exist
	if err := os.MkdirAll(absPath, 0755); err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to create storage directory")
	}

	// Verify we can write to the directory
	testFile := filepath.Join(absPath, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "storage directory is not writable")
	}
	os.Remove(testFile)

	return &LocalStorage{
		basePath: absPath,
	}, nil
}

// Type returns the storage type identifier.
func (s *LocalStorage) Type() string {
	return "local"
}

// Write writes data to storage.
func (s *LocalStorage) Write(ctx context.Context, path string, reader io.Reader, size int64) error {
	// Validate path
	fullPath, err := s.resolvePath(path)
	if err != nil {
		return err
	}

	// Create parent directory
	parentDir := filepath.Dir(fullPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to create parent directory")
	}

	// Create temporary file in same directory (for atomic write)
	tmpFile, err := os.CreateTemp(parentDir, ".backup_tmp_*")
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to create temporary file")
	}
	tmpPath := tmpFile.Name()

	// Clean up temp file on error
	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath)
		}
	}()

	// Copy data to temp file
	written, err := copyWithContext(ctx, tmpFile, reader)
	if err != nil {
		tmpFile.Close()
		return errors.Wrap(err, errors.CodeStorageError, "failed to write backup data")
	}

	// Sync to disk
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return errors.Wrap(err, errors.CodeStorageError, "failed to sync backup data")
	}
	tmpFile.Close()

	// Verify size if provided
	if size > 0 && written != size {
		return errors.New(errors.CodeStorageError,
			fmt.Sprintf("size mismatch: expected %d, got %d", size, written))
	}

	// Atomic rename
	if err := os.Rename(tmpPath, fullPath); err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to finalize backup file")
	}

	success = true
	return nil
}

// Read returns a reader for the backup at path.
func (s *LocalStorage) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	fullPath, err := s.resolvePath(path)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.NotFound("backup")
		}
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to open backup file")
	}

	return file, nil
}

// Delete removes a backup from storage.
func (s *LocalStorage) Delete(ctx context.Context, path string) error {
	fullPath, err := s.resolvePath(path)
	if err != nil {
		return err
	}

	if err := os.Remove(fullPath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
		}
		return errors.Wrap(err, errors.CodeStorageError, "failed to delete backup file")
	}

	// Try to remove empty parent directories
	s.cleanupEmptyDirs(filepath.Dir(fullPath))

	return nil
}

// Exists checks if a backup exists.
func (s *LocalStorage) Exists(ctx context.Context, path string) (bool, error) {
	fullPath, err := s.resolvePath(path)
	if err != nil {
		return false, err
	}

	_, err = os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errors.Wrap(err, errors.CodeStorageError, "failed to check backup existence")
	}

	return true, nil
}

// Size returns the size of a backup in bytes.
func (s *LocalStorage) Size(ctx context.Context, path string) (int64, error) {
	fullPath, err := s.resolvePath(path)
	if err != nil {
		return 0, err
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, errors.NotFound("backup")
		}
		return 0, errors.Wrap(err, errors.CodeStorageError, "failed to get backup size")
	}

	return info.Size(), nil
}

// List lists backups with optional prefix.
func (s *LocalStorage) List(ctx context.Context, prefix string) ([]backup.StorageEntry, error) {
	searchPath := s.basePath
	if prefix != "" {
		searchPath = filepath.Join(s.basePath, filepath.FromSlash(prefix))
	}

	var entries []backup.StorageEntry

	err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}

		// Check for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip hidden files
		if strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(s.basePath, path)
		if err != nil {
			return nil
		}

		entries = append(entries, backup.StorageEntry{
			Path:    filepath.ToSlash(relPath),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})

		return nil
	})

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to list backups")
	}

	return entries, nil
}

// Stats returns storage statistics.
func (s *LocalStorage) Stats(ctx context.Context) (*backup.StorageStats, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(s.basePath, &stat); err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to get filesystem stats")
	}

	// Calculate disk space
	blockSize := uint64(stat.Bsize)
	totalSpace := int64(stat.Blocks * blockSize)
	availableSpace := int64(stat.Bavail * blockSize)
	usedSpace := totalSpace - int64(stat.Bfree*blockSize)

	// Count backups
	var backupCount int64
	filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && !strings.HasPrefix(info.Name(), ".") {
			backupCount++
		}
		return nil
	})

	return &backup.StorageStats{
		TotalSpace:     totalSpace,
		UsedSpace:      usedSpace,
		AvailableSpace: availableSpace,
		FileCount:      backupCount,
	}, nil
}

// Close releases any resources.
func (s *LocalStorage) Close() error {
	return nil
}

// BasePath returns the base storage path.
func (s *LocalStorage) BasePath() string {
	return s.basePath
}

// resolvePath validates and resolves a relative path to a full path.
func (s *LocalStorage) resolvePath(path string) (string, error) {
	// Clean the path
	cleanPath := filepath.Clean(filepath.FromSlash(path))

	// Ensure path doesn't escape base directory
	fullPath := filepath.Join(s.basePath, cleanPath)
	if !strings.HasPrefix(fullPath, s.basePath) {
		return "", errors.New(errors.CodeStorageError, "invalid storage path")
	}

	return fullPath, nil
}

// cleanupEmptyDirs removes empty parent directories up to basePath.
func (s *LocalStorage) cleanupEmptyDirs(dir string) {
	for {
		// Don't go above basePath
		if dir == s.basePath || !strings.HasPrefix(dir, s.basePath) {
			break
		}

		// Try to remove directory
		if err := os.Remove(dir); err != nil {
			break // Directory not empty or other error
		}

		// Move to parent
		dir = filepath.Dir(dir)
	}
}

// copyWithContext copies from reader to writer with context cancellation support.
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024) // 32KB buffer
	var written int64

	for {
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
		}

		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return written, nil
			}
			return written, rerr
		}
	}
}

// EnsureSpace checks if there's enough space for a backup.
func (s *LocalStorage) EnsureSpace(ctx context.Context, requiredBytes int64) error {
	stats, err := s.Stats(ctx)
	if err != nil {
		return err
	}

	// Add 10% buffer
	requiredWithBuffer := int64(float64(requiredBytes) * 1.1)

	if stats.AvailableSpace < requiredWithBuffer {
		return errors.New(errors.CodeStorageFull,
			fmt.Sprintf("insufficient storage space: need %d bytes, have %d bytes",
				requiredWithBuffer, stats.AvailableSpace))
	}

	return nil
}

// CreateSubdir creates a subdirectory in the storage path.
func (s *LocalStorage) CreateSubdir(name string) (string, error) {
	path := filepath.Join(s.basePath, name)
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", errors.Wrap(err, errors.CodeStorageError, "failed to create subdirectory")
	}
	return path, nil
}

// GetLastModified returns the last modification time of a backup.
func (s *LocalStorage) GetLastModified(ctx context.Context, path string) (time.Time, error) {
	fullPath, err := s.resolvePath(path)
	if err != nil {
		return time.Time{}, err
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, errors.NotFound("backup")
		}
		return time.Time{}, errors.Wrap(err, errors.CodeStorageError, "failed to get backup info")
	}

	return info.ModTime(), nil
}
