// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// TarArchiver implements the Archiver interface using tar with gzip/zstd compression.
type TarArchiver struct {
	// BufferSize is the size of the copy buffer
	BufferSize int

	// ProgressCallback is called with progress updates
	ProgressCallback func(current, total int64, currentFile string)
}

// NewTarArchiver creates a new tar archiver.
func NewTarArchiver() *TarArchiver {
	return &TarArchiver{
		BufferSize: 32 * 1024, // 32KB buffer
	}
}

// Create creates a compressed tar archive from a source directory.
func (a *TarArchiver) Create(
	ctx context.Context,
	sourcePath string,
	destWriter io.Writer,
	compression models.BackupCompression,
) (*ArchiveResult, error) {
	// Validate source exists
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupFailed, "source path not found")
	}

	// Calculate original size and file count
	var originalSize int64
	var fileCount int
	err = filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if !info.IsDir() {
			originalSize += info.Size()
			fileCount++
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to calculate source size")
	}

	// Create checksum writer
	hashWriter := sha256.New()
	multiWriter := io.MultiWriter(destWriter, hashWriter)

	// Create compression writer
	var compWriter io.WriteCloser
	switch compression {
	case models.BackupCompressionGzip:
		compWriter, err = gzip.NewWriterLevel(multiWriter, gzip.BestCompression)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to create gzip writer")
		}
	case models.BackupCompressionZstd:
		compWriter, err = zstd.NewWriter(multiWriter, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to create zstd writer")
		}
	case models.BackupCompressionNone:
		compWriter = &nopWriteCloser{multiWriter}
	default:
		return nil, errors.New(errors.CodeBackupFailed, "unsupported compression type")
	}
	defer compWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(compWriter)
	defer tarWriter.Close()

	// Track progress
	var processedSize int64
	var processedFiles int

	// Walk source directory and add files to archive
	basePath := sourcePath
	if !sourceInfo.IsDir() {
		basePath = filepath.Dir(sourcePath)
	}

	err = filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Get relative path for archive
		relPath, err := filepath.Rel(basePath, path)
		if err != nil {
			return err
		}

		// Skip the root directory itself
		if relPath == "." {
			return nil
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("create header for %s: %w", relPath, err)
		}
		header.Name = filepath.ToSlash(relPath)

		// Handle symlinks
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("read symlink %s: %w", path, err)
			}
			header.Linkname = link
		}

		// Write header
		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("write header for %s: %w", relPath, err)
		}

		// Write file content if regular file
		if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("open file %s: %w", path, err)
			}

			written, err := io.Copy(tarWriter, file)
			file.Close()
			if err != nil {
				return fmt.Errorf("copy file %s: %w", path, err)
			}

			processedSize += written
			processedFiles++

			// Report progress
			if a.ProgressCallback != nil {
				a.ProgressCallback(processedSize, originalSize, relPath)
			}
		}

		return nil
	})

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to create archive")
	}

	// Close writers to flush all data
	if err := tarWriter.Close(); err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to close tar writer")
	}
	if err := compWriter.Close(); err != nil {
		return nil, errors.Wrap(err, errors.CodeBackupFailed, "failed to close compression writer")
	}

	return &ArchiveResult{
		OriginalSize: originalSize,
		FileCount:    fileCount,
		Checksum:     hex.EncodeToString(hashWriter.Sum(nil)),
	}, nil
}

// Extract extracts a compressed tar archive to a destination directory.
func (a *TarArchiver) Extract(
	ctx context.Context,
	reader io.Reader,
	destPath string,
	compression models.BackupCompression,
) (*ExtractResult, error) {
	// Create destination directory
	if err := os.MkdirAll(destPath, 0755); err != nil {
		return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to create destination directory")
	}

	// Create decompression reader
	var decompReader io.Reader
	var err error
	switch compression {
	case models.BackupCompressionGzip:
		decompReader, err = gzip.NewReader(reader)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to create gzip reader")
		}
		defer decompReader.(*gzip.Reader).Close()
	case models.BackupCompressionZstd:
		decompReader, err = zstd.NewReader(reader)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to create zstd reader")
		}
		defer decompReader.(*zstd.Decoder).Close()
	case models.BackupCompressionNone:
		decompReader = reader
	default:
		return nil, errors.New(errors.CodeRestoreFailed, "unsupported compression type")
	}

	// Create tar reader
	tarReader := tar.NewReader(decompReader)

	var bytesWritten int64
	var fileCount int

	// Extract files
	for {
		// Check for cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to read archive header")
		}

		// Validate path to prevent zip slip
		targetPath := filepath.Join(destPath, filepath.FromSlash(header.Name))
		if !strings.HasPrefix(filepath.Clean(targetPath), filepath.Clean(destPath)+string(os.PathSeparator)) {
			return nil, errors.New(errors.CodeRestoreFailed, "invalid file path in archive (zip slip detected)")
		}

		// Create parent directory
		parentDir := filepath.Dir(targetPath)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to create parent directory")
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to create directory")
			}

		case tar.TypeReg:
			file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to create file")
			}

			written, err := io.Copy(file, tarReader)
			file.Close()
			if err != nil {
				return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to extract file")
			}

			bytesWritten += written
			fileCount++

			// Report progress
			if a.ProgressCallback != nil {
				a.ProgressCallback(bytesWritten, 0, header.Name)
			}

		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to create symlink")
			}

		case tar.TypeLink:
			linkPath := filepath.Join(destPath, filepath.FromSlash(header.Linkname))
			if err := os.Link(linkPath, targetPath); err != nil {
				return nil, errors.Wrap(err, errors.CodeRestoreFailed, "failed to create hard link")
			}

		default:
			// Skip unknown types
			continue
		}

		// Restore modification time
		if err := os.Chtimes(targetPath, header.AccessTime, header.ModTime); err != nil {
			// Non-fatal, just log
		}
	}

	return &ExtractResult{
		BytesWritten: bytesWritten,
		FileCount:    fileCount,
	}, nil
}

// List lists the contents of a compressed tar archive.
func (a *TarArchiver) List(
	ctx context.Context,
	reader io.Reader,
	compression models.BackupCompression,
) ([]ArchiveEntry, error) {
	// Create decompression reader
	var decompReader io.Reader
	var err error
	switch compression {
	case models.BackupCompressionGzip:
		decompReader, err = gzip.NewReader(reader)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeBackupCorrupted, "failed to create gzip reader")
		}
		defer decompReader.(*gzip.Reader).Close()
	case models.BackupCompressionZstd:
		decompReader, err = zstd.NewReader(reader)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeBackupCorrupted, "failed to create zstd reader")
		}
		defer decompReader.(*zstd.Decoder).Close()
	case models.BackupCompressionNone:
		decompReader = reader
	default:
		return nil, errors.New(errors.CodeBackupCorrupted, "unsupported compression type")
	}

	// Create tar reader
	tarReader := tar.NewReader(decompReader)

	var entries []ArchiveEntry

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeBackupCorrupted, "failed to read archive header")
		}

		entries = append(entries, ArchiveEntry{
			Name:    header.Name,
			Size:    header.Size,
			Mode:    header.Mode,
			ModTime: header.ModTime,
			IsDir:   header.Typeflag == tar.TypeDir,
		})
	}

	return entries, nil
}

// CalculateChecksum calculates SHA256 checksum of a reader.
func CalculateChecksum(reader io.Reader) (string, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// VerifyChecksum verifies the checksum of a file.
func VerifyChecksum(path string, expectedChecksum string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	checksum, err := CalculateChecksum(file)
	if err != nil {
		return false, err
	}

	return checksum == expectedChecksum, nil
}

// nopWriteCloser wraps a writer with a no-op Close method.
type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

// GetCompressionExtension returns the file extension for a compression type.
func GetCompressionExtension(compression models.BackupCompression) string {
	switch compression {
	case models.BackupCompressionGzip:
		return ".tar.gz"
	case models.BackupCompressionZstd:
		return ".tar.zst"
	case models.BackupCompressionNone:
		return ".tar"
	default:
		return ".tar.gz"
	}
}

// DetectCompression detects compression type from filename.
func DetectCompression(filename string) models.BackupCompression {
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		return models.BackupCompressionGzip
	case strings.HasSuffix(lower, ".tar.zst") || strings.HasSuffix(lower, ".tar.zstd"):
		return models.BackupCompressionZstd
	case strings.HasSuffix(lower, ".tar"):
		return models.BackupCompressionNone
	default:
		return models.BackupCompressionGzip
	}
}
