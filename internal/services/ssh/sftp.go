// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package ssh

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// SFTPClient wraps an SFTP client with connection info.
type SFTPClient struct {
	*sftp.Client
	sshClient *ssh.Client
	connID    uuid.UUID
}

// Close closes both SFTP and SSH connections.
func (c *SFTPClient) Close() error {
	if c.Client != nil {
		c.Client.Close()
	}
	if c.sshClient != nil {
		return c.sshClient.Close()
	}
	return nil
}

// NewSFTPClient creates a new SFTP client from an existing SSH client.
func NewSFTPClient(sshClient *ssh.Client, connID uuid.UUID) (*SFTPClient, error) {
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create SFTP client")
	}

	return &SFTPClient{
		Client:    sftpClient,
		sshClient: sshClient,
		connID:    connID,
	}, nil
}

// ConnectSFTP establishes an SFTP connection.
func (s *Service) ConnectSFTP(ctx context.Context, connID uuid.UUID) (*SFTPClient, error) {
	conn, err := s.GetConnection(ctx, connID)
	if err != nil {
		return nil, err
	}

	sshClient, err := s.dial(ctx, conn)
	if err != nil {
		return nil, err
	}

	sftpClient, err := NewSFTPClient(sshClient, connID)
	if err != nil {
		sshClient.Close()
		return nil, err
	}

	_ = s.connRepo.UpdateStatus(ctx, connID, models.SSHConnectionActive, "")

	return sftpClient, nil
}

// ListDirectory lists files in a remote directory.
func (s *Service) ListDirectory(ctx context.Context, client *SFTPClient, path string) ([]models.SSHFileInfo, error) {
	if path == "" {
		path = "."
	}

	files, err := client.ReadDir(path)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to read directory")
	}

	var result []models.SSHFileInfo
	for _, file := range files {
		info := s.fileInfoFromStat(file, path)
		result = append(result, info)
	}

	// Sort: directories first, then by name
	sort.Slice(result, func(i, j int) bool {
		if result[i].IsDir != result[j].IsDir {
			return result[i].IsDir
		}
		return result[i].Name < result[j].Name
	})

	return result, nil
}

// GetFileInfo gets information about a single file.
func (s *Service) GetFileInfo(ctx context.Context, client *SFTPClient, path string) (*models.SSHFileInfo, error) {
	info, err := client.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.NotFound("file")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to stat file")
	}

	dir := filepath.Dir(path)
	result := s.fileInfoFromStat(info, dir)
	return &result, nil
}

// ReadFile reads a file's contents.
func (s *Service) ReadFile(ctx context.Context, client *SFTPClient, path string) (io.ReadCloser, *models.SSHFileInfo, error) {
	info, err := s.GetFileInfo(ctx, client, path)
	if err != nil {
		return nil, nil, err
	}

	if info.IsDir {
		return nil, nil, errors.New(errors.CodeValidationFailed, "cannot read directory")
	}

	file, err := client.Open(path)
	if err != nil {
		return nil, nil, errors.Wrap(err, errors.CodeInternal, "failed to open file")
	}

	return file, info, nil
}

// WriteFile writes content to a file.
func (s *Service) WriteFile(ctx context.Context, client *SFTPClient, path string, content io.Reader, mode os.FileMode) error {
	file, err := client.Create(path)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create file")
	}
	defer file.Close()

	if _, err := io.Copy(file, content); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to write file")
	}

	if mode != 0 {
		if err := client.Chmod(path, mode); err != nil {
			s.logger.Warn("failed to set file permissions", "path", path, "error", err)
		}
	}

	return nil
}

// DeleteFile deletes a file or empty directory.
func (s *Service) DeleteFile(ctx context.Context, client *SFTPClient, path string) error {
	info, err := client.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
		}
		return errors.Wrap(err, errors.CodeInternal, "failed to stat file")
	}

	if info.IsDir() {
		if err := client.RemoveDirectory(path); err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to remove directory")
		}
	} else {
		if err := client.Remove(path); err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to remove file")
		}
	}

	return nil
}

// DeleteRecursive deletes a file or directory recursively.
func (s *Service) DeleteRecursive(ctx context.Context, client *SFTPClient, path string) error {
	info, err := client.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errors.Wrap(err, errors.CodeInternal, "failed to stat file")
	}

	if !info.IsDir() {
		return client.Remove(path)
	}

	// List and delete contents
	entries, err := client.ReadDir(path)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to read directory")
	}

	for _, entry := range entries {
		childPath := filepath.Join(path, entry.Name())
		if err := s.DeleteRecursive(ctx, client, childPath); err != nil {
			return err
		}
	}

	return client.RemoveDirectory(path)
}

// CreateDirectory creates a new directory.
func (s *Service) CreateDirectory(ctx context.Context, client *SFTPClient, path string) error {
	if err := client.MkdirAll(path); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create directory")
	}
	return nil
}

// Rename renames a file or directory.
func (s *Service) Rename(ctx context.Context, client *SFTPClient, oldPath, newPath string) error {
	if err := client.Rename(oldPath, newPath); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to rename file")
	}
	return nil
}

// Chmod changes file permissions.
func (s *Service) Chmod(ctx context.Context, client *SFTPClient, path string, mode os.FileMode) error {
	if err := client.Chmod(path, mode); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to change permissions")
	}
	return nil
}

// DownloadFile downloads a file with progress tracking.
func (s *Service) DownloadFile(ctx context.Context, client *SFTPClient, remotePath string, localWriter io.Writer, progressFn func(bytesWritten int64)) error {
	file, err := client.Open(remotePath)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to open remote file")
	}
	defer file.Close()

	if progressFn != nil {
		// Wrap writer to track progress
		written, err := io.Copy(localWriter, &progressReader{reader: file, progressFn: progressFn})
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to download file")
		}
		progressFn(written)
	} else {
		if _, err := io.Copy(localWriter, file); err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to download file")
		}
	}

	return nil
}

// UploadFile uploads a file with progress tracking.
func (s *Service) UploadFile(ctx context.Context, client *SFTPClient, localReader io.Reader, remotePath string, progressFn func(bytesWritten int64)) error {
	file, err := client.Create(remotePath)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create remote file")
	}
	defer file.Close()

	if progressFn != nil {
		written, err := io.Copy(file, &progressReader{reader: localReader, progressFn: progressFn})
		if err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to upload file")
		}
		progressFn(written)
	} else {
		if _, err := io.Copy(file, localReader); err != nil {
			return errors.Wrap(err, errors.CodeInternal, "failed to upload file")
		}
	}

	return nil
}

// GetHomePath returns the user's home directory on the remote system.
func (s *Service) GetHomePath(ctx context.Context, client *SFTPClient) (string, error) {
	home, err := client.Getwd()
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to get working directory")
	}
	return home, nil
}

// fileInfoFromStat converts os.FileInfo to SSHFileInfo.
func (s *Service) fileInfoFromStat(info os.FileInfo, basePath string) models.SSHFileInfo {
	result := models.SSHFileInfo{
		Name:    info.Name(),
		Path:    filepath.Join(basePath, info.Name()),
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		IsDir:   info.IsDir(),
		ModTime: info.ModTime(),
	}

	// Mode in octal
	result.ModeOctal = modeToOctal(info.Mode())

	// Check for symlink
	if info.Mode()&os.ModeSymlink != 0 {
		result.IsLink = true
	}

	return result
}

// modeToOctal converts file mode to octal string.
func modeToOctal(mode os.FileMode) string {
	return string([]byte{
		'0',
		'0' + byte((mode>>6)&7),
		'0' + byte((mode>>3)&7),
		'0' + byte(mode&7),
	})
}

// progressReader wraps a reader to track progress.
type progressReader struct {
	reader     io.Reader
	progressFn func(int64)
	total      int64
	lastReport time.Time
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.total += int64(n)

	// Report progress every 100ms
	if time.Since(r.lastReport) > 100*time.Millisecond {
		r.progressFn(r.total)
		r.lastReport = time.Now()
	}

	return n, err
}
