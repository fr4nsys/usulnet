// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/services/backup"
)

// SFTPStorage implements backup.Storage for SFTP storage.
type SFTPStorage struct {
	client   *sftp.Client
	sshConn  *ssh.Client
	basePath string
	config   SFTPConfig
}

// SFTPConfig contains SFTP storage configuration.
type SFTPConfig struct {
	// Host is the SFTP server hostname
	Host string

	// Port is the SFTP server port (default: 22)
	Port int

	// Username is the SSH username
	Username string

	// Password is the SSH password (optional if using key)
	Password string

	// PrivateKey is the SSH private key (PEM encoded)
	PrivateKey string

	// PrivateKeyPassphrase is the passphrase for the private key
	PrivateKeyPassphrase string

	// KnownHostsFile is the path to the known_hosts file (optional)
	KnownHostsFile string

	// HostKeyFingerprint is the expected SSH host key fingerprint (SHA256:...).
	// If set, only this fingerprint is accepted. Takes precedence over KnownHostsFile.
	HostKeyFingerprint string

	// InsecureIgnoreHostKey skips host key verification (not recommended)
	InsecureIgnoreHostKey bool

	// BasePath is the base directory on the SFTP server
	BasePath string

	// ConnectTimeout is the connection timeout
	ConnectTimeout time.Duration
}

// NewSFTPStorage creates a new SFTP storage backend.
func NewSFTPStorage(ctx context.Context, cfg SFTPConfig) (*SFTPStorage, error) {
	if cfg.Host == "" {
		return nil, errors.New(errors.CodeStorageError, "SFTP host is required")
	}
	if cfg.Username == "" {
		return nil, errors.New(errors.CodeStorageError, "SFTP username is required")
	}
	if cfg.Password == "" && cfg.PrivateKey == "" {
		return nil, errors.New(errors.CodeStorageError, "SFTP password or private key is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 30 * time.Second
	}
	if cfg.BasePath == "" {
		cfg.BasePath = "/backups"
	}

	// Build SSH auth methods
	var authMethods []ssh.AuthMethod

	// Private key authentication
	if cfg.PrivateKey != "" {
		var signer ssh.Signer
		var err error

		if cfg.PrivateKeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cfg.PrivateKey), []byte(cfg.PrivateKeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
		}
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeStorageError, "failed to parse SSH private key")
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	// Password authentication
	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}

	// Build host key callback
	var hostKeyCallback ssh.HostKeyCallback
	if cfg.InsecureIgnoreHostKey {
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else if cfg.HostKeyFingerprint != "" {
		// Verify against a known fingerprint
		expected := cfg.HostKeyFingerprint
		hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hash := sha256.Sum256(key.Marshal())
			got := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
			if got != expected {
				return fmt.Errorf("SFTP host key mismatch for %s: expected %s, got %s", hostname, expected, got)
			}
			return nil
		}
	} else {
		// Default: accept any host key (TOFU - logs warning)
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	// SSH client config
	sshConfig := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         cfg.ConnectTimeout,
	}

	// Connect to SSH server
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	sshConn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to connect to SFTP server")
	}

	// Create SFTP client
	sftpClient, err := sftp.NewClient(sshConn)
	if err != nil {
		sshConn.Close()
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to create SFTP client")
	}

	// Ensure base path exists
	basePath := path.Clean(cfg.BasePath)
	if err := sftpClient.MkdirAll(basePath); err != nil {
		sftpClient.Close()
		sshConn.Close()
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to create base directory")
	}

	return &SFTPStorage{
		client:   sftpClient,
		sshConn:  sshConn,
		basePath: basePath,
		config:   cfg,
	}, nil
}

// Type returns the storage type identifier.
func (s *SFTPStorage) Type() string {
	return "sftp"
}

// Write writes data to SFTP storage.
func (s *SFTPStorage) Write(ctx context.Context, filePath string, reader io.Reader, size int64) error {
	fullPath := s.fullPath(filePath)

	// Create parent directory
	parentDir := path.Dir(fullPath)
	if err := s.client.MkdirAll(parentDir); err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to create parent directory")
	}

	// Create temporary file
	tmpPath := fullPath + ".tmp"
	file, err := s.client.Create(tmpPath)
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to create temporary file")
	}

	// Clean up on failure
	success := false
	defer func() {
		if !success {
			s.client.Remove(tmpPath)
		}
	}()

	// Copy data
	written, err := copyWithContext(ctx, file, reader)
	if err != nil {
		file.Close()
		return errors.Wrap(err, errors.CodeStorageError, "failed to write backup data")
	}
	file.Close()

	// Verify size if provided
	if size > 0 && written != size {
		return errors.New(errors.CodeStorageError,
			fmt.Sprintf("size mismatch: expected %d, got %d", size, written))
	}

	// Rename to final path (atomic on most systems)
	if err := s.client.Rename(tmpPath, fullPath); err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to finalize backup file")
	}

	success = true
	return nil
}

// Read returns a reader for the backup at path.
func (s *SFTPStorage) Read(ctx context.Context, filePath string) (io.ReadCloser, error) {
	fullPath := s.fullPath(filePath)

	file, err := s.client.Open(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.NotFound("backup")
		}
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to open backup file")
	}

	return file, nil
}

// Delete removes a backup from storage.
func (s *SFTPStorage) Delete(ctx context.Context, filePath string) error {
	fullPath := s.fullPath(filePath)

	if err := s.client.Remove(fullPath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
		}
		return errors.Wrap(err, errors.CodeStorageError, "failed to delete backup file")
	}

	// Try to remove empty parent directories
	s.cleanupEmptyDirs(path.Dir(fullPath))

	return nil
}

// Exists checks if a backup exists.
func (s *SFTPStorage) Exists(ctx context.Context, filePath string) (bool, error) {
	fullPath := s.fullPath(filePath)

	_, err := s.client.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errors.Wrap(err, errors.CodeStorageError, "failed to check backup existence")
	}

	return true, nil
}

// Size returns the size of a backup in bytes.
func (s *SFTPStorage) Size(ctx context.Context, filePath string) (int64, error) {
	fullPath := s.fullPath(filePath)

	info, err := s.client.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, errors.NotFound("backup")
		}
		return 0, errors.Wrap(err, errors.CodeStorageError, "failed to get backup size")
	}

	return info.Size(), nil
}

// List lists backups with optional prefix.
func (s *SFTPStorage) List(ctx context.Context, prefix string) ([]backup.StorageEntry, error) {
	searchPath := s.basePath
	if prefix != "" {
		searchPath = path.Join(s.basePath, prefix)
	}

	var entries []backup.StorageEntry

	walker := s.client.Walk(searchPath)
	for walker.Step() {
		// Check for cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if walker.Err() != nil {
			continue
		}

		info := walker.Stat()
		if info.IsDir() {
			continue
		}

		// Skip hidden files
		if strings.HasPrefix(info.Name(), ".") {
			continue
		}

		// Get relative path
		relPath := strings.TrimPrefix(walker.Path(), s.basePath+"/")

		entries = append(entries, backup.StorageEntry{
			Path:    relPath,
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}

	return entries, nil
}

// Stats returns storage statistics.
func (s *SFTPStorage) Stats(ctx context.Context) (*backup.StorageStats, error) {
	// SFTP has limited support for filesystem stats
	// Use statVFS if available
	stat, err := s.client.StatVFS(s.basePath)
	if err != nil {
		// Fallback: count files manually
		var totalSize int64
		var fileCount int64

		walker := s.client.Walk(s.basePath)
		for walker.Step() {
			if walker.Err() != nil {
				continue
			}
			info := walker.Stat()
			if !info.IsDir() {
				totalSize += info.Size()
				fileCount++
			}
		}

		return &backup.StorageStats{
			TotalSpace:     -1, // Unknown
			UsedSpace:      totalSize,
			AvailableSpace: -1, // Unknown
			FileCount:      fileCount,
		}, nil
	}

	// Calculate from StatVFS
	blockSize := int64(stat.Bsize)
	totalSpace := int64(stat.Blocks) * blockSize
	availableSpace := int64(stat.Bavail) * blockSize
	usedSpace := totalSpace - int64(stat.Bfree)*blockSize

	// Count files
	var fileCount int64
	walker := s.client.Walk(s.basePath)
	for walker.Step() {
		if walker.Err() == nil && !walker.Stat().IsDir() {
			fileCount++
		}
	}

	return &backup.StorageStats{
		TotalSpace:     totalSpace,
		UsedSpace:      usedSpace,
		AvailableSpace: availableSpace,
		FileCount:      fileCount,
	}, nil
}

// Close closes the SFTP connection.
func (s *SFTPStorage) Close() error {
	var errs []error

	if s.client != nil {
		if err := s.client.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if s.sshConn != nil {
		if err := s.sshConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Wrap(errs[0], errors.CodeStorageError, "failed to close SFTP connection")
	}

	return nil
}

// Reconnect attempts to reconnect to the SFTP server.
func (s *SFTPStorage) Reconnect(ctx context.Context) error {
	// Close existing connections
	s.Close()

	// Create new connection
	newStorage, err := NewSFTPStorage(ctx, s.config)
	if err != nil {
		return err
	}

	// Replace fields
	s.client = newStorage.client
	s.sshConn = newStorage.sshConn

	return nil
}

// fullPath returns the full path on the SFTP server.
func (s *SFTPStorage) fullPath(filePath string) string {
	return path.Join(s.basePath, path.Clean(filePath))
}

// cleanupEmptyDirs removes empty parent directories up to basePath.
func (s *SFTPStorage) cleanupEmptyDirs(dir string) {
	for {
		// Don't go above basePath
		if dir == s.basePath || !strings.HasPrefix(dir, s.basePath) {
			break
		}

		// Check if directory is empty
		entries, err := s.client.ReadDir(dir)
		if err != nil || len(entries) > 0 {
			break
		}

		// Remove empty directory
		if err := s.client.RemoveDirectory(dir); err != nil {
			break
		}

		// Move to parent
		dir = path.Dir(dir)
	}
}

// GetLastModified returns the last modification time of a backup.
func (s *SFTPStorage) GetLastModified(ctx context.Context, filePath string) (time.Time, error) {
	fullPath := s.fullPath(filePath)

	info, err := s.client.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, errors.NotFound("backup")
		}
		return time.Time{}, errors.Wrap(err, errors.CodeStorageError, "failed to get backup info")
	}

	return info.ModTime(), nil
}

// SetPermissions sets file permissions on the SFTP server.
func (s *SFTPStorage) SetPermissions(ctx context.Context, filePath string, mode os.FileMode) error {
	fullPath := s.fullPath(filePath)

	if err := s.client.Chmod(fullPath, mode); err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to set file permissions")
	}

	return nil
}
