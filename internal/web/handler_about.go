// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/web/templates/pages"
)

// ============================================================================
// About page interfaces — implemented by postgres.DB, redis.Client, etc.
// ============================================================================

// DatabaseProber provides database connectivity checks and backup operations.
type DatabaseProber interface {
	Ping(ctx context.Context) error
	GetVersion(ctx context.Context) (string, error)
	DumpSQL(ctx context.Context) ([]byte, error)
	RestoreSQL(ctx context.Context, data []byte) error
}

// RedisProber provides Redis connectivity checks.
type RedisProber interface {
	Ping(ctx context.Context) error
	GetVersion(ctx context.Context) (string, error)
}

// NATSProber provides NATS connection status.
type NATSProber interface {
	IsConnected() bool
	IsTLS() bool
	ServerInfo() string
}

// BackupEncryptor encrypts and decrypts byte data for instance backups.
// Satisfied directly by *crypto.AESEncryptor.
type BackupEncryptor interface {
	Encrypt(data []byte) (string, error)
	Decrypt(ciphertext string) ([]byte, error)
}

// ============================================================================
// About page handler
// ============================================================================

// AboutTempl renders the About page with system information.
func (h *Handler) AboutTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "About", "about")

	data := pages.AboutData{
		PageData:  pageData,
		Version:   h.version,
		Commit:    h.commit,
		BuildTime: h.buildTime,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Mode:      h.mode,
	}

	// Connection status
	data.Connections = h.probeConnections(ctx)

	// Docker info
	if hostSvc := h.services.Hosts(); hostSvc != nil {
		if info, err := hostSvc.GetDockerInfo(ctx); err == nil && info != nil {
			data.DockerVersion = info.ServerVersion
			data.DockerAPIVersion = info.APIVersion
			data.DockerOS = info.OSType
			data.DockerArch = info.Architecture
			data.DockerContainers = info.Containers
			data.DockerImages = info.Images
		}
	}

	h.renderTempl(w, r, pages.About(data))
}

// probeConnections checks the status of all infrastructure connections.
func (h *Handler) probeConnections(ctx context.Context) []pages.ConnectionStatus {
	var conns []pages.ConnectionStatus

	// PostgreSQL
	pgConn := pages.ConnectionStatus{
		Name:    "PostgreSQL",
		Status:  "disconnected",
		TLSInfo: "none",
	}
	if h.db != nil {
		start := time.Now()
		if err := h.db.Ping(ctx); err == nil {
			pgConn.Status = "connected"
			pgConn.Latency = fmt.Sprintf("%dms", time.Since(start).Milliseconds())

			pgConn.TLSInfo = h.getDBSSLMode()
			pgConn.TLS = pgConn.TLSInfo != "disable" && pgConn.TLSInfo != "none"

			if ver, err := h.db.GetVersion(ctx); err == nil && ver != "" {
				pgConn.Details = ver
			}
		} else {
			pgConn.Status = "error: " + err.Error()
		}
	}
	conns = append(conns, pgConn)

	// Redis
	redisConn := pages.ConnectionStatus{
		Name:    "Redis",
		Status:  "disconnected",
		TLSInfo: "none",
	}
	if h.redisProber != nil {
		start := time.Now()
		if err := h.redisProber.Ping(ctx); err == nil {
			redisConn.Status = "connected"
			redisConn.Latency = fmt.Sprintf("%dms", time.Since(start).Milliseconds())

			if h.redisURL != "" && strings.HasPrefix(h.redisURL, "rediss://") {
				redisConn.TLS = true
				redisConn.TLSInfo = "TLS"
			} else {
				redisConn.TLSInfo = "plaintext"
			}

			if ver, err := h.redisProber.GetVersion(ctx); err == nil && ver != "" {
				redisConn.Details = "Redis " + ver
			}
		} else {
			redisConn.Status = "error: " + err.Error()
		}
	}
	conns = append(conns, redisConn)

	// NATS
	natsConn := pages.ConnectionStatus{
		Name:    "NATS",
		Status:  "disconnected",
		TLSInfo: "none",
	}
	if h.natsProber != nil {
		if h.natsProber.IsConnected() {
			natsConn.Status = "connected"
			if h.natsProber.IsTLS() {
				natsConn.TLS = true
				natsConn.TLSInfo = "TLS"
			} else {
				natsConn.TLSInfo = "plaintext"
			}
			natsConn.Details = h.natsProber.ServerInfo()
		}
	}
	conns = append(conns, natsConn)

	return conns
}

// getDBSSLMode returns the current PostgreSQL SSL mode from the config.
func (h *Handler) getDBSSLMode() string {
	if h.dbSSLMode != "" {
		return h.dbSSLMode
	}
	return "unknown"
}

// ============================================================================
// Instance Backup / Restore
// ============================================================================

// instanceBackupManifest is the metadata stored inside an instance backup.
type instanceBackupManifest struct {
	Version   string    `json:"version"`
	Commit    string    `json:"commit"`
	CreatedAt time.Time `json:"created_at"`
	Mode      string    `json:"mode"`
	Format    string    `json:"format"` // "usulnet-instance-v1"
}

// InstanceBackup creates an encrypted backup of the entire usulnet instance.
// It exports the database (via SQL dump) into a tar.gz file encrypted with AES-256-GCM.
func (h *Handler) InstanceBackup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.backupEncryptor == nil {
		h.setFlash(w, r, "error", "Instance backup requires encryption key. Set security.config_encryption_key in config.yaml.")
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	if h.db == nil {
		h.setFlash(w, r, "error", "Database not available")
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	// Create tar.gz archive in memory
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	// 1. Manifest
	manifest := instanceBackupManifest{
		Version:   h.version,
		Commit:    h.commit,
		CreatedAt: time.Now().UTC(),
		Mode:      h.mode,
		Format:    "usulnet-instance-v1",
	}
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")
	if err := addTarEntry(tarWriter, "manifest.json", manifestJSON); err != nil {
		h.logger.Error("instance backup: failed to add manifest", "error", err)
		h.setFlash(w, r, "error", "Backup failed: "+err.Error())
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	// 2. Database dump (SQL)
	dump, err := h.db.DumpSQL(ctx)
	if err != nil {
		h.logger.Error("instance backup: database dump failed", "error", err)
		h.setFlash(w, r, "error", "Database dump failed: "+err.Error())
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}
	if err := addTarEntry(tarWriter, "database.sql", dump); err != nil {
		h.logger.Error("instance backup: failed to add database dump", "error", err)
		h.setFlash(w, r, "error", "Backup failed: "+err.Error())
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	// Close archive
	if err := tarWriter.Close(); err != nil {
		h.setFlash(w, r, "error", "Backup archive error: "+err.Error())
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}
	if err := gzWriter.Close(); err != nil {
		h.setFlash(w, r, "error", "Backup compression error: "+err.Error())
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	// 3. Encrypt the archive (returns base64-encoded ciphertext)
	encrypted, err := h.backupEncryptor.Encrypt(buf.Bytes())
	if err != nil {
		h.logger.Error("instance backup: encryption failed", "error", err)
		h.setFlash(w, r, "error", "Encryption failed: "+err.Error())
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	// Send as download
	encBytes := []byte(encrypted)
	filename := fmt.Sprintf("usulnet-backup-%s.enc", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(encBytes)))
	w.Write(encBytes) //nolint:errcheck
}

// InstanceRestore restores an instance from an encrypted backup.
func (h *Handler) InstanceRestore(w http.ResponseWriter, r *http.Request) {
	if h.backupEncryptor == nil {
		h.setFlash(w, r, "error", "Instance restore requires encryption key. The key must match the one used to create the backup.")
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	if h.db == nil {
		h.setFlash(w, r, "error", "Database not available")
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	// Parse multipart file
	file, _, err := r.FormFile("backup_file")
	if err != nil {
		h.setFlash(w, r, "error", "No backup file provided")
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}
	defer file.Close()

	// Read uploaded file (limit to 500MB)
	limited := io.LimitReader(file, 500<<20)
	encBytes, err := io.ReadAll(limited)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to read backup file: "+err.Error())
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	// Decrypt (base64-encoded ciphertext → plaintext bytes)
	decrypted, err := h.backupEncryptor.Decrypt(string(encBytes))
	if err != nil {
		h.setFlash(w, r, "error", "Decryption failed. Wrong encryption key or corrupted backup.")
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	// Parse tar.gz
	gzReader, err := gzip.NewReader(bytes.NewReader(decrypted))
	if err != nil {
		h.setFlash(w, r, "error", "Invalid backup format (not gzip)")
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	var sqlDump []byte
	var foundManifest bool

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			h.setFlash(w, r, "error", "Invalid backup archive: "+err.Error())
			http.Redirect(w, r, "/about", http.StatusSeeOther)
			return
		}

		data, err := io.ReadAll(tarReader)
		if err != nil {
			h.setFlash(w, r, "error", "Failed to read backup entry: "+err.Error())
			http.Redirect(w, r, "/about", http.StatusSeeOther)
			return
		}

		switch header.Name {
		case "manifest.json":
			var m instanceBackupManifest
			if err := json.Unmarshal(data, &m); err != nil {
				h.setFlash(w, r, "error", "Invalid backup manifest")
				http.Redirect(w, r, "/about", http.StatusSeeOther)
				return
			}
			if m.Format != "usulnet-instance-v1" {
				h.setFlash(w, r, "error", "Unsupported backup format: "+m.Format)
				http.Redirect(w, r, "/about", http.StatusSeeOther)
				return
			}
			foundManifest = true
		case "database.sql":
			sqlDump = data
		}
	}

	if !foundManifest {
		h.setFlash(w, r, "error", "Invalid backup: missing manifest")
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	if len(sqlDump) == 0 {
		h.setFlash(w, r, "error", "Invalid backup: missing database dump")
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	// Restore database
	if err := h.db.RestoreSQL(r.Context(), sqlDump); err != nil {
		h.logger.Error("instance restore: database restore failed", "error", err)
		h.setFlash(w, r, "error", "Database restore failed: "+err.Error())
		http.Redirect(w, r, "/about", http.StatusSeeOther)
		return
	}

	h.logger.Info("Instance restored from backup successfully")
	h.setFlash(w, r, "success", "Instance restored successfully. Please restart usulnet for changes to take full effect.")
	http.Redirect(w, r, "/about", http.StatusSeeOther)
}

// addTarEntry adds a single file entry to a tar writer.
func addTarEntry(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{
		Name:    name,
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
