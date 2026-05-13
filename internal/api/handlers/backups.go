// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/backup"
)

// BackupHandler handles backup-related HTTP requests.
type BackupHandler struct {
	BaseHandler
	backupService   *backup.Service
	licenseProvider middleware.LicenseProvider
}

// NewBackupHandler creates a new backup handler.
func NewBackupHandler(backupService *backup.Service, log *logger.Logger) *BackupHandler {
	return &BackupHandler{
		BaseHandler:   NewBaseHandler(log),
		backupService: backupService,
	}
}

// SetLicenseProvider sets the license provider for limit enforcement.
func (h *BackupHandler) SetLicenseProvider(provider middleware.LicenseProvider) {
	h.licenseProvider = provider
}

// Routes returns the router for backup endpoints.
func (h *BackupHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Read-only routes (viewer+)
	r.Get("/", h.ListBackups)
	r.Get("/stats", h.GetStats)
	r.Get("/storage", h.GetStorageInfo)
	r.Get("/target/{hostID}/{targetID}", h.ListByTarget)

	r.Route("/{backupID}", func(r chi.Router) {
		r.Get("/", h.GetBackup)
		r.Get("/contents", h.ListContents)
		r.Get("/download", h.Download)

		// Operator+ for mutations
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			r.Delete("/", h.DeleteBackup)
			r.Post("/restore", h.Restore)
			r.Post("/verify", h.Verify)
		})
	})

	// Schedules
	r.Route("/schedules", func(r chi.Router) {
		r.Get("/", h.ListSchedules)

		r.Route("/{scheduleID}", func(r chi.Router) {
			r.Get("/", h.GetSchedule)

			// Operator+ for mutations
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireOperator)
				r.Put("/", h.UpdateSchedule)
				r.Delete("/", h.DeleteSchedule)
				r.Post("/run", h.RunSchedule)
			})
		})

		// Schedule creation — operator+ with license limit
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			if h.licenseProvider != nil {
				r.Use(middleware.RequireLimit(
					h.licenseProvider,
					"backup schedules",
					func(r *http.Request) int {
						schedules, err := h.backupService.ListSchedules(r.Context(), nil)
						if err != nil {
							return 0
						}
						return len(schedules)
					},
					func(l license.Limits) int { return l.MaxBackupDestinations },
				))
			}
			r.Post("/", h.CreateSchedule)
		})
	})

	// Operator+ for other mutations
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireOperator)
		r.Post("/", h.CreateBackup)
		r.Post("/target/{hostID}/{targetID}/prune", h.PruneTarget)
	})

	// Admin-only maintenance
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Post("/cleanup", h.Cleanup)
		r.Post("/cleanup/orphaned", h.CleanupOrphaned)
	})

	return r
}

// ============================================================================
// Request/Response types
// ============================================================================

// CreateBackupRequest represents a backup creation request.
type CreateBackupRequest struct {
	HostID        string `json:"host_id"`
	Type          string `json:"type"`
	TargetID      string `json:"target_id"`
	TargetName    string `json:"target_name,omitempty"`
	Trigger       string `json:"trigger,omitempty"`
	Compression   string `json:"compression,omitempty"`
	Encrypt       bool   `json:"encrypt,omitempty"`
	RetentionDays *int   `json:"retention_days,omitempty"`
	StopContainer bool   `json:"stop_container,omitempty"`
}

// RestoreBackupRequest represents a restore request.
type RestoreBackupRequest struct {
	TargetName        string `json:"target_name,omitempty"`
	OverwriteExisting bool   `json:"overwrite_existing,omitempty"`
	StopContainers    bool   `json:"stop_containers,omitempty"`
	StartAfterRestore bool   `json:"start_after_restore,omitempty"`
}

// VerifyBackupRequest represents a verify request.
type VerifyBackupRequest struct {
	CheckChecksum   bool `json:"check_checksum,omitempty"`
	CheckContents   bool `json:"check_contents,omitempty"`
	CheckDecryption bool `json:"check_decryption,omitempty"`
	FullExtract     bool `json:"full_extract,omitempty"`
	ChecksumOnly    bool `json:"checksum_only,omitempty"`
}

// PruneTargetRequest represents a prune request.
type PruneTargetRequest struct {
	KeepCount int `json:"keep_count"`
}

// CreateScheduleRequest represents a schedule creation request.
type CreateScheduleRequest struct {
	HostID        string `json:"host_id"`
	Type          string `json:"type"`
	TargetID      string `json:"target_id"`
	Schedule      string `json:"schedule"`
	Compression   string `json:"compression,omitempty"`
	Encrypted     bool   `json:"encrypted,omitempty"`
	RetentionDays int    `json:"retention_days,omitempty"`
	MaxBackups    int    `json:"max_backups,omitempty"`
	IsEnabled     bool   `json:"is_enabled,omitempty"`
}

// UpdateScheduleRequest represents a schedule update request.
type UpdateScheduleRequest struct {
	Schedule      *string `json:"schedule,omitempty"`
	Compression   *string `json:"compression,omitempty"`
	Encrypted     *bool   `json:"encrypted,omitempty"`
	RetentionDays *int    `json:"retention_days,omitempty"`
	MaxBackups    *int    `json:"max_backups,omitempty"`
	IsEnabled     *bool   `json:"is_enabled,omitempty"`
}

// BackupResponse represents a backup in API responses.
type BackupResponse struct {
	ID           string                 `json:"id"`
	HostID       string                 `json:"host_id"`
	Type         string                 `json:"type"`
	TargetID     string                 `json:"target_id"`
	TargetName   string                 `json:"target_name"`
	Status       string                 `json:"status"`
	Trigger      string                 `json:"trigger"`
	Path         string                 `json:"path"`
	Filename     string                 `json:"filename"`
	SizeBytes    int64                  `json:"size_bytes"`
	Compression  string                 `json:"compression"`
	Encrypted    bool                   `json:"encrypted"`
	Checksum     *string                `json:"checksum,omitempty"`
	Verified     bool                   `json:"verified"`
	VerifiedAt   *string                `json:"verified_at,omitempty"`
	Metadata     *models.BackupMetadata `json:"metadata,omitempty"`
	ErrorMessage *string                `json:"error_message,omitempty"`
	CreatedBy    *string                `json:"created_by,omitempty"`
	StartedAt    *string                `json:"started_at,omitempty"`
	CompletedAt  *string                `json:"completed_at,omitempty"`
	ExpiresAt    *string                `json:"expires_at,omitempty"`
	CreatedAt    string                 `json:"created_at"`
}

// ScheduleResponse represents a backup schedule in API responses.
type ScheduleResponse struct {
	ID            string  `json:"id"`
	HostID        string  `json:"host_id"`
	Type          string  `json:"type"`
	TargetID      string  `json:"target_id"`
	TargetName    string  `json:"target_name"`
	Schedule      string  `json:"schedule"`
	Compression   string  `json:"compression"`
	Encrypted     bool    `json:"encrypted"`
	RetentionDays int     `json:"retention_days"`
	MaxBackups    int     `json:"max_backups"`
	IsEnabled     bool    `json:"is_enabled"`
	LastRunAt     *string `json:"last_run_at,omitempty"`
	LastRunStatus *string `json:"last_run_status,omitempty"`
	NextRunAt     *string `json:"next_run_at,omitempty"`
	CreatedBy     *string `json:"created_by,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// BackupStatsResponse represents backup statistics.
type BackupStatsResponse struct {
	TotalBackups     int            `json:"total_backups"`
	CompletedBackups int            `json:"completed_backups"`
	FailedBackups    int            `json:"failed_backups"`
	TotalSize        int64          `json:"total_size"`
	ByType           map[string]int `json:"by_type,omitempty"`
	ByTrigger        map[string]int `json:"by_trigger,omitempty"`
	LastBackupAt     *string        `json:"last_backup_at,omitempty"`
	OldestBackupAt   *string        `json:"oldest_backup_at,omitempty"`
}

// StorageInfoResponse represents storage information.
type StorageInfoResponse struct {
	Type        string `json:"type"`
	LocalPath   string `json:"local_path,omitempty"`
	S3Bucket    string `json:"s3_bucket,omitempty"`
	TotalSize   int64  `json:"total_size"`
	UsedSize    int64  `json:"used_size"`
	BackupCount int    `json:"backup_count"`
}

// RestoreResultResponse represents restore result.
type RestoreResultResponse struct {
	BackupID     string `json:"backup_id"`
	TargetID     string `json:"target_id"`
	TargetName   string `json:"target_name"`
	Duration     string `json:"duration"`
	BytesWritten int64  `json:"bytes_written"`
	FileCount    int    `json:"file_count"`
}

// VerifyResultResponse represents verification result.
type VerifyResultResponse struct {
	BackupID      string  `json:"backup_id"`
	IsValid       bool    `json:"is_valid"`
	ChecksumValid bool    `json:"checksum_valid"`
	Readable      bool    `json:"readable"`
	FileCount     int     `json:"file_count,omitempty"`
	ErrorMessage  *string `json:"error_message,omitempty"`
	VerifiedAt    string  `json:"verified_at"`
}

// ArchiveEntryResponse represents an archive entry.
type ArchiveEntryResponse struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Mode       string `json:"mode"`
	ModTime    string `json:"mod_time"`
	IsDir      bool   `json:"is_dir"`
	LinkTarget string `json:"link_target,omitempty"`
}

// BackupCleanupResponse represents cleanup result.
type BackupCleanupResponse struct {
	DeletedCount   int    `json:"deleted_count"`
	DeletedSize    int64  `json:"deleted_size"`
	FailedCount    int    `json:"failed_count"`
	SkippedCount   int    `json:"skipped_count"`
	ProcessedCount int    `json:"processed_count"`
	Duration       string `json:"duration"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListBackups returns all backups.
// GET /api/v1/backups
func (h *BackupHandler) ListBackups(w http.ResponseWriter, r *http.Request) {
	pagination := h.GetPagination(r)

	opts := models.BackupListOptions{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}

	// Optional filters
	if backupType := h.QueryParam(r, "type"); backupType != "" {
		bt := models.BackupType(backupType)
		opts.Type = &bt
	}
	if status := h.QueryParam(r, "status"); status != "" {
		bs := models.BackupStatus(status)
		opts.Status = &bs
	}
	if targetID := h.QueryParam(r, "target_id"); targetID != "" {
		opts.TargetID = &targetID
	}

	backups, total, err := h.backupService.List(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]BackupResponse, len(backups))
	for i, b := range backups {
		resp[i] = toBackupResponse(b)
	}

	h.OK(w, NewPaginatedResponse(resp, total, pagination))
}

// CreateBackup creates a new backup.
// POST /api/v1/backups
func (h *BackupHandler) CreateBackup(w http.ResponseWriter, r *http.Request) {
	var req CreateBackupRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.HostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if req.Type == "" {
		h.BadRequest(w, "type is required")
		return
	}
	if req.TargetID == "" {
		h.BadRequest(w, "target_id is required")
		return
	}

	hostID, err := uuid.Parse(req.HostID)
	if err != nil {
		h.BadRequest(w, "invalid host_id")
		return
	}

	userID, _ := h.GetUserID(r)

	opts := backup.CreateOptions{
		HostID:        hostID,
		Type:          models.BackupType(req.Type),
		TargetID:      req.TargetID,
		TargetName:    req.TargetName,
		Trigger:       models.BackupTriggerManual,
		Compression:   models.BackupCompression(req.Compression),
		Encrypt:       req.Encrypt,
		RetentionDays: req.RetentionDays,
		StopContainer: req.StopContainer,
		CreatedBy:     &userID,
	}

	if req.Trigger != "" {
		opts.Trigger = models.BackupTrigger(req.Trigger)
	}

	result, err := h.backupService.Create(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toBackupResponse(result.Backup))
}

// GetBackup returns a specific backup.
// GET /api/v1/backups/{backupID}
func (h *BackupHandler) GetBackup(w http.ResponseWriter, r *http.Request) {
	backupID, err := h.URLParamUUID(r, "backupID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	b, err := h.backupService.Get(r.Context(), backupID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toBackupResponse(b))
}

// DeleteBackup deletes a backup.
// DELETE /api/v1/backups/{backupID}
func (h *BackupHandler) DeleteBackup(w http.ResponseWriter, r *http.Request) {
	backupID, err := h.URLParamUUID(r, "backupID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.backupService.Delete(r.Context(), backupID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// ListContents lists backup archive contents.
// GET /api/v1/backups/{backupID}/contents
func (h *BackupHandler) ListContents(w http.ResponseWriter, r *http.Request) {
	backupID, err := h.URLParamUUID(r, "backupID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	entries, err := h.backupService.ListContents(r.Context(), backupID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ArchiveEntryResponse, len(entries))
	for i, e := range entries {
		resp[i] = ArchiveEntryResponse{
			Name:       e.Name,
			Size:       e.Size,
			Mode:       fmt.Sprintf("%04o", e.Mode),
			ModTime:    e.ModTime.Format(time.RFC3339),
			IsDir:      e.IsDir,
			LinkTarget: e.LinkTarget,
		}
	}

	h.OK(w, resp)
}

// Download downloads a backup file.
// GET /api/v1/backups/{backupID}/download
func (h *BackupHandler) Download(w http.ResponseWriter, r *http.Request) {
	backupID, err := h.URLParamUUID(r, "backupID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	info, err := h.backupService.Download(r.Context(), backupID)
	if err != nil {
		h.HandleError(w, err)
		return
	}
	defer info.Reader.Close()

	w.Header().Set("Content-Type", info.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", info.Filename))
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))

	io.Copy(w, info.Reader)
}

// Restore restores a backup.
// POST /api/v1/backups/{backupID}/restore
func (h *BackupHandler) Restore(w http.ResponseWriter, r *http.Request) {
	backupID, err := h.URLParamUUID(r, "backupID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req RestoreBackupRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	opts := backup.RestoreOptions{
		BackupID:          backupID,
		TargetName:        req.TargetName,
		OverwriteExisting: req.OverwriteExisting,
		StopContainers:    req.StopContainers,
		StartAfterRestore: req.StartAfterRestore,
	}

	result, err := h.backupService.Restore(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, RestoreResultResponse{
		BackupID:     result.BackupID.String(),
		TargetID:     result.TargetID,
		TargetName:   result.TargetName,
		Duration:     result.Duration.String(),
		BytesWritten: result.BytesWritten,
		FileCount:    result.FileCount,
	})
}

// Verify verifies a backup.
// POST /api/v1/backups/{backupID}/verify
func (h *BackupHandler) Verify(w http.ResponseWriter, r *http.Request) {
	backupID, err := h.URLParamUUID(r, "backupID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req VerifyBackupRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	opts := backup.VerifyOptions{
		CheckChecksum:   req.CheckChecksum,
		CheckContents:   req.CheckContents,
		CheckDecryption: req.CheckDecryption,
		FullExtract:     req.FullExtract,
		ChecksumOnly:    req.ChecksumOnly,
	}

	result, err := h.backupService.Verify(r.Context(), backupID, opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, VerifyResultResponse{
		BackupID:      result.BackupID.String(),
		IsValid:       result.IsValid,
		ChecksumValid: result.ChecksumValid,
		Readable:      result.Readable,
		FileCount:     result.FileCount,
		ErrorMessage:  result.ErrorMessage,
		VerifiedAt:    result.VerifiedAt.Format(time.RFC3339),
	})
}

// ListByTarget lists backups for a specific target.
// GET /api/v1/backups/target/{hostID}/{targetID}
func (h *BackupHandler) ListByTarget(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	targetID := h.URLParam(r, "targetID")
	if targetID == "" {
		h.BadRequest(w, "targetID is required")
		return
	}

	backups, err := h.backupService.ListByTarget(r.Context(), hostID, targetID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]BackupResponse, len(backups))
	for i, b := range backups {
		resp[i] = toBackupResponse(b)
	}

	h.OK(w, resp)
}

// PruneTarget prunes old backups for a target.
// POST /api/v1/backups/target/{hostID}/{targetID}/prune
func (h *BackupHandler) PruneTarget(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	targetID := h.URLParam(r, "targetID")
	if targetID == "" {
		h.BadRequest(w, "targetID is required")
		return
	}

	var req PruneTargetRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.KeepCount < 1 {
		req.KeepCount = 3
	}

	result, err := h.backupService.PruneTarget(r.Context(), hostID, targetID, req.KeepCount)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, BackupCleanupResponse{
		DeletedCount:   result.DeletedCount,
		DeletedSize:    result.DeletedSize,
		FailedCount:    result.FailedCount,
		SkippedCount:   result.SkippedCount,
		ProcessedCount: result.ProcessedCount,
		Duration:       result.Duration.String(),
	})
}

// GetStats returns backup statistics.
// GET /api/v1/backups/stats
func (h *BackupHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	var hostID *uuid.UUID
	if hid := h.QueryParamUUID(r, "host_id"); hid != nil {
		hostID = hid
	}

	stats, err := h.backupService.GetStats(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := BackupStatsResponse{
		TotalBackups:     stats.TotalBackups,
		CompletedBackups: stats.CompletedBackups,
		FailedBackups:    stats.FailedBackups,
		TotalSize:        stats.TotalSize,
		ByType:           stats.ByType,
		ByTrigger:        stats.ByTrigger,
	}

	if stats.LastBackupAt != nil {
		t := stats.LastBackupAt.Format(time.RFC3339)
		resp.LastBackupAt = &t
	}
	if stats.OldestBackupAt != nil {
		t := stats.OldestBackupAt.Format(time.RFC3339)
		resp.OldestBackupAt = &t
	}

	h.OK(w, resp)
}

// GetStorageInfo returns storage information.
// GET /api/v1/backups/storage
func (h *BackupHandler) GetStorageInfo(w http.ResponseWriter, r *http.Request) {
	info, err := h.backupService.GetStorageInfo(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, StorageInfoResponse{
		Type:        info.Type,
		LocalPath:   info.LocalPath,
		S3Bucket:    info.S3Bucket,
		TotalSize:   info.TotalSize,
		UsedSize:    info.UsedSize,
		BackupCount: info.BackupCount,
	})
}

// Cleanup cleans up old backups.
// POST /api/v1/backups/cleanup
func (h *BackupHandler) Cleanup(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	result, err := h.backupService.Cleanup(r.Context(), nil)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, BackupCleanupResponse{
		DeletedCount:   result.DeletedCount,
		DeletedSize:    result.DeletedSize,
		FailedCount:    result.FailedCount,
		SkippedCount:   result.SkippedCount,
		ProcessedCount: result.ProcessedCount,
		Duration:       result.Duration.String(),
	})
}

// CleanupOrphaned cleans up orphaned backups.
// POST /api/v1/backups/cleanup/orphaned
func (h *BackupHandler) CleanupOrphaned(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	result, err := h.backupService.CleanupOrphaned(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, BackupCleanupResponse{
		DeletedCount:   result.DeletedCount,
		DeletedSize:    result.DeletedSize,
		FailedCount:    result.FailedCount,
		SkippedCount:   result.SkippedCount,
		ProcessedCount: result.ProcessedCount,
		Duration:       result.Duration.String(),
	})
}

// ============================================================================
// Schedule handlers
// ============================================================================

// ListSchedules returns all backup schedules.
// GET /api/v1/backups/schedules
func (h *BackupHandler) ListSchedules(w http.ResponseWriter, r *http.Request) {
	var hostID *uuid.UUID
	if hid := h.QueryParamUUID(r, "host_id"); hid != nil {
		hostID = hid
	}

	schedules, err := h.backupService.ListSchedules(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]ScheduleResponse, len(schedules))
	for i, s := range schedules {
		resp[i] = toScheduleResponse(s)
	}

	h.OK(w, resp)
}

// CreateSchedule creates a new backup schedule.
// POST /api/v1/backups/schedules
func (h *BackupHandler) CreateSchedule(w http.ResponseWriter, r *http.Request) {
	var req CreateScheduleRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.HostID == "" {
		h.BadRequest(w, "host_id is required")
		return
	}
	if req.Type == "" {
		h.BadRequest(w, "type is required")
		return
	}
	if req.TargetID == "" {
		h.BadRequest(w, "target_id is required")
		return
	}
	if req.Schedule == "" {
		h.BadRequest(w, "schedule is required")
		return
	}

	hostID, err := uuid.Parse(req.HostID)
	if err != nil {
		h.BadRequest(w, "invalid host_id")
		return
	}

	userID, _ := h.GetUserID(r)

	input := models.CreateBackupScheduleInput{
		Type:          models.BackupType(req.Type),
		TargetID:      req.TargetID,
		Schedule:      req.Schedule,
		Compression:   models.BackupCompression(req.Compression),
		Encrypted:     req.Encrypted,
		RetentionDays: req.RetentionDays,
		MaxBackups:    req.MaxBackups,
		IsEnabled:     req.IsEnabled,
	}

	schedule, err := h.backupService.CreateSchedule(r.Context(), input, hostID, &userID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toScheduleResponse(schedule))
}

// GetSchedule returns a specific schedule.
// GET /api/v1/backups/schedules/{scheduleID}
func (h *BackupHandler) GetSchedule(w http.ResponseWriter, r *http.Request) {
	scheduleID, err := h.URLParamUUID(r, "scheduleID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	schedule, err := h.backupService.GetSchedule(r.Context(), scheduleID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toScheduleResponse(schedule))
}

// UpdateSchedule updates a schedule.
// PUT /api/v1/backups/schedules/{scheduleID}
func (h *BackupHandler) UpdateSchedule(w http.ResponseWriter, r *http.Request) {
	scheduleID, err := h.URLParamUUID(r, "scheduleID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	var req UpdateScheduleRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	input := models.UpdateBackupScheduleInput{
		Schedule:      req.Schedule,
		Encrypted:     req.Encrypted,
		RetentionDays: req.RetentionDays,
		MaxBackups:    req.MaxBackups,
		IsEnabled:     req.IsEnabled,
	}

	if req.Compression != nil {
		c := models.BackupCompression(*req.Compression)
		input.Compression = &c
	}

	schedule, err := h.backupService.UpdateSchedule(r.Context(), scheduleID, input)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toScheduleResponse(schedule))
}

// DeleteSchedule deletes a schedule.
// DELETE /api/v1/backups/schedules/{scheduleID}
func (h *BackupHandler) DeleteSchedule(w http.ResponseWriter, r *http.Request) {
	scheduleID, err := h.URLParamUUID(r, "scheduleID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.backupService.DeleteSchedule(r.Context(), scheduleID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// RunSchedule runs a schedule immediately.
// POST /api/v1/backups/schedules/{scheduleID}/run
func (h *BackupHandler) RunSchedule(w http.ResponseWriter, r *http.Request) {
	scheduleID, err := h.URLParamUUID(r, "scheduleID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	result, err := h.backupService.RunSchedule(r.Context(), scheduleID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.Created(w, toBackupResponse(result.Backup))
}

// ============================================================================
// Helpers
// ============================================================================

func toBackupResponse(b *models.Backup) BackupResponse {
	resp := BackupResponse{
		ID:           b.ID.String(),
		HostID:       b.HostID.String(),
		Type:         string(b.Type),
		TargetID:     b.TargetID,
		TargetName:   b.TargetName,
		Status:       string(b.Status),
		Trigger:      string(b.Trigger),
		Path:         b.Path,
		Filename:     b.Filename,
		SizeBytes:    b.SizeBytes,
		Compression:  string(b.Compression),
		Encrypted:    b.Encrypted,
		Checksum:     b.Checksum,
		Verified:     b.Verified,
		Metadata:     b.Metadata,
		ErrorMessage: b.ErrorMessage,
		CreatedAt:    b.CreatedAt.Format(time.RFC3339),
	}

	if b.VerifiedAt != nil {
		t := b.VerifiedAt.Format(time.RFC3339)
		resp.VerifiedAt = &t
	}
	if b.CreatedBy != nil {
		s := b.CreatedBy.String()
		resp.CreatedBy = &s
	}
	if b.StartedAt != nil {
		t := b.StartedAt.Format(time.RFC3339)
		resp.StartedAt = &t
	}
	if b.CompletedAt != nil {
		t := b.CompletedAt.Format(time.RFC3339)
		resp.CompletedAt = &t
	}
	if b.ExpiresAt != nil {
		t := b.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = &t
	}

	return resp
}

func toScheduleResponse(s *models.BackupSchedule) ScheduleResponse {
	resp := ScheduleResponse{
		ID:            s.ID.String(),
		HostID:        s.HostID.String(),
		Type:          string(s.Type),
		TargetID:      s.TargetID,
		TargetName:    s.TargetName,
		Schedule:      s.Schedule,
		Compression:   string(s.Compression),
		Encrypted:     s.Encrypted,
		RetentionDays: s.RetentionDays,
		MaxBackups:    s.MaxBackups,
		IsEnabled:     s.IsEnabled,
		CreatedAt:     s.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     s.UpdatedAt.Format(time.RFC3339),
	}

	if s.LastRunAt != nil {
		t := s.LastRunAt.Format(time.RFC3339)
		resp.LastRunAt = &t
	}
	if s.LastRunStatus != nil {
		status := string(*s.LastRunStatus)
		resp.LastRunStatus = &status
	}
	if s.NextRunAt != nil {
		t := s.NextRunAt.Format(time.RFC3339)
		resp.NextRunAt = &t
	}
	if s.CreatedBy != nil {
		id := s.CreatedBy.String()
		resp.CreatedBy = &id
	}

	return resp
}
