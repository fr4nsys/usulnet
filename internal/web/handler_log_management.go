// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
	logspages "github.com/fr4nsys/usulnet/internal/web/templates/pages/logs"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// CustomLogUploadRepository defines the interface for log upload persistence.
type CustomLogUploadRepository interface {
	Create(ctx context.Context, upload *models.CustomLogUpload) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.CustomLogUpload, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.CustomLogUpload, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// SetCustomLogUploadRepo sets the custom log upload repository.
func (h *Handler) SetCustomLogUploadRepo(repo CustomLogUploadRepository) {
	h.customLogUploadRepo = repo
}

// logUploadDir is the base directory for stored log uploads.
const logUploadDir = "/tmp/usulnet/log-uploads"

// ============================================================================
// Log Management Handlers
// ============================================================================

// LogManagement renders the log management page.
// GET /logs/management
func (h *Handler) LogManagement(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "aggregation"
	}

	pageData := h.prepareTemplPageData(r, "Log Management", "log-management")

	data := logspages.LogManagementData{
		PageData: pageData,
		Tab:      tab,
	}

	// Get containers for source dropdown
	ctx := r.Context()
	containerSvc := h.services.Containers()
	if containerSvc != nil {
		containers, _ := containerSvc.List(ctx, nil)
		for _, c := range containers {
			data.Containers = append(data.Containers, logspages.ContainerBasicView{
				ID:   c.ID[:12],
				Name: strings.TrimPrefix(c.Name, "/"),
			})
		}
	}

	// Load data based on active tab
	switch tab {
	case "aggregation":
		data.Aggregation = h.loadLogAggregation(ctx)
	case "patterns":
		data.Patterns = h.loadDetectedPatterns(ctx)
	case "uploads":
		data.Uploads = h.loadUploadedLogs(ctx, r)
	}

	h.renderTempl(w, r, logspages.LogManagement(data))
}

// loadLogAggregation loads aggregated log statistics
func (h *Handler) loadLogAggregation(ctx interface{}) logspages.LogAggregationView {
	return logspages.LogAggregationView{
		Timeframe:  "24h",
		TotalLogs:  0,
		BySeverity: make(map[string]int64),
		BySource:   make(map[string]int64),
		ErrorRate:  0,
	}
}

// loadDetectedPatterns loads detected error patterns
func (h *Handler) loadDetectedPatterns(ctx interface{}) []logspages.DetectedPattern {
	return []logspages.DetectedPattern{}
}

// loadUploadedLogs loads user's uploaded log files from the database.
func (h *Handler) loadUploadedLogs(ctx interface{}, r *http.Request) []logspages.UploadedLogFile {
	if h.customLogUploadRepo == nil {
		return []logspages.UploadedLogFile{}
	}

	user := h.getUserData(r)
	if user == nil || user.ID == "" {
		return []logspages.UploadedLogFile{}
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		return []logspages.UploadedLogFile{}
	}

	uploads, err := h.customLogUploadRepo.ListByUser(r.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to list uploaded logs", "error", err)
		return []logspages.UploadedLogFile{}
	}

	var result []logspages.UploadedLogFile
	for _, u := range uploads {
		result = append(result, logspages.UploadedLogFile{
			ID:          u.ID.String(),
			Filename:    u.Filename,
			Size:        formatSizeHuman(u.Size),
			Format:      string(u.Format),
			LineCount:   u.LineCount,
			ErrorCount:  u.ErrorCount,
			UploadedAt:  u.UploadedAt.Format("Jan 02, 2006 15:04"),
			Description: u.Description,
		})
	}

	return result
}

// LogUpload handles log file uploads.
// POST /logs/uploads
func (h *Handler) LogUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(100 << 20); err != nil { // 100MB max
		h.setFlash(w, r, "error", "File too large or invalid form")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		h.setFlash(w, r, "error", "No file provided")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}
	defer file.Close()

	// Read file content
	content, err := io.ReadAll(file)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to read file")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}

	// Detect format
	formatStr := r.FormValue("format")
	var format models.LogFormat
	if formatStr == "auto" || formatStr == "" {
		format = detectLogFormat(string(content))
	} else {
		format = models.LogFormat(formatStr)
	}

	// Parse logs and count errors
	lines := strings.Split(string(content), "\n")
	errorCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		result := models.ParseLogLine(line, models.LogSourceCustom, "", header.Filename)
		if result.Entry.Severity == models.LogSeverityError || result.Entry.Severity == models.LogSeverityCritical {
			errorCount++
		}
	}

	// Get current user
	user := h.getUserData(r)
	if user == nil || user.ID == "" {
		h.setFlash(w, r, "error", "Not authenticated")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}
	userID, parseErr := uuid.Parse(user.ID)
	if parseErr != nil {
		h.setFlash(w, r, "error", "Invalid user session")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}

	upload := models.CustomLogUpload{
		ID:          uuid.New(),
		UserID:      userID,
		Filename:    header.Filename,
		Size:        header.Size,
		Format:      format,
		LineCount:   len(lines),
		ErrorCount:  errorCount,
		UploadedAt:  time.Now(),
		Description: r.FormValue("description"),
	}

	// Save file to disk
	if err := os.MkdirAll(logUploadDir, 0o750); err == nil {
		filePath := filepath.Join(logUploadDir, upload.ID.String()+".log")
		if err := os.WriteFile(filePath, content, 0o640); err == nil {
			upload.FilePath = filePath
		} else {
			h.logger.Warn("Failed to save log file to disk", "error", err)
		}
	}

	// Save to database
	if h.customLogUploadRepo != nil {
		if err := h.customLogUploadRepo.Create(r.Context(), &upload); err != nil {
			h.logger.Error("Failed to save log upload to database", "error", err)
			h.setFlash(w, r, "error", "Failed to save upload: "+err.Error())
			http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
			return
		}
	}

	h.logger.Info("Log file uploaded",
		"filename", upload.Filename,
		"size", upload.Size,
		"format", upload.Format,
		"lines", upload.LineCount,
		"errors", upload.ErrorCount,
	)

	h.setFlash(w, r, "success", fmt.Sprintf("Uploaded %s: %d lines, %d errors detected", upload.Filename, upload.LineCount, upload.ErrorCount))
	http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
}

// LogUploadDelete deletes an uploaded log file.
// DELETE /logs/uploads/{id}
func (h *Handler) LogUploadDelete(w http.ResponseWriter, r *http.Request) {
	uploadIDStr := chi.URLParam(r, "id")
	if uploadIDStr == "" {
		h.setFlash(w, r, "error", "Missing upload ID")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}

	uploadID, err := uuid.Parse(uploadIDStr)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid upload ID")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}

	if h.customLogUploadRepo != nil {
		// Get the upload first to find the file path
		upload, err := h.customLogUploadRepo.GetByID(r.Context(), uploadID)
		if err == nil && upload.FilePath != "" {
			os.Remove(upload.FilePath)
		}

		// Delete from database
		if err := h.customLogUploadRepo.Delete(r.Context(), uploadID); err != nil {
			h.setFlash(w, r, "error", "Failed to delete upload: "+err.Error())
			http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
			return
		}
	}

	h.logger.Info("Log upload deleted", "id", uploadIDStr)

	h.setFlash(w, r, "success", "Log file deleted")
	http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
}

// LogUploadAnalyze shows analysis of an uploaded log file.
// GET /logs/uploads/{id}
func (h *Handler) LogUploadAnalyze(w http.ResponseWriter, r *http.Request) {
	uploadIDStr := chi.URLParam(r, "id")
	if uploadIDStr == "" {
		h.setFlash(w, r, "error", "Missing upload ID")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}

	uploadID, err := uuid.Parse(uploadIDStr)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid upload ID")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}

	if h.customLogUploadRepo == nil {
		h.setFlash(w, r, "error", "Log upload service not available")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}

	upload, err := h.customLogUploadRepo.GetByID(r.Context(), uploadID)
	if err != nil {
		h.setFlash(w, r, "error", "Upload not found")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}

	// Read and analyze the file
	if upload.FilePath == "" {
		h.setFlash(w, r, "error", "Log file not available")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}

	content, readErr := os.ReadFile(upload.FilePath)
	if readErr != nil {
		h.setFlash(w, r, "error", "Failed to read log file")
		http.Redirect(w, r, "/logs/management?tab=uploads", http.StatusSeeOther)
		return
	}

	// Parse and analyze log content
	lines := strings.Split(string(content), "\n")
	bySeverity := make(map[string]int64)
	bySource := make(map[string]int64)
	var totalLines int64
	patternMap := make(map[string]*logspages.DetectedPattern)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		totalLines++

		result := models.ParseLogLine(line, models.LogSourceCustom, "", upload.Filename)
		sevStr := string(result.Entry.Severity)
		bySeverity[sevStr]++
		bySource[upload.Filename]++

		// Track error patterns
		if result.Entry.Severity == models.LogSeverityError || result.Entry.Severity == models.LogSeverityCritical {
			// Use first 80 chars of message as pattern key
			patternKey := result.Entry.Message
			if len(patternKey) > 80 {
				patternKey = patternKey[:80]
			}
			if p, ok := patternMap[patternKey]; ok {
				p.Count++
				p.LastSeen = result.Entry.Timestamp.Format("15:04:05")
			} else {
				patternMap[patternKey] = &logspages.DetectedPattern{
					ID:        fmt.Sprintf("p-%d", len(patternMap)+1),
					Pattern:   patternKey,
					Type:      "error",
					Count:     1,
					FirstSeen: result.Entry.Timestamp.Format("15:04:05"),
					LastSeen:  result.Entry.Timestamp.Format("15:04:05"),
					Severity:  sevStr,
					Example:   line,
				}
			}
		}
	}

	// Collect top patterns
	var patterns []logspages.DetectedPattern
	for _, p := range patternMap {
		patterns = append(patterns, *p)
	}

	var errorRate float64
	if totalLines > 0 {
		errorRate = float64(bySeverity["error"]+bySeverity["critical"]) / float64(totalLines) * 100
	}

	pageData := h.prepareTemplPageData(r, "Log Analysis: "+upload.Filename, "log-management")

	data := logspages.LogManagementData{
		PageData: pageData,
		Tab:      "aggregation",
		Aggregation: logspages.LogAggregationView{
			Timeframe:   "file: " + upload.Filename,
			TotalLogs:   totalLines,
			BySeverity:  bySeverity,
			BySource:    bySource,
			ErrorRate:   errorRate,
			TopPatterns: patterns,
		},
		Patterns: patterns,
	}

	h.renderTempl(w, r, logspages.LogManagement(data))
}

// ============================================================================
// Log Search API
// ============================================================================

// LogSearchAPI handles log search requests.
// GET /api/logs/search
func (h *Handler) LogSearchAPI(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	timeRange := r.URL.Query().Get("time_range")
	severity := r.URL.Query().Get("severity")
	source := r.URL.Query().Get("source")
	formatFilter := r.URL.Query().Get("format")

	ctx := r.Context()

	// Build search options
	opts := models.LogSearchOptions{
		Query:    query,
		Limit:    100,
		SortDesc: true,
	}

	if severity != "" {
		opts.Severities = []models.LogSeverity{models.LogSeverity(severity)}
	}

	if source != "" {
		opts.Sources = []string{source}
	}

	// Parse time range
	now := time.Now()
	switch timeRange {
	case "1h":
		t := now.Add(-1 * time.Hour)
		opts.StartTime = &t
	case "6h":
		t := now.Add(-6 * time.Hour)
		opts.StartTime = &t
	case "24h":
		t := now.Add(-24 * time.Hour)
		opts.StartTime = &t
	case "7d":
		t := now.Add(-7 * 24 * time.Hour)
		opts.StartTime = &t
	case "30d":
		t := now.Add(-30 * 24 * time.Hour)
		opts.StartTime = &t
	}

	// Search logs
	var logs []map[string]interface{}

	// Get real-time container logs if Containers service is available
	containerSvc := h.services.Containers()
	if containerSvc != nil && source != "" {
		// Fetch logs from specific container
		logLines, err := containerSvc.GetLogs(ctx, source, 100)
		if err == nil {
			for _, line := range logLines {
				result := models.ParseLogLine(line, models.LogSourceContainer, source, source)

				// Apply filters
				if severity != "" && string(result.Entry.Severity) != severity {
					continue
				}
				if formatFilter != "" && string(result.Entry.Format) != formatFilter {
					continue
				}
				if query != "" && !strings.Contains(strings.ToLower(result.Entry.Message), strings.ToLower(query)) {
					continue
				}

				logs = append(logs, map[string]interface{}{
					"id":          result.Entry.ID.String(),
					"timestamp":   result.Entry.Timestamp.Format("15:04:05.000"),
					"source_name": result.Entry.SourceName,
					"severity":    string(result.Entry.Severity),
					"message":     result.Entry.Message,
					"fields":      result.Entry.Fields,
				})
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":  logs,
		"total": len(logs),
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

// detectLogFormat attempts to detect the log format from content
func detectLogFormat(content string) models.LogFormat {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		return models.LogFormatPlain
	}

	// Check first few non-empty lines
	jsonCount := 0
	syslogCount := 0
	apacheCount := 0

	for i, line := range lines {
		if i >= 10 { // Check first 10 lines
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			jsonCount++
		} else if strings.HasPrefix(line, "<") {
			syslogCount++
		} else if strings.Contains(line, "] \"") && strings.Contains(line, "\" ") {
			apacheCount++
		}
	}

	switch {
	case jsonCount > syslogCount && jsonCount > apacheCount:
		return models.LogFormatJSON
	case syslogCount > jsonCount && syslogCount > apacheCount:
		return models.LogFormatSyslog
	case apacheCount > jsonCount && apacheCount > syslogCount:
		return models.LogFormatApache
	default:
		return models.LogFormatPlain
	}
}

// formatSizeHuman formats bytes as human-readable string
func formatSizeHuman(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// getFileExtension returns the file extension without the dot
func getFileExtension(filename string) string {
	ext := filepath.Ext(filename)
	if ext != "" {
		return strings.ToLower(ext[1:])
	}
	return ""
}
