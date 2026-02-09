// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/services/audit"
)

// AuditHandler handles audit log API requests
type AuditHandler struct {
	BaseHandler
	auditSvc        *audit.Service
	licenseProvider middleware.LicenseProvider
}

// NewAuditHandler creates a new audit handler
func NewAuditHandler(auditSvc *audit.Service, log *logger.Logger) *AuditHandler {
	return &AuditHandler{
		BaseHandler: NewBaseHandler(log),
		auditSvc:    auditSvc,
	}
}

// SetLicenseProvider sets the license provider for feature gating.
func (h *AuditHandler) SetLicenseProvider(provider middleware.LicenseProvider) {
	h.licenseProvider = provider
}

// Routes returns the audit routes
func (h *AuditHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// All audit routes require admin role
	r.Use(middleware.RequireAdmin)

	r.Get("/", h.List)
	r.Get("/recent", h.GetRecent)
	r.Get("/stats", h.GetStats)
	r.Get("/user/{userID}", h.GetByUser)
	r.Get("/resource/{resourceType}/{resourceID}", h.GetByResource)

	// Export endpoints (require FeatureAuditExport — Business+)
	r.Route("/export", func(r chi.Router) {
		if h.licenseProvider != nil {
			r.Use(middleware.RequireFeature(h.licenseProvider, license.FeatureAuditExport))
		}
		r.Get("/csv", h.ExportCSV)
		r.Get("/pdf", h.ExportPDF)
	})

	return r
}

// ListResponse represents the response for listing audit logs
type AuditListResponse struct {
	Logs  any `json:"logs"`
	Total int `json:"total"`
	Limit int `json:"limit"`
	Page  int `json:"page"`
}

// List handles GET /api/v1/audit
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	opts := postgres.AuditLogListOptions{
		Limit:  h.QueryParamInt(r, "limit", 50),
		Offset: h.QueryParamInt(r, "offset", 0),
	}

	// Parse optional filters
	if userID := r.URL.Query().Get("user_id"); userID != "" {
		if uid, err := uuid.Parse(userID); err == nil {
			opts.UserID = &uid
		}
	}

	if action := r.URL.Query().Get("action"); action != "" {
		opts.Action = &action
	}

	if resourceType := r.URL.Query().Get("resource_type"); resourceType != "" {
		opts.ResourceType = &resourceType
	}

	if resourceID := r.URL.Query().Get("resource_id"); resourceID != "" {
		opts.ResourceID = &resourceID
	}

	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			opts.Since = &t
		}
	}

	if until := r.URL.Query().Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			opts.Until = &t
		}
	}

	logs, total, err := h.auditSvc.List(r.Context(), opts)
	if err != nil {
		h.InternalError(w, err)
		return
	}

	page := 1
	if opts.Offset > 0 && opts.Limit > 0 {
		page = (opts.Offset / opts.Limit) + 1
	}

	h.OK(w, AuditListResponse{
		Logs:  logs,
		Total: total,
		Limit: opts.Limit,
		Page:  page,
	})
}

// GetRecent handles GET /api/v1/audit/recent
func (h *AuditHandler) GetRecent(w http.ResponseWriter, r *http.Request) {
	limit := h.QueryParamInt(r, "limit", 50)

	logs, err := h.auditSvc.GetRecent(r.Context(), limit)
	if err != nil {
		h.InternalError(w, err)
		return
	}

	h.OK(w, map[string]any{
		"logs":  logs,
		"count": len(logs),
	})
}

// GetStats handles GET /api/v1/audit/stats
func (h *AuditHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	// Default to last 24 hours
	since := time.Now().Add(-24 * time.Hour)

	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	// Also support "days" parameter
	if days := h.QueryParamInt(r, "days", 0); days > 0 {
		since = time.Now().AddDate(0, 0, -days)
	}

	stats, err := h.auditSvc.GetStats(r.Context(), since)
	if err != nil {
		h.InternalError(w, err)
		return
	}

	h.OK(w, map[string]any{
		"stats": stats,
		"since": since,
	})
}

// GetByUser handles GET /api/v1/audit/user/{userID}
func (h *AuditHandler) GetByUser(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.BadRequest(w, "invalid user ID")
		return
	}

	limit := h.QueryParamInt(r, "limit", 50)

	logs, err := h.auditSvc.GetByUser(r.Context(), userID, limit)
	if err != nil {
		h.InternalError(w, err)
		return
	}

	h.OK(w, map[string]any{
		"logs":    logs,
		"user_id": userID,
		"count":   len(logs),
	})
}

// GetByResource handles GET /api/v1/audit/resource/{resourceType}/{resourceID}
func (h *AuditHandler) GetByResource(w http.ResponseWriter, r *http.Request) {
	resourceType := chi.URLParam(r, "resourceType")
	resourceID := chi.URLParam(r, "resourceID")

	if resourceType == "" || resourceID == "" {
		h.BadRequest(w, "resource type and ID are required")
		return
	}

	limit := h.QueryParamInt(r, "limit", 50)

	logs, err := h.auditSvc.GetByResource(r.Context(), resourceType, resourceID, limit)
	if err != nil {
		h.InternalError(w, err)
		return
	}

	h.OK(w, map[string]any{
		"logs":          logs,
		"resource_type": resourceType,
		"resource_id":   resourceID,
		"count":         len(logs),
	})
}

// ExportCSV handles GET /api/v1/audit/export/csv
// Exports audit logs as CSV file
func (h *AuditHandler) ExportCSV(w http.ResponseWriter, r *http.Request) {
	logs, err := h.getLogsForExport(r)
	if err != nil {
		h.InternalError(w, err)
		return
	}

	// Create CSV buffer
	buf := &bytes.Buffer{}
	writer := csv.NewWriter(buf)

	// Write header
	header := []string{
		"Timestamp",
		"User",
		"Action",
		"Resource Type",
		"Resource ID",
		"IP Address",
		"User Agent",
		"Success",
		"Error",
		"Details",
	}
	if err := writer.Write(header); err != nil {
		h.InternalError(w, err)
		return
	}

	// Write records
	for _, log := range logs {
		record := []string{
			log.CreatedAt.Format(time.RFC3339),
			safeString(log.Username),
			log.Action,
			log.EntityType,
			safeString(log.EntityID),
			safeString(log.IPAddress),
			safeString(log.UserAgent),
			fmt.Sprintf("%v", log.Success),
			safeString(log.ErrorMsg),
			formatDetails(log.Details),
		}
		if err := writer.Write(record); err != nil {
			h.InternalError(w, err)
			return
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		h.InternalError(w, err)
		return
	}

	// Set response headers
	filename := fmt.Sprintf("audit_logs_%s.csv", time.Now().Format("2006-01-02"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))

	w.Write(buf.Bytes())
}

// ExportPDF handles GET /api/v1/audit/export/pdf
// Exports audit logs as PDF-like text report (simplified implementation)
func (h *AuditHandler) ExportPDF(w http.ResponseWriter, r *http.Request) {
	logs, err := h.getLogsForExport(r)
	if err != nil {
		h.InternalError(w, err)
		return
	}

	// Generate PDF-like formatted text report
	// Note: For a true PDF, you would use a library like gofpdf or pdfcpu
	// This implementation creates a well-formatted text report
	buf := &bytes.Buffer{}

	// Header
	buf.WriteString("================================================================================\n")
	buf.WriteString("                           AUDIT LOG REPORT\n")
	buf.WriteString("================================================================================\n\n")
	buf.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05 MST")))
	buf.WriteString(fmt.Sprintf("Total Records: %d\n", len(logs)))

	// Date range
	if len(logs) > 0 {
		buf.WriteString(fmt.Sprintf("Date Range: %s to %s\n",
			logs[len(logs)-1].CreatedAt.Format("2006-01-02 15:04"),
			logs[0].CreatedAt.Format("2006-01-02 15:04")))
	}
	buf.WriteString("\n")

	// Summary by action
	actionCounts := make(map[string]int)
	resourceCounts := make(map[string]int)
	successCount := 0
	failureCount := 0

	for _, log := range logs {
		actionCounts[log.Action]++
		resourceCounts[log.EntityType]++
		if log.Success {
			successCount++
		} else {
			failureCount++
		}
	}

	buf.WriteString("--------------------------------------------------------------------------------\n")
	buf.WriteString("                              SUMMARY\n")
	buf.WriteString("--------------------------------------------------------------------------------\n\n")

	buf.WriteString("Actions:\n")
	for action, count := range actionCounts {
		buf.WriteString(fmt.Sprintf("  %-20s: %d\n", action, count))
	}
	buf.WriteString("\n")

	buf.WriteString("Resource Types:\n")
	for resource, count := range resourceCounts {
		buf.WriteString(fmt.Sprintf("  %-20s: %d\n", resource, count))
	}
	buf.WriteString("\n")

	buf.WriteString(fmt.Sprintf("Success/Failure: %d / %d\n\n", successCount, failureCount))

	// Detailed logs
	buf.WriteString("--------------------------------------------------------------------------------\n")
	buf.WriteString("                            DETAILED LOGS\n")
	buf.WriteString("--------------------------------------------------------------------------------\n\n")

	for i, log := range logs {
		buf.WriteString(fmt.Sprintf("Entry #%d\n", i+1))
		buf.WriteString(fmt.Sprintf("  Timestamp:     %s\n", log.CreatedAt.Format("2006-01-02 15:04:05")))
		buf.WriteString(fmt.Sprintf("  User:          %s\n", safeString(log.Username)))
		buf.WriteString(fmt.Sprintf("  Action:        %s\n", log.Action))
		buf.WriteString(fmt.Sprintf("  Resource Type: %s\n", log.EntityType))
		if log.EntityID != nil && *log.EntityID != "" {
			buf.WriteString(fmt.Sprintf("  Resource ID:   %s\n", *log.EntityID))
		}
		if log.IPAddress != nil && *log.IPAddress != "" {
			buf.WriteString(fmt.Sprintf("  IP Address:    %s\n", *log.IPAddress))
		}
		buf.WriteString(fmt.Sprintf("  Success:       %v\n", log.Success))
		if log.ErrorMsg != nil && *log.ErrorMsg != "" {
			buf.WriteString(fmt.Sprintf("  Error:         %s\n", *log.ErrorMsg))
		}
		if log.Details != nil && len(*log.Details) > 0 {
			buf.WriteString(fmt.Sprintf("  Details:       %s\n", formatDetails(log.Details)))
		}
		buf.WriteString("\n")
	}

	buf.WriteString("================================================================================\n")
	buf.WriteString("                           END OF REPORT\n")
	buf.WriteString("================================================================================\n")

	// Set response headers
	filename := fmt.Sprintf("audit_report_%s.txt", time.Now().Format("2006-01-02"))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))

	w.Write(buf.Bytes())
}

// getLogsForExport retrieves audit logs based on query parameters for export
func (h *AuditHandler) getLogsForExport(r *http.Request) ([]*models.AuditLogEntry, error) {
	// Use a higher default limit for exports
	opts := postgres.AuditLogListOptions{
		Limit:  h.QueryParamInt(r, "limit", 1000),
		Offset: 0,
	}

	// Parse optional filters
	if userID := r.URL.Query().Get("user_id"); userID != "" {
		if uid, err := uuid.Parse(userID); err == nil {
			opts.UserID = &uid
		}
	}

	if action := r.URL.Query().Get("action"); action != "" {
		opts.Action = &action
	}

	if resourceType := r.URL.Query().Get("resource_type"); resourceType != "" {
		opts.ResourceType = &resourceType
	}

	if resourceID := r.URL.Query().Get("resource_id"); resourceID != "" {
		opts.ResourceID = &resourceID
	}

	// Default to last 30 days if no date range specified
	defaultSince := time.Now().AddDate(0, 0, -30)

	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			opts.Since = &t
		}
	} else if days := h.QueryParamInt(r, "days", 0); days > 0 {
		t := time.Now().AddDate(0, 0, -days)
		opts.Since = &t
	} else {
		opts.Since = &defaultSince
	}

	if until := r.URL.Query().Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			opts.Until = &t
		}
	}

	logs, _, err := h.auditSvc.List(r.Context(), opts)
	return logs, err
}

// safeString returns the string value or empty string if nil
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// formatDetails formats the details map as a string
func formatDetails(details *map[string]any) string {
	if details == nil || len(*details) == 0 {
		return ""
	}

	var result string
	for k, v := range *details {
		if k == "success" || k == "error" || k == "username" {
			continue // These are already shown in other columns
		}
		if result != "" {
			result += "; "
		}
		result += fmt.Sprintf("%s=%v", k, v)
	}
	return result
}
