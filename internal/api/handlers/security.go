// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package handlers provides HTTP handlers for the API.
package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/security"
)

// SecurityHandler handles security-related HTTP requests.
type SecurityHandler struct {
	BaseHandler
	securityService *security.Service
}

// NewSecurityHandler creates a new security handler.
func NewSecurityHandler(securityService *security.Service, log *logger.Logger) *SecurityHandler {
	return &SecurityHandler{
		BaseHandler:     NewBaseHandler(log),
		securityService: securityService,
	}
}

// Routes returns the router for security endpoints.
func (h *SecurityHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Read-only routes (viewer+)
	r.Get("/scans", h.ListScans)
	r.Route("/scans/{scanID}", func(r chi.Router) {
		r.Get("/", h.GetScan)

		// Operator+ for mutations
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireOperator)
			r.Delete("/", h.DeleteScan)
		})
	})

	// Container scans (viewer+)
	r.Get("/containers/{containerID}/scans", h.GetContainerScans)
	r.Get("/containers/{containerID}/scans/latest", h.GetLatestScan)
	r.Get("/containers/{containerID}/issues", h.GetContainerIssues)

	// Host scans (viewer+)
	r.Get("/hosts/{hostID}/scans", h.GetHostScans)
	r.Get("/hosts/{hostID}/issues", h.GetHostIssues)
	r.Get("/hosts/{hostID}/summary", h.GetSecuritySummary)

	// Issues
	r.Get("/issues/{issueID}", h.GetIssue)

	// Operator+ for issue status changes
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireOperator)
		r.Put("/issues/{issueID}", h.UpdateIssueStatus)
	})

	// Summary (viewer+)
	r.Get("/summary", h.GetSummary)

	// Admin-only maintenance
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Post("/cleanup", h.CleanupOldScans)
	})

	return r
}

// ============================================================================
// Response types
// ============================================================================

// SecurityScanResponse represents a security scan in API responses.
type SecurityScanResponse struct {
	ID            string                   `json:"id"`
	HostID        string                   `json:"host_id"`
	ContainerID   string                   `json:"container_id"`
	ContainerName string                   `json:"container_name"`
	Image         string                   `json:"image"`
	Score         int                      `json:"score"`
	Grade         string                   `json:"grade"`
	IssueCount    int                      `json:"issue_count"`
	CriticalCount int                      `json:"critical_count"`
	HighCount     int                      `json:"high_count"`
	MediumCount   int                      `json:"medium_count"`
	LowCount      int                      `json:"low_count"`
	CVECount      int                      `json:"cve_count"`
	IncludeCVE    bool                     `json:"include_cve"`
	ScanDuration  string                   `json:"scan_duration"`
	CompletedAt   string                   `json:"completed_at"`
	CreatedAt     string                   `json:"created_at"`
	Issues        []SecurityIssueResponse  `json:"issues,omitempty"`
}

// SecurityIssueResponse represents a security issue in API responses.
type SecurityIssueResponse struct {
	ID             int64   `json:"id"`
	ScanID         string  `json:"scan_id"`
	ContainerID    string  `json:"container_id"`
	HostID         string  `json:"host_id"`
	Severity       string  `json:"severity"`
	Category       string  `json:"category"`
	CheckID        string  `json:"check_id"`
	Title          string  `json:"title"`
	Description    string  `json:"description"`
	Recommendation string  `json:"recommendation"`
	FixCommand     *string `json:"fix_command,omitempty"`
	DocumentationURL *string `json:"documentation_url,omitempty"`
	CVEID          *string `json:"cve_id,omitempty"`
	CVSSScore      *float64 `json:"cvss_score,omitempty"`
	Status         string  `json:"status"`
	AcknowledgedBy *string `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *string `json:"acknowledged_at,omitempty"`
	ResolvedBy     *string `json:"resolved_by,omitempty"`
	ResolvedAt     *string `json:"resolved_at,omitempty"`
	DetectedAt     string  `json:"detected_at"`
}

// SecuritySummaryResponse represents a security summary.
type SecuritySummaryResponse struct {
	GeneratedAt       string              `json:"generated_at"`
	TotalContainers   int                 `json:"total_containers"`
	TotalIssues       int                 `json:"total_issues"`
	AverageScore      float64             `json:"average_score"`
	GradeDistribution map[string]int      `json:"grade_distribution"`
	SeverityCounts    map[string]int      `json:"severity_counts"`
}

// UpdateIssueStatusRequest represents a request to update issue status.
type UpdateIssueStatusRequest struct {
	Status string `json:"status"`
}

// ============================================================================
// Handlers
// ============================================================================

// ListScans returns all security scans.
// GET /api/v1/security/scans
func (h *SecurityHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	pagination := h.GetPagination(r)

	opts := security.ListScansOptions{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}

	// Optional filters
	if hostID := h.QueryParamUUID(r, "host_id"); hostID != nil {
		opts.HostID = hostID
	}
	if containerID := h.QueryParam(r, "container_id"); containerID != "" {
		opts.ContainerID = &containerID
	}
	if grade := h.QueryParam(r, "grade"); grade != "" {
		secGrade := models.SecurityGrade(grade)
		opts.Grade = &secGrade
	}
	if minScore := h.QueryParamInt(r, "min_score", -1); minScore >= 0 {
		opts.MinScore = &minScore
	}
	if maxScore := h.QueryParamInt(r, "max_score", -1); maxScore >= 0 {
		opts.MaxScore = &maxScore
	}

	scans, total, err := h.securityService.ListScans(r.Context(), opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]SecurityScanResponse, len(scans))
	for i, scan := range scans {
		resp[i] = toSecurityScanResponse(scan)
	}

	h.OK(w, NewPaginatedResponse(resp, int64(total), pagination))
}

// GetScan returns a specific security scan.
// GET /api/v1/security/scans/{scanID}
func (h *SecurityHandler) GetScan(w http.ResponseWriter, r *http.Request) {
	scanID, err := h.URLParamUUID(r, "scanID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	scan, err := h.securityService.GetScan(r.Context(), scanID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toSecurityScanResponse(scan))
}

// DeleteScan deletes a security scan.
// DELETE /api/v1/security/scans/{scanID}
func (h *SecurityHandler) DeleteScan(w http.ResponseWriter, r *http.Request) {
	scanID, err := h.URLParamUUID(r, "scanID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	if err := h.securityService.DeleteScan(r.Context(), scanID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// GetContainerScans returns scans for a specific container.
// GET /api/v1/security/containers/{containerID}/scans
func (h *SecurityHandler) GetContainerScans(w http.ResponseWriter, r *http.Request) {
	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	limit := h.QueryParamInt(r, "limit", 10)

	scans, err := h.securityService.GetContainerScans(r.Context(), containerID, limit)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]SecurityScanResponse, len(scans))
	for i, scan := range scans {
		resp[i] = toSecurityScanResponse(scan)
	}

	h.OK(w, resp)
}

// GetLatestScan returns the latest scan for a container.
// GET /api/v1/security/containers/{containerID}/scans/latest
func (h *SecurityHandler) GetLatestScan(w http.ResponseWriter, r *http.Request) {
	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	scan, err := h.securityService.GetLatestScan(r.Context(), containerID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toSecurityScanResponse(scan))
}

// GetHostScans returns scans for a specific host.
// GET /api/v1/security/hosts/{hostID}/scans
func (h *SecurityHandler) GetHostScans(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	limit := h.QueryParamInt(r, "limit", 10)

	scans, err := h.securityService.GetHostScans(r.Context(), hostID, limit)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]SecurityScanResponse, len(scans))
	for i, scan := range scans {
		resp[i] = toSecurityScanResponse(scan)
	}

	h.OK(w, resp)
}

// GetIssue returns a specific security issue.
// GET /api/v1/security/issues/{issueID}
func (h *SecurityHandler) GetIssue(w http.ResponseWriter, r *http.Request) {
	issueIDStr := h.URLParam(r, "issueID")
	issueID, err := strconv.ParseInt(issueIDStr, 10, 64)
	if err != nil {
		h.BadRequest(w, "invalid issue ID")
		return
	}

	issue, err := h.securityService.GetIssue(r.Context(), issueID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toSecurityIssueResponse(issue))
}

// UpdateIssueStatus updates the status of a security issue.
// PUT /api/v1/security/issues/{issueID}
func (h *SecurityHandler) UpdateIssueStatus(w http.ResponseWriter, r *http.Request) {
	issueIDStr := h.URLParam(r, "issueID")
	issueID, err := strconv.ParseInt(issueIDStr, 10, 64)
	if err != nil {
		h.BadRequest(w, "invalid issue ID")
		return
	}

	var req UpdateIssueStatusRequest
	if err := h.ParseJSON(r, &req); err != nil {
		h.HandleError(w, err)
		return
	}

	if req.Status == "" {
		h.BadRequest(w, "status is required")
		return
	}

	userID, _ := h.GetUserID(r)

	if err := h.securityService.UpdateIssueStatus(r.Context(), issueID, models.IssueStatus(req.Status), &userID); err != nil {
		h.HandleError(w, err)
		return
	}

	h.NoContent(w)
}

// GetContainerIssues returns issues for a specific container.
// GET /api/v1/security/containers/{containerID}/issues
func (h *SecurityHandler) GetContainerIssues(w http.ResponseWriter, r *http.Request) {
	containerID := h.URLParam(r, "containerID")
	if containerID == "" {
		h.BadRequest(w, "containerID is required")
		return
	}

	var status *models.IssueStatus
	if s := h.QueryParam(r, "status"); s != "" {
		is := models.IssueStatus(s)
		status = &is
	}

	issues, err := h.securityService.GetContainerIssues(r.Context(), containerID, status)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]SecurityIssueResponse, len(issues))
	for i, issue := range issues {
		resp[i] = toSecurityIssueResponse(issue)
	}

	h.OK(w, resp)
}

// GetHostIssues returns issues for a specific host.
// GET /api/v1/security/hosts/{hostID}/issues
func (h *SecurityHandler) GetHostIssues(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	pagination := h.GetPagination(r)

	opts := security.ListIssuesOptions{
		Limit:  pagination.PerPage,
		Offset: pagination.Offset,
	}

	if severity := h.QueryParam(r, "severity"); severity != "" {
		sev := models.IssueSeverity(severity)
		opts.Severity = &sev
	}
	if status := h.QueryParam(r, "status"); status != "" {
		s := models.IssueStatus(status)
		opts.Status = &s
	}

	issues, total, err := h.securityService.GetHostIssues(r.Context(), hostID, opts)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	resp := make([]SecurityIssueResponse, len(issues))
	for i, issue := range issues {
		resp[i] = toSecurityIssueResponse(issue)
	}

	h.OK(w, NewPaginatedResponse(resp, int64(total), pagination))
}

// GetSecuritySummary returns security summary for a host.
// GET /api/v1/security/hosts/{hostID}/summary
func (h *SecurityHandler) GetSecuritySummary(w http.ResponseWriter, r *http.Request) {
	hostID, err := h.URLParamUUID(r, "hostID")
	if err != nil {
		h.HandleError(w, err)
		return
	}

	summary, err := h.securityService.GetSecuritySummary(r.Context(), &hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toSecuritySummaryResponse(summary))
}

// GetSummary returns overall security summary.
// GET /api/v1/security/summary
func (h *SecurityHandler) GetSummary(w http.ResponseWriter, r *http.Request) {
	var hostID *uuid.UUID
	if hid := h.QueryParamUUID(r, "host_id"); hid != nil {
		hostID = hid
	}

	summary, err := h.securityService.GetSecuritySummary(r.Context(), hostID)
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, toSecuritySummaryResponse(summary))
}

// CleanupOldScans removes old security scans.
// POST /api/v1/security/cleanup
func (h *SecurityHandler) CleanupOldScans(w http.ResponseWriter, r *http.Request) {
	if err := h.RequireAdmin(r); err != nil {
		h.HandleError(w, err)
		return
	}

	count, err := h.securityService.CleanupOldScans(r.Context())
	if err != nil {
		h.HandleError(w, err)
		return
	}

	h.OK(w, map[string]int64{"scans_deleted": count})
}

// ============================================================================
// Helpers
// ============================================================================

func toSecurityScanResponse(scan *models.SecurityScan) SecurityScanResponse {
	resp := SecurityScanResponse{
		ID:            scan.ID.String(),
		HostID:        scan.HostID.String(),
		ContainerID:   scan.ContainerID,
		ContainerName: scan.ContainerName,
		Image:         scan.Image,
		Score:         scan.Score,
		Grade:         string(scan.Grade),
		IssueCount:    scan.IssueCount,
		CriticalCount: scan.CriticalCount,
		HighCount:     scan.HighCount,
		MediumCount:   scan.MediumCount,
		LowCount:      scan.LowCount,
		CVECount:      scan.CVECount,
		IncludeCVE:    scan.IncludeCVE,
		ScanDuration:  scan.ScanDuration.String(),
		CompletedAt:   scan.CompletedAt.Format(time.RFC3339),
		CreatedAt:     scan.CreatedAt.Format(time.RFC3339),
	}

	if len(scan.Issues) > 0 {
		resp.Issues = make([]SecurityIssueResponse, len(scan.Issues))
		for i, issue := range scan.Issues {
			resp.Issues[i] = toSecurityIssueResponse(&issue)
		}
	}

	return resp
}

func toSecurityIssueResponse(issue *models.SecurityIssue) SecurityIssueResponse {
	resp := SecurityIssueResponse{
		ID:             issue.ID,
		ScanID:         issue.ScanID.String(),
		ContainerID:    issue.ContainerID,
		HostID:         issue.HostID.String(),
		Severity:       string(issue.Severity),
		Category:       string(issue.Category),
		CheckID:        issue.CheckID,
		Title:          issue.Title,
		Description:    issue.Description,
		Recommendation: issue.Recommendation,
		FixCommand:     issue.FixCommand,
		DocumentationURL: issue.DocumentationURL,
		CVEID:          issue.CVEID,
		CVSSScore:      issue.CVSSScore,
		Status:         string(issue.Status),
		DetectedAt:     issue.DetectedAt.Format(time.RFC3339),
	}

	if issue.AcknowledgedBy != nil {
		s := issue.AcknowledgedBy.String()
		resp.AcknowledgedBy = &s
	}
	if issue.AcknowledgedAt != nil {
		t := issue.AcknowledgedAt.Format(time.RFC3339)
		resp.AcknowledgedAt = &t
	}
	if issue.ResolvedBy != nil {
		s := issue.ResolvedBy.String()
		resp.ResolvedBy = &s
	}
	if issue.ResolvedAt != nil {
		t := issue.ResolvedAt.Format(time.RFC3339)
		resp.ResolvedAt = &t
	}

	return resp
}

func toSecuritySummaryResponse(summary *security.SecuritySummary) SecuritySummaryResponse {
	resp := SecuritySummaryResponse{
		GeneratedAt:     summary.GeneratedAt.Format(time.RFC3339),
		TotalContainers: summary.TotalContainers,
		TotalIssues:     summary.TotalIssues,
		AverageScore:    summary.AverageScore,
	}

	// Convert grade distribution
	if summary.GradeDistribution != nil {
		resp.GradeDistribution = make(map[string]int)
		for k, v := range summary.GradeDistribution {
			resp.GradeDistribution[string(k)] = v
		}
	}

	// Convert severity counts
	if summary.SeverityCounts != nil {
		resp.SeverityCounts = make(map[string]int)
		for k, v := range summary.SeverityCounts {
			resp.SeverityCounts[string(k)] = v
		}
	}

	return resp
}
