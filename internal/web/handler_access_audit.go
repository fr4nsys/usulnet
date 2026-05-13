// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auditsvc "github.com/fr4nsys/usulnet/internal/services/audit"
	aatmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/accessaudit"
)

// In-memory access audit cache for fast dashboard rendering.
// Events are also persisted to PostgreSQL via the audit service when configured.
var (
	accessAuditEntries []accessAuditEntry
	accessAuditMu      sync.RWMutex

	// auditDBService persists access events to the database when set.
	// Configured during app startup via SetAuditDBService.
	auditDBService   *auditsvc.Service
	auditDBServiceMu sync.RWMutex
)

// SetAuditDBService sets the audit service for database persistence of access events.
// Called during app startup to wire the persistent audit log.
func SetAuditDBService(svc *auditsvc.Service) {
	auditDBServiceMu.Lock()
	defer auditDBServiceMu.Unlock()
	auditDBService = svc
}

type accessAuditEntry struct {
	ID           string
	UserName     string
	UserID       string
	Action       string
	ResourceType string
	ResourceID   string
	ResourceName string
	Details      string
	IPAddress    string
	UserAgent    string
	Success      bool
	ErrorMsg     string
	CreatedAt    time.Time
}

// RecordAccessEvent records an access event to the in-memory audit log
// and persists it to the database via the audit service if configured.
func RecordAccessEvent(userName, userID, action, resourceType, resourceID, resourceName, details, ip, ua string, success bool, errMsg string) {
	// In-memory cache for fast dashboard rendering
	accessAuditMu.Lock()
	accessAuditEntries = append([]accessAuditEntry{{
		ID:           uuid.New().String(),
		UserName:     userName,
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		Details:      details,
		IPAddress:    ip,
		UserAgent:    ua,
		Success:      success,
		ErrorMsg:     errMsg,
		CreatedAt:    time.Now(),
	}}, accessAuditEntries...)
	if len(accessAuditEntries) > 500 {
		accessAuditEntries = accessAuditEntries[:500]
	}
	accessAuditMu.Unlock()

	// Persist to database asynchronously
	auditDBServiceMu.RLock()
	svc := auditDBService
	auditDBServiceMu.RUnlock()
	if svc != nil {
		entry := auditsvc.LogEntry{
			Username:     &userName,
			Action:       action,
			ResourceType: resourceType,
			ResourceID:   &resourceID,
			IPAddress:    &ip,
			UserAgent:    &ua,
			Success:      success,
		}
		if userID != "" {
			if parsed, err := uuid.Parse(userID); err == nil {
				entry.UserID = &parsed
			}
		}
		if resourceName != "" || details != "" {
			entry.Details = map[string]any{}
			if resourceName != "" {
				entry.Details["resource_name"] = resourceName
			}
			if details != "" {
				entry.Details["details"] = details
			}
		}
		if errMsg != "" {
			entry.ErrorMsg = &errMsg
		}
		svc.LogAsync(context.Background(), entry)
	}
}

// AccessAuditTempl renders the access control audit page.
func (h *Handler) AccessAuditTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Access Control Audit", "access-audit")

	stats := aatmpl.AccessAuditStats{}
	var auditLogs []aatmpl.AuditEntryView
	var users []aatmpl.UserActivityView

	// Collect in-memory audit entries
	accessAuditMu.RLock()
	uniqueUsers := make(map[string]bool)
	for _, entry := range accessAuditEntries {
		auditLogs = append(auditLogs, aatmpl.AuditEntryView{
			ID:           entry.ID,
			UserName:     entry.UserName,
			UserID:       entry.UserID,
			Action:       entry.Action,
			ActionIcon:   auditActionIcon(entry.Action),
			ActionColor:  auditActionColor(entry.Action),
			ResourceType: entry.ResourceType,
			ResourceID:   entry.ResourceID,
			ResourceName: entry.ResourceName,
			Details:      entry.Details,
			IPAddress:    entry.IPAddress,
			UserAgent:    entry.UserAgent,
			Success:      entry.Success,
			ErrorMsg:     entry.ErrorMsg,
			CreatedAt:    entry.CreatedAt.Format("Jan 02 15:04:05"),
		})
		stats.TotalEvents++
		uniqueUsers[entry.UserID] = true

		if entry.Action == "login" || entry.Action == "login_failed" {
			stats.LoginAttempts++
			if !entry.Success {
				stats.FailedLogins++
			}
		}
		if isHighRiskAction(entry.Action) {
			stats.HighRiskEvents++
		}
	}
	accessAuditMu.RUnlock()
	stats.UniqueUsers = len(uniqueUsers)

	// Also pull proxy audit logs if available
	if proxySvc := h.services.Proxy(); proxySvc != nil {
		if proxyLogs, _, err := proxySvc.ListAuditLogs(ctx, 50, 0); err == nil {
			for _, log := range proxyLogs {
				auditLogs = append(auditLogs, aatmpl.AuditEntryView{
					ID:           fmt.Sprintf("proxy-%s", log.ID),
					UserName:     log.UserName,
					Action:       log.Operation,
					ActionIcon:   auditActionIcon(log.Operation),
					ActionColor:  auditActionColor(log.Operation),
					ResourceType: log.ResourceType,
					ResourceID:   fmt.Sprintf("%d", log.ResourceID),
					ResourceName: log.ResourceName,
					Success:      true,
					CreatedAt:    log.CreatedAt,
				})
				stats.TotalEvents++
			}
		}
	}

	// Get user activity data
	if userSvc := h.services.Users(); userSvc != nil {
		if userList, _, err := userSvc.List(ctx, "", ""); err == nil {
			for _, u := range userList {
				uv := aatmpl.UserActivityView{
					UserID:   u.ID,
					UserName: u.Username,
					Email:    u.Email,
					Role:     u.Role,
					IsActive: u.IsActive,
					IsLocked: u.IsLocked,
				}
				if u.LastLogin != nil {
					uv.LastLoginAt = u.LastLogin.Format("Jan 02 15:04")
				}
				// Count actions per user from audit entries
				accessAuditMu.RLock()
				for _, entry := range accessAuditEntries {
					if entry.UserID == u.ID {
						uv.ActionCount++
						if entry.Action == "login_failed" {
							uv.FailedLogins++
						}
					}
				}
				accessAuditMu.RUnlock()
				users = append(users, uv)
			}
		}
	}

	// Build sessions from login audit events
	var sessions []aatmpl.SessionView
	accessAuditMu.RLock()
	seenUsers := make(map[string]bool)
	for _, entry := range accessAuditEntries {
		if entry.Action == "login" && entry.Success && !seenUsers[entry.UserID] {
			seenUsers[entry.UserID] = true
			sessions = append(sessions, aatmpl.SessionView{
				ID:           entry.ID,
				UserName:     entry.UserName,
				UserID:       entry.UserID,
				IPAddress:    entry.IPAddress,
				UserAgent:    entry.UserAgent,
				StartedAt:    entry.CreatedAt.Format("Jan 02 15:04:05"),
				LastActiveAt: entry.CreatedAt.Format("Jan 02 15:04:05"),
				IsActive:     time.Since(entry.CreatedAt) < 24*time.Hour,
			})
		}
	}
	accessAuditMu.RUnlock()

	// Count active sessions (those within last 24h)
	for _, s := range sessions {
		if s.IsActive {
			stats.ActiveSessions++
		}
	}

	data := aatmpl.AccessAuditData{
		PageData:  pageData,
		AuditLogs: auditLogs,
		Sessions:  sessions,
		Users:     users,
		Stats:     stats,
		ActiveTab: r.URL.Query().Get("tab"),
	}

	h.renderTempl(w, r, aatmpl.AccessAudit(data))
}

// AccessAuditExport exports the audit log as CSV.
func (h *Handler) AccessAuditExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=access_audit.csv")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintln(w, "Timestamp,User,Action,Resource Type,Resource ID,IP Address,Success,Error")

	accessAuditMu.RLock()
	defer accessAuditMu.RUnlock()

	for _, entry := range accessAuditEntries {
		errMsg := ""
		if entry.ErrorMsg != "" {
			errMsg = entry.ErrorMsg
		}
		fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s,%t,\"%s\"\n",
			entry.CreatedAt.Format(time.RFC3339), entry.UserName, entry.Action,
			entry.ResourceType, entry.ResourceID, entry.IPAddress, entry.Success, errMsg)
	}
}

// AccessAuditSessionRevoke revokes/terminates a user session.
func (h *Handler) AccessAuditSessionRevoke(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if sessionID == "" {
		h.setFlash(w, r, "error", "Session ID is required")
		http.Redirect(w, r, "/access-audit?tab=sessions", http.StatusSeeOther)
		return
	}

	// Attempt to invalidate the session via auth service Logout
	authSvc := h.services.Auth()
	if authSvc != nil {
		if err := authSvc.Logout(r.Context(), sessionID); err != nil {
			h.logger.Error("failed to revoke session", "session_id", sessionID, "error", err)
			// Even if revocation fails, record the attempt
		}
	}

	// Record the revocation in access audit
	user := h.getUserData(r)
	userName := "system"
	userID := ""
	if user != nil {
		userName = user.Username
		userID = user.ID
	}
	RecordAccessEvent(userName, userID, "session_revoke", "session", sessionID, "", "Session revoked by admin", getRealIP(r), r.UserAgent(), true, "")

	h.setFlash(w, r, "success", "Session revoked successfully")
	http.Redirect(w, r, "/access-audit?tab=sessions", http.StatusSeeOther)
}

// auditActionIcon returns a FontAwesome icon class for an audit action.
func auditActionIcon(action string) string {
	switch action {
	case "login":
		return "fas fa-sign-in-alt"
	case "logout":
		return "fas fa-sign-out-alt"
	case "login_failed":
		return "fas fa-user-times"
	case "create":
		return "fas fa-plus"
	case "update":
		return "fas fa-edit"
	case "delete":
		return "fas fa-trash"
	case "start":
		return "fas fa-play"
	case "stop":
		return "fas fa-stop"
	case "restart":
		return "fas fa-redo"
	case "backup":
		return "fas fa-archive"
	case "restore":
		return "fas fa-undo"
	case "security_scan":
		return "fas fa-shield-alt"
	case "password_change":
		return "fas fa-key"
	case "api_key_create":
		return "fas fa-key"
	default:
		return "fas fa-circle"
	}
}

// auditActionColor returns a Tailwind text color class for an audit action.
func auditActionColor(action string) string {
	switch action {
	case "login":
		return "text-green-400"
	case "logout":
		return "text-gray-400"
	case "login_failed":
		return "text-red-400"
	case "create":
		return "text-blue-400"
	case "update":
		return "text-yellow-400"
	case "delete":
		return "text-red-400"
	case "start":
		return "text-green-400"
	case "stop":
		return "text-orange-400"
	case "restart":
		return "text-cyan-400"
	case "security_scan":
		return "text-purple-400"
	default:
		return "text-gray-400"
	}
}

// isHighRiskAction returns true for actions that are considered high-risk.
func isHighRiskAction(action string) bool {
	switch action {
	case "delete", "login_failed", "password_change", "password_reset",
		"api_key_create", "api_key_delete", "restore", "rollback":
		return true
	default:
		return false
	}
}
