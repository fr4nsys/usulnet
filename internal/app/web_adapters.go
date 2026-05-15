// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	redisrepo "github.com/fr4nsys/usulnet/internal/repository/redis"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
	metricssvc "github.com/fr4nsys/usulnet/internal/services/metrics"
	"github.com/fr4nsys/usulnet/internal/services/notification"
	"github.com/fr4nsys/usulnet/internal/services/notification/channels"
	"github.com/fr4nsys/usulnet/internal/web"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/profile"
)

// ============================================================================
// H1: UserRepository adapter (postgres.UserRepository → web.UserRepository)
// ============================================================================

type webUserRepoAdapter struct {
	repo *postgres.UserRepository
}

func (a *webUserRepoAdapter) GetUserByID(id string) (*web.UserInfo, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}
	user, err := a.repo.GetByID(context.Background(), uid)
	if err != nil {
		return nil, err
	}
	email := ""
	if user.Email != nil {
		email = *user.Email
	}
	return &web.UserInfo{
		ID:        user.ID.String(),
		Username:  user.Username,
		Email:     email,
		Role:      string(user.Role),
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
	}, nil
}

func (a *webUserRepoAdapter) UpdateUser(id string, username string, email string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	user, err := a.repo.GetByID(context.Background(), uid)
	if err != nil {
		return err
	}
	user.Username = username
	if email != "" {
		user.Email = &email
	} else {
		user.Email = nil
	}
	return a.repo.Update(context.Background(), user)
}

func (a *webUserRepoAdapter) UpdatePassword(id string, currentHash string, newHash string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	return a.repo.UpdatePassword(context.Background(), uid, newHash)
}

func (a *webUserRepoAdapter) GetPasswordHash(id string) (string, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return "", fmt.Errorf("invalid user ID: %w", err)
	}
	user, err := a.repo.GetByID(context.Background(), uid)
	if err != nil {
		return "", err
	}
	return user.PasswordHash, nil
}

func (a *webUserRepoAdapter) DeleteUser(id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	return a.repo.Delete(context.Background(), uid)
}

// ============================================================================
// H2: SessionRepository adapter (redis.SessionStore → web.SessionRepository)
// ============================================================================

type webSessionRepoAdapter struct {
	redisStore *redisrepo.SessionStore
}

func (a *webSessionRepoAdapter) GetUserSessions(userID string) ([]profile.SessionInfo, error) {
	sessions, err := a.redisStore.GetAllForUser(context.Background(), userID)
	if err != nil {
		return nil, err
	}
	var infos []profile.SessionInfo
	for _, s := range sessions {
		infos = append(infos, profile.SessionInfo{
			ID:        s.ID,
			IP:        s.IPAddress,
			UserAgent: s.UserAgent,
			Created:   s.CreatedAt.Format("2006-01-02 15:04"),
			LastUsed:  s.LastAccessAt.Format("2006-01-02 15:04"),
		})
	}
	return infos, nil
}

func (a *webSessionRepoAdapter) DeleteSession(sessionID string) error {
	return a.redisStore.Delete(context.Background(), sessionID)
}

func (a *webSessionRepoAdapter) DeleteAllSessionsExcept(userID string, currentSessionID string) error {
	return a.redisStore.DeleteAllForUserExcept(context.Background(), userID, currentSessionID)
}

func (a *webSessionRepoAdapter) GetCurrentSessionID(r *http.Request) string {
	cookie, err := r.Cookie(web.CookieSession)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// ============================================================================
// H3: TerminalSessionRepository adapter
// (postgres.TerminalSessionRepository → web.TerminalSessionRepository)
// ============================================================================

type webTerminalSessionRepoAdapter struct {
	repo *postgres.TerminalSessionRepository
}

func (a *webTerminalSessionRepoAdapter) Create(ctx context.Context, input *web.CreateTerminalSessionInput) (uuid.UUID, error) {
	pgInput := &postgres.CreateTerminalSessionInput{
		UserID:     input.UserID,
		Username:   input.Username,
		TargetType: input.TargetType,
		TargetID:   input.TargetID,
		TargetName: input.TargetName,
		HostID:     input.HostID,
		Shell:      input.Shell,
		TermCols:   input.TermCols,
		TermRows:   input.TermRows,
		ClientIP:   input.ClientIP,
		UserAgent:  input.UserAgent,
	}
	return a.repo.Create(ctx, pgInput)
}

func (a *webTerminalSessionRepoAdapter) End(ctx context.Context, sessionID uuid.UUID, status, errorMsg string) error {
	return a.repo.End(ctx, sessionID, status, errorMsg)
}

func (a *webTerminalSessionRepoAdapter) UpdateResize(ctx context.Context, sessionID uuid.UUID, cols, rows int) error {
	return a.repo.UpdateResize(ctx, sessionID, cols, rows)
}

func (a *webTerminalSessionRepoAdapter) Get(ctx context.Context, sessionID uuid.UUID) (*web.TerminalSession, error) {
	pgSession, err := a.repo.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	return convertTerminalSession(pgSession), nil
}

func (a *webTerminalSessionRepoAdapter) List(ctx context.Context, opts web.TerminalSessionListOptions) ([]*web.TerminalSession, int, error) {
	pgOpts := postgres.ListTerminalSessionOptions{
		UserID:     opts.UserID,
		TargetType: opts.TargetType,
		TargetID:   opts.TargetID,
		HostID:     opts.HostID,
		Status:     opts.Status,
		Since:      opts.Since,
		Until:      opts.Until,
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}
	pgSessions, total, err := a.repo.List(ctx, pgOpts)
	if err != nil {
		return nil, 0, err
	}
	sessions := make([]*web.TerminalSession, 0, len(pgSessions))
	for _, s := range pgSessions {
		sessions = append(sessions, convertTerminalSession(s))
	}
	return sessions, total, nil
}

func (a *webTerminalSessionRepoAdapter) GetByTarget(ctx context.Context, targetType, targetID string, limit int) ([]*web.TerminalSession, error) {
	pgSessions, err := a.repo.GetByTarget(ctx, targetType, targetID, limit)
	if err != nil {
		return nil, err
	}
	sessions := make([]*web.TerminalSession, 0, len(pgSessions))
	for _, s := range pgSessions {
		sessions = append(sessions, convertTerminalSession(s))
	}
	return sessions, nil
}

func (a *webTerminalSessionRepoAdapter) GetByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*web.TerminalSession, error) {
	pgSessions, err := a.repo.GetByUser(ctx, userID, limit)
	if err != nil {
		return nil, err
	}
	sessions := make([]*web.TerminalSession, 0, len(pgSessions))
	for _, s := range pgSessions {
		sessions = append(sessions, convertTerminalSession(s))
	}
	return sessions, nil
}

func (a *webTerminalSessionRepoAdapter) GetActiveSessions(ctx context.Context) ([]*web.TerminalSession, error) {
	pgSessions, err := a.repo.GetActiveSessions(ctx)
	if err != nil {
		return nil, err
	}
	sessions := make([]*web.TerminalSession, 0, len(pgSessions))
	for _, s := range pgSessions {
		sessions = append(sessions, convertTerminalSession(s))
	}
	return sessions, nil
}

func convertTerminalSession(pg *postgres.TerminalSession) *web.TerminalSession {
	return &web.TerminalSession{
		ID:           pg.ID,
		UserID:       pg.UserID,
		Username:     pg.Username,
		TargetType:   pg.TargetType,
		TargetID:     pg.TargetID,
		TargetName:   pg.TargetName,
		HostID:       pg.HostID,
		Shell:        pg.Shell,
		TermCols:     pg.TermCols,
		TermRows:     pg.TermRows,
		ClientIP:     pg.ClientIP,
		StartedAt:    pg.StartedAt,
		EndedAt:      pg.EndedAt,
		DurationMs:   pg.DurationMs,
		Status:       pg.Status,
		ErrorMessage: pg.ErrorMessage,
	}
}

// ============================================================================
// RoleProvider adapter (postgres.RoleRepository → web.Middleware.RoleProvider)
// ============================================================================

type roleProviderAdapter struct {
	repo *postgres.RoleRepository
}

func (a *roleProviderAdapter) GetByID(ctx context.Context, id string) (*models.Role, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid role ID: %w", err)
	}
	return a.repo.GetByID(ctx, uid)
}

// ============================================================================
// MetricsProvider adapter (metrics.Service → monitoring.MetricsProvider)
// Bridges the metrics service (live collection) to the alert system (metric queries).
// ============================================================================

type alertMetricsProviderAdapter struct {
	metrics *metricssvc.Service
	hostID  uuid.UUID // standalone mode host
}

func (a *alertMetricsProviderAdapter) GetHostMetric(ctx context.Context, hostID uuid.UUID, metric models.AlertMetric) (float64, error) {
	hm, err := a.metrics.GetCurrentHostMetrics(ctx, hostID)
	if err != nil {
		return 0, fmt.Errorf("collect host metrics: %w", err)
	}
	return hostMetricValue(hm, metric)
}

func (a *alertMetricsProviderAdapter) GetContainerMetric(ctx context.Context, hostID uuid.UUID, containerID string, metric models.AlertMetric) (float64, error) {
	cms, err := a.metrics.GetCurrentContainerMetrics(ctx, hostID)
	if err != nil {
		return 0, fmt.Errorf("collect container metrics: %w", err)
	}
	for _, cm := range cms {
		if cm.ContainerID == containerID {
			return containerMetricValue(cm, metric)
		}
	}
	return 0, fmt.Errorf("container %s not found on host %s", containerID, hostID)
}

func (a *alertMetricsProviderAdapter) ListHosts(_ context.Context) ([]uuid.UUID, error) {
	return []uuid.UUID{a.hostID}, nil
}

func (a *alertMetricsProviderAdapter) ListContainers(ctx context.Context, hostID uuid.UUID) ([]string, error) {
	cms, err := a.metrics.GetCurrentContainerMetrics(ctx, hostID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(cms))
	for _, cm := range cms {
		ids = append(ids, cm.ContainerID)
	}
	return ids, nil
}

// hostMetricValue extracts a specific metric from a HostMetrics snapshot.
func hostMetricValue(hm *workers.HostMetrics, metric models.AlertMetric) (float64, error) {
	switch metric {
	case models.AlertMetricHostCPU:
		return hm.CPUUsagePercent, nil
	case models.AlertMetricHostMemory:
		return hm.MemoryPercent, nil
	case models.AlertMetricHostDisk:
		return hm.DiskPercent, nil
	case models.AlertMetricHostNetwork:
		return float64(hm.NetworkRxBytes + hm.NetworkTxBytes), nil
	default:
		return 0, fmt.Errorf("unsupported host metric: %s", metric)
	}
}

// containerMetricValue extracts a specific metric from a ContainerMetrics snapshot.
func containerMetricValue(cm *workers.ContainerMetrics, metric models.AlertMetric) (float64, error) {
	switch metric {
	case models.AlertMetricContainerCPU:
		return cm.CPUUsagePercent, nil
	case models.AlertMetricContainerMemory:
		return cm.MemoryPercent, nil
	case models.AlertMetricContainerNetwork:
		return float64(cm.NetworkRxBytes + cm.NetworkTxBytes), nil
	case models.AlertMetricContainerStatus:
		if cm.State == "running" {
			return 1, nil
		}
		return 0, nil
	case models.AlertMetricContainerHealth:
		switch cm.Health {
		case "healthy":
			return 1, nil
		case "unhealthy":
			return 0, nil
		default:
			return 0.5, nil // unknown/starting
		}
	default:
		return 0, fmt.Errorf("unsupported container metric: %s", metric)
	}
}

// ============================================================================
// NotificationSender adapter (notification.Service → monitoring.NotificationSender)
// Bridges the notification service to the alert system for alert dispatching.
// ============================================================================

type alertNotificationSenderAdapter struct {
	svc *notification.Service
}

func (a *alertNotificationSenderAdapter) SendAlert(ctx context.Context, rule *models.AlertRule, event *models.AlertEvent) error {
	return a.svc.Send(ctx, notification.Message{
		Type:     channels.TypeSecurityAlert,
		Title:    fmt.Sprintf("Alert: %s", rule.Name),
		Body:     fmt.Sprintf("Alert rule %q triggered: %s %s %.2f (current: %.2f)", rule.Name, rule.Metric, rule.Operator, rule.Threshold, event.Value),
		Priority: channels.PriorityCritical,
		Data: map[string]interface{}{
			"rule_id":   rule.ID.String(),
			"rule_name": rule.Name,
			"metric":    string(rule.Metric),
			"operator":  string(rule.Operator),
			"threshold": rule.Threshold,
			"value":     event.Value,
			"event_id":  event.ID.String(),
			"severity":  string(rule.Severity),
		},
	})
}

// ============================================================================
// Runbook Notification Adapter
// Bridges the notification service to runbook "notify" steps.
// ============================================================================

type runbookNotificationAdapter struct {
	svc *notification.Service
}

func (a *runbookNotificationAdapter) SendRunbookNotification(ctx context.Context, runbookName, stepName, channel, message string) error {
	msg := notification.Message{
		Type:     channels.TypeSystemInfo,
		Title:    fmt.Sprintf("Runbook: %s", runbookName),
		Body:     message,
		Priority: channels.PriorityNormal,
		Data: map[string]interface{}{
			"runbook_name": runbookName,
			"step_name":    stepName,
			"source":       "runbook",
		},
	}
	if channel != "" {
		msg.Channels = []string{channel}
	}
	return a.svc.Send(ctx, msg)
}

// ============================================================================
// SSL Observatory Notifier Adapter
// Bridges the notification service to the SSL observatory's cert-expiry
// alert hook. Each threshold crossing surfaces one notification.
// ============================================================================

type sslExpiryNotifierAdapter struct {
	svc *notification.Service
}

func (a *sslExpiryNotifierAdapter) NotifyCertExpiring(ctx context.Context, target *models.SSLTarget, scan *models.SSLScanResult, daysLeft, threshold int) error {
	if a.svc == nil {
		return nil
	}
	severity := channels.PriorityNormal
	switch {
	case daysLeft <= 3:
		severity = channels.PriorityCritical
	case daysLeft <= 7:
		severity = channels.PriorityHigh
	}

	hostname := scan.ScanHostname
	if hostname == "" {
		hostname = target.Hostname
	}

	return a.svc.Send(ctx, notification.Message{
		Type:     channels.TypeSecurityAlert,
		Title:    fmt.Sprintf("ssl certificate expiring in %d days: %s", daysLeft, hostname),
		Body:     fmt.Sprintf("the tls certificate for %q (target %q) expires in %d days, below the configured %d-day threshold.", hostname, target.Name, daysLeft, threshold),
		Priority: severity,
		Data: map[string]interface{}{
			"target_id":   target.ID.String(),
			"target_name": target.Name,
			"hostname":    hostname,
			"port":        target.Port,
			"days_left":   daysLeft,
			"threshold":   threshold,
			"grade":       scan.Grade,
			"source":      "ssl_observatory",
		},
	})
}
