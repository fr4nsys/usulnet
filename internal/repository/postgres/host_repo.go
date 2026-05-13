// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package postgres provides PostgreSQL repository implementations.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// HostRepository implements HostRepository interface.
type HostRepository struct {
	db *sqlx.DB
}

// NewHostRepository creates a new host repository.
func NewHostRepository(db *sqlx.DB) *HostRepository {
	return &HostRepository{db: db}
}



// GetByAgentToken finds a host by validating the agent token against stored hash.
func (r *HostRepository) GetByAgentToken(ctx context.Context, token string) (*models.HostInfo, error) {
	query := `
		SELECT id, name, agent_token_hash, status
		FROM hosts
		WHERE endpoint_type = 'agent'
		  AND agent_token_hash IS NOT NULL
		  AND agent_token_hash != ''
	`

	type hostRow struct {
		ID             uuid.UUID `db:"id"`
		Name           string    `db:"name"`
		AgentTokenHash string    `db:"agent_token_hash"`
		Status         string    `db:"status"`
	}

	var hosts []hostRow
	if err := r.db.SelectContext(ctx, &hosts, query); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to query hosts")
	}

	for _, h := range hosts {
		if err := bcrypt.CompareHashAndPassword([]byte(h.AgentTokenHash), []byte(token)); err == nil {
			return &models.HostInfo{
				ID:     h.ID,
				Name:   h.Name,
				Status: h.Status,
			}, nil
		}
	}

	return nil, errors.NotFound("host")
}

// UpdateStatus updates the host status and last seen timestamp.
func (r *HostRepository) UpdateStatus(ctx context.Context, hostID uuid.UUID, status string, lastSeen time.Time) error {
	query := `
		UPDATE hosts
		SET status = $1,
		    last_seen_at = $2,
		    updated_at = NOW()
		WHERE id = $3
	`

	result, err := r.db.ExecContext(ctx, query, status, lastSeen, hostID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update host status")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("host")
	}

	return nil
}

// UpdateAgentInfo updates the agent information for a host.
func (r *HostRepository) UpdateAgentInfo(ctx context.Context, hostID uuid.UUID, info *protocol.AgentInfo) error {
	query := `
		UPDATE hosts
		SET docker_version = $1,
		    os_type = $2,
		    architecture = $3,
		    agent_info = $4,
		    updated_at = NOW()
		WHERE id = $5
	`

	infoJSON, err := json.Marshal(info)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to marshal agent info")
	}

	result, err := r.db.ExecContext(ctx, query,
		info.Version,
		info.OS,
		info.Arch,
		string(infoJSON),
		hostID,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update agent info")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("host")
	}

	return nil
}

// GetByID retrieves a host by ID.
func (r *HostRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Host, error) {
	query := `
		SELECT id, name, display_name, endpoint_type, endpoint_url,
		       agent_id, tls_enabled, status, status_message,
		       last_seen_at, docker_version, os_type, architecture,
		       total_memory, total_cpus, labels, created_at, updated_at
		FROM hosts
		WHERE id = $1
	`

	var host models.Host
	if err := r.db.GetContext(ctx, &host, query, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NotFound("host")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get host")
	}

	return &host, nil
}

// GetByName retrieves a host by name.
func (r *HostRepository) GetByName(ctx context.Context, name string) (*models.Host, error) {
	query := `
		SELECT id, name, display_name, endpoint_type, endpoint_url,
		       agent_id, tls_enabled, status, status_message,
		       last_seen_at, docker_version, os_type, architecture,
		       total_memory, total_cpus, labels, created_at, updated_at
		FROM hosts
		WHERE name = $1
	`

	var host models.Host
	if err := r.db.GetContext(ctx, &host, query, name); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NotFound("host")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get host by name")
	}

	return &host, nil
}

// HostFilter defines filtering options for host listing.
type HostFilter struct {
	Status       string
	EndpointType string
	Limit        int
	Offset       int
}

// List retrieves all hosts with optional filtering.
func (r *HostRepository) List(ctx context.Context, filter HostFilter) ([]*models.Host, error) {
	query := `
		SELECT id, name, display_name, endpoint_type, endpoint_url,
		       agent_id, tls_enabled, status, status_message,
		       last_seen_at, docker_version, os_type, architecture,
		       total_memory, total_cpus, labels, created_at, updated_at
		FROM hosts
		WHERE 1=1
	`

	args := make([]interface{}, 0)
	argIdx := 1

	if filter.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, filter.Status)
		argIdx++
	}

	if filter.EndpointType != "" {
		query += fmt.Sprintf(" AND endpoint_type = $%d", argIdx)
		args = append(args, filter.EndpointType)
		argIdx++
	}

	query += " ORDER BY name ASC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, filter.Limit)
		argIdx++
	}

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filter.Offset)
	}

	var hosts []*models.Host
	if err := r.db.SelectContext(ctx, &hosts, query, args...); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list hosts")
	}

	return hosts, nil
}

// Create creates a new host.
func (r *HostRepository) Create(ctx context.Context, input *models.CreateHostInput) (*models.Host, error) {
	host := &models.Host{
		ID:           uuid.New(),
		Name:         input.Name,
		DisplayName:  input.DisplayName,
		EndpointType: input.EndpointType,
		EndpointURL:  input.EndpointURL,
		TLSEnabled:   input.TLSEnabled,
		TLSCACert:    input.TLSCACert,
		TLSClientCert: input.TLSClientCert,
		TLSClientKey: input.TLSClientKey,
		Status:       models.HostStatusUnknown,
		Labels:       models.JSONStringMap(input.Labels),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	query := `
		INSERT INTO hosts (
			id, name, display_name, endpoint_type, endpoint_url,
			tls_enabled, tls_ca_cert, tls_client_cert, tls_client_key,
			status, labels, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
	`

	labels := host.Labels
	if labels == nil {
		labels = models.JSONStringMap{}
	}
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to marshal labels")
	}

	_, err = r.db.ExecContext(ctx, query,
		host.ID, host.Name, host.DisplayName, host.EndpointType, host.EndpointURL,
		host.TLSEnabled, host.TLSCACert, host.TLSClientCert, host.TLSClientKey,
		host.Status, string(labelsJSON), host.CreatedAt, host.UpdatedAt,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create host")
	}

	return host, nil
}

// Update updates an existing host.
func (r *HostRepository) Update(ctx context.Context, id uuid.UUID, input *models.UpdateHostInput) (*models.Host, error) {
	setClauses := []string{"updated_at = NOW()"}
	args := make([]interface{}, 0)
	argIdx := 1

	if input.DisplayName != nil {
		setClauses = append(setClauses, fmt.Sprintf("display_name = $%d", argIdx))
		args = append(args, *input.DisplayName)
		argIdx++
	}

	if input.EndpointURL != nil {
		setClauses = append(setClauses, fmt.Sprintf("endpoint_url = $%d", argIdx))
		args = append(args, *input.EndpointURL)
		argIdx++
	}

	if input.TLSEnabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("tls_enabled = $%d", argIdx))
		args = append(args, *input.TLSEnabled)
		argIdx++
	}

	if input.Labels != nil {
		labelsJSON, err := json.Marshal(input.Labels)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "failed to marshal labels")
		}
		setClauses = append(setClauses, fmt.Sprintf("labels = $%d", argIdx))
		args = append(args, string(labelsJSON))
		argIdx++
	}

	args = append(args, id)

	query := fmt.Sprintf(`
		UPDATE hosts
		SET %s
		WHERE id = $%d
	`, joinStrings(setClauses, ", "), argIdx)

	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to update host")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get affected rows")
	}

	if rows == 0 {
		return nil, errors.NotFound("host")
	}

	return r.GetByID(ctx, id)
}

// Delete deletes a host by ID.
func (r *HostRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM hosts WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to delete host")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("host")
	}

	return nil
}

// SetAgentToken sets the agent token hash for a host.
func (r *HostRepository) SetAgentToken(ctx context.Context, hostID uuid.UUID, token string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to hash token")
	}

	query := `
		UPDATE hosts
		SET agent_token_hash = $1,
		    updated_at = NOW()
		WHERE id = $2
	`

	result, err := r.db.ExecContext(ctx, query, string(hash), hostID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to set agent token")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("host")
	}

	return nil
}

// ClearAgentToken removes the agent token for a host.
func (r *HostRepository) ClearAgentToken(ctx context.Context, hostID uuid.UUID) error {
	query := `
		UPDATE hosts
		SET agent_token_hash = NULL,
		    updated_at = NOW()
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, hostID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to clear agent token")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to get affected rows")
	}

	if rows == 0 {
		return errors.NotFound("host")
	}

	return nil
}

// GetAgentHosts returns all hosts configured for agent-based connection.
func (r *HostRepository) GetAgentHosts(ctx context.Context) ([]*models.Host, error) {
	query := `
		SELECT id, name, display_name, endpoint_type, endpoint_url,
		       agent_id, tls_enabled, status, status_message,
		       last_seen_at, docker_version, os_type, architecture,
		       total_memory, total_cpus, labels, created_at, updated_at
		FROM hosts
		WHERE endpoint_type = 'agent'
		ORDER BY name ASC
	`

	var hosts []*models.Host
	if err := r.db.SelectContext(ctx, &hosts, query); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get agent hosts")
	}

	return hosts, nil
}

// GetOnlineHosts returns all hosts that are currently online.
func (r *HostRepository) GetOnlineHosts(ctx context.Context) ([]*models.Host, error) {
	query := `
		SELECT id, name, display_name, endpoint_type, endpoint_url,
		       agent_id, tls_enabled, status, status_message,
		       last_seen_at, docker_version, os_type, architecture,
		       total_memory, total_cpus, labels, created_at, updated_at
		FROM hosts
		WHERE status = 'online'
		ORDER BY name ASC
	`

	var hosts []*models.Host
	if err := r.db.SelectContext(ctx, &hosts, query); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get online hosts")
	}

	return hosts, nil
}

// CountByStatus returns the count of hosts by status.
func (r *HostRepository) CountByStatus(ctx context.Context) (map[string]int, error) {
	query := `
		SELECT status, COUNT(*) as count
		FROM hosts
		GROUP BY status
	`

	type statusCount struct {
		Status string `db:"status"`
		Count  int    `db:"count"`
	}

	var counts []statusCount
	if err := r.db.SelectContext(ctx, &counts, query); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to count hosts by status")
	}

	result := make(map[string]int)
	for _, sc := range counts {
		result[sc.Status] = sc.Count
	}

	return result, nil
}

// joinStrings joins strings with a separator.
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

// ============================================================================
// Additional Methods Required by Host Service
// ============================================================================

// HostListOptions defines options for listing hosts with pagination.
type HostListOptions struct {
	Status       string
	EndpointType string
	Search       string
	Limit        int
	Offset       int
	OrderBy      string
	OrderDir     string
}

// HostStats holds host statistics.
type HostStats struct {
	Total    int            `json:"total"`
	Online   int            `json:"online"`
	Offline  int            `json:"offline"`
	Error    int            `json:"error"`
	Unknown  int            `json:"unknown"`
	ByType   map[string]int `json:"by_type"`
	ByStatus map[string]int `json:"by_status"`
}

// ListOnline returns all hosts that are currently online.
func (r *HostRepository) ListOnline(ctx context.Context) ([]*models.Host, error) {
	return r.GetOnlineHosts(ctx)
}

// SetOffline marks a host as offline with a reason.
func (r *HostRepository) SetOffline(ctx context.Context, hostID uuid.UUID, reason string) error {
	query := `
		UPDATE hosts
		SET status = 'offline',
		    status_message = $1,
		    updated_at = NOW()
		WHERE id = $2
	`

	_, err := r.db.ExecContext(ctx, query, reason, hostID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to set host offline")
	}

	return nil
}

// SetError marks a host as having an error.
func (r *HostRepository) SetError(ctx context.Context, hostID uuid.UUID, errMsg string) error {
	query := `
		UPDATE hosts
		SET status = 'error',
		    status_message = $1,
		    updated_at = NOW()
		WHERE id = $2
	`

	_, err := r.db.ExecContext(ctx, query, errMsg, hostID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to set host error")
	}

	return nil
}

// MarkStaleHostsOffline marks hosts that haven't been seen recently as offline.
func (r *HostRepository) MarkStaleHostsOffline(ctx context.Context, threshold time.Duration) (int64, error) {
	query := `
		UPDATE hosts
		SET status = 'offline',
		    status_message = 'Host became stale',
		    updated_at = NOW()
		WHERE status = 'online'
		  AND endpoint_type = 'agent'
		  AND last_seen_at < $1
	`

	cutoff := time.Now().Add(-threshold)
	result, err := r.db.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to mark stale hosts offline")
	}

	return result.RowsAffected()
}

// ExistsByName checks if a host with the given name exists.
func (r *HostRepository) ExistsByName(ctx context.Context, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM hosts WHERE name = $1)`

	var exists bool
	if err := r.db.GetContext(ctx, &exists, query, name); err != nil {
		return false, errors.Wrap(err, errors.CodeInternal, "failed to check host existence")
	}

	return exists, nil
}

// DeleteOldMetrics deletes host metrics older than the given retention period.
func (r *HostRepository) DeleteOldMetrics(ctx context.Context, retention time.Duration) (int64, error) {
	query := `DELETE FROM host_metrics WHERE created_at < $1`

	cutoff := time.Now().Add(-retention)
	result, err := r.db.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to delete old metrics")
	}

	return result.RowsAffected()
}

// GetStats returns host statistics.
func (r *HostRepository) GetStats(ctx context.Context) (*HostStats, error) {
	stats := &HostStats{
		ByType:   make(map[string]int),
		ByStatus: make(map[string]int),
	}

	statusCounts, err := r.CountByStatus(ctx)
	if err != nil {
		return nil, err
	}
	stats.ByStatus = statusCounts

	for status, count := range statusCounts {
		stats.Total += count
		switch status {
		case "online":
			stats.Online = count
		case "offline":
			stats.Offline = count
		case "error":
			stats.Error = count
		default:
			stats.Unknown += count
		}
	}

	typeQuery := `
		SELECT endpoint_type, COUNT(*) as count
		FROM hosts
		GROUP BY endpoint_type
	`

	type typeCount struct {
		EndpointType string `db:"endpoint_type"`
		Count        int    `db:"count"`
	}

	var typeCounts []typeCount
	if err := r.db.SelectContext(ctx, &typeCounts, typeQuery); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to count hosts by type")
	}

	for _, tc := range typeCounts {
		stats.ByType[tc.EndpointType] = tc.Count
	}

	return stats, nil
}

// ListWithOptions returns hosts with pagination and total count.
func (r *HostRepository) ListWithOptions(ctx context.Context, opts HostListOptions) ([]*models.Host, int64, error) {
	countQuery := `SELECT COUNT(*) FROM hosts WHERE 1=1`
	query := `
		SELECT id, name, display_name, endpoint_type, endpoint_url,
		       agent_id, tls_enabled, status, status_message,
		       last_seen_at, docker_version, os_type, architecture,
		       total_memory, total_cpus, labels, created_at, updated_at
		FROM hosts
		WHERE 1=1
	`

	args := make([]interface{}, 0)
	countArgs := make([]interface{}, 0)
	argIdx := 1

	if opts.Status != "" {
		countQuery += fmt.Sprintf(" AND status = $%d", argIdx)
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, opts.Status)
		countArgs = append(countArgs, opts.Status)
		argIdx++
	}

	if opts.EndpointType != "" {
		countQuery += fmt.Sprintf(" AND endpoint_type = $%d", argIdx)
		query += fmt.Sprintf(" AND endpoint_type = $%d", argIdx)
		args = append(args, opts.EndpointType)
		countArgs = append(countArgs, opts.EndpointType)
		argIdx++
	}

	if opts.Search != "" {
		countQuery += fmt.Sprintf(" AND (name ILIKE $%d OR display_name ILIKE $%d)", argIdx, argIdx)
		query += fmt.Sprintf(" AND (name ILIKE $%d OR display_name ILIKE $%d)", argIdx, argIdx)
		searchTerm := "%" + opts.Search + "%"
		args = append(args, searchTerm)
		countArgs = append(countArgs, searchTerm)
		argIdx++
	}

	var total int64
	if err := r.db.GetContext(ctx, &total, countQuery, countArgs...); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "failed to count hosts")
	}

	allowedSortFields := map[string]bool{
		"name": true, "display_name": true, "status": true,
		"endpoint_type": true, "created_at": true, "updated_at": true,
	}
	orderBy := "name"
	if opts.OrderBy != "" && allowedSortFields[opts.OrderBy] {
		orderBy = opts.OrderBy
	}
	orderDir := "ASC"
	if opts.OrderDir == "desc" {
		orderDir = "DESC"
	}
	query += fmt.Sprintf(" ORDER BY %s %s", orderBy, orderDir)

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, opts.Limit)
		argIdx++
	}

	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, opts.Offset)
	}

	var hosts []*models.Host
	if err := r.db.SelectContext(ctx, &hosts, query, args...); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "failed to list hosts")
	}

	return hosts, total, nil
}

// GetHostSummaries returns all hosts with their summary metrics.
func (r *HostRepository) GetHostSummaries(ctx context.Context) ([]*models.HostSummary, error) {
	hosts, err := r.List(ctx, HostFilter{})
	if err != nil {
		return nil, err
	}

	summaries := make([]*models.HostSummary, len(hosts))
	for i, h := range hosts {
		summaries[i] = &models.HostSummary{Host: *h}
	}
	return summaries, nil
}

// CreateHost creates a new host directly from a Host model.
func (r *HostRepository) CreateHost(ctx context.Context, host *models.Host) error {
	query := `
		INSERT INTO hosts (
			id, name, display_name, endpoint_type, endpoint_url,
			tls_enabled, tls_ca_cert, tls_client_cert, tls_client_key,
			status, status_message, labels, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)
	`

	labels := host.Labels
	if labels == nil {
		labels = models.JSONStringMap{}
	}
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to marshal labels")
	}

	if host.CreatedAt.IsZero() {
		host.CreatedAt = time.Now().UTC()
	}
	if host.UpdatedAt.IsZero() {
		host.UpdatedAt = time.Now().UTC()
	}

	_, err = r.db.ExecContext(ctx, query,
		host.ID, host.Name, host.DisplayName, host.EndpointType, host.EndpointURL,
		host.TLSEnabled, host.TLSCACert, host.TLSClientCert, host.TLSClientKey,
		host.Status, host.StatusMessage, string(labelsJSON), host.CreatedAt, host.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to create host")
	}

	return nil
}

// UpdateHost updates a host directly from a Host model.
func (r *HostRepository) UpdateHost(ctx context.Context, host *models.Host) error {
	query := `
		UPDATE hosts
		SET display_name = $1,
		    endpoint_url = $2,
		    tls_enabled = $3,
		    tls_ca_cert = $4,
		    tls_client_cert = $5,
		    tls_client_key = $6,
		    status = $7,
		    status_message = $8,
		    labels = $9,
		    updated_at = NOW()
		WHERE id = $10
	`

	labels := host.Labels
	if labels == nil {
		labels = models.JSONStringMap{}
	}
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to marshal labels")
	}

	_, err = r.db.ExecContext(ctx, query,
		host.DisplayName, host.EndpointURL,
		host.TLSEnabled, host.TLSCACert, host.TLSClientCert, host.TLSClientKey,
		host.Status, host.StatusMessage, string(labelsJSON), host.ID,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update host")
	}

	return nil
}

// UpdateDockerInfo updates the Docker information for a host.
func (r *HostRepository) UpdateDockerInfo(ctx context.Context, hostID uuid.UUID, info *models.HostDockerInfo) error {
	query := `
		UPDATE hosts
		SET docker_version = $1,
		    os_type = $2,
		    architecture = $3,
		    total_cpus = $4,
		    total_memory = $5,
		    updated_at = NOW()
		WHERE id = $6
	`

	_, err := r.db.ExecContext(ctx, query,
		info.ServerVersion, info.OSType, info.Architecture,
		info.NCPU, info.MemTotal, hostID,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update docker info")
	}

	return nil
}

// SetMaintenance sets a host to maintenance mode.
func (r *HostRepository) SetMaintenance(ctx context.Context, hostID uuid.UUID, reason string) error {
	query := `
		UPDATE hosts
		SET status = 'maintenance',
		    status_message = $1,
		    updated_at = NOW()
		WHERE id = $2
	`

	_, err := r.db.ExecContext(ctx, query, reason, hostID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to set maintenance")
	}

	return nil
}

// InsertMetrics inserts metrics for a host.
func (r *HostRepository) InsertMetrics(ctx context.Context, metrics *models.HostMetrics) error {
	query := `
		INSERT INTO host_metrics (
			host_id, cpu_percent, memory_used, memory_total, memory_percent,
			disk_used, disk_total, disk_percent, network_rx_bytes, network_tx_bytes,
			container_count, running_count, collected_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
	`

	_, err := r.db.ExecContext(ctx, query,
		metrics.HostID, metrics.CPUPercent, metrics.MemoryUsed, metrics.MemoryTotal,
		metrics.MemoryPercent, metrics.DiskUsed, metrics.DiskTotal, metrics.DiskPercent,
		metrics.NetworkRxBytes, metrics.NetworkTxBytes, metrics.ContainerCount,
		metrics.RunningCount, metrics.CollectedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to insert metrics")
	}

	return nil
}

// GetLatestMetrics retrieves the latest metrics for a host.
func (r *HostRepository) GetLatestMetrics(ctx context.Context, hostID uuid.UUID) (*models.HostMetrics, error) {
	query := `
		SELECT id, host_id, cpu_percent, memory_used, memory_total, memory_percent,
		       disk_used, disk_total, disk_percent, network_rx_bytes, network_tx_bytes,
		       container_count, running_count, collected_at
		FROM host_metrics
		WHERE host_id = $1
		ORDER BY collected_at DESC
		LIMIT 1
	`

	var metrics models.HostMetrics
	if err := r.db.GetContext(ctx, &metrics, query, hostID); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get latest metrics")
	}

	return &metrics, nil
}

// GetMetricsHistory retrieves metrics history for a host.
func (r *HostRepository) GetMetricsHistory(ctx context.Context, hostID uuid.UUID, since time.Time, limit int) ([]*models.HostMetrics, error) {
	query := `
		SELECT id, host_id, cpu_percent, memory_used, memory_total, memory_percent,
		       disk_used, disk_total, disk_percent, network_rx_bytes, network_tx_bytes,
		       container_count, running_count, collected_at
		FROM host_metrics
		WHERE host_id = $1 AND collected_at >= $2
		ORDER BY collected_at DESC
		LIMIT $3
	`

	var metrics []*models.HostMetrics
	if err := r.db.SelectContext(ctx, &metrics, query, hostID, since, limit); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get metrics history")
	}

	return metrics, nil
}

// GetByAgentID retrieves a host by agent ID.
func (r *HostRepository) GetByAgentID(ctx context.Context, agentID uuid.UUID) (*models.Host, error) {
	query := `
		SELECT id, name, display_name, endpoint_type, endpoint_url,
		       agent_id, agent_token_hash, tls_enabled, status, status_message,
		       last_seen_at, docker_version, os_type, architecture,
		       total_memory, total_cpus, labels, created_at, updated_at
		FROM hosts
		WHERE agent_id = $1
	`

	var host models.Host
	if err := r.db.GetContext(ctx, &host, query, agentID); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NotFound("host")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get host by agent ID")
	}

	return &host, nil
}

// ValidateAgentToken validates an agent token and returns the host if valid.
func (r *HostRepository) ValidateAgentToken(ctx context.Context, agentID uuid.UUID, tokenHash string) (*models.Host, error) {
	query := `
		SELECT id, name, display_name, endpoint_type, endpoint_url,
		       agent_id, agent_token_hash, tls_enabled, status, status_message,
		       last_seen_at, docker_version, os_type, architecture,
		       total_memory, total_cpus, labels, created_at, updated_at
		FROM hosts
		WHERE agent_id = $1 AND agent_token_hash = $2
	`

	var host models.Host
	if err := r.db.GetContext(ctx, &host, query, agentID, tokenHash); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New(errors.CodeUnauthorized, "invalid agent token")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to validate agent token")
	}

	return &host, nil
}

// UpdateLastSeen updates the last seen timestamp for a host.
func (r *HostRepository) UpdateLastSeen(ctx context.Context, hostID uuid.UUID) error {
	query := `
		UPDATE hosts
		SET last_seen_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, hostID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to update last seen")
	}

	return nil
}
