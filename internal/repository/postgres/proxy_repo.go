// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// ProxyHostRepository
// ============================================================================

// ProxyHostRepository implements proxy host persistence.
type ProxyHostRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewProxyHostRepository creates a new proxy host repository.
func NewProxyHostRepository(db *DB, log *logger.Logger) *ProxyHostRepository {
	return &ProxyHostRepository{
		db:     db,
		logger: log.Named("proxy_host_repo"),
	}
}

// Create inserts a new proxy host.
func (r *ProxyHostRepository) Create(ctx context.Context, h *models.ProxyHost) error {
	if h.ID == uuid.Nil {
		h.ID = uuid.New()
	}
	now := time.Now()
	if h.CreatedAt.IsZero() {
		h.CreatedAt = now
	}
	h.UpdatedAt = now

	query := `
		INSERT INTO proxy_hosts (
			id, host_id, name, domains, enabled, status, status_message,
			upstream_scheme, upstream_host, upstream_port, upstream_path,
			ssl_mode, ssl_force_https, certificate_id, dns_provider_id,
			enable_websocket, enable_compression, enable_hsts, enable_http2,
			health_check_enabled, health_check_path, health_check_interval,
			container_id, container_name, auto_created,
			created_by, updated_by, created_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
			$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29
		)`

	_, err := r.db.Exec(ctx, query,
		h.ID, h.HostID, h.Name, h.Domains, h.Enabled, string(h.Status), h.StatusMsg,
		string(h.UpstreamScheme), h.UpstreamHost, h.UpstreamPort, h.UpstreamPath,
		string(h.SSLMode), h.SSLForceHTTPS, h.CertificateID, h.DNSProviderID,
		h.EnableWebSocket, h.EnableCompression, h.EnableHSTS, h.EnableHTTP2,
		h.HealthCheckEnabled, h.HealthCheckPath, h.HealthCheckInterval,
		h.ContainerID, h.ContainerName, h.AutoCreated,
		h.CreatedBy, h.UpdatedBy, h.CreatedAt, h.UpdatedAt,
	)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("proxy_host").WithDetail("name", h.Name)
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create proxy host")
	}
	return nil
}

// GetByID retrieves a proxy host by ID.
func (r *ProxyHostRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyHost, error) {
	query := `SELECT * FROM proxy_hosts WHERE id = $1`
	row, err := r.db.Query(ctx, query, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query proxy host")
	}
	defer row.Close()

	h, err := pgx.CollectOneRow(row, pgx.RowToAddrOfStructByName[models.ProxyHost])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("proxy_host").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan proxy host")
	}
	return h, nil
}

// List retrieves proxy hosts for a host, optionally filtered.
func (r *ProxyHostRepository) List(ctx context.Context, hostID uuid.UUID, enabledOnly bool) ([]*models.ProxyHost, error) {
	query := `SELECT * FROM proxy_hosts WHERE host_id = $1`
	args := []interface{}{hostID}

	if enabledOnly {
		query += ` AND enabled = true`
	}
	query += ` ORDER BY name ASC`

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list proxy hosts")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.ProxyHost])
}

// ListAll retrieves all proxy hosts across all usulnet hosts (for global sync).
func (r *ProxyHostRepository) ListAll(ctx context.Context, enabledOnly bool) ([]*models.ProxyHost, error) {
	query := `SELECT * FROM proxy_hosts`
	if enabledOnly {
		query += ` WHERE enabled = true`
	}
	query += ` ORDER BY host_id, name ASC`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list all proxy hosts")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.ProxyHost])
}

// Update updates a proxy host.
func (r *ProxyHostRepository) Update(ctx context.Context, h *models.ProxyHost) error {
	h.UpdatedAt = time.Now()

	query := `
		UPDATE proxy_hosts SET
			name=$2, domains=$3, enabled=$4, status=$5, status_message=$6,
			upstream_scheme=$7, upstream_host=$8, upstream_port=$9, upstream_path=$10,
			ssl_mode=$11, ssl_force_https=$12, certificate_id=$13, dns_provider_id=$14,
			enable_websocket=$15, enable_compression=$16, enable_hsts=$17, enable_http2=$18,
			health_check_enabled=$19, health_check_path=$20, health_check_interval=$21,
			container_id=$22, container_name=$23,
			updated_by=$24, updated_at=$25
		WHERE id=$1`

	ct, err := r.db.Exec(ctx, query,
		h.ID, h.Name, h.Domains, h.Enabled, string(h.Status), h.StatusMsg,
		string(h.UpstreamScheme), h.UpstreamHost, h.UpstreamPort, h.UpstreamPath,
		string(h.SSLMode), h.SSLForceHTTPS, h.CertificateID, h.DNSProviderID,
		h.EnableWebSocket, h.EnableCompression, h.EnableHSTS, h.EnableHTTP2,
		h.HealthCheckEnabled, h.HealthCheckPath, h.HealthCheckInterval,
		h.ContainerID, h.ContainerName,
		h.UpdatedBy, h.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update proxy host")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("proxy_host").WithDetail("id", h.ID.String())
	}
	return nil
}

// Delete removes a proxy host.
func (r *ProxyHostRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM proxy_hosts WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete proxy host")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("proxy_host").WithDetail("id", id.String())
	}
	return nil
}

// UpdateStatus updates only the status fields.
func (r *ProxyHostRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.ProxyHostStatus, msg string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE proxy_hosts SET status=$2, status_message=$3, updated_at=$4 WHERE id=$1`,
		id, string(status), msg, time.Now(),
	)
	return err
}

// GetByContainerID finds a proxy host linked to a container.
func (r *ProxyHostRepository) GetByContainerID(ctx context.Context, containerID string) (*models.ProxyHost, error) {
	query := `SELECT * FROM proxy_hosts WHERE container_id = $1 LIMIT 1`
	rows, err := r.db.Query(ctx, query, containerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	h, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.ProxyHost])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil // Not found is OK for container lookup
		}
		return nil, err
	}
	return h, nil
}

// ============================================================================
// ProxyHeaderRepository
// ============================================================================

// ProxyHeaderRepository manages custom headers for proxy hosts.
type ProxyHeaderRepository struct {
	db *DB
}

// NewProxyHeaderRepository creates a new header repository.
func NewProxyHeaderRepository(db *DB) *ProxyHeaderRepository {
	return &ProxyHeaderRepository{db: db}
}

// ListByHost retrieves all headers for a proxy host.
func (r *ProxyHeaderRepository) ListByHost(ctx context.Context, proxyHostID uuid.UUID) ([]models.ProxyHeader, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, proxy_host_id, direction, operation, name, value FROM proxy_headers WHERE proxy_host_id = $1 ORDER BY direction, name`,
		proxyHostID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[models.ProxyHeader])
}

// ReplaceForHost replaces all headers for a proxy host atomically.
func (r *ProxyHeaderRepository) ReplaceForHost(ctx context.Context, proxyHostID uuid.UUID, headers []models.ProxyHeader) error {
	// Delete existing
	if _, err := r.db.Exec(ctx, `DELETE FROM proxy_headers WHERE proxy_host_id = $1`, proxyHostID); err != nil {
		return err
	}

	if len(headers) == 0 {
		return nil
	}

	// Batch insert
	values := make([]string, 0, len(headers))
	args := make([]interface{}, 0, len(headers)*6)
	for i, h := range headers {
		if h.ID == uuid.Nil {
			h.ID = uuid.New()
		}
		base := i * 6
		values = append(values, fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,$%d)", base+1, base+2, base+3, base+4, base+5, base+6))
		args = append(args, h.ID, proxyHostID, h.Direction, h.Operation, h.Name, h.Value)
	}

	query := `INSERT INTO proxy_headers (id, proxy_host_id, direction, operation, name, value) VALUES ` + strings.Join(values, ",")
	_, err := r.db.Exec(ctx, query, args...)
	return err
}

// ============================================================================
// ProxyCertificateRepository
// ============================================================================

// ProxyCertificateRepository manages proxy certificates.
type ProxyCertificateRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewProxyCertificateRepository creates a new certificate repository.
func NewProxyCertificateRepository(db *DB, log *logger.Logger) *ProxyCertificateRepository {
	return &ProxyCertificateRepository{db: db, logger: log.Named("proxy_cert_repo")}
}

// Create inserts a new certificate.
func (r *ProxyCertificateRepository) Create(ctx context.Context, c *models.ProxyCertificate) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	now := time.Now()
	c.CreatedAt = now
	c.UpdatedAt = now

	query := `
		INSERT INTO proxy_certificates (
			id, host_id, name, domains, provider, cert_pem, key_pem, chain_pem,
			expires_at, is_wildcard, auto_renew, last_renewed, error_message,
			created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`

	_, err := r.db.Exec(ctx, query,
		c.ID, c.HostID, c.Name, c.Domains, c.Provider, c.CertPEM, c.KeyPEM, c.ChainPEM,
		c.ExpiresAt, c.IsWildcard, c.AutoRenew, c.LastRenewed, c.ErrorMessage,
		c.CreatedAt, c.UpdatedAt,
	)
	return err
}

// GetByID retrieves a certificate by ID.
func (r *ProxyCertificateRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyCertificate, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM proxy_certificates WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	c, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.ProxyCertificate])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("proxy_certificate")
		}
		return nil, err
	}
	return c, nil
}

// List retrieves all certificates for a host.
func (r *ProxyCertificateRepository) List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyCertificate, error) {
	rows, err := r.db.Query(ctx,
		`SELECT * FROM proxy_certificates WHERE host_id = $1 ORDER BY name ASC`, hostID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.ProxyCertificate])
}

// Delete removes a certificate.
func (r *ProxyCertificateRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM proxy_certificates WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("proxy_certificate")
	}
	return nil
}

// Update updates a certificate.
func (r *ProxyCertificateRepository) Update(ctx context.Context, c *models.ProxyCertificate) error {
	c.UpdatedAt = time.Now()
	_, err := r.db.Exec(ctx,
		`UPDATE proxy_certificates SET name=$2, domains=$3, cert_pem=$4, key_pem=$5, chain_pem=$6,
		 expires_at=$7, is_wildcard=$8, auto_renew=$9, last_renewed=$10, error_message=$11,
		 updated_at=$12 WHERE id=$1`,
		c.ID, c.Name, c.Domains, c.CertPEM, c.KeyPEM, c.ChainPEM,
		c.ExpiresAt, c.IsWildcard, c.AutoRenew, c.LastRenewed, c.ErrorMessage,
		c.UpdatedAt,
	)
	return err
}

// ============================================================================
// ProxyDNSProviderRepository
// ============================================================================

// ProxyDNSProviderRepository manages DNS provider credentials.
type ProxyDNSProviderRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewProxyDNSProviderRepository creates a new DNS provider repository.
func NewProxyDNSProviderRepository(db *DB, log *logger.Logger) *ProxyDNSProviderRepository {
	return &ProxyDNSProviderRepository{db: db, logger: log.Named("proxy_dns_repo")}
}

// Create inserts a new DNS provider.
func (r *ProxyDNSProviderRepository) Create(ctx context.Context, p *models.ProxyDNSProvider) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now

	_, err := r.db.Exec(ctx,
		`INSERT INTO proxy_dns_providers (id, host_id, name, provider, api_token, zone, propagation, is_default, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		p.ID, p.HostID, p.Name, p.Provider, p.APIToken, p.Zone, p.Propagation, p.IsDefault, p.CreatedAt, p.UpdatedAt,
	)
	return err
}

// GetByID retrieves a DNS provider by ID.
func (r *ProxyDNSProviderRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyDNSProvider, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM proxy_dns_providers WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	p, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.ProxyDNSProvider])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("proxy_dns_provider")
		}
		return nil, err
	}
	return p, nil
}

// List retrieves all DNS providers for a host.
func (r *ProxyDNSProviderRepository) List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyDNSProvider, error) {
	rows, err := r.db.Query(ctx,
		`SELECT * FROM proxy_dns_providers WHERE host_id = $1 ORDER BY name ASC`, hostID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.ProxyDNSProvider])
}

// GetDefault retrieves the default DNS provider for a host.
func (r *ProxyDNSProviderRepository) GetDefault(ctx context.Context, hostID uuid.UUID) (*models.ProxyDNSProvider, error) {
	rows, err := r.db.Query(ctx,
		`SELECT * FROM proxy_dns_providers WHERE host_id = $1 AND is_default = true LIMIT 1`, hostID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	p, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.ProxyDNSProvider])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return p, nil
}

// Update updates a DNS provider.
func (r *ProxyDNSProviderRepository) Update(ctx context.Context, p *models.ProxyDNSProvider) error {
	p.UpdatedAt = time.Now()
	_, err := r.db.Exec(ctx,
		`UPDATE proxy_dns_providers SET name=$2, provider=$3, api_token=$4, zone=$5, propagation=$6, is_default=$7, updated_at=$8 WHERE id=$1`,
		p.ID, p.Name, p.Provider, p.APIToken, p.Zone, p.Propagation, p.IsDefault, p.UpdatedAt,
	)
	return err
}

// Delete removes a DNS provider.
func (r *ProxyDNSProviderRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM proxy_dns_providers WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("proxy_dns_provider")
	}
	return nil
}

// ============================================================================
// ProxyAuditLogRepository
// ============================================================================

// ProxyAuditLogRepository manages proxy audit log entries.
type ProxyAuditLogRepository struct {
	db *DB
}

// NewProxyAuditLogRepository creates a new audit log repository.
func NewProxyAuditLogRepository(db *DB) *ProxyAuditLogRepository {
	return &ProxyAuditLogRepository{db: db}
}

// Create inserts an audit log entry.
func (r *ProxyAuditLogRepository) Create(ctx context.Context, entry *models.ProxyAuditLog) error {
	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}
	entry.CreatedAt = time.Now()

	_, err := r.db.Exec(ctx,
		`INSERT INTO proxy_audit_log (id, host_id, user_id, action, resource_type, resource_id, resource_name, details, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		entry.ID, entry.HostID, entry.UserID, entry.Action, entry.ResourceType, entry.ResourceID, entry.ResourceName, entry.Details, entry.CreatedAt,
	)
	return err
}

// List retrieves audit log entries for a host.
func (r *ProxyAuditLogRepository) List(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.ProxyAuditLog, int, error) {
	if limit <= 0 {
		limit = 50
	}

	var total int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM proxy_audit_log WHERE host_id = $1`, hostID).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := r.db.Query(ctx,
		`SELECT * FROM proxy_audit_log WHERE host_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		hostID, limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	entries, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.ProxyAuditLog])
	if err != nil {
		return nil, 0, err
	}
	return entries, total, nil
}
