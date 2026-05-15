// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// DNSProviderRepository
// ============================================================================

// DNSProviderRepository persists DNSProvider rows. Credentials are
// stored encrypted; encryption is the service's responsibility, not
// the repo's, so the repo writes/reads the column verbatim.
type DNSProviderRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewDNSProviderRepository constructs a provider repository.
func NewDNSProviderRepository(db *DB, log *logger.Logger) *DNSProviderRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &DNSProviderRepository{db: db, logger: log.Named("dns_provider_repo")}
}

// Create inserts a provider row.
func (r *DNSProviderRepository) Create(ctx context.Context, p *models.DNSProvider) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	cfg, err := json.Marshal(p.Config)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "dns: marshal provider config")
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO dns_providers (
			id, host_id, name, provider_kind, enabled, description,
			credentials, config, created_by, updated_by, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		p.ID, p.HostID, p.Name, string(p.ProviderKind), p.Enabled, p.Description,
		p.Credentials, cfg, p.CreatedBy, p.UpdatedBy, p.CreatedAt, p.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "dns: create provider")
	}
	return nil
}

// GetByID fetches a provider by ID.
func (r *DNSProviderRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DNSProvider, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, host_id, name, provider_kind, enabled, description,
		       credentials, config, created_by, updated_by, created_at, updated_at
		FROM dns_providers WHERE id = $1`, id)

	p, err := scanDNSProvider(row)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("dns provider").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "dns: scan provider")
	}
	return p, nil
}

// List returns the providers attached to a host, ordered by name.
func (r *DNSProviderRepository) List(ctx context.Context, hostID uuid.UUID) ([]*models.DNSProvider, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, host_id, name, provider_kind, enabled, description,
		       credentials, config, created_by, updated_by, created_at, updated_at
		FROM dns_providers WHERE host_id = $1 ORDER BY name ASC`, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "dns: list providers")
	}
	defer rows.Close()

	out := make([]*models.DNSProvider, 0)
	for rows.Next() {
		p, scanErr := scanDNSProvider(rows)
		if scanErr != nil {
			return nil, errors.Wrap(scanErr, errors.CodeDatabaseError, "dns: scan provider row")
		}
		out = append(out, p)
	}
	return out, nil
}

// ListAll returns every provider across every host. Used at boot to
// resume in-flight ACME orders.
func (r *DNSProviderRepository) ListAll(ctx context.Context) ([]*models.DNSProvider, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, host_id, name, provider_kind, enabled, description,
		       credentials, config, created_by, updated_by, created_at, updated_at
		FROM dns_providers ORDER BY host_id, name ASC`)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "dns: list all providers")
	}
	defer rows.Close()

	out := make([]*models.DNSProvider, 0)
	for rows.Next() {
		p, scanErr := scanDNSProvider(rows)
		if scanErr != nil {
			return nil, errors.Wrap(scanErr, errors.CodeDatabaseError, "dns: scan provider row")
		}
		out = append(out, p)
	}
	return out, nil
}

// Update overwrites an existing provider row. If Credentials is empty
// the existing column is preserved (callers that want to wipe the
// credentials must pass an empty JSON ciphertext explicitly via
// dedicated method).
func (r *DNSProviderRepository) Update(ctx context.Context, p *models.DNSProvider) error {
	p.UpdatedAt = time.Now()
	cfg, err := json.Marshal(p.Config)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "dns: marshal provider config")
	}

	if p.Credentials == "" {
		_, err = r.db.Exec(ctx, `
			UPDATE dns_providers SET
				name = $2, provider_kind = $3, enabled = $4, description = $5,
				config = $6, updated_by = $7, updated_at = $8
			WHERE id = $1`,
			p.ID, p.Name, string(p.ProviderKind), p.Enabled, p.Description,
			cfg, p.UpdatedBy, p.UpdatedAt,
		)
	} else {
		_, err = r.db.Exec(ctx, `
			UPDATE dns_providers SET
				name = $2, provider_kind = $3, enabled = $4, description = $5,
				credentials = $6, config = $7, updated_by = $8, updated_at = $9
			WHERE id = $1`,
			p.ID, p.Name, string(p.ProviderKind), p.Enabled, p.Description,
			p.Credentials, cfg, p.UpdatedBy, p.UpdatedAt,
		)
	}
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "dns: update provider")
	}
	return nil
}

// Delete removes a provider (cascades to records and acme orders).
func (r *DNSProviderRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM dns_providers WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "dns: delete provider")
	}
	return nil
}

// scanDNSProvider scans a single row into a DNSProvider, decoding
// the JSONB config column. Works for both *pgx.Row and pgx.Rows.
func scanDNSProvider(row pgx.Row) (*models.DNSProvider, error) {
	var p models.DNSProvider
	var cfg []byte
	if err := row.Scan(
		&p.ID, &p.HostID, &p.Name, &p.ProviderKind, &p.Enabled, &p.Description,
		&p.Credentials, &cfg, &p.CreatedBy, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if len(cfg) > 0 {
		_ = json.Unmarshal(cfg, &p.Config)
	}
	if p.Config == nil {
		p.Config = map[string]any{}
	}
	return &p, nil
}

// ============================================================================
// DNSRecordRepository
// ============================================================================

// DNSRecordRepository persists DNSRecord rows.
type DNSRecordRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewDNSRecordRepository constructs a record repository.
func NewDNSRecordRepository(db *DB, log *logger.Logger) *DNSRecordRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &DNSRecordRepository{db: db, logger: log.Named("dns_record_repo")}
}

// Create inserts a new DNS record row.
func (r *DNSRecordRepository) Create(ctx context.Context, rec *models.DNSRecord) error {
	if rec.ID == uuid.Nil {
		rec.ID = uuid.New()
	}
	now := time.Now()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now

	_, err := r.db.Exec(ctx, `
		INSERT INTO dns_records (
			id, provider_id, host_id, name, type, content, ttl,
			provider_record_id, managed_by, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		rec.ID, rec.ProviderID, rec.HostID, rec.Name, string(rec.Type), rec.Content, rec.TTL,
		rec.ProviderRecordID, rec.ManagedBy, rec.CreatedAt, rec.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "dns: create record")
	}
	return nil
}

// GetByID fetches a record by ID.
func (r *DNSRecordRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DNSRecord, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM dns_records WHERE id = $1`, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "dns: query record")
	}
	defer rows.Close()

	rec, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.DNSRecord])
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("dns record").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "dns: scan record")
	}
	return rec, nil
}

// ListByProvider returns all records owned by a provider.
func (r *DNSRecordRepository) ListByProvider(ctx context.Context, providerID uuid.UUID) ([]*models.DNSRecord, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM dns_records WHERE provider_id = $1 ORDER BY name ASC, type ASC`, providerID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "dns: list records by provider")
	}
	defer rows.Close()
	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.DNSRecord])
}

// ListByHost returns records across all providers for a host. Useful for
// the per-host record audit view.
func (r *DNSRecordRepository) ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.DNSRecord, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM dns_records WHERE host_id = $1 ORDER BY name ASC, type ASC`, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "dns: list records by host")
	}
	defer rows.Close()
	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.DNSRecord])
}

// Update writes back the mutable columns of a record row.
func (r *DNSRecordRepository) Update(ctx context.Context, rec *models.DNSRecord) error {
	rec.UpdatedAt = time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE dns_records SET
			name = $2, type = $3, content = $4, ttl = $5,
			provider_record_id = $6, managed_by = $7, updated_at = $8
		WHERE id = $1`,
		rec.ID, rec.Name, string(rec.Type), rec.Content, rec.TTL,
		rec.ProviderRecordID, rec.ManagedBy, rec.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "dns: update record")
	}
	return nil
}

// Delete removes a record row.
func (r *DNSRecordRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM dns_records WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "dns: delete record")
	}
	return nil
}

// ============================================================================
// DNSACMEOrderRepository
// ============================================================================

// DNSACMEOrderRepository persists ACME DNS-01 orders.
type DNSACMEOrderRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewDNSACMEOrderRepository constructs an ACME order repository.
func NewDNSACMEOrderRepository(db *DB, log *logger.Logger) *DNSACMEOrderRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &DNSACMEOrderRepository{db: db, logger: log.Named("dns_acme_order_repo")}
}

// Create inserts a new order row.
func (r *DNSACMEOrderRepository) Create(ctx context.Context, o *models.DNSACMEOrder) error {
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}
	now := time.Now()
	if o.CreatedAt.IsZero() {
		o.CreatedAt = now
	}
	o.UpdatedAt = now
	if o.State == "" {
		o.State = models.ACMEOrderStatePending
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO dns_acme_orders (
			id, host_id, provider_id, domain, challenge_fqdn, challenge_value,
			state, error_msg, record_id, propagation_check_count,
			last_check_at, completed_at, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		o.ID, o.HostID, o.ProviderID, o.Domain, o.ChallengeFQDN, o.ChallengeValue,
		string(o.State), o.ErrorMsg, o.RecordID, o.PropagationCheckCount,
		o.LastCheckAt, o.CompletedAt, o.CreatedAt, o.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "dns: create acme order")
	}
	return nil
}

// GetByID fetches an order by ID.
func (r *DNSACMEOrderRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DNSACMEOrder, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM dns_acme_orders WHERE id = $1`, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "dns: query acme order")
	}
	defer rows.Close()

	o, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.DNSACMEOrder])
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("dns acme order").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "dns: scan acme order")
	}
	return o, nil
}

// ListByHost returns the ACME orders attached to a host, newest first.
func (r *DNSACMEOrderRepository) ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.DNSACMEOrder, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM dns_acme_orders WHERE host_id = $1 ORDER BY created_at DESC`, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "dns: list acme orders by host")
	}
	defer rows.Close()
	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.DNSACMEOrder])
}

// ListInFlight returns all orders that are not in a terminal state. The
// service calls this on boot to resume the state machine.
func (r *DNSACMEOrderRepository) ListInFlight(ctx context.Context) ([]*models.DNSACMEOrder, error) {
	rows, err := r.db.Query(ctx, `
		SELECT * FROM dns_acme_orders
		WHERE state NOT IN ('completed','failed')
		ORDER BY created_at ASC`)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "dns: list in-flight acme orders")
	}
	defer rows.Close()
	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.DNSACMEOrder])
}

// Update writes back the mutable columns of an order row.
func (r *DNSACMEOrderRepository) Update(ctx context.Context, o *models.DNSACMEOrder) error {
	o.UpdatedAt = time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE dns_acme_orders SET
			state = $2, error_msg = $3, record_id = $4,
			propagation_check_count = $5, last_check_at = $6,
			completed_at = $7, updated_at = $8
		WHERE id = $1`,
		o.ID, string(o.State), o.ErrorMsg, o.RecordID,
		o.PropagationCheckCount, o.LastCheckAt, o.CompletedAt, o.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "dns: update acme order")
	}
	return nil
}

// Delete removes an order row.
func (r *DNSACMEOrderRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM dns_acme_orders WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "dns: delete acme order")
	}
	return nil
}

// ============================================================================
// DNSAuditLogRepository
// ============================================================================

// DNSAuditLogRepository persists audit entries.
type DNSAuditLogRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewDNSAuditLogRepository constructs an audit log repository.
func NewDNSAuditLogRepository(db *DB, log *logger.Logger) *DNSAuditLogRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &DNSAuditLogRepository{db: db, logger: log.Named("dns_audit_repo")}
}

// Create inserts an audit row.
func (r *DNSAuditLogRepository) Create(ctx context.Context, e *models.DNSAuditLog) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO dns_audit_log (
			id, host_id, user_id, action, resource_type, resource_id,
			resource_name, details, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		e.ID, e.HostID, e.UserID, e.Action, e.ResourceType, e.ResourceID,
		e.ResourceName, e.Details, e.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "dns: create audit entry")
	}
	return nil
}

// List returns paginated audit entries for a host, newest first.
func (r *DNSAuditLogRepository) List(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.DNSAuditLog, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM dns_audit_log WHERE host_id = $1`, hostID).Scan(&total); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "dns: count audit entries")
	}

	rows, err := r.db.Query(ctx, `
		SELECT * FROM dns_audit_log WHERE host_id = $1
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`, hostID, limit, offset)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "dns: list audit entries")
	}
	defer rows.Close()

	out, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.DNSAuditLog])
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "dns: scan audit entries")
	}
	return out, total, nil
}

// ListByOrder returns audit entries about a specific ACME order.
func (r *DNSAuditLogRepository) ListByOrder(ctx context.Context, orderID uuid.UUID) ([]*models.DNSAuditLog, error) {
	rows, err := r.db.Query(ctx, `
		SELECT * FROM dns_audit_log
		WHERE resource_type = 'acme_order' AND resource_id = $1
		ORDER BY created_at ASC`, orderID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "dns: list acme order audit")
	}
	defer rows.Close()
	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.DNSAuditLog])
}
