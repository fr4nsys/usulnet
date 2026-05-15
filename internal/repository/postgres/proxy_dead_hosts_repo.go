// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	pkgerrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ProxyDeadHostRepository implements persistence for proxy dead hosts (404 catch-alls).
type ProxyDeadHostRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewProxyDeadHostRepository creates a new dead host repository.
func NewProxyDeadHostRepository(db *DB, log *logger.Logger) *ProxyDeadHostRepository {
	return &ProxyDeadHostRepository{db: db, logger: log.Named("proxy_dead_host_repo")}
}

// Create inserts a new proxy dead host.
func (r *ProxyDeadHostRepository) Create(ctx context.Context, d *models.ProxyDeadHost) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	now := time.Now()
	d.CreatedAt = now
	d.UpdatedAt = now

	_, err := r.db.Exec(ctx,
		`INSERT INTO proxy_dead_hosts
			(id, host_id, domains, ssl_mode, ssl_force_https, certificate_id,
			 enabled, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		d.ID, d.HostID, d.Domains, string(d.SSLMode), d.SSLForceHTTPS, d.CertificateID,
		d.Enabled, d.CreatedAt, d.UpdatedAt,
	)
	if err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to create proxy dead host")
	}
	return nil
}

// GetByID retrieves a dead host by ID.
func (r *ProxyDeadHostRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyDeadHost, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM proxy_dead_hosts WHERE id = $1`, id)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to query proxy dead host")
	}
	defer rows.Close()

	d, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.ProxyDeadHost])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pkgerrors.NotFound("proxy_dead_host").WithDetail("id", id.String())
		}
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to scan proxy dead host")
	}
	return d, nil
}

// List retrieves all dead hosts for a host.
func (r *ProxyDeadHostRepository) List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyDeadHost, error) {
	rows, err := r.db.Query(ctx,
		`SELECT * FROM proxy_dead_hosts WHERE host_id = $1 ORDER BY created_at ASC`, hostID,
	)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to list proxy dead hosts")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.ProxyDeadHost])
}

// Update updates a proxy dead host.
func (r *ProxyDeadHostRepository) Update(ctx context.Context, d *models.ProxyDeadHost) error {
	d.UpdatedAt = time.Now()

	ct, err := r.db.Exec(ctx,
		`UPDATE proxy_dead_hosts
		    SET domains=$2, ssl_mode=$3, ssl_force_https=$4, certificate_id=$5,
		        enabled=$6, updated_at=$7
		  WHERE id=$1`,
		d.ID, d.Domains, string(d.SSLMode), d.SSLForceHTTPS, d.CertificateID,
		d.Enabled, d.UpdatedAt,
	)
	if err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to update proxy dead host")
	}
	if ct.RowsAffected() == 0 {
		return pkgerrors.NotFound("proxy_dead_host").WithDetail("id", d.ID.String())
	}
	return nil
}

// Delete removes a proxy dead host.
func (r *ProxyDeadHostRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM proxy_dead_hosts WHERE id = $1`, id)
	if err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to delete proxy dead host")
	}
	if ct.RowsAffected() == 0 {
		return pkgerrors.NotFound("proxy_dead_host").WithDetail("id", id.String())
	}
	return nil
}
