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

// ProxyRedirectionRepository implements persistence for proxy redirections.
type ProxyRedirectionRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewProxyRedirectionRepository creates a new redirection repository.
func NewProxyRedirectionRepository(db *DB, log *logger.Logger) *ProxyRedirectionRepository {
	return &ProxyRedirectionRepository{db: db, logger: log.Named("proxy_redirection_repo")}
}

// Create inserts a new proxy redirection.
func (r *ProxyRedirectionRepository) Create(ctx context.Context, rd *models.ProxyRedirection) error {
	if rd.ID == uuid.Nil {
		rd.ID = uuid.New()
	}
	now := time.Now()
	rd.CreatedAt = now
	rd.UpdatedAt = now

	_, err := r.db.Exec(ctx,
		`INSERT INTO proxy_redirections
			(id, host_id, domains, forward_scheme, forward_domain,
			 forward_http_code, preserve_path,
			 ssl_mode, ssl_force_https, certificate_id,
			 enabled, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		rd.ID, rd.HostID, rd.Domains, rd.ForwardScheme, rd.ForwardDomain,
		rd.ForwardHTTPCode, rd.PreservePath,
		string(rd.SSLMode), rd.SSLForceHTTPS, rd.CertificateID,
		rd.Enabled, rd.CreatedAt, rd.UpdatedAt,
	)
	if err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to create proxy redirection")
	}
	return nil
}

// GetByID retrieves a redirection by ID.
func (r *ProxyRedirectionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyRedirection, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM proxy_redirections WHERE id = $1`, id)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to query proxy redirection")
	}
	defer rows.Close()

	rd, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.ProxyRedirection])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pkgerrors.NotFound("proxy_redirection").WithDetail("id", id.String())
		}
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to scan proxy redirection")
	}
	return rd, nil
}

// List retrieves all redirections for a host.
func (r *ProxyRedirectionRepository) List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyRedirection, error) {
	rows, err := r.db.Query(ctx,
		`SELECT * FROM proxy_redirections WHERE host_id = $1 ORDER BY created_at ASC`, hostID,
	)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to list proxy redirections")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.ProxyRedirection])
}

// Update updates a proxy redirection.
func (r *ProxyRedirectionRepository) Update(ctx context.Context, rd *models.ProxyRedirection) error {
	rd.UpdatedAt = time.Now()

	ct, err := r.db.Exec(ctx,
		`UPDATE proxy_redirections
		    SET domains=$2, forward_scheme=$3, forward_domain=$4,
		        forward_http_code=$5, preserve_path=$6,
		        ssl_mode=$7, ssl_force_https=$8, certificate_id=$9,
		        enabled=$10, updated_at=$11
		  WHERE id=$1`,
		rd.ID, rd.Domains, rd.ForwardScheme, rd.ForwardDomain,
		rd.ForwardHTTPCode, rd.PreservePath,
		string(rd.SSLMode), rd.SSLForceHTTPS, rd.CertificateID,
		rd.Enabled, rd.UpdatedAt,
	)
	if err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to update proxy redirection")
	}
	if ct.RowsAffected() == 0 {
		return pkgerrors.NotFound("proxy_redirection").WithDetail("id", rd.ID.String())
	}
	return nil
}

// Delete removes a proxy redirection.
func (r *ProxyRedirectionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM proxy_redirections WHERE id = $1`, id)
	if err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to delete proxy redirection")
	}
	if ct.RowsAffected() == 0 {
		return pkgerrors.NotFound("proxy_redirection").WithDetail("id", id.String())
	}
	return nil
}
