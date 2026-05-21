// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet
//
// Locations are per-path routes within a proxy host. They are stored in
// proxy_locations and replaced in bulk for a given host on every update.

package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	pkgerrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ProxyLocationRepository implements persistence for proxy custom locations.
type ProxyLocationRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewProxyLocationRepository creates a new location repository.
func NewProxyLocationRepository(db *DB, log *logger.Logger) *ProxyLocationRepository {
	return &ProxyLocationRepository{db: db, logger: log.Named("proxy_location_repo")}
}

// ListByHost retrieves all locations for a proxy host.
func (r *ProxyLocationRepository) ListByHost(ctx context.Context, proxyHostID uuid.UUID) ([]models.ProxyLocation, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, proxy_host_id, path, upstream_scheme, upstream_host, upstream_port, enabled
		   FROM proxy_locations
		  WHERE proxy_host_id = $1
		  ORDER BY path`,
		proxyHostID,
	)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to list proxy locations")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[models.ProxyLocation])
}

// ListAllGrouped returns every location across all proxy hosts, grouped by
// proxy_host_id. Replaces N per-host queries with a single scan for callers
// that need the full snapshot (e.g. the extended-sync apply loop).
// Hosts with no locations are absent from the map.
func (r *ProxyLocationRepository) ListAllGrouped(ctx context.Context) (map[uuid.UUID][]models.ProxyLocation, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, proxy_host_id, path, upstream_scheme, upstream_host, upstream_port, enabled
		   FROM proxy_locations
		  ORDER BY proxy_host_id, path`,
	)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to list proxy locations")
	}
	defer rows.Close()

	all, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.ProxyLocation])
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to scan proxy locations")
	}

	out := make(map[uuid.UUID][]models.ProxyLocation)
	for _, loc := range all {
		out[loc.ProxyHostID] = append(out[loc.ProxyHostID], loc)
	}
	return out, nil
}

// ReplaceForHost replaces all locations for a proxy host atomically.
func (r *ProxyLocationRepository) ReplaceForHost(ctx context.Context, proxyHostID uuid.UUID, locations []models.ProxyLocation) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM proxy_locations WHERE proxy_host_id = $1`, proxyHostID); err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to clear proxy locations")
	}

	if len(locations) == 0 {
		return nil
	}

	values := make([]string, 0, len(locations))
	args := make([]interface{}, 0, len(locations)*7)
	for i, loc := range locations {
		if loc.ID == uuid.Nil {
			loc.ID = uuid.New()
		}
		base := i * 7
		values = append(values, fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7))
		args = append(args, loc.ID, proxyHostID, loc.Path, loc.UpstreamScheme, loc.UpstreamHost, loc.UpstreamPort, loc.Enabled)
	}

	query := `INSERT INTO proxy_locations (id, proxy_host_id, path, upstream_scheme, upstream_host, upstream_port, enabled) VALUES ` + strings.Join(values, ",")
	if _, err := r.db.Exec(ctx, query, args...); err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to insert proxy locations")
	}
	return nil
}
