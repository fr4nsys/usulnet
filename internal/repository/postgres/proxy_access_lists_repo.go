// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	pkgerrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ProxyAccessListRepository implements persistence for proxy access lists.
type ProxyAccessListRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewProxyAccessListRepository creates a new access list repository.
func NewProxyAccessListRepository(db *DB, log *logger.Logger) *ProxyAccessListRepository {
	return &ProxyAccessListRepository{db: db, logger: log.Named("proxy_access_list_repo")}
}

// Create inserts a new access list with its auth items and client entries.
func (r *ProxyAccessListRepository) Create(ctx context.Context, al *models.ProxyAccessList) error {
	if al.ID == uuid.Nil {
		al.ID = uuid.New()
	}
	now := time.Now()
	al.CreatedAt = now
	al.UpdatedAt = now

	_, err := r.db.Exec(ctx,
		`INSERT INTO proxy_access_lists
			(id, host_id, name, satisfy_any, pass_auth, enabled, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		al.ID, al.HostID, al.Name, al.SatisfyAny, al.PassAuth, al.Enabled, al.CreatedAt, al.UpdatedAt,
	)
	if err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to create proxy access list")
	}

	if err := r.replaceAuthItems(ctx, al.ID, al.Items); err != nil {
		return err
	}
	return r.replaceClients(ctx, al.ID, al.Clients)
}

// GetByID retrieves an access list by ID, including auth items and clients.
func (r *ProxyAccessListRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyAccessList, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM proxy_access_lists WHERE id = $1`, id)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to query proxy access list")
	}
	defer rows.Close()

	al, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.ProxyAccessList])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pkgerrors.NotFound("proxy_access_list").WithDetail("id", id.String())
		}
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to scan proxy access list")
	}

	al.Items, err = r.listAuthItems(ctx, id)
	if err != nil {
		return nil, err
	}
	al.Clients, err = r.listClients(ctx, id)
	if err != nil {
		return nil, err
	}
	return al, nil
}

// List retrieves all access lists for a host, eagerly loading items and clients.
func (r *ProxyAccessListRepository) List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyAccessList, error) {
	rows, err := r.db.Query(ctx,
		`SELECT * FROM proxy_access_lists WHERE host_id = $1 ORDER BY name ASC`, hostID,
	)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to list proxy access lists")
	}
	defer rows.Close()

	lists, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.ProxyAccessList])
	if err != nil {
		return nil, err
	}

	for _, al := range lists {
		items, err := r.listAuthItems(ctx, al.ID)
		if err != nil {
			return nil, err
		}
		clients, err := r.listClients(ctx, al.ID)
		if err != nil {
			return nil, err
		}
		al.Items = items
		al.Clients = clients
	}
	return lists, nil
}

// Update updates an access list and replaces its items and clients.
func (r *ProxyAccessListRepository) Update(ctx context.Context, al *models.ProxyAccessList) error {
	al.UpdatedAt = time.Now()

	ct, err := r.db.Exec(ctx,
		`UPDATE proxy_access_lists
		    SET name=$2, satisfy_any=$3, pass_auth=$4, enabled=$5, updated_at=$6
		  WHERE id=$1`,
		al.ID, al.Name, al.SatisfyAny, al.PassAuth, al.Enabled, al.UpdatedAt,
	)
	if err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to update proxy access list")
	}
	if ct.RowsAffected() == 0 {
		return pkgerrors.NotFound("proxy_access_list").WithDetail("id", al.ID.String())
	}

	if err := r.replaceAuthItems(ctx, al.ID, al.Items); err != nil {
		return err
	}
	return r.replaceClients(ctx, al.ID, al.Clients)
}

// Delete removes an access list and its items/clients (cascaded).
func (r *ProxyAccessListRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM proxy_access_lists WHERE id = $1`, id)
	if err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to delete proxy access list")
	}
	if ct.RowsAffected() == 0 {
		return pkgerrors.NotFound("proxy_access_list").WithDetail("id", id.String())
	}
	return nil
}

// ---- Internal helpers ----

func (r *ProxyAccessListRepository) listAuthItems(ctx context.Context, accessListID uuid.UUID) ([]models.ProxyAccessListAuth, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, access_list_id, username, password_hash
		   FROM proxy_access_list_auth
		  WHERE access_list_id = $1
		  ORDER BY username`,
		accessListID,
	)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to list proxy access list auth items")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[models.ProxyAccessListAuth])
}

func (r *ProxyAccessListRepository) listClients(ctx context.Context, accessListID uuid.UUID) ([]models.ProxyAccessListClient, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, access_list_id, address, directive
		   FROM proxy_access_list_clients
		  WHERE access_list_id = $1
		  ORDER BY address`,
		accessListID,
	)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to list proxy access list clients")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[models.ProxyAccessListClient])
}

func (r *ProxyAccessListRepository) replaceAuthItems(ctx context.Context, accessListID uuid.UUID, items []models.ProxyAccessListAuth) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM proxy_access_list_auth WHERE access_list_id = $1`, accessListID); err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to clear proxy access list auth items")
	}
	if len(items) == 0 {
		return nil
	}

	values := make([]string, 0, len(items))
	args := make([]interface{}, 0, len(items)*4)
	for i, item := range items {
		if item.ID == uuid.Nil {
			item.ID = uuid.New()
		}
		base := i * 4
		values = append(values, fmt.Sprintf("($%d,$%d,$%d,$%d)", base+1, base+2, base+3, base+4))
		args = append(args, item.ID, accessListID, item.Username, item.PasswordHash)
	}

	query := `INSERT INTO proxy_access_list_auth (id, access_list_id, username, password_hash) VALUES ` + strings.Join(values, ",")
	if _, err := r.db.Exec(ctx, query, args...); err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to insert proxy access list auth items")
	}
	return nil
}

func (r *ProxyAccessListRepository) replaceClients(ctx context.Context, accessListID uuid.UUID, clients []models.ProxyAccessListClient) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM proxy_access_list_clients WHERE access_list_id = $1`, accessListID); err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to clear proxy access list clients")
	}
	if len(clients) == 0 {
		return nil
	}

	values := make([]string, 0, len(clients))
	args := make([]interface{}, 0, len(clients)*4)
	for i, c := range clients {
		if c.ID == uuid.Nil {
			c.ID = uuid.New()
		}
		directive := c.Directive
		if directive == "" {
			directive = models.AccessDirectiveAllow
		}
		base := i * 4
		values = append(values, fmt.Sprintf("($%d,$%d,$%d,$%d)", base+1, base+2, base+3, base+4))
		args = append(args, c.ID, accessListID, c.Address, directive)
	}

	query := `INSERT INTO proxy_access_list_clients (id, access_list_id, address, directive) VALUES ` + strings.Join(values, ",")
	if _, err := r.db.Exec(ctx, query, args...); err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeDatabaseError, "failed to insert proxy access list clients")
	}
	return nil
}
