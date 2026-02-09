// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// SSHKeyRepository
// ============================================================================

// SSHKeyRepository manages SSH key records.
type SSHKeyRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewSSHKeyRepository creates a new SSHKeyRepository.
func NewSSHKeyRepository(db *DB, log *logger.Logger) *SSHKeyRepository {
	return &SSHKeyRepository{
		db:     db,
		logger: log.Named("ssh_key_repo"),
	}
}

// Create inserts a new SSH key.
func (r *SSHKeyRepository) Create(ctx context.Context, key *models.SSHKey) error {
	key.ID = uuid.New()
	now := time.Now()
	key.CreatedAt = now
	key.UpdatedAt = now

	_, err := r.db.Exec(ctx, `
		INSERT INTO ssh_keys (
			id, name, key_type, public_key, private_key, passphrase,
			fingerprint, comment, created_by, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		key.ID, key.Name, key.KeyType, key.PublicKey, key.PrivateKey,
		key.Passphrase, key.Fingerprint, key.Comment, key.CreatedBy,
		key.CreatedAt, key.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create SSH key")
	}
	return nil
}

// GetByID retrieves an SSH key by ID.
func (r *SSHKeyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.SSHKey, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, key_type, public_key, private_key, passphrase,
			fingerprint, comment, created_by, created_at, updated_at, last_used
		FROM ssh_keys WHERE id = $1`, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query SSH key")
	}
	key, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.SSHKey])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("SSH key")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan SSH key")
	}
	return key, nil
}

// ListByUser retrieves all SSH keys for a user.
func (r *SSHKeyRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.SSHKey, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, key_type, public_key, private_key, passphrase,
			fingerprint, comment, created_by, created_at, updated_at, last_used
		FROM ssh_keys WHERE created_by = $1
		ORDER BY name ASC`, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list SSH keys")
	}
	keys, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.SSHKey])
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan SSH keys")
	}
	return keys, nil
}

// Update updates an SSH key.
func (r *SSHKeyRepository) Update(ctx context.Context, key *models.SSHKey) error {
	key.UpdatedAt = time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE ssh_keys SET
			name=$2, passphrase=$3, comment=$4, updated_at=$5
		WHERE id = $1`,
		key.ID, key.Name, key.Passphrase, key.Comment, key.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update SSH key")
	}
	return nil
}

// Delete removes an SSH key.
func (r *SSHKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM ssh_keys WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete SSH key")
	}
	return nil
}

// UpdateLastUsed updates the last_used timestamp.
func (r *SSHKeyRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE ssh_keys SET last_used=$2 WHERE id = $1`, id, now)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update SSH key last_used")
	}
	return nil
}

// GetByFingerprint retrieves an SSH key by fingerprint.
func (r *SSHKeyRepository) GetByFingerprint(ctx context.Context, fingerprint string) (*models.SSHKey, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, key_type, public_key, private_key, passphrase,
			fingerprint, comment, created_by, created_at, updated_at, last_used
		FROM ssh_keys WHERE fingerprint = $1`, fingerprint)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query SSH key by fingerprint")
	}
	key, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.SSHKey])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan SSH key")
	}
	return key, nil
}

// ============================================================================
// SSHConnectionRepository
// ============================================================================

// SSHConnectionRepository manages SSH connection records.
type SSHConnectionRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewSSHConnectionRepository creates a new SSHConnectionRepository.
func NewSSHConnectionRepository(db *DB, log *logger.Logger) *SSHConnectionRepository {
	return &SSHConnectionRepository{
		db:     db,
		logger: log.Named("ssh_conn_repo"),
	}
}

// Create inserts a new SSH connection.
func (r *SSHConnectionRepository) Create(ctx context.Context, conn *models.SSHConnection) error {
	conn.ID = uuid.New()
	now := time.Now()
	conn.CreatedAt = now
	conn.UpdatedAt = now

	optionsJSON, _ := json.Marshal(conn.Options)
	tagsJSON, _ := json.Marshal(conn.Tags)

	_, err := r.db.Exec(ctx, `
		INSERT INTO ssh_connections (
			id, name, description, host, port, username, auth_type,
			key_id, password, jump_host, tags, category, status,
			status_message, options, created_by, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		conn.ID, conn.Name, conn.Description, conn.Host, conn.Port,
		conn.Username, conn.AuthType, conn.KeyID, conn.Password, conn.JumpHost,
		string(tagsJSON), conn.Category, conn.Status, conn.StatusMsg,
		string(optionsJSON), conn.CreatedBy, conn.CreatedAt, conn.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create SSH connection")
	}
	return nil
}

// GetByID retrieves an SSH connection by ID.
func (r *SSHConnectionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.SSHConnection, error) {
	var conn models.SSHConnection
	var optionsJSON, tagsJSON []byte

	err := r.db.QueryRow(ctx, `
		SELECT id, name, description, host, port, username, auth_type,
			key_id, password, jump_host, tags, category, status,
			status_message, options, last_checked, created_by, created_at, updated_at
		FROM ssh_connections WHERE id = $1`, id,
	).Scan(
		&conn.ID, &conn.Name, &conn.Description, &conn.Host, &conn.Port,
		&conn.Username, &conn.AuthType, &conn.KeyID, &conn.Password, &conn.JumpHost,
		&tagsJSON, &conn.Category, &conn.Status, &conn.StatusMsg,
		&optionsJSON, &conn.LastChecked, &conn.CreatedBy, &conn.CreatedAt, &conn.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("SSH connection")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan SSH connection")
	}

	if len(optionsJSON) > 0 {
		_ = json.Unmarshal(optionsJSON, &conn.Options)
	}
	if len(tagsJSON) > 0 {
		_ = json.Unmarshal(tagsJSON, &conn.Tags)
	}

	return &conn, nil
}

// ListByUser retrieves all SSH connections for a user.
func (r *SSHConnectionRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.SSHConnection, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, host, port, username, auth_type,
			key_id, password, jump_host, tags, category, status,
			status_message, options, last_checked, created_by, created_at, updated_at
		FROM ssh_connections WHERE created_by = $1
		ORDER BY category, name ASC`, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list SSH connections")
	}
	defer rows.Close()

	var conns []*models.SSHConnection
	for rows.Next() {
		var conn models.SSHConnection
		var optionsJSON, tagsJSON []byte

		err := rows.Scan(
			&conn.ID, &conn.Name, &conn.Description, &conn.Host, &conn.Port,
			&conn.Username, &conn.AuthType, &conn.KeyID, &conn.Password, &conn.JumpHost,
			&tagsJSON, &conn.Category, &conn.Status, &conn.StatusMsg,
			&optionsJSON, &conn.LastChecked, &conn.CreatedBy, &conn.CreatedAt, &conn.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan SSH connection")
		}

		if len(optionsJSON) > 0 {
			_ = json.Unmarshal(optionsJSON, &conn.Options)
		}
		if len(tagsJSON) > 0 {
			_ = json.Unmarshal(tagsJSON, &conn.Tags)
		}

		conns = append(conns, &conn)
	}

	return conns, nil
}

// ListByCategory retrieves SSH connections for a user by category.
func (r *SSHConnectionRepository) ListByCategory(ctx context.Context, userID uuid.UUID, category string) ([]*models.SSHConnection, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, description, host, port, username, auth_type,
			key_id, password, jump_host, tags, category, status,
			status_message, options, last_checked, created_by, created_at, updated_at
		FROM ssh_connections WHERE created_by = $1 AND category = $2
		ORDER BY name ASC`, userID, category)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list SSH connections by category")
	}
	defer rows.Close()

	var conns []*models.SSHConnection
	for rows.Next() {
		var conn models.SSHConnection
		var optionsJSON, tagsJSON []byte

		err := rows.Scan(
			&conn.ID, &conn.Name, &conn.Description, &conn.Host, &conn.Port,
			&conn.Username, &conn.AuthType, &conn.KeyID, &conn.Password, &conn.JumpHost,
			&tagsJSON, &conn.Category, &conn.Status, &conn.StatusMsg,
			&optionsJSON, &conn.LastChecked, &conn.CreatedBy, &conn.CreatedAt, &conn.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan SSH connection")
		}

		if len(optionsJSON) > 0 {
			_ = json.Unmarshal(optionsJSON, &conn.Options)
		}
		if len(tagsJSON) > 0 {
			_ = json.Unmarshal(tagsJSON, &conn.Tags)
		}

		conns = append(conns, &conn)
	}

	return conns, nil
}

// Update updates an SSH connection.
func (r *SSHConnectionRepository) Update(ctx context.Context, conn *models.SSHConnection) error {
	conn.UpdatedAt = time.Now()

	optionsJSON, _ := json.Marshal(conn.Options)
	tagsJSON, _ := json.Marshal(conn.Tags)

	_, err := r.db.Exec(ctx, `
		UPDATE ssh_connections SET
			name=$2, description=$3, host=$4, port=$5, username=$6, auth_type=$7,
			key_id=$8, password=$9, jump_host=$10, tags=$11, category=$12,
			options=$13, updated_at=$14
		WHERE id = $1`,
		conn.ID, conn.Name, conn.Description, conn.Host, conn.Port,
		conn.Username, conn.AuthType, conn.KeyID, conn.Password, conn.JumpHost,
		string(tagsJSON), conn.Category, string(optionsJSON), conn.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update SSH connection")
	}
	return nil
}

// Delete removes an SSH connection.
func (r *SSHConnectionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM ssh_connections WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete SSH connection")
	}
	return nil
}

// UpdateStatus updates only the status fields.
func (r *SSHConnectionRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.SSHConnectionStatus, msg string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE ssh_connections SET status=$2, status_message=$3, last_checked=$4, updated_at=$4
		WHERE id = $1`, id, status, msg, now)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update SSH connection status")
	}
	return nil
}

// GetCategories returns all unique categories for a user.
func (r *SSHConnectionRepository) GetCategories(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT category FROM ssh_connections
		WHERE created_by = $1 AND category != ''
		ORDER BY category`, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get SSH categories")
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var cat string
		if err := rows.Scan(&cat); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan category")
		}
		categories = append(categories, cat)
	}
	return categories, nil
}

// ============================================================================
// SSHSessionRepository
// ============================================================================

// SSHSessionRepository manages SSH session records.
type SSHSessionRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewSSHSessionRepository creates a new SSHSessionRepository.
func NewSSHSessionRepository(db *DB, log *logger.Logger) *SSHSessionRepository {
	return &SSHSessionRepository{
		db:     db,
		logger: log.Named("ssh_session_repo"),
	}
}

// Create inserts a new SSH session.
func (r *SSHSessionRepository) Create(ctx context.Context, session *models.SSHSession) error {
	session.ID = uuid.New()
	session.StartedAt = time.Now()

	_, err := r.db.Exec(ctx, `
		INSERT INTO ssh_sessions (
			id, connection_id, user_id, started_at, client_ip,
			term_type, term_cols, term_rows
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		session.ID, session.ConnectionID, session.UserID, session.StartedAt,
		session.ClientIP, session.TermType, session.TermCols, session.TermRows,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create SSH session")
	}
	return nil
}

// End marks a session as ended.
func (r *SSHSessionRepository) End(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE ssh_sessions SET ended_at=$2 WHERE id = $1`, id, now)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to end SSH session")
	}
	return nil
}

// ListByConnection retrieves sessions for a connection.
func (r *SSHSessionRepository) ListByConnection(ctx context.Context, connID uuid.UUID, limit int) ([]*models.SSHSession, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, connection_id, user_id, started_at, ended_at, client_ip,
			term_type, term_cols, term_rows
		FROM ssh_sessions WHERE connection_id = $1
		ORDER BY started_at DESC LIMIT $2`, connID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list SSH sessions")
	}
	sessions, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.SSHSession])
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan SSH sessions")
	}
	return sessions, nil
}

// ListActive retrieves active (not ended) sessions.
func (r *SSHSessionRepository) ListActive(ctx context.Context) ([]*models.SSHSession, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, connection_id, user_id, started_at, ended_at, client_ip,
			term_type, term_cols, term_rows
		FROM ssh_sessions WHERE ended_at IS NULL
		ORDER BY started_at DESC`)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list active SSH sessions")
	}
	sessions, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.SSHSession])
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan SSH sessions")
	}
	return sessions, nil
}

// ============================================================================
// SSHTunnelRepository
// ============================================================================

// SSHTunnelRepository handles SSH tunnel persistence.
type SSHTunnelRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewSSHTunnelRepository creates a new SSH tunnel repository.
func NewSSHTunnelRepository(db *DB, log *logger.Logger) *SSHTunnelRepository {
	return &SSHTunnelRepository{
		db:     db,
		logger: log.Named("ssh_tunnel_repo"),
	}
}

// Create creates a new SSH tunnel configuration.
func (r *SSHTunnelRepository) Create(ctx context.Context, tunnel *models.SSHTunnel) error {
	tunnel.ID = uuid.New()
	tunnel.CreatedAt = time.Now()
	tunnel.UpdatedAt = tunnel.CreatedAt
	if tunnel.Status == "" {
		tunnel.Status = models.SSHTunnelStatusStopped
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO ssh_tunnels (id, connection_id, user_id, type, local_host, local_port,
			remote_host, remote_port, status, status_message, auto_start, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		tunnel.ID, tunnel.ConnectionID, tunnel.UserID, tunnel.Type,
		tunnel.LocalHost, tunnel.LocalPort, tunnel.RemoteHost, tunnel.RemotePort,
		tunnel.Status, tunnel.StatusMsg, tunnel.AutoStart, tunnel.CreatedAt, tunnel.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create SSH tunnel")
	}
	return nil
}

// GetByID retrieves a tunnel by ID.
func (r *SSHTunnelRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.SSHTunnel, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, connection_id, user_id, type, local_host, local_port,
			remote_host, remote_port, status, status_message, auto_start, created_at, updated_at
		FROM ssh_tunnels WHERE id = $1`, id)

	var tunnel models.SSHTunnel
	err := row.Scan(
		&tunnel.ID, &tunnel.ConnectionID, &tunnel.UserID, &tunnel.Type,
		&tunnel.LocalHost, &tunnel.LocalPort, &tunnel.RemoteHost, &tunnel.RemotePort,
		&tunnel.Status, &tunnel.StatusMsg, &tunnel.AutoStart, &tunnel.CreatedAt, &tunnel.UpdatedAt,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, errors.Wrap(err, errors.CodeNotFound, "SSH tunnel not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get SSH tunnel")
	}
	return &tunnel, nil
}

// ListByConnection retrieves all tunnels for a connection.
func (r *SSHTunnelRepository) ListByConnection(ctx context.Context, connID uuid.UUID) ([]*models.SSHTunnel, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, connection_id, user_id, type, local_host, local_port,
			remote_host, remote_port, status, status_message, auto_start, created_at, updated_at
		FROM ssh_tunnels WHERE connection_id = $1
		ORDER BY created_at DESC`, connID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list SSH tunnels")
	}
	tunnels, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.SSHTunnel])
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan SSH tunnels")
	}
	return tunnels, nil
}

// ListByUser retrieves all tunnels for a user.
func (r *SSHTunnelRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.SSHTunnel, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, connection_id, user_id, type, local_host, local_port,
			remote_host, remote_port, status, status_message, auto_start, created_at, updated_at
		FROM ssh_tunnels WHERE user_id = $1
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list SSH tunnels")
	}
	tunnels, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.SSHTunnel])
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan SSH tunnels")
	}
	return tunnels, nil
}

// UpdateStatus updates the status of a tunnel.
func (r *SSHTunnelRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.SSHTunnelStatus, msg string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE ssh_tunnels SET status = $2, status_message = $3, updated_at = $4
		WHERE id = $1`, id, status, msg, time.Now())
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update SSH tunnel status")
	}
	return nil
}

// Delete removes a tunnel.
func (r *SSHTunnelRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM ssh_tunnels WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete SSH tunnel")
	}
	return nil
}
