// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// StorageConnectionRepository
// ============================================================================

// StorageConnectionRepository manages storage connection records.
type StorageConnectionRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewStorageConnectionRepository creates a new StorageConnectionRepository.
func NewStorageConnectionRepository(db *DB, log *logger.Logger) *StorageConnectionRepository {
	return &StorageConnectionRepository{
		db:     db,
		logger: log.Named("storage_conn_repo"),
	}
}

// Create inserts a new storage connection.
func (r *StorageConnectionRepository) Create(ctx context.Context, conn *models.StorageConnection) error {
	conn.ID = uuid.New()
	now := time.Now()
	conn.CreatedAt = now
	conn.UpdatedAt = now

	_, err := r.db.Exec(ctx, `
		INSERT INTO storage_connections (
			id, host_id, name, endpoint, region, access_key, secret_key,
			use_path_style, use_ssl, is_default, status, status_message,
			created_at, updated_at, created_by
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		conn.ID, conn.HostID, conn.Name, conn.Endpoint, conn.Region,
		conn.AccessKey, conn.SecretKey, conn.UsePathStyle, conn.UseSSL,
		conn.IsDefault, conn.Status, conn.StatusMsg,
		conn.CreatedAt, conn.UpdatedAt, conn.CreatedBy,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create storage connection")
	}
	return nil
}

// GetByID retrieves a connection by ID.
func (r *StorageConnectionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.StorageConnection, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, host_id, name, endpoint, region, access_key, secret_key,
			use_path_style, use_ssl, is_default, status, status_message,
			created_at, updated_at, created_by, last_checked
		FROM storage_connections WHERE id = $1`, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query storage connection")
	}
	conn, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.StorageConnection])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("storage connection")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan storage connection")
	}
	return conn, nil
}

// List retrieves connections for a host.
func (r *StorageConnectionRepository) List(ctx context.Context, hostID uuid.UUID) ([]*models.StorageConnection, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, host_id, name, endpoint, region, access_key, secret_key,
			use_path_style, use_ssl, is_default, status, status_message,
			created_at, updated_at, created_by, last_checked
		FROM storage_connections WHERE host_id = $1
		ORDER BY is_default DESC, name ASC`, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list storage connections")
	}
	conns, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.StorageConnection])
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan storage connections")
	}
	return conns, nil
}

// ListScoped returns storage connections for a host, filtered by resource scope.
// Opt-in model: shows allowed connections OR unassigned connections.
func (r *StorageConnectionRepository) ListScoped(ctx context.Context, hostID uuid.UUID, allowedIDs, assignedIDs []uuid.UUID) ([]*models.StorageConnection, error) {
	if len(assignedIDs) == 0 {
		return r.List(ctx, hostID)
	}

	var query string
	var args []interface{}

	if len(allowedIDs) == 0 {
		query = `
			SELECT id, host_id, name, endpoint, region, access_key, secret_key,
				use_path_style, use_ssl, is_default, status, status_message,
				created_at, updated_at, created_by, last_checked
			FROM storage_connections
			WHERE host_id = $1 AND NOT (id = ANY($2))
			ORDER BY is_default DESC, name ASC`
		args = []interface{}{hostID, assignedIDs}
	} else {
		query = `
			SELECT id, host_id, name, endpoint, region, access_key, secret_key,
				use_path_style, use_ssl, is_default, status, status_message,
				created_at, updated_at, created_by, last_checked
			FROM storage_connections
			WHERE host_id = $1 AND (id = ANY($2) OR NOT (id = ANY($3)))
			ORDER BY is_default DESC, name ASC`
		args = []interface{}{hostID, allowedIDs, assignedIDs}
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list scoped storage connections")
	}
	conns, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.StorageConnection])
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan scoped storage connections")
	}
	return conns, nil
}

// Update updates a storage connection.
func (r *StorageConnectionRepository) Update(ctx context.Context, conn *models.StorageConnection) error {
	conn.UpdatedAt = time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE storage_connections SET
			name=$2, endpoint=$3, region=$4, access_key=$5, secret_key=$6,
			use_path_style=$7, use_ssl=$8, is_default=$9, status=$10,
			status_message=$11, updated_at=$12, last_checked=$13
		WHERE id = $1`,
		conn.ID, conn.Name, conn.Endpoint, conn.Region, conn.AccessKey, conn.SecretKey,
		conn.UsePathStyle, conn.UseSSL, conn.IsDefault, conn.Status,
		conn.StatusMsg, conn.UpdatedAt, conn.LastChecked,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update storage connection")
	}
	return nil
}

// Delete removes a storage connection.
func (r *StorageConnectionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM storage_connections WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete storage connection")
	}
	return nil
}

// UpdateStatus updates only the status fields.
func (r *StorageConnectionRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.StorageConnectionStatus, msg string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE storage_connections SET status=$2, status_message=$3, last_checked=$4, updated_at=$4
		WHERE id = $1`, id, status, msg, now)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update storage connection status")
	}
	return nil
}

// GetDefault returns the default connection for a host.
func (r *StorageConnectionRepository) GetDefault(ctx context.Context, hostID uuid.UUID) (*models.StorageConnection, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, host_id, name, endpoint, region, access_key, secret_key,
			use_path_style, use_ssl, is_default, status, status_message,
			created_at, updated_at, created_by, last_checked
		FROM storage_connections WHERE host_id = $1 AND is_default = true
		LIMIT 1`, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query default connection")
	}
	conn, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.StorageConnection])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan default connection")
	}
	return conn, nil
}

// ============================================================================
// StorageBucketRepository
// ============================================================================

// StorageBucketRepository manages tracked bucket records.
type StorageBucketRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewStorageBucketRepository creates a new StorageBucketRepository.
func NewStorageBucketRepository(db *DB, log *logger.Logger) *StorageBucketRepository {
	return &StorageBucketRepository{
		db:     db,
		logger: log.Named("storage_bucket_repo"),
	}
}

// Upsert inserts or updates a bucket record (used during sync).
func (r *StorageBucketRepository) Upsert(ctx context.Context, bucket *models.StorageBucket) error {
	now := time.Now()
	bucket.UpdatedAt = now

	_, err := r.db.Exec(ctx, `
		INSERT INTO storage_buckets (id, connection_id, name, region, size_bytes, object_count,
			is_public, versioning, tags, created_at, updated_at, last_synced)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (connection_id, name)
		DO UPDATE SET
			size_bytes = EXCLUDED.size_bytes,
			object_count = EXCLUDED.object_count,
			is_public = EXCLUDED.is_public,
			versioning = EXCLUDED.versioning,
			tags = EXCLUDED.tags,
			updated_at = EXCLUDED.updated_at,
			last_synced = EXCLUDED.last_synced`,
		bucket.ID, bucket.ConnectionID, bucket.Name, bucket.Region,
		bucket.SizeBytes, bucket.ObjectCount, bucket.IsPublic, bucket.Versioning,
		bucket.Tags, bucket.CreatedAt, bucket.UpdatedAt, bucket.LastSynced,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to upsert storage bucket")
	}
	return nil
}

// ListByConnection retrieves buckets for a connection.
func (r *StorageBucketRepository) ListByConnection(ctx context.Context, connID uuid.UUID) ([]*models.StorageBucket, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, connection_id, name, region, size_bytes, object_count,
			is_public, versioning, tags, created_at, updated_at, last_synced
		FROM storage_buckets WHERE connection_id = $1
		ORDER BY name ASC`, connID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list buckets")
	}
	buckets, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.StorageBucket])
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan buckets")
	}
	return buckets, nil
}

// GetByName retrieves a bucket by connection and name.
func (r *StorageBucketRepository) GetByName(ctx context.Context, connID uuid.UUID, name string) (*models.StorageBucket, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, connection_id, name, region, size_bytes, object_count,
			is_public, versioning, tags, created_at, updated_at, last_synced
		FROM storage_buckets WHERE connection_id = $1 AND name = $2`, connID, name)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query bucket")
	}
	bucket, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.StorageBucket])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan bucket")
	}
	return bucket, nil
}

// Delete removes a tracked bucket.
func (r *StorageBucketRepository) Delete(ctx context.Context, connID uuid.UUID, name string) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM storage_buckets WHERE connection_id = $1 AND name = $2`, connID, name)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete bucket record")
	}
	return nil
}

// DeleteByConnection removes all buckets for a connection.
func (r *StorageBucketRepository) DeleteByConnection(ctx context.Context, connID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM storage_buckets WHERE connection_id = $1`, connID)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete connection buckets")
	}
	return nil
}

// GetStats retrieves aggregate stats for a connection.
func (r *StorageBucketRepository) GetStats(ctx context.Context, connID uuid.UUID) (*models.StorageStats, error) {
	var stats models.StorageStats
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(SUM(size_bytes),0), COALESCE(SUM(object_count),0)
		FROM storage_buckets WHERE connection_id = $1`, connID,
	).Scan(&stats.TotalBuckets, &stats.TotalSize, &stats.TotalObjects)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get storage stats")
	}
	return &stats, nil
}

// ============================================================================
// StorageAuditLogRepository
// ============================================================================

// StorageAuditLogRepository manages storage audit log entries.
type StorageAuditLogRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewStorageAuditLogRepository creates a new StorageAuditLogRepository.
func NewStorageAuditLogRepository(db *DB, log *logger.Logger) *StorageAuditLogRepository {
	return &StorageAuditLogRepository{
		db:     db,
		logger: log.Named("storage_audit_repo"),
	}
}

// Create inserts an audit log entry.
func (r *StorageAuditLogRepository) Create(ctx context.Context, entry *models.StorageAuditLog) error {
	entry.ID = uuid.New()
	entry.CreatedAt = time.Now()
	_, err := r.db.Exec(ctx, `
		INSERT INTO storage_audit_log (id, connection_id, action, resource_type, resource_name, details, user_id, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		entry.ID, entry.ConnectionID, entry.Action, entry.ResourceType,
		entry.ResourceName, entry.Details, entry.UserID, entry.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create storage audit log")
	}
	return nil
}

// List retrieves audit entries for a connection with pagination.
func (r *StorageAuditLogRepository) List(ctx context.Context, connID uuid.UUID, limit, offset int) ([]*models.StorageAuditLog, int64, error) {
	var total int64
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM storage_audit_log WHERE connection_id = $1`, connID,
	).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count audit entries")
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, connection_id, action, resource_type, resource_name, details, user_id, created_at
		FROM storage_audit_log WHERE connection_id = $1
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`, connID, limit, offset)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list audit entries")
	}
	entries, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.StorageAuditLog])
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan audit entries")
	}
	return entries, total, nil
}
