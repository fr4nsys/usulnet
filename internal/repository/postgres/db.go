// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options configures the database connection pool
type Options struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// DefaultOptions returns production-tuned default options.
// MaxIdleConns close to MaxOpenConns avoids connection churn.
// Longer lifetimes reduce unnecessary reconnects (pgx handles health checks).
func DefaultOptions() Options {
	return Options{
		MaxOpenConns:    25,
		MaxIdleConns:    10,
		ConnMaxLifetime: 30 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
	}
}

// DB wraps pgxpool.Pool with additional functionality
type DB struct {
	pool *pgxpool.Pool
}

// New creates a new database connection pool
func New(ctx context.Context, connString string, opts Options) (*DB, error) {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Apply options
	if opts.MaxOpenConns > 0 {
		config.MaxConns = int32(opts.MaxOpenConns)
	}
	if opts.MaxIdleConns > 0 {
		config.MinConns = int32(opts.MaxIdleConns)
	}
	if opts.ConnMaxLifetime > 0 {
		config.MaxConnLifetime = opts.ConnMaxLifetime
	}
	if opts.ConnMaxIdleTime > 0 {
		config.MaxConnIdleTime = opts.ConnMaxIdleTime
	}

	// Configure connection
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	// Create pool
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{pool: pool}, nil
}

// Pool returns the underlying pgxpool.Pool
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}

// Close closes the database connection pool
func (db *DB) Close() {
	db.pool.Close()
}

// Ping checks database connectivity
func (db *DB) Ping(ctx context.Context) error {
	return db.pool.Ping(ctx)
}

// Stats returns pool statistics
func (db *DB) Stats() *pgxpool.Stat {
	return db.pool.Stat()
}

// Exec executes a query that doesn't return rows
func (db *DB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return db.pool.Exec(ctx, sql, args...)
}

// Query executes a query that returns rows
func (db *DB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return db.pool.Query(ctx, sql, args...)
}

// QueryRow executes a query that returns at most one row
func (db *DB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return db.pool.QueryRow(ctx, sql, args...)
}

// Begin starts a new transaction
func (db *DB) Begin(ctx context.Context) (pgx.Tx, error) {
	return db.pool.Begin(ctx)
}

// BeginTx starts a new transaction with options
func (db *DB) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	return db.pool.BeginTx(ctx, opts)
}

// Acquire acquires a connection from the pool
func (db *DB) Acquire(ctx context.Context) (*pgxpool.Conn, error) {
	return db.pool.Acquire(ctx)
}

// HealthCheck performs a comprehensive health check
func (db *DB) HealthCheck(ctx context.Context) error {
	// Check connectivity
	if err := db.Ping(ctx); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	// Check pool stats
	stats := db.Stats()
	if stats.TotalConns() == 0 {
		return fmt.Errorf("no connections available")
	}

	// Execute a simple query
	var result int
	if err := db.QueryRow(ctx, "SELECT 1").Scan(&result); err != nil {
		return fmt.Errorf("query failed: %w", err)
	}

	return nil
}

// IsDuplicateKeyError checks if an error is a duplicate key violation
func IsDuplicateKeyError(err error) bool {
	if pgErr, ok := err.(*pgconn.PgError); ok {
		return pgErr.Code == "23505" // unique_violation
	}
	return false
}

// IsForeignKeyError checks if an error is a foreign key violation
func IsForeignKeyError(err error) bool {
	if pgErr, ok := err.(*pgconn.PgError); ok {
		return pgErr.Code == "23503" // foreign_key_violation
	}
	return false
}

// IsNotNullError checks if an error is a not null violation
func IsNotNullError(err error) bool {
	if pgErr, ok := err.(*pgconn.PgError); ok {
		return pgErr.Code == "23502" // not_null_violation
	}
	return false
}

// IsCheckConstraintError checks if an error is a check constraint violation
func IsCheckConstraintError(err error) bool {
	if pgErr, ok := err.(*pgconn.PgError); ok {
		return pgErr.Code == "23514" // check_violation
	}
	return false
}

// IsConnectionError checks if an error is a connection-related error
func IsConnectionError(err error) bool {
	if pgErr, ok := err.(*pgconn.PgError); ok {
		// Connection exception class
		return pgErr.Code[:2] == "08"
	}
	return false
}
