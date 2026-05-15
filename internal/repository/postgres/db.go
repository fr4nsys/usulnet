// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"errors"
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
	QueryTimeout    time.Duration // Default timeout for queries (0 = no default)
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
	pool         *pgxpool.Pool
	queryTimeout time.Duration
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

	return &DB{pool: pool, queryTimeout: opts.QueryTimeout}, nil
}

// Pool returns the underlying pgxpool.Pool
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}

// QueryTimeout returns the configured default query timeout.
// Returns 0 if no default timeout is set.
func (db *DB) QueryTimeout() time.Duration {
	return db.queryTimeout
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

// GetVersion returns the PostgreSQL server version string.
func (db *DB) GetVersion(ctx context.Context) (string, error) {
	var version string
	if err := db.QueryRow(ctx, "SELECT version()").Scan(&version); err != nil {
		return "", fmt.Errorf("get version: %w", err)
	}
	return version, nil
}

// DumpSQL exports all application tables as a SQL script (DELETE + INSERT statements).
// This is used for instance-level backups.
func (db *DB) DumpSQL(ctx context.Context) ([]byte, error) {
	rows, err := db.Query(ctx,
		`SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan table name: %w", err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tables: %w", err)
	}

	var buf []byte
	buf = append(buf, "-- usulnet instance backup\n-- Generated by usulnet DumpSQL\nBEGIN;\n\n"...)

	for _, table := range tables {
		colRows, err := db.Query(ctx,
			`SELECT column_name FROM information_schema.columns
			 WHERE table_schema = 'public' AND table_name = $1
			 ORDER BY ordinal_position`, table)
		if err != nil {
			return nil, fmt.Errorf("list columns for %s: %w", table, err)
		}

		var columns []string
		for colRows.Next() {
			var colName string
			if err := colRows.Scan(&colName); err != nil {
				colRows.Close()
				return nil, fmt.Errorf("scan column: %w", err)
			}
			columns = append(columns, colName)
		}
		colRows.Close()
		if len(columns) == 0 {
			continue
		}

		buf = append(buf, fmt.Sprintf("-- Table: %s\nDELETE FROM %q;\n", table, table)...)

		dataRows, err := db.Query(ctx, fmt.Sprintf("SELECT * FROM %q", table))
		if err != nil {
			return nil, fmt.Errorf("select from %s: %w", table, err)
		}

		fieldDescs := dataRows.FieldDescriptions()
		colCount := len(fieldDescs)

		for dataRows.Next() {
			values, err := dataRows.Values()
			if err != nil {
				dataRows.Close()
				return nil, fmt.Errorf("scan row in %s: %w", table, err)
			}

			buf = append(buf, fmt.Sprintf("INSERT INTO %q (", table)...)
			for i, col := range columns[:colCount] {
				if i > 0 {
					buf = append(buf, ", "...)
				}
				buf = append(buf, fmt.Sprintf("%q", col)...)
			}
			buf = append(buf, ") VALUES ("...)

			for i, val := range values {
				if i > 0 {
					buf = append(buf, ", "...)
				}
				if val == nil {
					buf = append(buf, "NULL"...)
				} else {
					buf = append(buf, pgEscapeLiteral(val)...)
				}
			}
			buf = append(buf, ");\n"...)
		}
		dataRows.Close()
		buf = append(buf, '\n')
	}

	buf = append(buf, "COMMIT;\n"...)
	return buf, nil
}

// RestoreSQL executes a SQL dump within a transaction.
func (db *DB) RestoreSQL(ctx context.Context, data []byte) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, string(data)); err != nil {
		return fmt.Errorf("execute SQL dump: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit restore: %w", err)
	}
	return nil
}

// pgEscapeLiteral converts a Go value to a SQL literal string.
func pgEscapeLiteral(v interface{}) string {
	switch val := v.(type) {
	case string:
		escaped := ""
		for _, c := range val {
			if c == '\'' {
				escaped += "''"
			} else {
				escaped += string(c)
			}
		}
		return "'" + escaped + "'"
	case []byte:
		return fmt.Sprintf("'\\x%x'", val)
	case bool:
		if val {
			return "TRUE"
		}
		return "FALSE"
	case nil:
		return "NULL"
	default:
		return fmt.Sprintf("'%v'", val)
	}
}

// IsDuplicateKeyError checks if an error is a duplicate key violation
func IsDuplicateKeyError(err error) bool {
	pgErr := &pgconn.PgError{}
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505" // unique_violation
	}
	return false
}

// IsForeignKeyError checks if an error is a foreign key violation
func IsForeignKeyError(err error) bool {
	pgErr := &pgconn.PgError{}
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23503" // foreign_key_violation
	}
	return false
}

// IsNotNullError checks if an error is a not null violation
func IsNotNullError(err error) bool {
	pgErr := &pgconn.PgError{}
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23502" // not_null_violation
	}
	return false
}

// IsCheckConstraintError checks if an error is a check constraint violation
func IsCheckConstraintError(err error) bool {
	pgErr := &pgconn.PgError{}
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23514" // check_violation
	}
	return false
}

// IsConnectionError checks if an error is a connection-related error
func IsConnectionError(err error) bool {
	pgErr := &pgconn.PgError{}
	if errors.As(err, &pgErr) {
		// Connection exception class
		return pgErr.Code[:2] == "08"
	}
	return false
}
