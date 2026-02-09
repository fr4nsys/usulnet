// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// TxFn is a function that runs within a transaction
type TxFn func(tx pgx.Tx) error

// WithTx executes a function within a database transaction
// If the function returns an error, the transaction is rolled back
// Otherwise, the transaction is committed
func (db *DB) WithTx(ctx context.Context, fn TxFn) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Handle panic
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p) // Re-throw panic after rollback
		}
	}()

	// Execute function
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("tx error: %v, rollback error: %w", err, rbErr)
		}
		return err
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// WithTxOptions executes a function within a transaction with custom options
func (db *DB) WithTxOptions(ctx context.Context, opts pgx.TxOptions, fn TxFn) error {
	tx, err := db.pool.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("tx error: %v, rollback error: %w", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// WithReadOnlyTx executes a function within a read-only transaction
func (db *DB) WithReadOnlyTx(ctx context.Context, fn TxFn) error {
	return db.WithTxOptions(ctx, pgx.TxOptions{
		AccessMode: pgx.ReadOnly,
	}, fn)
}

// WithSerializableTx executes a function within a serializable transaction
func (db *DB) WithSerializableTx(ctx context.Context, fn TxFn) error {
	return db.WithTxOptions(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable,
	}, fn)
}

// TxManager provides a way to manage nested transactions using savepoints
type TxManager struct {
	db *DB
	tx pgx.Tx
}

// NewTxManager creates a new transaction manager
func (db *DB) NewTxManager(ctx context.Context) (*TxManager, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &TxManager{db: db, tx: tx}, nil
}

// Tx returns the underlying transaction
func (tm *TxManager) Tx() pgx.Tx {
	return tm.tx
}

// Savepoint creates a savepoint within the transaction
func (tm *TxManager) Savepoint(ctx context.Context, name string) error {
	_, err := tm.tx.Exec(ctx, fmt.Sprintf("SAVEPOINT %s", name))
	return err
}

// RollbackToSavepoint rolls back to a savepoint
func (tm *TxManager) RollbackToSavepoint(ctx context.Context, name string) error {
	_, err := tm.tx.Exec(ctx, fmt.Sprintf("ROLLBACK TO SAVEPOINT %s", name))
	return err
}

// ReleaseSavepoint releases a savepoint
func (tm *TxManager) ReleaseSavepoint(ctx context.Context, name string) error {
	_, err := tm.tx.Exec(ctx, fmt.Sprintf("RELEASE SAVEPOINT %s", name))
	return err
}

// Commit commits the transaction
func (tm *TxManager) Commit(ctx context.Context) error {
	return tm.tx.Commit(ctx)
}

// Rollback rolls back the transaction
func (tm *TxManager) Rollback(ctx context.Context) error {
	return tm.tx.Rollback(ctx)
}

// Querier is an interface for database query methods
// This allows functions to work with both *DB and pgx.Tx
type Querier interface {
	Exec(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}
