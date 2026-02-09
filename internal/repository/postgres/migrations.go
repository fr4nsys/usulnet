// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migration represents a database migration
type Migration struct {
	Version   string
	Name      string
	AppliedAt *time.Time
}

// migrationLockID is the advisory lock ID for migration safety.
// Derived from 'usul' in hex: 0x7573756C = 1970500972
const migrationLockID = 1970500972

// Migrate runs all pending migrations with advisory lock protection.
// Safe for concurrent startup of multiple instances.
func (db *DB) Migrate(ctx context.Context) error {
	// Acquire advisory lock to prevent concurrent migrations
	var locked bool
	if err := db.pool.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", migrationLockID).Scan(&locked); err != nil {
		return fmt.Errorf("failed to acquire migration lock: %w", err)
	}
	if !locked {
		return fmt.Errorf("another instance is running migrations, skipping")
	}
	defer func() {
		_, _ = db.pool.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLockID)
	}()

	// Ensure migrations table exists
	if err := db.createMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get applied migrations
	applied, err := db.getAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Get available migrations
	available, err := db.getAvailableMigrations()
	if err != nil {
		return fmt.Errorf("failed to get available migrations: %w", err)
	}

	// Apply pending migrations
	for _, m := range available {
		if _, ok := applied[m.Version]; ok {
			continue // Already applied
		}

		if err := db.applyMigration(ctx, m); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", m.Version, err)
		}
	}

	return nil
}

// MigrateDown rolls back N migrations
func (db *DB) MigrateDown(ctx context.Context, steps string) error {
	n, err := strconv.Atoi(steps)
	if err != nil {
		return fmt.Errorf("invalid steps: %s", steps)
	}

	// Get applied migrations in reverse order
	applied, err := db.getAppliedMigrationsOrdered(ctx)
	if err != nil {
		return err
	}

	// Rollback the last N migrations
	count := 0
	for i := len(applied) - 1; i >= 0 && count < n; i-- {
		if err := db.rollbackMigration(ctx, applied[i]); err != nil {
			return fmt.Errorf("failed to rollback migration %s: %w", applied[i].Version, err)
		}
		count++
	}

	return nil
}

// MigrationStatus prints the status of all migrations
func (db *DB) MigrationStatus(ctx context.Context) error {
	// Ensure migrations table exists
	if err := db.createMigrationsTable(ctx); err != nil {
		return err
	}

	applied, err := db.getAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	available, err := db.getAvailableMigrations()
	if err != nil {
		return err
	}

	fmt.Println("Migration Status:")
	fmt.Println("=================")

	for _, m := range available {
		status := "Pending"
		if appliedAt, ok := applied[m.Version]; ok {
			status = fmt.Sprintf("Applied at %s", appliedAt.Format(time.RFC3339))
		}
		fmt.Printf("%-20s %s\n", m.Version, status)
	}

	return nil
}

// createMigrationsTable creates the schema_migrations table if it doesn't exist
func (db *DB) createMigrationsTable(ctx context.Context) error {
	_, err := db.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

// getAppliedMigrations returns a map of applied migration versions
func (db *DB) getAppliedMigrations(ctx context.Context) (map[string]time.Time, error) {
	rows, err := db.pool.Query(ctx, "SELECT version, applied_at FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[string]time.Time)
	for rows.Next() {
		var version string
		var appliedAt time.Time
		if err := rows.Scan(&version, &appliedAt); err != nil {
			return nil, err
		}
		applied[version] = appliedAt
	}

	return applied, rows.Err()
}

// getAppliedMigrationsOrdered returns applied migrations in order
func (db *DB) getAppliedMigrationsOrdered(ctx context.Context) ([]Migration, error) {
	rows, err := db.pool.Query(ctx, "SELECT version, applied_at FROM schema_migrations ORDER BY version ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var migrations []Migration
	for rows.Next() {
		var m Migration
		var appliedAt time.Time
		if err := rows.Scan(&m.Version, &appliedAt); err != nil {
			return nil, err
		}
		m.AppliedAt = &appliedAt
		migrations = append(migrations, m)
	}

	return migrations, rows.Err()
}

// getAvailableMigrations reads migration files from embedded FS
func (db *DB) getAvailableMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}

	var migrations []Migration
	seen := make(map[string]bool)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}

		version := strings.TrimSuffix(name, ".up.sql")
		if seen[version] {
			continue
		}
		seen[version] = true

		// Extract name from version (e.g., "001_users" -> "users")
		parts := strings.SplitN(version, "_", 2)
		migrationName := version
		if len(parts) > 1 {
			migrationName = parts[1]
		}

		migrations = append(migrations, Migration{
			Version: version,
			Name:    migrationName,
		})
	}

	// Sort by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// applyMigration applies a single migration
func (db *DB) applyMigration(ctx context.Context, m Migration) error {
	filename := fmt.Sprintf("migrations/%s.up.sql", m.Version)
	content, err := migrationsFS.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read migration file: %w", err)
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Execute migration
	if _, err := tx.Exec(ctx, string(content)); err != nil {
		return fmt.Errorf("failed to execute migration: %w", err)
	}

	// Record migration
	if _, err := tx.Exec(ctx,
		"INSERT INTO schema_migrations (version) VALUES ($1)",
		m.Version,
	); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	return tx.Commit(ctx)
}

// rollbackMigration rolls back a single migration
func (db *DB) rollbackMigration(ctx context.Context, m Migration) error {
	filename := fmt.Sprintf("migrations/%s.down.sql", m.Version)
	content, err := migrationsFS.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read rollback file: %w", err)
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Execute rollback
	if _, err := tx.Exec(ctx, string(content)); err != nil {
		return fmt.Errorf("failed to execute rollback: %w", err)
	}

	// Remove migration record
	if _, err := tx.Exec(ctx,
		"DELETE FROM schema_migrations WHERE version = $1",
		m.Version,
	); err != nil {
		return fmt.Errorf("failed to remove migration record: %w", err)
	}

	return tx.Commit(ctx)
}
