// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	stderrors "errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// FirewallRuleRepository
// ============================================================================

// FirewallRuleRepository implements firewall rule persistence.
type FirewallRuleRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewFirewallRuleRepository creates a new firewall rule repository.
func NewFirewallRuleRepository(db *DB, log *logger.Logger) *FirewallRuleRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &FirewallRuleRepository{
		db:     db,
		logger: log.Named("firewall_rule_repo"),
	}
}

// Create inserts a new firewall rule.
func (r *FirewallRuleRepository) Create(ctx context.Context, rule *models.FirewallRule) error {
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	now := time.Now()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	rule.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO firewall_rules (
			id, host_id, name, description, chain, protocol,
			source, destination, src_port, dst_port, action, direction,
			interface_name, position, enabled, applied,
			container_id, network_name, comment, created_by,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16,
			$17, $18, $19, $20,
			$21, $22
		)`,
		rule.ID, rule.HostID, rule.Name, rule.Description, rule.Chain, rule.Protocol,
		rule.Source, rule.Destination, rule.SrcPort, rule.DstPort, rule.Action, rule.Direction,
		rule.InterfaceName, rule.Position, rule.Enabled, rule.Applied,
		rule.ContainerID, rule.NetworkName, rule.Comment, rule.CreatedBy,
		rule.CreatedAt, rule.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "firewall: create rule")
	}
	return nil
}

// GetByID returns a firewall rule by ID.
func (r *FirewallRuleRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.FirewallRule, error) {
	var rule models.FirewallRule
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, host_id, name, description, chain, protocol,
			source, destination, src_port, dst_port, action, direction,
			interface_name, position, enabled, applied,
			container_id, network_name, comment, created_by,
			created_at, updated_at
		FROM firewall_rules WHERE id = $1`, id,
	).Scan(
		&rule.ID, &rule.HostID, &rule.Name, &rule.Description, &rule.Chain, &rule.Protocol,
		&rule.Source, &rule.Destination, &rule.SrcPort, &rule.DstPort, &rule.Action, &rule.Direction,
		&rule.InterfaceName, &rule.Position, &rule.Enabled, &rule.Applied,
		&rule.ContainerID, &rule.NetworkName, &rule.Comment, &rule.CreatedBy,
		&rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("firewall rule")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "firewall: get rule by id")
	}
	return &rule, nil
}

// List returns all firewall rules for a host, ordered by chain then position.
func (r *FirewallRuleRepository) List(ctx context.Context, hostID uuid.UUID) ([]models.FirewallRule, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, host_id, name, description, chain, protocol,
			source, destination, src_port, dst_port, action, direction,
			interface_name, position, enabled, applied,
			container_id, network_name, comment, created_by,
			created_at, updated_at
		FROM firewall_rules
		WHERE host_id = $1
		ORDER BY chain, position ASC, created_at ASC`, hostID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "firewall: list rules")
	}
	defer rows.Close()

	var rules []models.FirewallRule
	for rows.Next() {
		var rule models.FirewallRule
		if err := rows.Scan(
			&rule.ID, &rule.HostID, &rule.Name, &rule.Description, &rule.Chain, &rule.Protocol,
			&rule.Source, &rule.Destination, &rule.SrcPort, &rule.DstPort, &rule.Action, &rule.Direction,
			&rule.InterfaceName, &rule.Position, &rule.Enabled, &rule.Applied,
			&rule.ContainerID, &rule.NetworkName, &rule.Comment, &rule.CreatedBy,
			&rule.CreatedAt, &rule.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "firewall: scan rule")
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "firewall: iterate rules")
	}
	return rules, nil
}

// Update updates a firewall rule and resets the applied flag so the
// caller knows the host state is stale.
func (r *FirewallRuleRepository) Update(ctx context.Context, rule *models.FirewallRule) error {
	rule.UpdatedAt = time.Now()
	rule.Applied = false

	tag, err := r.db.Pool().Exec(ctx, `
		UPDATE firewall_rules SET
			name=$2, description=$3, chain=$4, protocol=$5,
			source=$6, destination=$7, src_port=$8, dst_port=$9,
			action=$10, direction=$11, interface_name=$12, position=$13,
			enabled=$14, applied=$15,
			container_id=$16, network_name=$17, comment=$18,
			updated_at=$19
		WHERE id=$1`,
		rule.ID, rule.Name, rule.Description, rule.Chain, rule.Protocol,
		rule.Source, rule.Destination, rule.SrcPort, rule.DstPort,
		rule.Action, rule.Direction, rule.InterfaceName, rule.Position,
		rule.Enabled, rule.Applied,
		rule.ContainerID, rule.NetworkName, rule.Comment,
		rule.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "firewall: update rule")
	}
	if tag.RowsAffected() == 0 {
		return errors.NotFound("firewall rule")
	}
	return nil
}

// Delete removes a firewall rule.
func (r *FirewallRuleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Pool().Exec(ctx, `DELETE FROM firewall_rules WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "firewall: delete rule")
	}
	if tag.RowsAffected() == 0 {
		return errors.NotFound("firewall rule")
	}
	return nil
}

// MarkApplied marks all enabled rules for a host as applied.
func (r *FirewallRuleRepository) MarkApplied(ctx context.Context, hostID uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx, `
		UPDATE firewall_rules SET applied = true, updated_at = $2
		WHERE host_id = $1 AND enabled = true`,
		hostID, time.Now(),
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "firewall: mark applied")
	}
	return nil
}

// NextPosition returns the next position value for a chain on a host.
// Returns 0 when the chain is empty.
func (r *FirewallRuleRepository) NextPosition(ctx context.Context, hostID uuid.UUID, chain string) (int, error) {
	var pos *int
	err := r.db.Pool().QueryRow(ctx, `
		SELECT MAX(position) FROM firewall_rules
		WHERE host_id = $1 AND chain = $2`, hostID, chain,
	).Scan(&pos)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "firewall: next position")
	}
	if pos == nil {
		return 0, nil
	}
	return *pos + 1, nil
}

// ============================================================================
// FirewallAuditRepository
// ============================================================================

// FirewallAuditRepository implements firewall audit log persistence.
type FirewallAuditRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewFirewallAuditRepository creates a new firewall audit repository.
func NewFirewallAuditRepository(db *DB, log *logger.Logger) *FirewallAuditRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &FirewallAuditRepository{
		db:     db,
		logger: log.Named("firewall_audit_repo"),
	}
}

// Create inserts a firewall audit log entry.
func (r *FirewallAuditRepository) Create(ctx context.Context, entry *models.FirewallAuditLog) error {
	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO firewall_audit_log (id, host_id, user_id, action, rule_id, rule_summary, details, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		entry.ID, entry.HostID, entry.UserID, entry.Action, entry.RuleID,
		entry.RuleSummary, entry.Details, entry.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "firewall: create audit log")
	}
	return nil
}

// List returns paginated audit logs for a host, ordered by created_at DESC.
func (r *FirewallAuditRepository) List(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.FirewallAuditLog, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	err := r.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM firewall_audit_log WHERE host_id = $1`, hostID,
	).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "firewall: count audit logs")
	}

	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, host_id, user_id, action, rule_id, rule_summary, details, created_at
		FROM firewall_audit_log
		WHERE host_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`, hostID, limit, offset,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "firewall: list audit logs")
	}
	defer rows.Close()

	var entries []models.FirewallAuditLog
	for rows.Next() {
		var e models.FirewallAuditLog
		if err := rows.Scan(
			&e.ID, &e.HostID, &e.UserID, &e.Action, &e.RuleID,
			&e.RuleSummary, &e.Details, &e.CreatedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "firewall: scan audit log")
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "firewall: iterate audit logs")
	}
	return entries, total, nil
}
