// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// Type aliases pointing to shared model types.
type GitOpsPipeline = models.GitOpsPipelineRecord
type GitOpsDeployment = models.GitOpsDeploymentRecord

// GitOpsRepository handles CRUD for GitOps pipelines and deployments.
type GitOpsRepository struct {
	db *DB
}

// NewGitOpsRepository creates a new GitOps repository.
func NewGitOpsRepository(db *DB) *GitOpsRepository {
	return &GitOpsRepository{db: db}
}

// CreatePipeline creates a new GitOps pipeline.
func (r *GitOpsRepository) CreatePipeline(ctx context.Context, p *GitOpsPipeline) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO gitops_pipelines (id, name, repository, branch, provider, target_stack, target_service,
			action, trigger_type, schedule, is_enabled, auto_rollback, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		p.ID, p.Name, p.Repository, p.Branch, p.Provider, p.TargetStack, p.TargetService,
		p.Action, p.TriggerType, p.Schedule, p.IsEnabled, p.AutoRollback, p.CreatedBy,
	)
	return err
}

// GetPipeline retrieves a pipeline by ID.
func (r *GitOpsRepository) GetPipeline(ctx context.Context, id uuid.UUID) (*GitOpsPipeline, error) {
	p := &GitOpsPipeline{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, repository, branch, provider, target_stack, target_service,
			action, trigger_type, schedule, is_enabled, auto_rollback,
			deploy_count, last_deploy_at, last_status, created_by, created_at, updated_at
		FROM gitops_pipelines WHERE id = $1`, id).Scan(
		&p.ID, &p.Name, &p.Repository, &p.Branch, &p.Provider, &p.TargetStack, &p.TargetService,
		&p.Action, &p.TriggerType, &p.Schedule, &p.IsEnabled, &p.AutoRollback,
		&p.DeployCount, &p.LastDeployAt, &p.LastStatus, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ListPipelines returns all GitOps pipelines.
func (r *GitOpsRepository) ListPipelines(ctx context.Context) ([]*GitOpsPipeline, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, repository, branch, provider, target_stack, target_service,
			action, trigger_type, schedule, is_enabled, auto_rollback,
			deploy_count, last_deploy_at, last_status, created_by, created_at, updated_at
		FROM gitops_pipelines ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pipelines []*GitOpsPipeline
	for rows.Next() {
		p := &GitOpsPipeline{}
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Repository, &p.Branch, &p.Provider, &p.TargetStack, &p.TargetService,
			&p.Action, &p.TriggerType, &p.Schedule, &p.IsEnabled, &p.AutoRollback,
			&p.DeployCount, &p.LastDeployAt, &p.LastStatus, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		pipelines = append(pipelines, p)
	}
	return pipelines, nil
}

// DeletePipeline deletes a pipeline.
func (r *GitOpsRepository) DeletePipeline(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM gitops_pipelines WHERE id = $1`, id)
	return err
}

// TogglePipeline toggles a pipeline's enabled status.
func (r *GitOpsRepository) TogglePipeline(ctx context.Context, id uuid.UUID) (bool, error) {
	var newState bool
	err := r.db.QueryRow(ctx, `
		UPDATE gitops_pipelines SET is_enabled = NOT is_enabled WHERE id = $1
		RETURNING is_enabled`, id).Scan(&newState)
	return newState, err
}

// IncrementDeployCount increments the deploy count and updates last deploy status.
func (r *GitOpsRepository) IncrementDeployCount(ctx context.Context, id uuid.UUID, deployAt time.Time, status string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE gitops_pipelines SET deploy_count = deploy_count + 1, last_deploy_at=$2, last_status=$3 WHERE id=$1`,
		id, deployAt, status,
	)
	return err
}

// CreateDeployment records a deployment execution.
func (r *GitOpsRepository) CreateDeployment(ctx context.Context, d *GitOpsDeployment) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO gitops_deployments (id, pipeline_id, pipeline_name, repository, branch, commit_sha, commit_msg,
			action, status, duration_ms, started_at, finished_at, error_message, triggered_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		d.ID, d.PipelineID, d.PipelineName, d.Repository, d.Branch, d.CommitSHA, d.CommitMsg,
		d.Action, d.Status, d.DurationMs, d.StartedAt, d.FinishedAt, d.ErrorMessage, d.TriggeredBy,
	)
	return err
}

// ListDeployments returns recent deployments.
func (r *GitOpsRepository) ListDeployments(ctx context.Context, limit int) ([]*GitOpsDeployment, error) {
	query := `SELECT id, pipeline_id, pipeline_name, repository, branch, commit_sha, commit_msg,
		action, status, duration_ms, started_at, finished_at, error_message, triggered_by
		FROM gitops_deployments ORDER BY started_at DESC`
	var args []interface{}
	if limit > 0 {
		query += ` LIMIT $1`
		args = append(args, limit)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deployments []*GitOpsDeployment
	for rows.Next() {
		d := &GitOpsDeployment{}
		if err := rows.Scan(
			&d.ID, &d.PipelineID, &d.PipelineName, &d.Repository, &d.Branch, &d.CommitSHA, &d.CommitMsg,
			&d.Action, &d.Status, &d.DurationMs, &d.StartedAt, &d.FinishedAt, &d.ErrorMessage, &d.TriggeredBy,
		); err != nil {
			return nil, err
		}
		deployments = append(deployments, d)
	}
	return deployments, nil
}
