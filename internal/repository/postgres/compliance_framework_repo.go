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
)

// ComplianceFrameworkRepository handles CRUD for compliance frameworks,
// controls, assessments, and evidence records.
type ComplianceFrameworkRepository struct {
	db *DB
}

// NewComplianceFrameworkRepository creates a new ComplianceFrameworkRepository.
func NewComplianceFrameworkRepository(db *DB) *ComplianceFrameworkRepository {
	return &ComplianceFrameworkRepository{db: db}
}

// ---------------------------------------------------------------------------
// Frameworks
// ---------------------------------------------------------------------------

// CreateFramework inserts a new compliance framework.
func (r *ComplianceFrameworkRepository) CreateFramework(ctx context.Context, f *models.ComplianceFramework) error {
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	now := time.Now()
	if f.CreatedAt.IsZero() {
		f.CreatedAt = now
	}
	if f.UpdatedAt.IsZero() {
		f.UpdatedAt = now
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO compliance_frameworks (
			id, name, display_name, description, version,
			is_enabled, config, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		f.ID, f.Name, f.DisplayName, f.Description, f.Version,
		f.IsEnabled, f.Config, f.CreatedAt, f.UpdatedAt,
	)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("compliance framework")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create compliance framework")
	}
	return nil
}

// GetFramework retrieves a compliance framework by ID.
func (r *ComplianceFrameworkRepository) GetFramework(ctx context.Context, id uuid.UUID) (*models.ComplianceFramework, error) {
	f := &models.ComplianceFramework{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, display_name, description, version,
			is_enabled, config, created_at, updated_at
		FROM compliance_frameworks WHERE id = $1`, id).Scan(
		&f.ID, &f.Name, &f.DisplayName, &f.Description, &f.Version,
		&f.IsEnabled, &f.Config, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("compliance framework")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get compliance framework")
	}
	return f, nil
}

// GetFrameworkByName retrieves a compliance framework by its unique name.
func (r *ComplianceFrameworkRepository) GetFrameworkByName(ctx context.Context, name string) (*models.ComplianceFramework, error) {
	f := &models.ComplianceFramework{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, display_name, description, version,
			is_enabled, config, created_at, updated_at
		FROM compliance_frameworks WHERE name = $1`, name).Scan(
		&f.ID, &f.Name, &f.DisplayName, &f.Description, &f.Version,
		&f.IsEnabled, &f.Config, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("compliance framework")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get compliance framework by name")
	}
	return f, nil
}

// ListFrameworks returns all compliance frameworks ordered by name.
func (r *ComplianceFrameworkRepository) ListFrameworks(ctx context.Context) ([]*models.ComplianceFramework, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, display_name, description, version,
			is_enabled, config, created_at, updated_at
		FROM compliance_frameworks ORDER BY name ASC`)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list compliance frameworks")
	}
	defer rows.Close()

	var frameworks []*models.ComplianceFramework
	for rows.Next() {
		f := &models.ComplianceFramework{}
		if err := rows.Scan(
			&f.ID, &f.Name, &f.DisplayName, &f.Description, &f.Version,
			&f.IsEnabled, &f.Config, &f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan compliance framework")
		}
		frameworks = append(frameworks, f)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate compliance frameworks")
	}
	return frameworks, nil
}

// UpdateFramework updates an existing compliance framework.
func (r *ComplianceFrameworkRepository) UpdateFramework(ctx context.Context, f *models.ComplianceFramework) error {
	f.UpdatedAt = time.Now()

	result, err := r.db.Exec(ctx, `
		UPDATE compliance_frameworks SET
			name = $2, display_name = $3, description = $4, version = $5,
			is_enabled = $6, config = $7, updated_at = $8
		WHERE id = $1`,
		f.ID, f.Name, f.DisplayName, f.Description, f.Version,
		f.IsEnabled, f.Config, f.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update compliance framework")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("compliance framework")
	}
	return nil
}

// DeleteFramework removes a compliance framework by ID.
func (r *ComplianceFrameworkRepository) DeleteFramework(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, `DELETE FROM compliance_frameworks WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete compliance framework")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("compliance framework")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

// CreateControl inserts a new compliance control.
func (r *ComplianceFrameworkRepository) CreateControl(ctx context.Context, c *models.ComplianceControl) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	now := time.Now()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO compliance_controls (
			id, framework_id, control_id, title, description,
			category, severity, implementation_status, evidence_type,
			check_query, remediation, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		c.ID, c.FrameworkID, c.ControlID, c.Title, c.Description,
		c.Category, c.Severity, c.ImplementationStatus, c.EvidenceType,
		c.CheckQuery, c.Remediation, c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("compliance control")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create compliance control")
	}
	return nil
}

// ListControls returns all controls for a given framework, ordered by control_id.
func (r *ComplianceFrameworkRepository) ListControls(ctx context.Context, frameworkID uuid.UUID) ([]*models.ComplianceControl, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, framework_id, control_id, title, description,
			category, severity, implementation_status, evidence_type,
			check_query, remediation, created_at, updated_at
		FROM compliance_controls
		WHERE framework_id = $1
		ORDER BY control_id ASC`, frameworkID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list compliance controls")
	}
	defer rows.Close()

	var controls []*models.ComplianceControl
	for rows.Next() {
		c := &models.ComplianceControl{}
		if err := rows.Scan(
			&c.ID, &c.FrameworkID, &c.ControlID, &c.Title, &c.Description,
			&c.Category, &c.Severity, &c.ImplementationStatus, &c.EvidenceType,
			&c.CheckQuery, &c.Remediation, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan compliance control")
		}
		controls = append(controls, c)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate compliance controls")
	}
	return controls, nil
}

// UpdateControlStatus updates the implementation_status of a control.
func (r *ComplianceFrameworkRepository) UpdateControlStatus(ctx context.Context, controlID uuid.UUID, status string) error {
	result, err := r.db.Exec(ctx, `
		UPDATE compliance_controls SET implementation_status = $2, updated_at = $3
		WHERE id = $1`,
		controlID, status, time.Now(),
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update control status")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("compliance control")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Assessments
// ---------------------------------------------------------------------------

// CreateAssessment inserts a new compliance assessment.
func (r *ComplianceFrameworkRepository) CreateAssessment(ctx context.Context, a *models.ComplianceAssessment) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO compliance_assessments (
			id, framework_id, name, status, total_controls,
			passed_controls, failed_controls, na_controls, score,
			results, started_at, completed_at, created_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		a.ID, a.FrameworkID, a.Name, a.Status, a.TotalControls,
		a.PassedControls, a.FailedControls, a.NAControls, a.Score,
		a.Results, a.StartedAt, a.CompletedAt, a.CreatedBy, a.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create compliance assessment")
	}
	return nil
}

// GetAssessment retrieves a compliance assessment by ID.
func (r *ComplianceFrameworkRepository) GetAssessment(ctx context.Context, id uuid.UUID) (*models.ComplianceAssessment, error) {
	a := &models.ComplianceAssessment{}
	err := r.db.QueryRow(ctx, `
		SELECT id, framework_id, name, status, total_controls,
			passed_controls, failed_controls, na_controls, score,
			results, started_at, completed_at, created_by, created_at
		FROM compliance_assessments WHERE id = $1`, id).Scan(
		&a.ID, &a.FrameworkID, &a.Name, &a.Status, &a.TotalControls,
		&a.PassedControls, &a.FailedControls, &a.NAControls, &a.Score,
		&a.Results, &a.StartedAt, &a.CompletedAt, &a.CreatedBy, &a.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("compliance assessment")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get compliance assessment")
	}
	return a, nil
}

// ListAssessments returns all assessments for a framework, newest first.
func (r *ComplianceFrameworkRepository) ListAssessments(ctx context.Context, frameworkID uuid.UUID) ([]*models.ComplianceAssessment, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, framework_id, name, status, total_controls,
			passed_controls, failed_controls, na_controls, score,
			results, started_at, completed_at, created_by, created_at
		FROM compliance_assessments
		WHERE framework_id = $1
		ORDER BY created_at DESC`, frameworkID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list compliance assessments")
	}
	defer rows.Close()

	var assessments []*models.ComplianceAssessment
	for rows.Next() {
		a := &models.ComplianceAssessment{}
		if err := rows.Scan(
			&a.ID, &a.FrameworkID, &a.Name, &a.Status, &a.TotalControls,
			&a.PassedControls, &a.FailedControls, &a.NAControls, &a.Score,
			&a.Results, &a.StartedAt, &a.CompletedAt, &a.CreatedBy, &a.CreatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan compliance assessment")
		}
		assessments = append(assessments, a)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate compliance assessments")
	}
	return assessments, nil
}

// UpdateAssessment updates an existing compliance assessment.
func (r *ComplianceFrameworkRepository) UpdateAssessment(ctx context.Context, a *models.ComplianceAssessment) error {
	result, err := r.db.Exec(ctx, `
		UPDATE compliance_assessments SET
			status = $2, total_controls = $3, passed_controls = $4,
			failed_controls = $5, na_controls = $6, score = $7,
			results = $8, completed_at = $9
		WHERE id = $1`,
		a.ID, a.Status, a.TotalControls, a.PassedControls,
		a.FailedControls, a.NAControls, a.Score,
		a.Results, a.CompletedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update compliance assessment")
	}
	if result.RowsAffected() == 0 {
		return errors.NotFound("compliance assessment")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

// CreateEvidence inserts a new compliance evidence record.
func (r *ComplianceFrameworkRepository) CreateEvidence(ctx context.Context, e *models.ComplianceEvidence) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CollectedAt.IsZero() {
		e.CollectedAt = time.Now()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO compliance_evidence (
			id, assessment_id, control_id, evidence_type, title,
			description, data, file_path, status, collected_at,
			expires_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		e.ID, e.AssessmentID, e.ControlID, e.EvidenceType, e.Title,
		e.Description, e.Data, e.FilePath, e.Status, e.CollectedAt,
		e.ExpiresAt, e.CreatedBy,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create compliance evidence")
	}
	return nil
}

// ListEvidence returns all evidence records for a given assessment, ordered by
// collection time (newest first).
func (r *ComplianceFrameworkRepository) ListEvidence(ctx context.Context, assessmentID uuid.UUID) ([]*models.ComplianceEvidence, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, assessment_id, control_id, evidence_type, title,
			description, data, file_path, status, collected_at,
			expires_at, created_by
		FROM compliance_evidence
		WHERE assessment_id = $1
		ORDER BY collected_at DESC`, assessmentID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list compliance evidence")
	}
	defer rows.Close()

	var evidence []*models.ComplianceEvidence
	for rows.Next() {
		e := &models.ComplianceEvidence{}
		if err := rows.Scan(
			&e.ID, &e.AssessmentID, &e.ControlID, &e.EvidenceType, &e.Title,
			&e.Description, &e.Data, &e.FilePath, &e.Status, &e.CollectedAt,
			&e.ExpiresAt, &e.CreatedBy,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan compliance evidence")
		}
		evidence = append(evidence, e)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to iterate compliance evidence")
	}
	return evidence, nil
}
