// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	stderrors "errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// MarketplaceAppRepository
// ============================================================================

// MarketplaceAppRepository persists marketplace apps (catalog entries).
type MarketplaceAppRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewMarketplaceAppRepository creates a new marketplace app repository.
func NewMarketplaceAppRepository(db *DB, log *logger.Logger) *MarketplaceAppRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &MarketplaceAppRepository{
		db:     db,
		logger: log.Named("marketplace_apps_repo"),
	}
}

const marketplaceAppColumns = `id, slug, name, description, long_description,
	icon, icon_color, icon_svg, category, version, manifest_version,
	website, source, author, license, compose_template, fields, tags,
	min_memory_mb, min_cpu_cores, is_official, is_verified, featured, built_in,
	install_count, avg_rating, rating_count,
	created_by, created_at, updated_at`

func scanMarketplaceApp(row pgx.Row, app *models.MarketplaceApp) error {
	return row.Scan(
		&app.ID, &app.Slug, &app.Name, &app.Description, &app.LongDescription,
		&app.Icon, &app.IconColor, &app.IconSVG, &app.Category, &app.Version, &app.ManifestVersion,
		&app.Website, &app.Source, &app.Author, &app.License, &app.ComposeTemplate, &app.Fields, &app.Tags,
		&app.MinMemoryMB, &app.MinCPUCores, &app.IsOfficial, &app.IsVerified, &app.Featured, &app.BuiltIn,
		&app.InstallCount, &app.AvgRating, &app.RatingCount,
		&app.CreatedBy, &app.CreatedAt, &app.UpdatedAt,
	)
}

// Create inserts a new marketplace app.
func (r *MarketplaceAppRepository) Create(ctx context.Context, app *models.MarketplaceApp) error {
	if app.ID == uuid.Nil {
		app.ID = uuid.New()
	}
	now := time.Now()
	if app.CreatedAt.IsZero() {
		app.CreatedAt = now
	}
	app.UpdatedAt = now
	if app.ManifestVersion == 0 {
		app.ManifestVersion = 1
	}

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO marketplace_apps (
			id, slug, name, description, long_description,
			icon, icon_color, icon_svg, category, version, manifest_version,
			website, source, author, license, compose_template, fields, tags,
			min_memory_mb, min_cpu_cores, is_official, is_verified, featured, built_in,
			install_count, avg_rating, rating_count,
			created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)`,
		app.ID, app.Slug, app.Name, app.Description, app.LongDescription,
		app.Icon, app.IconColor, app.IconSVG, app.Category, app.Version, app.ManifestVersion,
		app.Website, app.Source, app.Author, app.License, app.ComposeTemplate, app.Fields, app.Tags,
		app.MinMemoryMB, app.MinCPUCores, app.IsOfficial, app.IsVerified, app.Featured, app.BuiltIn,
		app.InstallCount, app.AvgRating, app.RatingCount,
		app.CreatedBy, app.CreatedAt, app.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create marketplace app")
	}
	return nil
}

// GetByID returns a marketplace app by primary key.
func (r *MarketplaceAppRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.MarketplaceApp, error) {
	var app models.MarketplaceApp
	row := r.db.Pool().QueryRow(ctx, `SELECT `+marketplaceAppColumns+` FROM marketplace_apps WHERE id = $1`, id)
	if err := scanMarketplaceApp(row, &app); err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("marketplace_app")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get marketplace app")
	}
	return &app, nil
}

// GetBySlug returns a marketplace app by slug.
func (r *MarketplaceAppRepository) GetBySlug(ctx context.Context, slug string) (*models.MarketplaceApp, error) {
	var app models.MarketplaceApp
	row := r.db.Pool().QueryRow(ctx, `SELECT `+marketplaceAppColumns+` FROM marketplace_apps WHERE slug = $1`, slug)
	if err := scanMarketplaceApp(row, &app); err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("marketplace_app")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get marketplace app by slug")
	}
	return &app, nil
}

// Search returns paginated apps matching the query and optional category filter.
func (r *MarketplaceAppRepository) Search(ctx context.Context, query string, category string, limit, offset int) ([]*models.MarketplaceApp, int, error) {
	var total int
	args := []interface{}{}
	countSQL := `SELECT COUNT(*) FROM marketplace_apps WHERE 1=1`
	listSQL := `SELECT ` + marketplaceAppColumns + ` FROM marketplace_apps WHERE 1=1`

	paramIdx := 1
	if query != "" {
		filter := ` AND (name ILIKE $` + strconv.Itoa(paramIdx) + ` OR description ILIKE $` + strconv.Itoa(paramIdx) + `)`
		countSQL += filter
		listSQL += filter
		args = append(args, "%"+query+"%")
		paramIdx++
	}
	if category != "" {
		filter := ` AND category = $` + strconv.Itoa(paramIdx)
		countSQL += filter
		listSQL += filter
		args = append(args, category)
		paramIdx++
	}

	if err := r.db.Pool().QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "count marketplace apps search")
	}

	listSQL += ` ORDER BY install_count DESC, name ASC LIMIT $` + strconv.Itoa(paramIdx) + ` OFFSET $` + strconv.Itoa(paramIdx+1)
	args = append(args, limit, offset)

	rows, err := r.db.Pool().Query(ctx, listSQL, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "search marketplace apps")
	}
	defer rows.Close()

	var results []*models.MarketplaceApp
	for rows.Next() {
		var app models.MarketplaceApp
		if err := scanMarketplaceApp(rows, &app); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "scan marketplace app")
		}
		results = append(results, &app)
	}
	return results, total, nil
}

// ListFeatured returns featured apps ordered by popularity.
func (r *MarketplaceAppRepository) ListFeatured(ctx context.Context, limit int) ([]*models.MarketplaceApp, error) {
	rows, err := r.db.Pool().Query(ctx, `SELECT `+marketplaceAppColumns+`
		FROM marketplace_apps WHERE featured = true
		ORDER BY install_count DESC, name ASC LIMIT $1`, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list featured marketplace apps")
	}
	defer rows.Close()

	var results []*models.MarketplaceApp
	for rows.Next() {
		var app models.MarketplaceApp
		if err := scanMarketplaceApp(rows, &app); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan featured marketplace app")
		}
		results = append(results, &app)
	}
	return results, nil
}

// ListByCategory returns paginated apps in the given category.
func (r *MarketplaceAppRepository) ListByCategory(ctx context.Context, category string, limit, offset int) ([]*models.MarketplaceApp, int, error) {
	var total int
	if err := r.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM marketplace_apps WHERE category = $1`, category).Scan(&total); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "count marketplace apps by category")
	}

	rows, err := r.db.Pool().Query(ctx, `SELECT `+marketplaceAppColumns+`
		FROM marketplace_apps WHERE category = $1
		ORDER BY install_count DESC, name ASC LIMIT $2 OFFSET $3`, category, limit, offset)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "list marketplace apps by category")
	}
	defer rows.Close()

	var results []*models.MarketplaceApp
	for rows.Next() {
		var app models.MarketplaceApp
		if err := scanMarketplaceApp(rows, &app); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "scan marketplace app by category")
		}
		results = append(results, &app)
	}
	return results, total, nil
}

// Update updates a marketplace app row.
func (r *MarketplaceAppRepository) Update(ctx context.Context, app *models.MarketplaceApp) error {
	app.UpdatedAt = time.Now()
	if app.ManifestVersion == 0 {
		app.ManifestVersion = 1
	}
	_, err := r.db.Pool().Exec(ctx, `
		UPDATE marketplace_apps SET
			slug = $2, name = $3, description = $4, long_description = $5,
			icon = $6, icon_color = $7, icon_svg = $8, category = $9, version = $10, manifest_version = $11,
			website = $12, source = $13, author = $14, license = $15,
			compose_template = $16, fields = $17, tags = $18,
			min_memory_mb = $19, min_cpu_cores = $20,
			is_official = $21, is_verified = $22, featured = $23, built_in = $24,
			updated_at = $25
		WHERE id = $1`,
		app.ID, app.Slug, app.Name, app.Description, app.LongDescription,
		app.Icon, app.IconColor, app.IconSVG, app.Category, app.Version, app.ManifestVersion,
		app.Website, app.Source, app.Author, app.License,
		app.ComposeTemplate, app.Fields, app.Tags,
		app.MinMemoryMB, app.MinCPUCores,
		app.IsOfficial, app.IsVerified, app.Featured, app.BuiltIn,
		app.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update marketplace app")
	}
	return nil
}

// Delete removes a marketplace app.
func (r *MarketplaceAppRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx, `DELETE FROM marketplace_apps WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "delete marketplace app")
	}
	return nil
}

// IncrementInstallCount bumps the install counter atomically.
func (r *MarketplaceAppRepository) IncrementInstallCount(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx,
		`UPDATE marketplace_apps SET install_count = install_count + 1 WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "increment marketplace app install count")
	}
	return nil
}

// UpdateRating recomputes avg/count from reviews.
func (r *MarketplaceAppRepository) UpdateRating(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx, `
		UPDATE marketplace_apps SET
			avg_rating = COALESCE((SELECT AVG(rating)::FLOAT FROM marketplace_reviews WHERE app_id = $1), 0),
			rating_count = (SELECT COUNT(*) FROM marketplace_reviews WHERE app_id = $1)
		WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update marketplace app rating")
	}
	return nil
}

// ============================================================================
// MarketplaceInstallationRepository
// ============================================================================

// MarketplaceInstallationRepository persists installations.
type MarketplaceInstallationRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewMarketplaceInstallationRepository creates a new installations repository.
func NewMarketplaceInstallationRepository(db *DB, log *logger.Logger) *MarketplaceInstallationRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &MarketplaceInstallationRepository{
		db:     db,
		logger: log.Named("marketplace_installations_repo"),
	}
}

const marketplaceInstallationColumns = `id, app_id, host_id, stack_id, name,
	status, version, config_values, notes,
	installed_by, installed_at, updated_at`

func scanMarketplaceInstallation(row pgx.Row, inst *models.MarketplaceInstallation) error {
	return row.Scan(
		&inst.ID, &inst.AppID, &inst.HostID, &inst.StackID, &inst.Name,
		&inst.Status, &inst.Version, &inst.ConfigValues, &inst.Notes,
		&inst.InstalledBy, &inst.InstalledAt, &inst.UpdatedAt,
	)
}

// Create inserts a new installation row.
func (r *MarketplaceInstallationRepository) Create(ctx context.Context, inst *models.MarketplaceInstallation) error {
	if inst.ID == uuid.Nil {
		inst.ID = uuid.New()
	}
	now := time.Now()
	if inst.InstalledAt.IsZero() {
		inst.InstalledAt = now
	}
	inst.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO marketplace_installations (
			id, app_id, host_id, stack_id, name,
			status, version, config_values, notes,
			installed_by, installed_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		inst.ID, inst.AppID, inst.HostID, inst.StackID, inst.Name,
		inst.Status, inst.Version, inst.ConfigValues, inst.Notes,
		inst.InstalledBy, inst.InstalledAt, inst.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create marketplace installation")
	}
	return nil
}

// GetByID returns a single installation.
func (r *MarketplaceInstallationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.MarketplaceInstallation, error) {
	var inst models.MarketplaceInstallation
	row := r.db.Pool().QueryRow(ctx, `SELECT `+marketplaceInstallationColumns+`
		FROM marketplace_installations WHERE id = $1`, id)
	if err := scanMarketplaceInstallation(row, &inst); err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("marketplace_installation")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get marketplace installation")
	}
	return &inst, nil
}

// ListByHost returns paginated installations for a host.
func (r *MarketplaceInstallationRepository) ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.MarketplaceInstallation, int, error) {
	var total int
	if err := r.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM marketplace_installations WHERE host_id = $1`, hostID).Scan(&total); err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "count marketplace installations by host")
	}

	rows, err := r.db.Pool().Query(ctx, `SELECT `+marketplaceInstallationColumns+`
		FROM marketplace_installations WHERE host_id = $1
		ORDER BY installed_at DESC LIMIT $2 OFFSET $3`, hostID, limit, offset)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "list marketplace installations by host")
	}
	defer rows.Close()

	var results []*models.MarketplaceInstallation
	for rows.Next() {
		var inst models.MarketplaceInstallation
		if err := scanMarketplaceInstallation(rows, &inst); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "scan marketplace installation")
		}
		results = append(results, &inst)
	}
	return results, total, nil
}

// ListByApp returns all installations for an app.
func (r *MarketplaceInstallationRepository) ListByApp(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceInstallation, error) {
	rows, err := r.db.Pool().Query(ctx, `SELECT `+marketplaceInstallationColumns+`
		FROM marketplace_installations WHERE app_id = $1
		ORDER BY installed_at DESC`, appID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list marketplace installations by app")
	}
	defer rows.Close()

	var results []*models.MarketplaceInstallation
	for rows.Next() {
		var inst models.MarketplaceInstallation
		if err := scanMarketplaceInstallation(rows, &inst); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan marketplace installation by app")
		}
		results = append(results, &inst)
	}
	return results, nil
}

// Update updates an installation row.
func (r *MarketplaceInstallationRepository) Update(ctx context.Context, inst *models.MarketplaceInstallation) error {
	inst.UpdatedAt = time.Now()
	_, err := r.db.Pool().Exec(ctx, `
		UPDATE marketplace_installations SET
			stack_id = $2, name = $3, status = $4, version = $5,
			config_values = $6, notes = $7, updated_at = $8
		WHERE id = $1`,
		inst.ID, inst.StackID, inst.Name, inst.Status, inst.Version,
		inst.ConfigValues, inst.Notes, inst.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update marketplace installation")
	}
	return nil
}

// Delete removes an installation row.
func (r *MarketplaceInstallationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx, `DELETE FROM marketplace_installations WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "delete marketplace installation")
	}
	return nil
}

// ============================================================================
// MarketplaceReviewRepository
// ============================================================================

// MarketplaceReviewRepository persists reviews.
type MarketplaceReviewRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewMarketplaceReviewRepository creates a new reviews repository.
func NewMarketplaceReviewRepository(db *DB, log *logger.Logger) *MarketplaceReviewRepository {
	if log == nil {
		log = logger.Nop()
	}
	return &MarketplaceReviewRepository{
		db:     db,
		logger: log.Named("marketplace_reviews_repo"),
	}
}

// Upsert atomically inserts or updates a review using the unique
// (user_id, app_id) constraint declared in migration 056.
func (r *MarketplaceReviewRepository) Upsert(ctx context.Context, review *models.MarketplaceReview) error {
	if review.ID == uuid.Nil {
		review.ID = uuid.New()
	}
	now := time.Now()
	if review.CreatedAt.IsZero() {
		review.CreatedAt = now
	}
	review.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO marketplace_reviews (
			id, app_id, user_id, rating, title, comment, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT ON CONSTRAINT marketplace_reviews_user_app_unique
		DO UPDATE SET
			rating = EXCLUDED.rating,
			title = EXCLUDED.title,
			comment = EXCLUDED.comment,
			updated_at = EXCLUDED.updated_at`,
		review.ID, review.AppID, review.UserID, review.Rating, review.Title, review.Comment,
		review.CreatedAt, review.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "upsert marketplace review")
	}
	return nil
}

// ListByApp returns all reviews for an app, newest first.
func (r *MarketplaceReviewRepository) ListByApp(ctx context.Context, appID uuid.UUID) ([]*models.MarketplaceReview, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, app_id, user_id, rating, title, comment, created_at, updated_at
		FROM marketplace_reviews WHERE app_id = $1
		ORDER BY created_at DESC`, appID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list marketplace reviews by app")
	}
	defer rows.Close()

	var results []*models.MarketplaceReview
	for rows.Next() {
		var review models.MarketplaceReview
		if err := rows.Scan(
			&review.ID, &review.AppID, &review.UserID, &review.Rating, &review.Title, &review.Comment,
			&review.CreatedAt, &review.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan marketplace review")
		}
		results = append(results, &review)
	}
	return results, nil
}

// GetByUserAndApp returns the review (if any) by user + app.
func (r *MarketplaceReviewRepository) GetByUserAndApp(ctx context.Context, userID, appID uuid.UUID) (*models.MarketplaceReview, error) {
	var review models.MarketplaceReview
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, app_id, user_id, rating, title, comment, created_at, updated_at
		FROM marketplace_reviews WHERE user_id = $1 AND app_id = $2`, userID, appID,
	).Scan(
		&review.ID, &review.AppID, &review.UserID, &review.Rating, &review.Title, &review.Comment,
		&review.CreatedAt, &review.UpdatedAt,
	)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return nil, errors.NotFound("marketplace_review")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get marketplace review by user and app")
	}
	return &review, nil
}

// Delete removes a review.
func (r *MarketplaceReviewRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx, `DELETE FROM marketplace_reviews WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "delete marketplace review")
	}
	return nil
}
