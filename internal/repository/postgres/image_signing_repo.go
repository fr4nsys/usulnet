// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ImageSigningRepository handles CRUD for image signatures, attestations,
// and trust policies.
type ImageSigningRepository struct {
	db *DB
}

// NewImageSigningRepository creates a new ImageSigningRepository.
func NewImageSigningRepository(db *DB) *ImageSigningRepository {
	return &ImageSigningRepository{db: db}
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

// CreateSignature persists a new image signature record.
func (r *ImageSigningRepository) CreateSignature(ctx context.Context, sig *models.ImageSignature) error {
	if sig.ID == uuid.Nil {
		sig.ID = uuid.New()
	}
	if sig.CreatedAt.IsZero() {
		sig.CreatedAt = time.Now()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO image_signatures (
			id, image_ref, image_digest, signature_type, signature_data,
			certificate, signer_identity, issuer, transparency_log_id,
			verified, verified_at, verification_error, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		sig.ID, sig.ImageRef, sig.ImageDigest, sig.SignatureType, sig.SignatureData,
		sig.Certificate, sig.SignerIdentity, sig.Issuer, sig.TransparencyLogID,
		sig.Verified, sig.VerifiedAt, sig.VerificationError, sig.CreatedAt,
	)
	return err
}

// signatureColumns is the standard column list for image_signatures queries.
const signatureColumns = `id, image_ref, image_digest, signature_type, signature_data,
	certificate, signer_identity, issuer, transparency_log_id,
	verified, verified_at, verification_error, created_at`

// scanSignatureRows scans multiple rows into a slice of ImageSignature pointers.
func scanSignatureRows(rows pgx.Rows) ([]*models.ImageSignature, error) {
	defer rows.Close()

	var sigs []*models.ImageSignature
	for rows.Next() {
		var s models.ImageSignature
		if err := rows.Scan(
			&s.ID, &s.ImageRef, &s.ImageDigest, &s.SignatureType, &s.SignatureData,
			&s.Certificate, &s.SignerIdentity, &s.Issuer, &s.TransparencyLogID,
			&s.Verified, &s.VerifiedAt, &s.VerificationError, &s.CreatedAt,
		); err != nil {
			return nil, err
		}
		sigs = append(sigs, &s)
	}
	return sigs, rows.Err()
}

// GetSignaturesByDigest returns all signatures matching the given image digest.
func (r *ImageSigningRepository) GetSignaturesByDigest(ctx context.Context, digest string) ([]*models.ImageSignature, error) {
	rows, err := r.db.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM image_signatures WHERE image_digest = $1 ORDER BY created_at DESC`, signatureColumns),
		digest,
	)
	if err != nil {
		return nil, err
	}
	return scanSignatureRows(rows)
}

// GetSignaturesByRef returns all signatures matching the given image reference.
func (r *ImageSigningRepository) GetSignaturesByRef(ctx context.Context, imageRef string) ([]*models.ImageSignature, error) {
	rows, err := r.db.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM image_signatures WHERE image_ref = $1 ORDER BY created_at DESC`, signatureColumns),
		imageRef,
	)
	if err != nil {
		return nil, err
	}
	return scanSignatureRows(rows)
}

// UpdateVerification updates the verification status of a signature.
func (r *ImageSigningRepository) UpdateVerification(ctx context.Context, id uuid.UUID, verified bool, verifiedAt *time.Time, verificationError string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE image_signatures
		SET verified = $2, verified_at = $3, verification_error = $4
		WHERE id = $1`,
		id, verified, verifiedAt, verificationError,
	)
	return err
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

// CreateAttestation persists a new image attestation record.
func (r *ImageSigningRepository) CreateAttestation(ctx context.Context, att *models.ImageAttestation) error {
	if att.ID == uuid.Nil {
		att.ID = uuid.New()
	}
	if att.CreatedAt.IsZero() {
		att.CreatedAt = time.Now()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO image_attestations (
			id, image_ref, image_digest, predicate_type, predicate,
			signer_identity, verified, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		att.ID, att.ImageRef, att.ImageDigest, att.PredicateType, att.Predicate,
		att.SignerIdentity, att.Verified, att.CreatedAt,
	)
	return err
}

// attestationColumns is the standard column list for image_attestations queries.
const attestationColumns = `id, image_ref, image_digest, predicate_type, predicate,
	signer_identity, verified, created_at`

// GetAttestationsByDigest returns all attestations for the given image digest.
func (r *ImageSigningRepository) GetAttestationsByDigest(ctx context.Context, digest string) ([]*models.ImageAttestation, error) {
	rows, err := r.db.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM image_attestations WHERE image_digest = $1 ORDER BY created_at DESC`, attestationColumns),
		digest,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var atts []*models.ImageAttestation
	for rows.Next() {
		var a models.ImageAttestation
		if err := rows.Scan(
			&a.ID, &a.ImageRef, &a.ImageDigest, &a.PredicateType, &a.Predicate,
			&a.SignerIdentity, &a.Verified, &a.CreatedAt,
		); err != nil {
			return nil, err
		}
		atts = append(atts, &a)
	}
	return atts, rows.Err()
}

// ---------------------------------------------------------------------------
// Trust Policies
// ---------------------------------------------------------------------------

// trustPolicyColumns is the standard column list for image_trust_policies queries.
const trustPolicyColumns = `id, name, description, image_pattern, require_signature,
	require_attestation, allowed_signers, allowed_issuers,
	is_enabled, is_enforcing, created_at, updated_at`

// scanTrustPolicyRow scans a single row into an ImageTrustPolicy.
func scanTrustPolicyRow(row pgx.Row) (*models.ImageTrustPolicy, error) {
	var p models.ImageTrustPolicy
	err := row.Scan(
		&p.ID, &p.Name, &p.Description, &p.ImagePattern, &p.RequireSignature,
		&p.RequireAttestation, &p.AllowedSigners, &p.AllowedIssuers,
		&p.IsEnabled, &p.IsEnforcing, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// scanTrustPolicyRows scans multiple rows into a slice of ImageTrustPolicy pointers.
func scanTrustPolicyRows(rows pgx.Rows) ([]*models.ImageTrustPolicy, error) {
	defer rows.Close()

	var policies []*models.ImageTrustPolicy
	for rows.Next() {
		var p models.ImageTrustPolicy
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.ImagePattern, &p.RequireSignature,
			&p.RequireAttestation, &p.AllowedSigners, &p.AllowedIssuers,
			&p.IsEnabled, &p.IsEnforcing, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		policies = append(policies, &p)
	}
	return policies, rows.Err()
}

// CreateTrustPolicy persists a new image trust policy.
func (r *ImageSigningRepository) CreateTrustPolicy(ctx context.Context, p *models.ImageTrustPolicy) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = now
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO image_trust_policies (
			id, name, description, image_pattern, require_signature,
			require_attestation, allowed_signers, allowed_issuers,
			is_enabled, is_enforcing, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		p.ID, p.Name, p.Description, p.ImagePattern, p.RequireSignature,
		p.RequireAttestation, p.AllowedSigners, p.AllowedIssuers,
		p.IsEnabled, p.IsEnforcing, p.CreatedAt, p.UpdatedAt,
	)
	return err
}

// GetTrustPolicy retrieves a trust policy by ID.
func (r *ImageSigningRepository) GetTrustPolicy(ctx context.Context, id uuid.UUID) (*models.ImageTrustPolicy, error) {
	row := r.db.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM image_trust_policies WHERE id = $1`, trustPolicyColumns),
		id,
	)
	return scanTrustPolicyRow(row)
}

// ListTrustPolicies returns all trust policies ordered by name.
func (r *ImageSigningRepository) ListTrustPolicies(ctx context.Context) ([]*models.ImageTrustPolicy, error) {
	rows, err := r.db.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM image_trust_policies ORDER BY name ASC`, trustPolicyColumns),
	)
	if err != nil {
		return nil, err
	}
	return scanTrustPolicyRows(rows)
}

// UpdateTrustPolicy updates an existing trust policy.
func (r *ImageSigningRepository) UpdateTrustPolicy(ctx context.Context, p *models.ImageTrustPolicy) error {
	p.UpdatedAt = time.Now()

	_, err := r.db.Exec(ctx, `
		UPDATE image_trust_policies SET
			name = $2, description = $3, image_pattern = $4,
			require_signature = $5, require_attestation = $6,
			allowed_signers = $7, allowed_issuers = $8,
			is_enabled = $9, is_enforcing = $10, updated_at = $11
		WHERE id = $1`,
		p.ID, p.Name, p.Description, p.ImagePattern,
		p.RequireSignature, p.RequireAttestation,
		p.AllowedSigners, p.AllowedIssuers,
		p.IsEnabled, p.IsEnforcing, p.UpdatedAt,
	)
	return err
}

// DeleteTrustPolicy removes a trust policy by ID.
func (r *ImageSigningRepository) DeleteTrustPolicy(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM image_trust_policies WHERE id = $1`, id)
	return err
}

// GetMatchingPolicies returns all enabled trust policies whose image_pattern
// matches the given imageRef. The image_pattern column uses SQL LIKE syntax
// where '%' matches any sequence of characters and '_' matches a single
// character. Glob-style '*' and '?' are translated before the query.
func (r *ImageSigningRepository) GetMatchingPolicies(ctx context.Context, imageRef string) ([]*models.ImageTrustPolicy, error) {
	rows, err := r.db.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM image_trust_policies
			WHERE is_enabled = true
			  AND $1 LIKE replace(replace(image_pattern, '*', '%%'), '?', '_')
			ORDER BY name ASC`, trustPolicyColumns),
		imageRef,
	)
	if err != nil {
		return nil, err
	}
	return scanTrustPolicyRows(rows)
}
