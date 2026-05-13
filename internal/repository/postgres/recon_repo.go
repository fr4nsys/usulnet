// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// gcmNonceSize is the standard nonce size for AES-256-GCM. It must match the
// nonce produced by internal/pkg/crypto.AESEncryptor.
const gcmNonceSize = 12

// ReconRepository implements recon.Repository against PostgreSQL.
//
// The repository is purely persistence: it does not call any service-layer
// code and does not implement business rules (ownership gating, profile
// resolution, retention) — those live in the service layer.
//
// Raw engine payloads (recon_findings_raw.payload_encrypted) are encrypted
// at rest using the installation-wide data encryption key supplied at
// construction time. The DEK never appears in logs or query traces.
type ReconRepository struct {
	db        *DB
	encryptor *crypto.AESEncryptor
}

// NewReconRepository constructs a ReconRepository. The encryptor must be
// non-nil and is used to seal/open raw finding payloads written to
// recon_findings_raw. The caller owns the encryptor's lifetime.
func NewReconRepository(db *DB, encryptor *crypto.AESEncryptor) *ReconRepository {
	return &ReconRepository{db: db, encryptor: encryptor}
}

// ============================================================================
// Targets
// ============================================================================

// InsertTarget inserts a new target. On return, t.ID, t.CreatedAt and
// t.UpdatedAt are populated with the server-assigned values.
func (r *ReconRepository) InsertTarget(ctx context.Context, t *recon.Target) error {
	const query = `
		INSERT INTO recon_targets (type, value, value_hash, label, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at`

	var label any
	if t.Label != "" {
		label = t.Label
	}

	err := r.db.QueryRow(ctx, query,
		string(t.Type), t.Value, t.ValueHash, label, t.CreatedBy,
	).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return fmt.Errorf("recon repo: insert target: %w", err)
	}
	return nil
}

// GetTargetByID returns a target by primary key, or pgx.ErrNoRows when
// no row matches.
func (r *ReconRepository) GetTargetByID(ctx context.Context, id uuid.UUID) (*recon.Target, error) {
	const query = `
		SELECT id, type, value, value_hash, COALESCE(label, ''), created_by,
		       created_at, updated_at
		FROM recon_targets WHERE id = $1`
	t, err := r.scanTarget(r.db.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("recon repo: get target by id: %w", err)
	}
	return t, nil
}

// GetTargetByHash returns the target with the given type and value_hash, or
// pgx.ErrNoRows when no row matches.
func (r *ReconRepository) GetTargetByHash(ctx context.Context, typ recon.TargetType, hash []byte) (*recon.Target, error) {
	const query = `
		SELECT id, type, value, value_hash, COALESCE(label, ''), created_by,
		       created_at, updated_at
		FROM recon_targets WHERE type = $1 AND value_hash = $2`
	t, err := r.scanTarget(r.db.QueryRow(ctx, query, string(typ), hash))
	if err != nil {
		return nil, fmt.Errorf("recon repo: get target by hash: %w", err)
	}
	return t, nil
}

// ListTargets returns targets matching filter, ordered by creation time
// descending. A zero Limit applies a default of 50.
func (r *ReconRepository) ListTargets(ctx context.Context, filter recon.ListTargetsFilter) ([]recon.Target, error) {
	var (
		conds []string
		args  []any
	)
	if filter.Type != nil {
		conds = append(conds, fmt.Sprintf("type = $%d", len(args)+1))
		args = append(args, string(*filter.Type))
	}
	if filter.CreatedBy != nil {
		conds = append(conds, fmt.Sprintf("created_by = $%d", len(args)+1))
		args = append(args, *filter.CreatedBy)
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	limit, offset := paginate(filter.Limit, filter.Offset, 50)
	args = append(args, limit, offset)

	query := fmt.Sprintf(`
		SELECT id, type, value, value_hash, COALESCE(label, ''), created_by,
		       created_at, updated_at
		FROM recon_targets
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, len(args)-1, len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("recon repo: list targets: %w", err)
	}
	defer rows.Close()

	var out []recon.Target
	for rows.Next() {
		t, err := r.scanTarget(rows)
		if err != nil {
			return nil, fmt.Errorf("recon repo: list targets: %w", err)
		}
		out = append(out, *t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recon repo: list targets: %w", err)
	}
	return out, nil
}

// DeleteTarget removes a target. Cascade rules in migration 044 take care of
// scans, findings, raw payloads, and ownership proofs. Audit log rows are
// preserved (target_id is set to NULL).
func (r *ReconRepository) DeleteTarget(ctx context.Context, id uuid.UUID) error {
	const query = `DELETE FROM recon_targets WHERE id = $1`
	if _, err := r.db.Exec(ctx, query, id); err != nil {
		return fmt.Errorf("recon repo: delete target: %w", err)
	}
	return nil
}

func (r *ReconRepository) scanTarget(row pgx.Row) (*recon.Target, error) {
	var (
		t      recon.Target
		typStr string
	)
	if err := row.Scan(
		&t.ID, &typStr, &t.Value, &t.ValueHash, &t.Label, &t.CreatedBy,
		&t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, err
	}
	t.Type = recon.TargetType(typStr)
	return &t, nil
}

// ============================================================================
// Ownership proofs
// ============================================================================

// InsertOwnershipProof persists a new ownership proof.
func (r *ReconRepository) InsertOwnershipProof(ctx context.Context, p *recon.OwnershipProof) error {
	const query = `
		INSERT INTO recon_ownership_proofs
			(target_id, method, status, challenge, evidence, verified_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`

	evidence, err := encodeJSONObject(p.Evidence)
	if err != nil {
		return fmt.Errorf("recon repo: insert ownership proof: %w", err)
	}

	var challenge any
	if p.Challenge != "" {
		challenge = p.Challenge
	}

	err = r.db.QueryRow(ctx, query,
		p.TargetID, string(p.Method), string(p.Status), challenge,
		evidence, p.VerifiedAt,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("recon repo: insert ownership proof: %w", err)
	}
	return nil
}

// UpdateOwnershipProof updates the mutable fields of an existing proof. The
// updated_at column is refreshed by the trigger-less UPDATE statement
// (we set it explicitly because migration 044 does not install a trigger).
func (r *ReconRepository) UpdateOwnershipProof(ctx context.Context, p *recon.OwnershipProof) error {
	const query = `
		UPDATE recon_ownership_proofs
		SET status = $2,
		    challenge = $3,
		    evidence = $4,
		    verified_at = $5,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at`

	evidence, err := encodeJSONObject(p.Evidence)
	if err != nil {
		return fmt.Errorf("recon repo: update ownership proof: %w", err)
	}

	var challenge any
	if p.Challenge != "" {
		challenge = p.Challenge
	}

	err = r.db.QueryRow(ctx, query,
		p.ID, string(p.Status), challenge, evidence, p.VerifiedAt,
	).Scan(&p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("recon repo: update ownership proof: %w", err)
	}
	return nil
}

// GetOwnershipProofByID returns one proof by primary key, or
// pgx.ErrNoRows when no row exists.
func (r *ReconRepository) GetOwnershipProofByID(ctx context.Context, id uuid.UUID) (*recon.OwnershipProof, error) {
	const query = `
		SELECT id, target_id, method, status, COALESCE(challenge, ''),
		       evidence, verified_at, created_at, updated_at
		FROM recon_ownership_proofs
		WHERE id = $1`
	p, err := r.scanOwnershipProof(r.db.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("recon repo: get ownership proof by id: %w", err)
	}
	return p, nil
}

// LatestVerifiedOwnership returns the most recent verified proof for the
// target, or pgx.ErrNoRows when no verified proof exists.
func (r *ReconRepository) LatestVerifiedOwnership(ctx context.Context, targetID uuid.UUID) (*recon.OwnershipProof, error) {
	const query = `
		SELECT id, target_id, method, status, COALESCE(challenge, ''),
		       evidence, verified_at, created_at, updated_at
		FROM recon_ownership_proofs
		WHERE target_id = $1 AND status = 'verified'
		ORDER BY COALESCE(verified_at, created_at) DESC
		LIMIT 1`
	p, err := r.scanOwnershipProof(r.db.QueryRow(ctx, query, targetID))
	if err != nil {
		return nil, fmt.Errorf("recon repo: latest verified ownership: %w", err)
	}
	return p, nil
}

func (r *ReconRepository) scanOwnershipProof(row pgx.Row) (*recon.OwnershipProof, error) {
	var (
		p         recon.OwnershipProof
		methodStr string
		statusStr string
		evidence  []byte
	)
	if err := row.Scan(
		&p.ID, &p.TargetID, &methodStr, &statusStr, &p.Challenge,
		&evidence, &p.VerifiedAt, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	p.Method = recon.OwnershipMethod(methodStr)
	p.Status = recon.OwnershipStatus(statusStr)
	if len(evidence) > 0 {
		if err := json.Unmarshal(evidence, &p.Evidence); err != nil {
			return nil, fmt.Errorf("decode evidence: %w", err)
		}
	}
	return &p, nil
}

// ============================================================================
// Profiles
// ============================================================================

// GetProfileByID returns a profile by primary key.
func (r *ReconRepository) GetProfileByID(ctx context.Context, id uuid.UUID) (*recon.Profile, error) {
	p, err := r.scanProfile(r.db.QueryRow(ctx, profileSelect+` WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("recon repo: get profile by id: %w", err)
	}
	return p, nil
}

// GetProfileByName returns a profile by its unique name.
func (r *ReconRepository) GetProfileByName(ctx context.Context, name string) (*recon.Profile, error) {
	p, err := r.scanProfile(r.db.QueryRow(ctx, profileSelect+` WHERE name = $1`, name))
	if err != nil {
		return nil, fmt.Errorf("recon repo: get profile by name: %w", err)
	}
	return p, nil
}

// ListProfiles returns every profile, ordered by name.
func (r *ReconRepository) ListProfiles(ctx context.Context) ([]recon.Profile, error) {
	rows, err := r.db.Query(ctx, profileSelect+` ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("recon repo: list profiles: %w", err)
	}
	defer rows.Close()

	var out []recon.Profile
	for rows.Next() {
		p, err := r.scanProfile(rows)
		if err != nil {
			return nil, fmt.Errorf("recon repo: list profiles: %w", err)
		}
		out = append(out, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recon repo: list profiles: %w", err)
	}
	return out, nil
}

// InsertProfile persists a new user-defined profile. On return, p.ID,
// p.CreatedAt and p.UpdatedAt are populated by the server. The Kind
// column is set to 'custom' unconditionally — the service layer is the
// only place that picks the kind, and migration 044's CHECK constraint
// would reject anything else outside the {'builtin','custom'} set.
//
// A 23505 unique_violation on (name) surfaces as recon.ErrProfileExists
// so the handler can map to 409 without parsing pg error strings.
func (r *ReconRepository) InsertProfile(ctx context.Context, p *recon.Profile) error {
	modules, err := marshalJSONString(p.Modules, "[]")
	if err != nil {
		return fmt.Errorf("recon repo: insert profile: %w", err)
	}
	options, err := encodeJSONObject(p.Options)
	if err != nil {
		return fmt.Errorf("recon repo: insert profile: %w", err)
	}

	targetTypes := make([]string, len(p.TargetTypes))
	for i, t := range p.TargetTypes {
		targetTypes[i] = string(t)
	}

	var description any
	if p.Description != "" {
		description = p.Description
	}

	const query = `
		INSERT INTO recon_profiles
			(name, description, kind, target_types, modules, options, created_by)
		VALUES ($1, $2, 'custom', $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`
	err = r.db.QueryRow(ctx, query,
		p.Name, description, targetTypes, modules, options, p.CreatedBy,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return recon.ErrProfileExists
		}
		return fmt.Errorf("recon repo: insert profile: %w", err)
	}
	p.Kind = "custom"
	return nil
}

// UpdateProfile mutates a user-defined profile. The repository refuses
// to update a row whose kind is 'builtin' — a WHERE kind = 'custom'
// clause is included so the UPDATE silently affects zero rows for
// builtin targets; the caller distinguishes the two cases by reading
// the existing row first (service layer does exactly that).
//
// A 23505 unique_violation on (name) surfaces as
// recon.ErrProfileExists; pgx.ErrNoRows from the RETURNING clause is
// returned unchanged so the caller can disambiguate "row doesn't
// exist" from "row exists but is builtin".
func (r *ReconRepository) UpdateProfile(ctx context.Context, p *recon.Profile) error {
	modules, err := marshalJSONString(p.Modules, "[]")
	if err != nil {
		return fmt.Errorf("recon repo: update profile: %w", err)
	}
	options, err := encodeJSONObject(p.Options)
	if err != nil {
		return fmt.Errorf("recon repo: update profile: %w", err)
	}

	targetTypes := make([]string, len(p.TargetTypes))
	for i, t := range p.TargetTypes {
		targetTypes[i] = string(t)
	}

	var description any
	if p.Description != "" {
		description = p.Description
	}

	const query = `
		UPDATE recon_profiles
		SET name = $2,
		    description = $3,
		    target_types = $4,
		    modules = $5,
		    options = $6,
		    updated_at = NOW()
		WHERE id = $1 AND kind = 'custom'
		RETURNING updated_at`
	err = r.db.QueryRow(ctx, query,
		p.ID, p.Name, description, targetTypes, modules, options,
	).Scan(&p.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return recon.ErrProfileExists
		}
		return fmt.Errorf("recon repo: update profile: %w", err)
	}
	return nil
}

// DeleteProfile removes a profile row. The repository refuses to
// delete a builtin row by adding `WHERE kind = 'custom'`; the caller
// reads the row first to distinguish "not found" from "builtin". The
// FK recon_scans.profile_id is ON DELETE RESTRICT, so any scan that
// references the profile blocks the delete and surfaces as
// recon.ErrProfileInUse.
func (r *ReconRepository) DeleteProfile(ctx context.Context, id uuid.UUID) error {
	const query = `DELETE FROM recon_profiles WHERE id = $1 AND kind = 'custom'`
	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return recon.ErrProfileInUse
		}
		return fmt.Errorf("recon repo: delete profile: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Distinguishing "not found" vs "builtin" is the service
		// layer's job; the repo returns pgx.ErrNoRows so the service
		// can re-query and decide.
		return pgx.ErrNoRows
	}
	return nil
}

const profileSelect = `
	SELECT id, name, COALESCE(description, ''), kind, target_types,
	       modules, options, created_by, created_at, updated_at
	FROM recon_profiles`

func (r *ReconRepository) scanProfile(row pgx.Row) (*recon.Profile, error) {
	var (
		p           recon.Profile
		targetTypes []string
		modules     []byte
		options     []byte
	)
	if err := row.Scan(
		&p.ID, &p.Name, &p.Description, &p.Kind, &targetTypes,
		&modules, &options, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	p.TargetTypes = make([]recon.TargetType, len(targetTypes))
	for i, t := range targetTypes {
		p.TargetTypes[i] = recon.TargetType(t)
	}
	if len(modules) > 0 {
		if err := json.Unmarshal(modules, &p.Modules); err != nil {
			return nil, fmt.Errorf("decode modules: %w", err)
		}
	}
	if len(options) > 0 {
		if err := json.Unmarshal(options, &p.Options); err != nil {
			return nil, fmt.Errorf("decode options: %w", err)
		}
	}
	return &p, nil
}

// ============================================================================
// Scans
// ============================================================================

// InsertScan persists a new scan.
func (r *ReconRepository) InsertScan(ctx context.Context, s *recon.Scan) error {
	const query = `
		INSERT INTO recon_scans
			(target_id, profile_id, status, engine, engine_run_id, error,
			 started_at, finished_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at`

	engine := s.Engine
	if engine == "" {
		engine = "spiderfoot"
	}
	status := s.Status
	if status == "" {
		status = recon.ScanQueued
	}

	err := r.db.QueryRow(ctx, query,
		s.TargetID, s.ProfileID, string(status), engine, nullableString(s.EngineRunID),
		nullableString(s.Error), s.StartedAt, s.FinishedAt, s.CreatedBy,
	).Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return fmt.Errorf("recon repo: insert scan: %w", err)
	}
	s.Status = status
	s.Engine = engine
	return nil
}

// UpdateScan updates the mutable fields of a scan.
func (r *ReconRepository) UpdateScan(ctx context.Context, s *recon.Scan) error {
	const query = `
		UPDATE recon_scans
		SET status = $2,
		    engine_run_id = $3,
		    error = $4,
		    started_at = $5,
		    finished_at = $6,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at`
	err := r.db.QueryRow(ctx, query,
		s.ID, string(s.Status), nullableString(s.EngineRunID), nullableString(s.Error),
		s.StartedAt, s.FinishedAt,
	).Scan(&s.UpdatedAt)
	if err != nil {
		return fmt.Errorf("recon repo: update scan: %w", err)
	}
	return nil
}

// GetScanByID returns a scan by primary key.
func (r *ReconRepository) GetScanByID(ctx context.Context, id uuid.UUID) (*recon.Scan, error) {
	s, err := r.scanScan(r.db.QueryRow(ctx, scanSelect+` WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("recon repo: get scan by id: %w", err)
	}
	return s, nil
}

// ListScans returns scans matching filter, ordered by creation time
// descending.
func (r *ReconRepository) ListScans(ctx context.Context, filter recon.ListScansFilter) ([]recon.Scan, error) {
	var (
		conds []string
		args  []any
	)
	if filter.TargetID != nil {
		conds = append(conds, fmt.Sprintf("target_id = $%d", len(args)+1))
		args = append(args, *filter.TargetID)
	}
	if filter.Status != nil {
		conds = append(conds, fmt.Sprintf("status = $%d", len(args)+1))
		args = append(args, string(*filter.Status))
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	limit, offset := paginate(filter.Limit, filter.Offset, 50)
	args = append(args, limit, offset)

	query := fmt.Sprintf("%s %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		scanSelect, where, len(args)-1, len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("recon repo: list scans: %w", err)
	}
	defer rows.Close()

	var out []recon.Scan
	for rows.Next() {
		s, err := r.scanScan(rows)
		if err != nil {
			return nil, fmt.Errorf("recon repo: list scans: %w", err)
		}
		out = append(out, *s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recon repo: list scans: %w", err)
	}
	return out, nil
}

const scanSelect = `
	SELECT id, target_id, profile_id, status, engine, COALESCE(engine_run_id, ''),
	       COALESCE(error, ''), started_at, finished_at, created_by,
	       created_at, updated_at
	FROM recon_scans`

func (r *ReconRepository) scanScan(row pgx.Row) (*recon.Scan, error) {
	var (
		s         recon.Scan
		statusStr string
	)
	if err := row.Scan(
		&s.ID, &s.TargetID, &s.ProfileID, &statusStr, &s.Engine, &s.EngineRunID,
		&s.Error, &s.StartedAt, &s.FinishedAt, &s.CreatedBy,
		&s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, err
	}
	s.Status = recon.ScanStatus(statusStr)
	return &s, nil
}

// ============================================================================
// Findings (with raw payload encryption)
// ============================================================================

// UpsertFinding inserts a finding row and its encrypted raw payload. On
// conflict (scan_id, module, value_hash) the existing finding's last_seen
// timestamp is refreshed and the raw payload is replaced with the new one.
//
// rawPayload is the plaintext bytes produced by the engine; the repository
// encrypts them using the AES-256-GCM helper before they ever hit the
// database. rawEngine is stored alongside the ciphertext so callers can
// route decryption when multiple engines are wired.
func (r *ReconRepository) UpsertFinding(ctx context.Context, f *recon.Finding, rawEngine string, rawPayload []byte) error {
	if r.encryptor == nil {
		return fmt.Errorf("recon repo: upsert finding: %w", errors.New("encryptor not configured"))
	}

	nonce, ciphertext, err := r.sealPayload(rawPayload)
	if err != nil {
		return fmt.Errorf("recon repo: upsert finding: %w", err)
	}

	return r.db.WithTx(ctx, func(tx pgx.Tx) error {
		const insertFinding = `
			INSERT INTO recon_findings
				(scan_id, target_id, module, category, severity, value,
				 value_hash, source, confidence, first_seen, last_seen)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
			ON CONFLICT (scan_id, module, value_hash) DO UPDATE SET
				last_seen = NOW(),
				severity   = EXCLUDED.severity,
				value      = EXCLUDED.value,
				source     = EXCLUDED.source,
				confidence = EXCLUDED.confidence,
				category   = EXCLUDED.category
			RETURNING id, first_seen, last_seen`

		severity := f.Severity
		if severity == "" {
			severity = recon.SeverityInfo
		}
		if err := tx.QueryRow(ctx, insertFinding,
			f.ScanID, f.TargetID, f.Module, f.Category, string(severity),
			f.Value, f.ValueHash, nullableString(f.Source), f.Confidence,
		).Scan(&f.ID, &f.FirstSeen, &f.LastSeen); err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
		f.Severity = severity

		const upsertRaw = `
			INSERT INTO recon_findings_raw (finding_id, engine, payload_encrypted, nonce)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (finding_id) DO UPDATE SET
				engine            = EXCLUDED.engine,
				payload_encrypted = EXCLUDED.payload_encrypted,
				nonce             = EXCLUDED.nonce,
				created_at        = NOW()`
		if _, err := tx.Exec(ctx, upsertRaw, f.ID, rawEngine, ciphertext, nonce); err != nil {
			return fmt.Errorf("upsert raw payload: %w", err)
		}
		return nil
	})
}

// ListFindings returns findings matching filter, ordered by last_seen
// descending. A zero Limit applies a default of 200.
func (r *ReconRepository) ListFindings(ctx context.Context, filter recon.ListFindingsFilter) ([]recon.Finding, error) {
	var (
		conds []string
		args  []any
	)
	if filter.ScanID != nil {
		conds = append(conds, fmt.Sprintf("scan_id = $%d", len(args)+1))
		args = append(args, *filter.ScanID)
	}
	if filter.TargetID != nil {
		conds = append(conds, fmt.Sprintf("target_id = $%d", len(args)+1))
		args = append(args, *filter.TargetID)
	}
	if filter.Severity != nil {
		conds = append(conds, fmt.Sprintf("severity = $%d", len(args)+1))
		args = append(args, string(*filter.Severity))
	}
	if filter.Module != "" {
		conds = append(conds, fmt.Sprintf("module = $%d", len(args)+1))
		args = append(args, filter.Module)
	}
	if filter.Category != "" {
		conds = append(conds, fmt.Sprintf("category = $%d", len(args)+1))
		args = append(args, filter.Category)
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	limit, offset := paginate(filter.Limit, filter.Offset, 200)
	args = append(args, limit, offset)

	query := fmt.Sprintf(`
		SELECT id, scan_id, target_id, module, category, severity, value,
		       value_hash, COALESCE(source, ''), confidence, first_seen, last_seen
		FROM recon_findings
		%s
		ORDER BY last_seen DESC
		LIMIT $%d OFFSET $%d`, where, len(args)-1, len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("recon repo: list findings: %w", err)
	}
	defer rows.Close()

	var out []recon.Finding
	for rows.Next() {
		var (
			f      recon.Finding
			sevStr string
		)
		if err := rows.Scan(
			&f.ID, &f.ScanID, &f.TargetID, &f.Module, &f.Category, &sevStr,
			&f.Value, &f.ValueHash, &f.Source, &f.Confidence,
			&f.FirstSeen, &f.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("recon repo: list findings: %w", err)
		}
		f.Severity = recon.Severity(sevStr)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recon repo: list findings: %w", err)
	}
	return out, nil
}

// GetFindingRawPayload returns the decrypted raw payload bytes for a
// finding, alongside the engine name that produced it. Use sparingly:
// payloads can be large and contain sensitive data.
func (r *ReconRepository) GetFindingRawPayload(ctx context.Context, findingID uuid.UUID) (engine string, payload []byte, err error) {
	if r.encryptor == nil {
		return "", nil, fmt.Errorf("recon repo: get finding raw payload: %w", errors.New("encryptor not configured"))
	}

	const query = `
		SELECT engine, payload_encrypted, nonce
		FROM recon_findings_raw WHERE finding_id = $1`
	var (
		eng        string
		ciphertext []byte
		nonce      []byte
	)
	if err := r.db.QueryRow(ctx, query, findingID).Scan(&eng, &ciphertext, &nonce); err != nil {
		return "", nil, fmt.Errorf("recon repo: get finding raw payload: %w", err)
	}

	plaintext, err := r.openPayload(nonce, ciphertext)
	if err != nil {
		return "", nil, fmt.Errorf("recon repo: get finding raw payload: %w", err)
	}
	return eng, plaintext, nil
}

// sealPayload encrypts plaintext via the AES-256-GCM helper and splits the
// resulting blob into a separately-stored nonce and ciphertext, matching the
// recon_findings_raw schema. plaintext may be nil or empty; an empty input
// still produces an authenticated ciphertext.
func (r *ReconRepository) sealPayload(plaintext []byte) (nonce, ciphertext []byte, err error) {
	encoded, err := r.encryptor.Encrypt(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("decode encryptor output: %w", err)
	}
	if len(raw) < gcmNonceSize {
		return nil, nil, fmt.Errorf("encrypt: produced %d bytes, want >= %d", len(raw), gcmNonceSize)
	}
	nonce = make([]byte, gcmNonceSize)
	copy(nonce, raw[:gcmNonceSize])
	ciphertext = make([]byte, len(raw)-gcmNonceSize)
	copy(ciphertext, raw[gcmNonceSize:])
	return nonce, ciphertext, nil
}

// openPayload is the inverse of sealPayload.
func (r *ReconRepository) openPayload(nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != gcmNonceSize {
		return nil, fmt.Errorf("invalid nonce length: %d", len(nonce))
	}
	combined := make([]byte, 0, len(nonce)+len(ciphertext))
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)
	return r.encryptor.Decrypt(base64.StdEncoding.EncodeToString(combined))
}

// ============================================================================
// Scan summary
// ============================================================================

// UpsertScanSummary writes or replaces the summary row for a scan.
func (r *ReconRepository) UpsertScanSummary(ctx context.Context, s *recon.ScanSummary) error {
	counts, err := marshalJSONString(s.Counts, "{}")
	if err != nil {
		return fmt.Errorf("recon repo: upsert scan summary: %w", err)
	}
	corr, err := marshalJSONString(s.Correlations, "[]")
	if err != nil {
		return fmt.Errorf("recon repo: upsert scan summary: %w", err)
	}

	const query = `
		INSERT INTO recon_scan_summary (scan_id, counts, grade, correlations, generated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (scan_id) DO UPDATE SET
			counts       = EXCLUDED.counts,
			grade        = EXCLUDED.grade,
			correlations = EXCLUDED.correlations,
			generated_at = NOW()
		RETURNING generated_at`
	if err := r.db.QueryRow(ctx, query,
		s.ScanID, counts, nullableString(s.Grade), corr,
	).Scan(&s.GeneratedAt); err != nil {
		return fmt.Errorf("recon repo: upsert scan summary: %w", err)
	}
	return nil
}

// GetScanSummary returns the summary for a scan, or pgx.ErrNoRows if none
// has been written yet.
func (r *ReconRepository) GetScanSummary(ctx context.Context, scanID uuid.UUID) (*recon.ScanSummary, error) {
	const query = `
		SELECT scan_id, counts, COALESCE(grade, ''), correlations, generated_at
		FROM recon_scan_summary WHERE scan_id = $1`
	var (
		s      recon.ScanSummary
		counts []byte
		corr   []byte
	)
	if err := r.db.QueryRow(ctx, query, scanID).Scan(
		&s.ScanID, &counts, &s.Grade, &corr, &s.GeneratedAt,
	); err != nil {
		return nil, fmt.Errorf("recon repo: get scan summary: %w", err)
	}
	if len(counts) > 0 {
		if err := json.Unmarshal(counts, &s.Counts); err != nil {
			return nil, fmt.Errorf("recon repo: get scan summary: decode counts: %w", err)
		}
	}
	if len(corr) > 0 {
		if err := json.Unmarshal(corr, &s.Correlations); err != nil {
			return nil, fmt.Errorf("recon repo: get scan summary: decode correlations: %w", err)
		}
	}
	return &s, nil
}

// ============================================================================
// Audit log (append-only)
// ============================================================================

// AppendAudit appends a single row to recon_audit_log. The table is
// append-only: no UPDATE or DELETE statements exist anywhere in the
// repository. Pass a zero/empty IP to omit the column.
func (r *ReconRepository) AppendAudit(ctx context.Context, entry recon.AuditEntry) error {
	details, err := encodeJSONObject(entry.Details)
	if err != nil {
		return fmt.Errorf("recon repo: append audit: %w", err)
	}

	var ipArg any
	if entry.IP != "" {
		parsed := net.ParseIP(entry.IP)
		if parsed == nil {
			return fmt.Errorf("recon repo: append audit: invalid ip %q", entry.IP)
		}
		ipArg = parsed.String()
	}

	const query = `
		INSERT INTO recon_audit_log (actor_id, action, target_id, scan_id, ip, details)
		VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := r.db.Exec(ctx, query,
		entry.ActorID, entry.Action, entry.TargetID, entry.ScanID, ipArg, details,
	); err != nil {
		return fmt.Errorf("recon repo: append audit: %w", err)
	}
	return nil
}

// ============================================================================
// Shared helpers
// ============================================================================

// encodeJSONObject marshals m into a JSONB-compatible string, returning
// "{}" when m is nil or empty so the column's NOT NULL constraint is
// honored without callers having to allocate an empty map.
//
// String (not []byte) is the return type because the connection pool
// uses pgx.QueryExecModeSimpleProtocol (see db.go), under which a
// []byte argument is rendered as a hex-encoded bytea literal that
// PostgreSQL cannot parse as JSON ("invalid input syntax for type
// json", SQLSTATE 22P02). Passing the value as string sidesteps the
// bytea encoder and lands as a plain JSON document.
func encodeJSONObject(m map[string]any) (string, error) {
	if len(m) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("marshal json: %w", err)
	}
	return string(b), nil
}

// marshalJSONString marshals v as JSON and returns the result as a
// string (see encodeJSONObject for why string and not []byte). When the
// marshaled output is empty or the literal "null" — both of which a
// JSONB NOT NULL column would reject — the supplied emptyDefault is
// substituted (typically "[]" for array columns or "{}" for object
// columns).
func marshalJSONString(v any, emptyDefault string) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal json: %w", err)
	}
	if len(b) == 0 || string(b) == "null" {
		return emptyDefault, nil
	}
	return string(b), nil
}

// nullableString returns nil for an empty string so the resulting SQL
// argument becomes NULL rather than the empty string.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableJSONBytes converts a JSON-marshaled []byte into a value
// pgx can bind to a nullable JSONB column. A nil/empty slice yields
// SQL NULL (preserving the column's nullable contract); a non-empty
// slice is returned as `string` because the connection pool runs in
// pgx.QueryExecModeSimpleProtocol and a raw []byte would be encoded as
// a bytea hex literal that PostgreSQL refuses to parse as JSON. See
// encodeJSONObject for the full rationale on the simple-protocol +
// JSONB encoding interaction.
func nullableJSONBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

// paginate returns a (limit, offset) pair clamped to sane bounds. A
// non-positive limit becomes defaultLimit; a negative offset becomes 0.
func paginate(limit, offset, defaultLimit int) (int, int) {
	if limit <= 0 {
		limit = defaultLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
