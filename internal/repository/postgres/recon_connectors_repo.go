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

	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
)

// ReconConnectorsRepository persists the encrypted credentials and the
// enabled flag for the optional recon connectors (HIBP today; Shodan
// and IntelX land in v26.5.2). The row layout mirrors the schema from
// migration 044:
//
//	id                       UUID    primary key
//	kind                     TEXT    unique          (e.g. "hibp")
//	enabled                  BOOLEAN
//	credentials_encrypted    BYTEA
//	nonce                    BYTEA
//	config                   JSONB   (reserved, unused today)
//	created_at / updated_at
//
// The credentials map (e.g. {"api_key": "<value>"}) is JSON-encoded
// then encrypted with the installation-wide AES-256-GCM data key. The
// nonce is split into its own column for parity with recon_findings_raw
// — see sealPayload/openPayload on ReconRepository for the same split.
type ReconConnectorsRepository struct {
	db        *DB
	encryptor *crypto.AESEncryptor
}

// NewReconConnectorsRepository constructs the repository. encryptor
// MUST be non-nil — every Save / Load round-trips through it. The
// wiring layer is responsible for refusing to construct the repo
// without an encryptor.
func NewReconConnectorsRepository(db *DB, encryptor *crypto.AESEncryptor) *ReconConnectorsRepository {
	return &ReconConnectorsRepository{db: db, encryptor: encryptor}
}

// ConnectorRow is the API-shaped view of one stored connector row.
// Credentials are NEVER included — Load returns them only by explicit
// caller request.
type ConnectorRow struct {
	Kind    string
	Enabled bool
}

// ErrConnectorNotFound is returned by Load and Delete when no row
// exists for the given kind.
var ErrConnectorNotFound = errors.New("recon connectors repo: not found")

// Save upserts the credentials + enabled flag for a connector. The
// credentials map is JSON-encoded, encrypted with AES-256-GCM, and
// stored alongside the nonce. The kind column has a UNIQUE constraint
// so ON CONFLICT DO UPDATE is the atomic upsert primitive.
//
// An empty creds map is permitted and stored as the encrypted JSON
// `{}` — that lets an operator toggle enabled=false on a previously
// configured connector without re-supplying the key.
func (r *ReconConnectorsRepository) Save(ctx context.Context, kind string, creds map[string]string, enabled bool) error {
	if r.encryptor == nil {
		return errors.New("recon connectors repo: encryptor is required")
	}
	if creds == nil {
		creds = map[string]string{}
	}
	plain, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("recon connectors repo: marshal creds: %w", err)
	}
	nonce, ciphertext, err := r.seal(plain)
	if err != nil {
		return err
	}
	const query = `
		INSERT INTO recon_connectors (kind, enabled, credentials_encrypted, nonce, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (kind) DO UPDATE
		   SET enabled               = EXCLUDED.enabled,
		       credentials_encrypted = EXCLUDED.credentials_encrypted,
		       nonce                 = EXCLUDED.nonce,
		       updated_at            = NOW()`
	if _, err := r.db.Exec(ctx, query, kind, enabled, ciphertext, nonce); err != nil {
		return fmt.Errorf("recon connectors repo: upsert: %w", err)
	}
	return nil
}

// Load returns the decrypted credentials map plus the enabled flag for
// the supplied kind. Returns ErrConnectorNotFound when no row exists.
// The credentials map may legitimately be empty (operator toggled
// enabled=false without supplying a key) — callers should not treat
// "empty map" as "no row".
func (r *ReconConnectorsRepository) Load(ctx context.Context, kind string) (map[string]string, bool, error) {
	if r.encryptor == nil {
		return nil, false, errors.New("recon connectors repo: encryptor is required")
	}
	const query = `
		SELECT enabled, credentials_encrypted, nonce
		FROM recon_connectors
		WHERE kind = $1`
	var (
		enabled    bool
		ciphertext []byte
		nonce      []byte
	)
	row := r.db.QueryRow(ctx, query, kind)
	if err := row.Scan(&enabled, &ciphertext, &nonce); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, ErrConnectorNotFound
		}
		return nil, false, fmt.Errorf("recon connectors repo: load: %w", err)
	}
	if len(ciphertext) == 0 {
		// Row exists but credentials were never set (operator toggled
		// enabled and nothing else). Return an empty map so callers
		// can branch on len() without nil-checks.
		return map[string]string{}, enabled, nil
	}
	plain, err := r.open(nonce, ciphertext)
	if err != nil {
		return nil, false, err
	}
	out := map[string]string{}
	if len(plain) > 0 {
		if err := json.Unmarshal(plain, &out); err != nil {
			return nil, false, fmt.Errorf("recon connectors repo: decode creds: %w", err)
		}
	}
	return out, enabled, nil
}

// List returns one ConnectorRow per stored kind, sorted ascending. The
// returned rows DO NOT carry credentials — callers needing the
// decrypted map must call Load explicitly. ListConnectors on the
// registry is the public surface; this helper is for diagnostics.
func (r *ReconConnectorsRepository) List(ctx context.Context) ([]ConnectorRow, error) {
	const query = `SELECT kind, enabled FROM recon_connectors ORDER BY kind ASC`
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("recon connectors repo: list: %w", err)
	}
	defer rows.Close()
	var out []ConnectorRow
	for rows.Next() {
		var row ConnectorRow
		if err := rows.Scan(&row.Kind, &row.Enabled); err != nil {
			return nil, fmt.Errorf("recon connectors repo: scan list row: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recon connectors repo: iterate list: %w", err)
	}
	return out, nil
}

// Delete removes the row for the supplied kind, including the
// encrypted credentials. Returns ErrConnectorNotFound when no row
// exists so the handler can render 404 rather than swallow the call.
func (r *ReconConnectorsRepository) Delete(ctx context.Context, kind string) error {
	const query = `DELETE FROM recon_connectors WHERE kind = $1`
	tag, err := r.db.Exec(ctx, query, kind)
	if err != nil {
		return fmt.Errorf("recon connectors repo: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrConnectorNotFound
	}
	return nil
}

// seal encrypts plaintext via the AES-256-GCM helper and splits the
// resulting blob into the nonce + ciphertext columns. Identical to
// ReconRepository.sealPayload — copied here so this repo file is
// independently navigable.
func (r *ReconConnectorsRepository) seal(plaintext []byte) (nonce, ciphertext []byte, err error) {
	encoded, err := r.encryptor.Encrypt(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("recon connectors repo: encrypt: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("recon connectors repo: decode encryptor output: %w", err)
	}
	if len(raw) < gcmNonceSize {
		return nil, nil, fmt.Errorf("recon connectors repo: encryptor produced %d bytes, want >= %d", len(raw), gcmNonceSize)
	}
	nonce = make([]byte, gcmNonceSize)
	copy(nonce, raw[:gcmNonceSize])
	ciphertext = make([]byte, len(raw)-gcmNonceSize)
	copy(ciphertext, raw[gcmNonceSize:])
	return nonce, ciphertext, nil
}

// open is the inverse of seal. Mirrors ReconRepository.openPayload.
func (r *ReconConnectorsRepository) open(nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != gcmNonceSize {
		return nil, fmt.Errorf("recon connectors repo: invalid nonce length %d", len(nonce))
	}
	combined := make([]byte, 0, len(nonce)+len(ciphertext))
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)
	plain, err := r.encryptor.Decrypt(base64.StdEncoding.EncodeToString(combined))
	if err != nil {
		return nil, fmt.Errorf("recon connectors repo: decrypt: %w", err)
	}
	return plain, nil
}
