// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package imagesign

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Repository interface
// ---------------------------------------------------------------------------

// Repository defines the data-access contract required by the image signing
// service. It is satisfied by postgres.ImageSigningRepository.
type Repository interface {
	CreateSignature(ctx context.Context, sig *models.ImageSignature) error
	GetSignaturesByDigest(ctx context.Context, digest string) ([]*models.ImageSignature, error)
	GetSignaturesByRef(ctx context.Context, imageRef string) ([]*models.ImageSignature, error)
	UpdateVerification(ctx context.Context, id uuid.UUID, verified bool, verifiedAt *time.Time, verificationError string) error

	CreateAttestation(ctx context.Context, att *models.ImageAttestation) error
	GetAttestationsByDigest(ctx context.Context, digest string) ([]*models.ImageAttestation, error)

	CreateTrustPolicy(ctx context.Context, p *models.ImageTrustPolicy) error
	GetTrustPolicy(ctx context.Context, id uuid.UUID) (*models.ImageTrustPolicy, error)
	ListTrustPolicies(ctx context.Context) ([]*models.ImageTrustPolicy, error)
	UpdateTrustPolicy(ctx context.Context, p *models.ImageTrustPolicy) error
	DeleteTrustPolicy(ctx context.Context, id uuid.UUID) error
	GetMatchingPolicies(ctx context.Context, imageRef string) ([]*models.ImageTrustPolicy, error)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Config holds configuration for the image signing service.
type Config struct {
	// CosignBinaryPath is the absolute path to the cosign binary.
	// When empty the service will search $PATH.
	CosignBinaryPath string

	// KeylessMode enables Sigstore keyless signing via Fulcio/Rekor.
	KeylessMode bool

	// FulcioURL is the URL of the Fulcio CA for keyless signing.
	FulcioURL string

	// RekorURL is the URL of the Rekor transparency log.
	RekorURL string

	// VerificationEnabled controls whether verification is performed.
	VerificationEnabled bool
}

// DefaultConfig returns a sensible default configuration that uses keyless
// signing with public Sigstore infrastructure.
func DefaultConfig() Config {
	return Config{
		CosignBinaryPath:    "cosign",
		KeylessMode:         true,
		FulcioURL:           "https://fulcio.sigstore.dev",
		RekorURL:            "https://rekor.sigstore.dev",
		VerificationEnabled: true,
	}
}

// ---------------------------------------------------------------------------
// Option types
// ---------------------------------------------------------------------------

// SignOptions controls how an image is signed.
type SignOptions struct {
	// KeyPath is the path to a private key file (used when KeylessMode is false).
	KeyPath string

	// CertPath is the path to a certificate file to attach to the signature.
	CertPath string

	// KeylessMode overrides the service-level keyless setting for this call.
	KeylessMode bool

	// Annotations are key-value pairs embedded in the signature payload.
	Annotations map[string]string
}

// VerifyResult holds the outcome of a cosign verify operation.
type VerifyResult struct {
	Verified   bool            `json:"verified"`
	Signatures []SignatureInfo `json:"signatures,omitempty"`
	Errors     []string        `json:"errors,omitempty"`
}

// SignatureInfo describes a single verified signature.
type SignatureInfo struct {
	SignerIdentity string    `json:"signer_identity"`
	Issuer         string    `json:"issuer"`
	Timestamp      time.Time `json:"timestamp"`
}

// PolicyVerifyResult holds the outcome of verifying an image against the
// configured trust policies.
type PolicyVerifyResult struct {
	Allowed         bool     `json:"allowed"`
	MatchedPolicies []string `json:"matched_policies,omitempty"`
	Violations      []string `json:"violations,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// Service implements image signing and verification using cosign and an
// internal trust-policy engine.
type Service struct {
	repo   Repository
	config Config
	logger *logger.Logger
}

// NewService creates a new image signing service.
func NewService(repo Repository, cfg Config, log *logger.Logger) *Service {
	return &Service{
		repo:   repo,
		config: cfg,
		logger: log.Named("imagesign"),
	}
}

// IsCosignAvailable returns true when the configured cosign binary can be
// found on disk or in $PATH.
func (s *Service) IsCosignAvailable() bool {
	path := s.config.CosignBinaryPath
	if path == "" {
		path = "cosign"
	}
	_, err := exec.LookPath(path)
	return err == nil
}

// cosignBin returns the resolved binary name for cosign.
func (s *Service) cosignBin() string {
	if s.config.CosignBinaryPath != "" {
		return s.config.CosignBinaryPath
	}
	return "cosign"
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

// SignImage signs a container image using cosign and records the resulting
// signature in the database.
func (s *Service) SignImage(ctx context.Context, imageRef string, opts SignOptions) (*models.ImageSignature, error) {
	if imageRef == "" {
		return nil, errors.New(errors.CodeInvalidInput, "image reference is required")
	}

	if !s.IsCosignAvailable() {
		return nil, errors.New(errors.CodeInternal, "cosign binary not found")
	}

	args := s.buildSignArgs(imageRef, opts)

	s.logger.Info("signing image",
		"image_ref", imageRef,
		"keyless", opts.KeylessMode || s.config.KeylessMode)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, s.cosignBin(), args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		s.logger.Error("cosign sign failed",
			"image_ref", imageRef,
			"stderr", stderr.String(),
			"error", err)
		return nil, fmt.Errorf("cosign sign failed: %s: %w", stderr.String(), err)
	}

	// Build signature record.
	now := time.Now()
	sig := &models.ImageSignature{
		ID:            uuid.New(),
		ImageRef:      imageRef,
		ImageDigest:   extractDigestFromOutput(stdout.String(), stderr.String()),
		SignatureType: models.SignatureTypeCosign,
		Verified:      true,
		VerifiedAt:    &now,
		CreatedAt:     now,
	}

	if opts.KeylessMode || s.config.KeylessMode {
		sig.SignerIdentity = "keyless"
		sig.Issuer = s.config.FulcioURL
	}

	// Persist.
	if err := s.repo.CreateSignature(ctx, sig); err != nil {
		return nil, fmt.Errorf("failed to save signature: %w", err)
	}

	s.logger.Info("image signed successfully",
		"image_ref", imageRef,
		"signature_id", sig.ID)

	return sig, nil
}

// buildSignArgs assembles the cosign sign CLI arguments.
func (s *Service) buildSignArgs(imageRef string, opts SignOptions) []string {
	args := []string{"sign"}

	keyless := opts.KeylessMode || s.config.KeylessMode

	if keyless {
		// Keyless mode uses an OIDC identity token via Fulcio.
		if s.config.FulcioURL != "" {
			args = append(args, "--fulcio-url", s.config.FulcioURL)
		}
		if s.config.RekorURL != "" {
			args = append(args, "--rekor-url", s.config.RekorURL)
		}
		args = append(args, "--yes")
	} else {
		if opts.KeyPath != "" {
			args = append(args, "--key", opts.KeyPath)
		}
		if opts.CertPath != "" {
			args = append(args, "--cert", opts.CertPath)
		}
	}

	// Annotations.
	for k, v := range opts.Annotations {
		args = append(args, "-a", fmt.Sprintf("%s=%s", k, v))
	}

	args = append(args, imageRef)
	return args
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

// VerifyImage verifies the signatures of a container image using cosign and
// returns the verification result.
func (s *Service) VerifyImage(ctx context.Context, imageRef string) (*VerifyResult, error) {
	if imageRef == "" {
		return nil, errors.New(errors.CodeInvalidInput, "image reference is required")
	}

	if !s.IsCosignAvailable() {
		return nil, errors.New(errors.CodeInternal, "cosign binary not found")
	}

	result := &VerifyResult{}

	args := s.buildVerifyArgs(imageRef)

	s.logger.Debug("verifying image",
		"image_ref", imageRef)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, s.cosignBin(), args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// result envelope: cosign's non-zero exit is verification info,
		// surfaced via VerifyResult.{Verified,Errors}
		result.Verified = false
		result.Errors = append(result.Errors, stderr.String())

		s.logger.Debug("cosign verify returned non-zero",
			"image_ref", imageRef,
			"stderr", stderr.String())

		return result, nil //nolint:nilerr
	}

	// Parse the JSON array that cosign verify writes to stdout.
	sigs, parseErr := parseCosignVerifyOutput(stdout.Bytes())
	if parseErr != nil {
		result.Verified = true
		result.Errors = append(result.Errors, fmt.Sprintf("signature verified but output parsing failed: %v", parseErr))
		return result, nil
	}

	result.Verified = true
	result.Signatures = sigs

	return result, nil
}

// buildVerifyArgs assembles the cosign verify CLI arguments.
func (s *Service) buildVerifyArgs(imageRef string) []string {
	args := []string{"verify"}

	if s.config.RekorURL != "" {
		args = append(args, "--rekor-url", s.config.RekorURL)
	}

	// For keyless verification the caller typically supplies identity and
	// issuer flags. When using public Sigstore we accept any identity.
	if s.config.KeylessMode {
		args = append(args, "--certificate-identity-regexp", ".*")
		args = append(args, "--certificate-oidc-issuer-regexp", ".*")
	}

	args = append(args, "--output", "json")
	args = append(args, imageRef)
	return args
}

// cosignPayload represents one entry in the JSON array returned by
// `cosign verify --output json`.
type cosignPayload struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
	} `json:"critical"`
	Optional map[string]string `json:"optional"`
}

// parseCosignVerifyOutput parses the JSON output from cosign verify into
// a slice of SignatureInfo.
func parseCosignVerifyOutput(data []byte) ([]SignatureInfo, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}

	var payloads []cosignPayload
	if err := json.Unmarshal(data, &payloads); err != nil {
		return nil, fmt.Errorf("failed to parse cosign output: %w", err)
	}

	sigs := make([]SignatureInfo, 0, len(payloads))
	for _, p := range payloads {
		si := SignatureInfo{
			Timestamp: time.Now(),
		}
		if v, ok := p.Optional["Subject"]; ok {
			si.SignerIdentity = v
		}
		if v, ok := p.Optional["Issuer"]; ok {
			si.Issuer = v
		}
		sigs = append(sigs, si)
	}
	return sigs, nil
}

// extractDigestFromOutput attempts to extract a sha256 digest from cosign
// sign/verify output. Cosign typically includes the digest in the form
// "sha256:<hex>" somewhere in stdout or stderr.
func extractDigestFromOutput(stdout, stderr string) string {
	for _, s := range []string{stdout, stderr} {
		// Look for sha256:abc123... pattern (64 hex chars).
		idx := strings.Index(s, "sha256:")
		if idx == -1 {
			continue
		}
		rest := s[idx:]
		// Take up to 71 chars (sha256: + 64 hex)
		candidate := rest
		if len(candidate) > 71 {
			candidate = candidate[:71]
		}
		// Trim any trailing whitespace or non-hex
		candidate = strings.TrimRight(candidate, " \t\n\r,\"'}")
		if len(candidate) >= 71 && strings.HasPrefix(candidate, "sha256:") {
			return candidate
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Policy verification
// ---------------------------------------------------------------------------

// VerifyImageAgainstPolicies evaluates an image reference against all
// matching trust policies and returns whether the image is allowed to run.
func (s *Service) VerifyImageAgainstPolicies(ctx context.Context, imageRef string) (*PolicyVerifyResult, error) {
	if imageRef == "" {
		return nil, errors.New(errors.CodeInvalidInput, "image reference is required")
	}

	result := &PolicyVerifyResult{
		Allowed: true,
	}

	// Fetch all enabled policies whose image_pattern matches imageRef.
	policies, err := s.repo.GetMatchingPolicies(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to query matching policies: %w", err)
	}

	// No matching policies -- allow by default.
	if len(policies) == 0 {
		return result, nil
	}

	// Check verification status lazily: only call cosign if at least one
	// policy requires a signature.
	var verifyResult *VerifyResult
	needsVerify := false
	for _, p := range policies {
		if p.RequireSignature {
			needsVerify = true
			break
		}
	}

	if needsVerify && s.config.VerificationEnabled && s.IsCosignAvailable() {
		verifyResult, err = s.VerifyImage(ctx, imageRef)
		if err != nil {
			s.logger.Warn("verification failed during policy check",
				"image_ref", imageRef,
				"error", err)
			verifyResult = &VerifyResult{Verified: false, Errors: []string{err.Error()}}
		}
	}

	// Check attestations lazily.
	var attestations []*models.ImageAttestation
	needsAttest := false
	for _, p := range policies {
		if p.RequireAttestation {
			needsAttest = true
			break
		}
	}

	if needsAttest {
		// Look up attestations by image ref since we may not have the digest.
		sigs, sigErr := s.repo.GetSignaturesByRef(ctx, imageRef)
		if sigErr != nil {
			s.logger.Warn("failed to look up signatures for attestation check",
				"image_ref", imageRef, "error", sigErr)
		}
		for _, sig := range sigs {
			if sig.ImageDigest != "" {
				atts, attErr := s.repo.GetAttestationsByDigest(ctx, sig.ImageDigest)
				if attErr != nil {
					s.logger.Warn("failed to look up attestations by digest",
						"image_ref", imageRef, "digest", sig.ImageDigest, "error", attErr)
				}
				attestations = append(attestations, atts...)
				break
			}
		}
	}

	isSigned := verifyResult != nil && verifyResult.Verified
	hasAttestation := len(attestations) > 0

	for _, policy := range policies {
		result.MatchedPolicies = append(result.MatchedPolicies, policy.Name)

		if policy.RequireSignature && !isSigned {
			msg := fmt.Sprintf("policy %q requires a valid signature for %q", policy.Name, imageRef)
			if policy.IsEnforcing {
				result.Violations = append(result.Violations, msg)
				result.Allowed = false
			} else {
				result.Warnings = append(result.Warnings, msg)
			}
		}

		if policy.RequireAttestation && !hasAttestation {
			msg := fmt.Sprintf("policy %q requires an attestation for %q", policy.Name, imageRef)
			if policy.IsEnforcing {
				result.Violations = append(result.Violations, msg)
				result.Allowed = false
			} else {
				result.Warnings = append(result.Warnings, msg)
			}
		}

		// Validate allowed signers when the image is signed and the policy
		// specifies a whitelist.
		if isSigned && policy.AllowedSigners != nil && len(policy.AllowedSigners) > 0 {
			allowed, parseErr := parseJSONStringSlice(policy.AllowedSigners)
			if parseErr == nil && len(allowed) > 0 {
				if !signerInList(verifyResult, allowed) {
					msg := fmt.Sprintf("policy %q: signer not in allowed list for %q", policy.Name, imageRef)
					if policy.IsEnforcing {
						result.Violations = append(result.Violations, msg)
						result.Allowed = false
					} else {
						result.Warnings = append(result.Warnings, msg)
					}
				}
			}
		}
	}

	return result, nil
}

// parseJSONStringSlice tries to unmarshal a json.RawMessage into []string.
func parseJSONStringSlice(data json.RawMessage) ([]string, error) {
	if data == nil {
		return nil, nil
	}
	var s []string
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return s, nil
}

// signerInList returns true if any signature in the verify result was
// produced by a signer in the allowed list.
func signerInList(vr *VerifyResult, allowed []string) bool {
	if vr == nil {
		return false
	}
	for _, sig := range vr.Signatures {
		for _, a := range allowed {
			if strings.EqualFold(sig.SignerIdentity, a) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

// ListTrustPolicies returns all image trust policies.
func (s *Service) ListTrustPolicies(ctx context.Context) ([]*models.ImageTrustPolicy, error) {
	return s.repo.ListTrustPolicies(ctx)
}

// GetImageSignatures retrieves all stored signatures for an image reference.
func (s *Service) GetImageSignatures(ctx context.Context, imageRef string) ([]*models.ImageSignature, error) {
	if imageRef == "" {
		return nil, errors.New(errors.CodeInvalidInput, "image reference is required")
	}
	return s.repo.GetSignaturesByRef(ctx, imageRef)
}

// RecordSignature saves a discovered or externally verified signature.
func (s *Service) RecordSignature(ctx context.Context, sig *models.ImageSignature) error {
	if sig == nil {
		return errors.New(errors.CodeInvalidInput, "signature is required")
	}
	if sig.ImageRef == "" {
		return errors.New(errors.CodeInvalidInput, "image reference is required")
	}
	if sig.ID == uuid.Nil {
		sig.ID = uuid.New()
	}
	if sig.CreatedAt.IsZero() {
		sig.CreatedAt = time.Now()
	}
	return s.repo.CreateSignature(ctx, sig)
}

// ---------------------------------------------------------------------------
// Default policies
// ---------------------------------------------------------------------------

// SeedDefaultPolicies creates a set of sensible default trust policies if no
// policies exist yet.
func (s *Service) SeedDefaultPolicies(ctx context.Context) error {
	existing, err := s.repo.ListTrustPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to list existing trust policies: %w", err)
	}
	if len(existing) > 0 {
		s.logger.Debug("trust policies already exist, skipping seed")
		return nil
	}

	now := time.Now()
	defaults := []*models.ImageTrustPolicy{
		{
			ID:                 uuid.New(),
			Name:               "internal-registry",
			Description:        "Require signature for images from the internal registry",
			ImagePattern:       "registry.internal/*",
			RequireSignature:   true,
			RequireAttestation: false,
			AllowedSigners:     json.RawMessage(`[]`),
			AllowedIssuers:     json.RawMessage(`[]`),
			IsEnabled:          true,
			IsEnforcing:        true,
			CreatedAt:          now,
			UpdatedAt:          now,
		},
		{
			ID:                 uuid.New(),
			Name:               "public-critical",
			Description:        "Require signature and attestation for production images",
			ImagePattern:       "*/production-*",
			RequireSignature:   true,
			RequireAttestation: true,
			AllowedSigners:     json.RawMessage(`[]`),
			AllowedIssuers:     json.RawMessage(`[]`),
			IsEnabled:          true,
			IsEnforcing:        true,
			CreatedAt:          now,
			UpdatedAt:          now,
		},
		{
			ID:                 uuid.New(),
			Name:               "default-warn",
			Description:        "Warn on unsigned images (non-enforcing catch-all)",
			ImagePattern:       "*",
			RequireSignature:   true,
			RequireAttestation: false,
			AllowedSigners:     json.RawMessage(`[]`),
			AllowedIssuers:     json.RawMessage(`[]`),
			IsEnabled:          true,
			IsEnforcing:        false,
			CreatedAt:          now,
			UpdatedAt:          now,
		},
	}

	for _, p := range defaults {
		if err := s.repo.CreateTrustPolicy(ctx, p); err != nil {
			return fmt.Errorf("failed to create default policy %q: %w", p.Name, err)
		}
		s.logger.Info("seeded default trust policy",
			"name", p.Name,
			"pattern", p.ImagePattern)
	}

	return nil
}
