// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package trivy provides integration with Trivy vulnerability scanner.
// Trivy is used for CVE scanning of container images.
// See: https://github.com/aquasecurity/trivy
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/security"
)

// ClientConfig holds configuration for the Trivy client
type ClientConfig struct {
	// Path to trivy binary (default: "trivy")
	BinaryPath string

	// Cache directory for Trivy DB
	CacheDir string

	// Timeout for scan operations
	Timeout time.Duration

	// Severity levels to report (default: all)
	Severities []string

	// Ignore unfixed vulnerabilities
	IgnoreUnfixed bool

	// Skip DB update (use cached)
	SkipDBUpdate bool

	// Custom Trivy arguments
	ExtraArgs []string
}

// DefaultClientConfig returns the default Trivy configuration
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		BinaryPath:    "trivy",
		CacheDir:      "/tmp/trivy-cache",
		Timeout:       5 * time.Minute,
		Severities:    []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"},
		IgnoreUnfixed: false,
		SkipDBUpdate:  false,
	}
}

// Client provides Trivy vulnerability scanning
type Client struct {
	config    *ClientConfig
	logger    *logger.Logger
	available bool
	mu        sync.RWMutex
}

// NewClient creates a new Trivy client
func NewClient(config *ClientConfig, log *logger.Logger) *Client {
	if config == nil {
		config = DefaultClientConfig()
	}

	c := &Client{
		config: config,
		logger: log.Named("trivy"),
	}

	// Check if Trivy is available
	c.checkAvailability()

	return c
}

// checkAvailability checks if Trivy binary is available
func (c *Client) checkAvailability() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.config.BinaryPath, "--version")
	output, err := cmd.Output()

	c.mu.Lock()
	defer c.mu.Unlock()

	if err != nil {
		c.available = false
		c.logger.Warn("Trivy not available", "error", err)
		return
	}

	c.available = true
	version := strings.TrimSpace(string(output))
	c.logger.Info("Trivy available", "version", version)
}

// IsAvailable returns true if Trivy is available
func (c *Client) IsAvailable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.available
}

// ScanImage scans a container image for vulnerabilities
func (c *Client) ScanImage(ctx context.Context, image string) ([]security.Issue, error) {
	log := logger.FromContext(ctx)

	if !c.IsAvailable() {
		return nil, errors.New(errors.CodeTrivyError, "Trivy is not available")
	}

	log.Debug("Starting Trivy scan", "image", image)
	start := time.Now()

	// Build command arguments
	args := []string{
		"image",
		"--format", "json",
		"--quiet",
	}

	// Add severity filter
	if len(c.config.Severities) > 0 {
		args = append(args, "--severity", strings.Join(c.config.Severities, ","))
	}

	// Add cache directory
	if c.config.CacheDir != "" {
		args = append(args, "--cache-dir", c.config.CacheDir)
	}

	// Ignore unfixed
	if c.config.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}

	// Skip DB update
	if c.config.SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}

	// Add extra args
	args = append(args, c.config.ExtraArgs...)

	// Add image name
	args = append(args, image)

	// Create command with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, c.config.BinaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Check if it's a timeout
		if cmdCtx.Err() == context.DeadlineExceeded {
			return nil, errors.New(errors.CodeTimeout, "Trivy scan timed out")
		}

		// Trivy returns non-zero exit code when vulnerabilities are found
		// Check if we still got JSON output
		if stdout.Len() == 0 {
			return nil, errors.Wrap(err, errors.CodeTrivyError,
				fmt.Sprintf("Trivy scan failed: %s", stderr.String()))
		}
	}

	// Parse JSON output
	var report TrivyReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, errors.Wrap(err, errors.CodeTrivyError, "failed to parse Trivy output")
	}

	// Convert to security issues
	issues := c.convertToIssues(report)

	duration := time.Since(start)
	log.Info("Trivy scan completed",
		"image", image,
		"vulnerabilities", len(issues),
		"duration", duration)

	return issues, nil
}

// TrivyReport represents the JSON output from Trivy
type TrivyReport struct {
	SchemaVersion int            `json:"SchemaVersion"`
	ArtifactName  string         `json:"ArtifactName"`
	ArtifactType  string         `json:"ArtifactType"`
	Metadata      TrivyMetadata  `json:"Metadata"`
	Results       []TrivyResult  `json:"Results"`
}

// TrivyMetadata represents image metadata
type TrivyMetadata struct {
	OS          *TrivyOS `json:"OS,omitempty"`
	ImageID     string   `json:"ImageID"`
	DiffIDs     []string `json:"DiffIDs"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
}

// TrivyOS represents OS information
type TrivyOS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

// TrivyResult represents scan results for a target
type TrivyResult struct {
	Target          string             `json:"Target"`
	Class           string             `json:"Class"`
	Type            string             `json:"Type"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

// TrivyVulnerability represents a single vulnerability
type TrivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgID            string   `json:"PkgID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	SeveritySource   string   `json:"SeveritySource"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
	CVSS             *CVSS    `json:"CVSS,omitempty"`
	PublishedDate    *string  `json:"PublishedDate,omitempty"`
	LastModifiedDate *string  `json:"LastModifiedDate,omitempty"`
}

// CVSS represents CVSS scoring
type CVSS struct {
	Nvd    *CVSSData `json:"nvd,omitempty"`
	RedHat *CVSSData `json:"redhat,omitempty"`
}

// CVSSData represents CVSS data from a source
type CVSSData struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
}

// convertToIssues converts Trivy vulnerabilities to security issues
func (c *Client) convertToIssues(report TrivyReport) []security.Issue {
	var issues []security.Issue

	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			issue := security.Issue{
				CheckID:     models.CheckImageVulnerability,
				Severity:    mapTrivySeverity(vuln.Severity),
				Category:    models.IssueCategoryVulnerability,
				Title:       fmt.Sprintf("CVE: %s in %s", vuln.VulnerabilityID, vuln.PkgName),
				Description: truncateDescription(vuln.Description, 500),
				DocURL:      vuln.PrimaryURL,
				Penalty:     penaltyForCVESeverity(vuln.Severity),
				Details: map[string]interface{}{
					"cve_id":            vuln.VulnerabilityID,
					"package":           vuln.PkgName,
					"installed_version": vuln.InstalledVersion,
					"fixed_version":     vuln.FixedVersion,
					"target":            result.Target,
				},
			}

			// Add CVSS score if available
			if vuln.CVSS != nil {
				if vuln.CVSS.Nvd != nil && vuln.CVSS.Nvd.V3Score > 0 {
					issue.Details["cvss_score"] = vuln.CVSS.Nvd.V3Score
					issue.Details["cvss_vector"] = vuln.CVSS.Nvd.V3Vector
				} else if vuln.CVSS.RedHat != nil && vuln.CVSS.RedHat.V3Score > 0 {
					issue.Details["cvss_score"] = vuln.CVSS.RedHat.V3Score
					issue.Details["cvss_vector"] = vuln.CVSS.RedHat.V3Vector
				}
			}

			// Add fix recommendation
			if vuln.FixedVersion != "" {
				issue.Recommendation = fmt.Sprintf("Update %s from %s to %s",
					vuln.PkgName, vuln.InstalledVersion, vuln.FixedVersion)
				issue.FixCommand = fmt.Sprintf("# Update %s to version %s or later",
					vuln.PkgName, vuln.FixedVersion)
			} else {
				issue.Recommendation = fmt.Sprintf("No fix available yet for %s in %s. Consider using an alternative package or wait for upstream fix.",
					vuln.VulnerabilityID, vuln.PkgName)
			}

			issues = append(issues, issue)
		}
	}

	return issues
}

// mapTrivySeverity maps Trivy severity to our severity
func mapTrivySeverity(severity string) models.IssueSeverity {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return models.IssueSeverityCritical
	case "HIGH":
		return models.IssueSeverityHigh
	case "MEDIUM":
		return models.IssueSeverityMedium
	case "LOW":
		return models.IssueSeverityLow
	default:
		return models.IssueSeverityInfo
	}
}

// penaltyForCVESeverity returns the score penalty for a CVE severity
func penaltyForCVESeverity(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 15
	case "HIGH":
		return 10
	case "MEDIUM":
		return 5
	case "LOW":
		return 2
	default:
		return 1
	}
}

// truncateDescription truncates a description to max length
func truncateDescription(desc string, maxLen int) string {
	if len(desc) <= maxLen {
		return desc
	}
	return desc[:maxLen-3] + "..."
}

// UpdateDB updates the Trivy vulnerability database
func (c *Client) UpdateDB(ctx context.Context) error {
	if !c.IsAvailable() {
		return errors.New(errors.CodeTrivyError, "Trivy is not available")
	}

	c.logger.Info("Updating Trivy database")

	args := []string{
		"image",
		"--download-db-only",
	}

	if c.config.CacheDir != "" {
		args = append(args, "--cache-dir", c.config.CacheDir)
	}

	cmd := exec.CommandContext(ctx, c.config.BinaryPath, args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, errors.CodeTrivyError,
			fmt.Sprintf("failed to update Trivy DB: %s", stderr.String()))
	}

	c.logger.Info("Trivy database updated")
	return nil
}

// GetDBInfo returns information about the Trivy database
func (c *Client) GetDBInfo(ctx context.Context) (*DBInfo, error) {
	if !c.IsAvailable() {
		return nil, errors.New(errors.CodeTrivyError, "Trivy is not available")
	}

	// Trivy doesn't have a direct DB info command
	// We can infer from the cache directory or just return nil
	return nil, nil
}

// DBInfo holds Trivy database information
type DBInfo struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Size      int64     `json:"size"`
}

// ============================================================================
// SBOM Generation
// ============================================================================

// SBOMFormat represents the SBOM output format
type SBOMFormat string

const (
	SBOMFormatCycloneDX SBOMFormat = "cyclonedx"
	SBOMFormatSPDX      SBOMFormat = "spdx"
	SBOMFormatSPDXJSON  SBOMFormat = "spdx-json"
)

// SBOM represents a Software Bill of Materials
type SBOM struct {
	Format       SBOMFormat             `json:"format"`
	Image        string                 `json:"image"`
	GeneratedAt  time.Time              `json:"generated_at"`
	Components   []SBOMComponent        `json:"components"`
	Dependencies []SBOMDependency       `json:"dependencies,omitempty"`
	RawOutput    json.RawMessage        `json:"raw_output,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// SBOMComponent represents a component in the SBOM
type SBOMComponent struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Type      string   `json:"type"`     // library, application, os, etc.
	PURL      string   `json:"purl"`     // Package URL
	Licenses  []string `json:"licenses"` // SPDX license identifiers
	Supplier  string   `json:"supplier,omitempty"`
	Publisher string   `json:"publisher,omitempty"`
}

// SBOMDependency represents a dependency relationship
type SBOMDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"depends_on"`
}

// GenerateSBOM generates a Software Bill of Materials for an image
func (c *Client) GenerateSBOM(ctx context.Context, image string, format SBOMFormat) (*SBOM, error) {
	log := logger.FromContext(ctx)

	if !c.IsAvailable() {
		return nil, errors.New(errors.CodeTrivyError, "Trivy is not available")
	}

	if format == "" {
		format = SBOMFormatCycloneDX
	}

	log.Debug("Generating SBOM", "image", image, "format", format)
	start := time.Now()

	// Build command arguments
	args := []string{
		"image",
		"--format", string(format),
		"--quiet",
	}

	// Add cache directory
	if c.config.CacheDir != "" {
		args = append(args, "--cache-dir", c.config.CacheDir)
	}

	// Skip DB update for SBOM generation
	args = append(args, "--skip-db-update")

	// Add image name
	args = append(args, image)

	// Create command with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, c.config.BinaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if cmdCtx.Err() == context.DeadlineExceeded {
			return nil, errors.New(errors.CodeTimeout, "SBOM generation timed out")
		}
		if stdout.Len() == 0 {
			return nil, errors.Wrap(err, errors.CodeTrivyError,
				fmt.Sprintf("SBOM generation failed: %s", stderr.String()))
		}
	}

	sbom := &SBOM{
		Format:      format,
		Image:       image,
		GeneratedAt: time.Now(),
		RawOutput:   json.RawMessage(stdout.Bytes()),
	}

	// Parse the output based on format to extract components
	if format == SBOMFormatCycloneDX {
		sbom.Components = c.parseCycloneDXComponents(stdout.Bytes())
	}

	duration := time.Since(start)
	log.Info("SBOM generated",
		"image", image,
		"format", format,
		"components", len(sbom.Components),
		"duration", duration)

	return sbom, nil
}

// CycloneDXReport represents a CycloneDX SBOM
type CycloneDXReport struct {
	BomFormat   string               `json:"bomFormat"`
	SpecVersion string               `json:"specVersion"`
	Version     int                  `json:"version"`
	Components  []CycloneDXComponent `json:"components"`
}

// CycloneDXComponent represents a component in CycloneDX format
type CycloneDXComponent struct {
	Type     string                 `json:"type"`
	Name     string                 `json:"name"`
	Version  string                 `json:"version"`
	Purl     string                 `json:"purl"`
	Licenses []CycloneDXLicense     `json:"licenses,omitempty"`
	Supplier *CycloneDXSupplier     `json:"supplier,omitempty"`
	BomRef   string                 `json:"bom-ref"`
}

// CycloneDXLicense represents a license in CycloneDX format
type CycloneDXLicense struct {
	License struct {
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"license"`
}

// CycloneDXSupplier represents a supplier in CycloneDX format
type CycloneDXSupplier struct {
	Name string `json:"name"`
}

// parseCycloneDXComponents parses CycloneDX output to extract components
func (c *Client) parseCycloneDXComponents(data []byte) []SBOMComponent {
	var report CycloneDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		c.logger.Warn("Failed to parse CycloneDX output", "error", err)
		return nil
	}

	components := make([]SBOMComponent, 0, len(report.Components))
	for _, comp := range report.Components {
		licenses := make([]string, 0)
		for _, lic := range comp.Licenses {
			if lic.License.ID != "" {
				licenses = append(licenses, lic.License.ID)
			} else if lic.License.Name != "" {
				licenses = append(licenses, lic.License.Name)
			}
		}

		component := SBOMComponent{
			Name:     comp.Name,
			Version:  comp.Version,
			Type:     comp.Type,
			PURL:     comp.Purl,
			Licenses: licenses,
		}
		if comp.Supplier != nil {
			component.Supplier = comp.Supplier.Name
		}
		components = append(components, component)
	}

	return components
}

// ============================================================================
// Filesystem Scanning
// ============================================================================

// ScanFilesystemOptions options for filesystem scanning
type ScanFilesystemOptions struct {
	// Path to scan (within the container, e.g., "/app" or "/")
	Path string
	// Severities to report
	Severities []string
	// IgnoreUnfixed ignores vulnerabilities without fixes
	IgnoreUnfixed bool
	// ScanSecrets enables secret scanning
	ScanSecrets bool
	// ScanMisconfigs enables misconfiguration scanning
	ScanMisconfigs bool
}

// DefaultFilesystemOptions returns default filesystem scanning options
func DefaultFilesystemOptions() *ScanFilesystemOptions {
	return &ScanFilesystemOptions{
		Path:           "/",
		Severities:     []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"},
		IgnoreUnfixed:  false,
		ScanSecrets:    true,
		ScanMisconfigs: true,
	}
}

// FilesystemScanResult represents the result of a filesystem scan
type FilesystemScanResult struct {
	Path           string            `json:"path"`
	ScannedAt      time.Time         `json:"scanned_at"`
	Duration       time.Duration     `json:"duration"`
	Vulnerabilities []security.Issue `json:"vulnerabilities"`
	Secrets        []SecretFinding   `json:"secrets,omitempty"`
	Misconfigs     []MisconfigFinding `json:"misconfigs,omitempty"`
}

// SecretFinding represents a detected secret
type SecretFinding struct {
	RuleID      string `json:"rule_id"`
	Category    string `json:"category"` // aws, generic, etc.
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	TargetFile  string `json:"target_file"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	Match       string `json:"match"` // Masked version of the secret
	Description string `json:"description,omitempty"`
}

// MisconfigFinding represents a detected misconfiguration
type MisconfigFinding struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // dockerfile, kubernetes, terraform, etc.
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Resolution  string `json:"resolution"`
	TargetFile  string `json:"target_file"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
}

// ScanFilesystem scans a filesystem path for vulnerabilities and issues
// This is typically used to scan a mounted container filesystem
func (c *Client) ScanFilesystem(ctx context.Context, path string, opts *ScanFilesystemOptions) (*FilesystemScanResult, error) {
	log := logger.FromContext(ctx)

	if !c.IsAvailable() {
		return nil, errors.New(errors.CodeTrivyError, "Trivy is not available")
	}

	if opts == nil {
		opts = DefaultFilesystemOptions()
	}

	log.Debug("Scanning filesystem", "path", path)
	start := time.Now()

	// Build command arguments
	args := []string{
		"filesystem",
		"--format", "json",
		"--quiet",
	}

	// Add severity filter
	if len(opts.Severities) > 0 {
		args = append(args, "--severity", strings.Join(opts.Severities, ","))
	}

	// Add cache directory
	if c.config.CacheDir != "" {
		args = append(args, "--cache-dir", c.config.CacheDir)
	}

	// Ignore unfixed
	if opts.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}

	// Secrets scanning
	if opts.ScanSecrets {
		args = append(args, "--scanners", "vuln,secret")
	}

	// Misconfig scanning
	if opts.ScanMisconfigs {
		args = append(args, "--scanners", "vuln,misconfig")
	}

	// Skip DB update if enabled
	if c.config.SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}

	// Add path to scan
	args = append(args, path)

	// Create command with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, c.config.BinaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if cmdCtx.Err() == context.DeadlineExceeded {
			return nil, errors.New(errors.CodeTimeout, "Filesystem scan timed out")
		}
		if stdout.Len() == 0 {
			return nil, errors.Wrap(err, errors.CodeTrivyError,
				fmt.Sprintf("Filesystem scan failed: %s", stderr.String()))
		}
	}

	// Parse results
	result := &FilesystemScanResult{
		Path:      path,
		ScannedAt: time.Now(),
		Duration:  time.Since(start),
	}

	var report FilesystemReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, errors.Wrap(err, errors.CodeTrivyError, "failed to parse filesystem scan output")
	}

	// Convert vulnerabilities
	result.Vulnerabilities = c.convertFilesystemVulns(report)

	// Convert secrets
	result.Secrets = c.convertSecrets(report)

	// Convert misconfigs
	result.Misconfigs = c.convertMisconfigs(report)

	log.Info("Filesystem scan completed",
		"path", path,
		"vulnerabilities", len(result.Vulnerabilities),
		"secrets", len(result.Secrets),
		"misconfigs", len(result.Misconfigs),
		"duration", result.Duration)

	return result, nil
}

// FilesystemReport represents the JSON output from Trivy filesystem scan
type FilesystemReport struct {
	SchemaVersion int                   `json:"SchemaVersion"`
	Results       []FilesystemResult    `json:"Results"`
}

// FilesystemResult represents results for a target in filesystem scan
type FilesystemResult struct {
	Target          string                 `json:"Target"`
	Class           string                 `json:"Class"`
	Type            string                 `json:"Type"`
	Vulnerabilities []TrivyVulnerability   `json:"Vulnerabilities,omitempty"`
	Secrets         []TrivySecret          `json:"Secrets,omitempty"`
	Misconfigurations []TrivyMisconfig     `json:"Misconfigurations,omitempty"`
}

// TrivySecret represents a secret found by Trivy
type TrivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Title     string `json:"Title"`
	Severity  string `json:"Severity"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

// TrivyMisconfig represents a misconfiguration found by Trivy
type TrivyMisconfig struct {
	ID          string `json:"ID"`
	Type        string `json:"Type"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Message     string `json:"Message"`
	Severity    string `json:"Severity"`
	Resolution  string `json:"Resolution"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
}

// convertFilesystemVulns converts filesystem vulnerabilities to security issues
func (c *Client) convertFilesystemVulns(report FilesystemReport) []security.Issue {
	var issues []security.Issue

	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			issue := security.Issue{
				CheckID:     models.CheckImageVulnerability,
				Severity:    mapTrivySeverity(vuln.Severity),
				Category:    models.IssueCategoryVulnerability,
				Title:       fmt.Sprintf("CVE: %s in %s", vuln.VulnerabilityID, vuln.PkgName),
				Description: truncateDescription(vuln.Description, 500),
				DocURL:      vuln.PrimaryURL,
				Penalty:     penaltyForCVESeverity(vuln.Severity),
				Details: map[string]interface{}{
					"cve_id":            vuln.VulnerabilityID,
					"package":           vuln.PkgName,
					"installed_version": vuln.InstalledVersion,
					"fixed_version":     vuln.FixedVersion,
					"target":            result.Target,
					"scan_type":         "filesystem",
				},
			}

			if vuln.FixedVersion != "" {
				issue.Recommendation = fmt.Sprintf("Update %s from %s to %s",
					vuln.PkgName, vuln.InstalledVersion, vuln.FixedVersion)
			}

			issues = append(issues, issue)
		}
	}

	return issues
}

// convertSecrets converts Trivy secrets to SecretFinding
func (c *Client) convertSecrets(report FilesystemReport) []SecretFinding {
	var secrets []SecretFinding

	for _, result := range report.Results {
		for _, secret := range result.Secrets {
			secrets = append(secrets, SecretFinding{
				RuleID:     secret.RuleID,
				Category:   secret.Category,
				Title:      secret.Title,
				Severity:   secret.Severity,
				TargetFile: result.Target,
				StartLine:  secret.StartLine,
				EndLine:    secret.EndLine,
				Match:      secret.Match,
			})
		}
	}

	return secrets
}

// convertMisconfigs converts Trivy misconfigurations to MisconfigFinding
func (c *Client) convertMisconfigs(report FilesystemReport) []MisconfigFinding {
	var misconfigs []MisconfigFinding

	for _, result := range report.Results {
		for _, mc := range result.Misconfigurations {
			misconfigs = append(misconfigs, MisconfigFinding{
				ID:          mc.ID,
				Type:        mc.Type,
				Title:       mc.Title,
				Description: mc.Description,
				Severity:    mc.Severity,
				Resolution:  mc.Resolution,
				TargetFile:  result.Target,
				StartLine:   mc.StartLine,
				EndLine:     mc.EndLine,
			})
		}
	}

	return misconfigs
}

// ============================================================================
// Scanning Policies
// ============================================================================

// ScanPolicy defines a policy for scanning
type ScanPolicy struct {
	Name                string   `json:"name"`
	BlockOnCritical     bool     `json:"block_on_critical"`
	BlockOnHigh         bool     `json:"block_on_high"`
	MaxCriticalCount    int      `json:"max_critical_count"`   // -1 for unlimited
	MaxHighCount        int      `json:"max_high_count"`       // -1 for unlimited
	MaxCVSSScore        float64  `json:"max_cvss_score"`       // Block if any CVE exceeds this
	AllowedCVEs         []string `json:"allowed_cves"`         // CVEs to ignore
	RequiredFixes       bool     `json:"required_fixes"`       // Only block if fix is available
}

// DefaultScanPolicy returns a default (permissive) scan policy
func DefaultScanPolicy() *ScanPolicy {
	return &ScanPolicy{
		Name:             "default",
		BlockOnCritical:  false,
		BlockOnHigh:      false,
		MaxCriticalCount: -1,
		MaxHighCount:     -1,
		MaxCVSSScore:     10.0,
		AllowedCVEs:      []string{},
		RequiredFixes:    false,
	}
}

// StrictScanPolicy returns a strict scan policy that blocks critical CVEs
func StrictScanPolicy() *ScanPolicy {
	return &ScanPolicy{
		Name:             "strict",
		BlockOnCritical:  true,
		BlockOnHigh:      true,
		MaxCriticalCount: 0,
		MaxHighCount:     5,
		MaxCVSSScore:     9.0,
		AllowedCVEs:      []string{},
		RequiredFixes:    true,
	}
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	PolicyName string   `json:"policy_name"`
	Reason     string   `json:"reason"`
	CVEs       []string `json:"cves,omitempty"`
	Blocked    bool     `json:"blocked"`
}

// EvaluatePolicy checks if scan results violate the given policy
func (c *Client) EvaluatePolicy(issues []security.Issue, policy *ScanPolicy) (*PolicyViolation, error) {
	if policy == nil {
		policy = DefaultScanPolicy()
	}

	// Build set of allowed CVEs
	allowedSet := make(map[string]bool)
	for _, cve := range policy.AllowedCVEs {
		allowedSet[cve] = true
	}

	var criticalCVEs, highCVEs []string
	var maxCVSS float64

	for _, issue := range issues {
		if issue.Category != models.IssueCategoryVulnerability {
			continue
		}

		cveID, _ := issue.Details["cve_id"].(string)
		if cveID == "" {
			continue
		}

		// Skip allowed CVEs
		if allowedSet[cveID] {
			continue
		}

		// Check if fix is required but not available
		if policy.RequiredFixes {
			fixedVersion, _ := issue.Details["fixed_version"].(string)
			if fixedVersion == "" {
				continue // Skip unfixed CVEs when RequiredFixes is set
			}
		}

		// Track CVSS score
		if cvss, ok := issue.Details["cvss_score"].(float64); ok && cvss > maxCVSS {
			maxCVSS = cvss
		}

		// Categorize by severity
		switch issue.Severity {
		case models.IssueSeverityCritical:
			criticalCVEs = append(criticalCVEs, cveID)
		case models.IssueSeverityHigh:
			highCVEs = append(highCVEs, cveID)
		}
	}

	// Check policy violations
	violation := &PolicyViolation{
		PolicyName: policy.Name,
		Blocked:    false,
	}

	// Check critical count
	if policy.BlockOnCritical && len(criticalCVEs) > 0 {
		violation.Blocked = true
		violation.Reason = fmt.Sprintf("Found %d critical CVE(s)", len(criticalCVEs))
		violation.CVEs = criticalCVEs
		return violation, nil
	}

	if policy.MaxCriticalCount >= 0 && len(criticalCVEs) > policy.MaxCriticalCount {
		violation.Blocked = true
		violation.Reason = fmt.Sprintf("Critical CVE count (%d) exceeds maximum (%d)", len(criticalCVEs), policy.MaxCriticalCount)
		violation.CVEs = criticalCVEs
		return violation, nil
	}

	// Check high count
	if policy.BlockOnHigh && len(highCVEs) > 0 {
		violation.Blocked = true
		violation.Reason = fmt.Sprintf("Found %d high severity CVE(s)", len(highCVEs))
		violation.CVEs = highCVEs
		return violation, nil
	}

	if policy.MaxHighCount >= 0 && len(highCVEs) > policy.MaxHighCount {
		violation.Blocked = true
		violation.Reason = fmt.Sprintf("High CVE count (%d) exceeds maximum (%d)", len(highCVEs), policy.MaxHighCount)
		violation.CVEs = highCVEs
		return violation, nil
	}

	// Check CVSS score
	if maxCVSS > policy.MaxCVSSScore {
		violation.Blocked = true
		violation.Reason = fmt.Sprintf("Maximum CVSS score (%.1f) exceeds policy limit (%.1f)", maxCVSS, policy.MaxCVSSScore)
		return violation, nil
	}

	return violation, nil
}

// ScanWithPolicy scans an image and evaluates it against a policy
func (c *Client) ScanWithPolicy(ctx context.Context, image string, policy *ScanPolicy) ([]security.Issue, *PolicyViolation, error) {
	issues, err := c.ScanImage(ctx, image)
	if err != nil {
		return nil, nil, err
	}

	violation, err := c.EvaluatePolicy(issues, policy)
	if err != nil {
		return issues, nil, err
	}

	return issues, violation, nil
}
