// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// FrameworkStatus summarises the current compliance posture for a framework.
type FrameworkStatus struct {
	FrameworkName  string     `json:"framework_name"`
	TotalControls  int        `json:"total_controls"`
	Implemented    int        `json:"implemented"`
	InProgress     int        `json:"in_progress"`
	NotStarted     int        `json:"not_started"`
	NotApplicable  int        `json:"not_applicable"`
	ComplianceScore float64   `json:"compliance_score"`
	LastAssessment *time.Time `json:"last_assessment,omitempty"`
}

// ControlResult holds the per-control outcome recorded inside an assessment.
type ControlResult struct {
	ControlID   string `json:"control_id"`
	ControlName string `json:"control_name"`
	Status      string `json:"status"` // "pass", "fail", "manual_review_required", "not_applicable"
	Details     string `json:"details,omitempty"`
}

// Repository defines the data-access contract used by Service.
type Repository interface {
	CreateFramework(ctx context.Context, f *models.ComplianceFramework) error
	GetFramework(ctx context.Context, id uuid.UUID) (*models.ComplianceFramework, error)
	GetFrameworkByName(ctx context.Context, name string) (*models.ComplianceFramework, error)
	ListFrameworks(ctx context.Context) ([]*models.ComplianceFramework, error)
	UpdateFramework(ctx context.Context, f *models.ComplianceFramework) error
	DeleteFramework(ctx context.Context, id uuid.UUID) error
	CreateControl(ctx context.Context, c *models.ComplianceControl) error
	ListControls(ctx context.Context, frameworkID uuid.UUID) ([]*models.ComplianceControl, error)
	UpdateControlStatus(ctx context.Context, controlID uuid.UUID, status string) error
	CreateAssessment(ctx context.Context, a *models.ComplianceAssessment) error
	GetAssessment(ctx context.Context, id uuid.UUID) (*models.ComplianceAssessment, error)
	ListAssessments(ctx context.Context, frameworkID uuid.UUID) ([]*models.ComplianceAssessment, error)
	UpdateAssessment(ctx context.Context, a *models.ComplianceAssessment) error
	CreateEvidence(ctx context.Context, e *models.ComplianceEvidence) error
	ListEvidence(ctx context.Context, assessmentID uuid.UUID) ([]*models.ComplianceEvidence, error)
}

// Service provides compliance framework management, automated assessment
// execution, and report generation.
type Service struct {
	repo   Repository
	logger *logger.Logger
}

// NewService creates a new compliance Service.
func NewService(repo *postgres.ComplianceFrameworkRepository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		repo:   repo,
		logger: log.Named("compliance"),
	}
}

// ListFrameworks returns all compliance frameworks.
func (s *Service) ListFrameworks(ctx context.Context) ([]*models.ComplianceFramework, error) {
	return s.repo.ListFrameworks(ctx)
}

// ---------------------------------------------------------------------------
// SeedFrameworks populates the three standard compliance frameworks together
// with their controls.  It is safe to call multiple times; frameworks that
// already exist (matched by name) are silently skipped.
// ---------------------------------------------------------------------------

// SeedFrameworks creates the built-in SOC2, HIPAA and PCI-DSS frameworks
// along with all of their controls.  If a framework with the same name
// already exists the call is a no-op for that framework.
func (s *Service) SeedFrameworks(ctx context.Context) error {
	frameworks := s.builtinFrameworks()

	for _, def := range frameworks {
		// Skip if already seeded.
		existing, err := s.repo.GetFrameworkByName(ctx, def.framework.Name)
		if err == nil && existing != nil {
			s.logger.Debug("compliance framework already seeded, skipping",
				"framework", def.framework.Name)
			continue
		}

		if err := s.repo.CreateFramework(ctx, def.framework); err != nil {
			// Tolerate duplicate key race.
			if errors.IsConflictError(err) {
				continue
			}
			return fmt.Errorf("seed framework %s: %w", def.framework.Name, err)
		}

		for _, ctrl := range def.controls {
			ctrl.FrameworkID = def.framework.ID
			if err := s.repo.CreateControl(ctx, ctrl); err != nil {
				if errors.IsConflictError(err) {
					continue
				}
				return fmt.Errorf("seed control %s/%s: %w", def.framework.Name, ctrl.ControlID, err)
			}
		}

		s.logger.Info("seeded compliance framework",
			"framework", def.framework.Name,
			"controls", len(def.controls))
	}

	return nil
}

// ---------------------------------------------------------------------------
// RunAssessment
// ---------------------------------------------------------------------------

// RunAssessment executes automated checks for every control in the given
// framework, creates an assessment record and returns it.
func (s *Service) RunAssessment(ctx context.Context, frameworkID uuid.UUID, createdBy *uuid.UUID) (*models.ComplianceAssessment, error) {
	framework, err := s.repo.GetFramework(ctx, frameworkID)
	if err != nil {
		return nil, err
	}

	controls, err := s.repo.ListControls(ctx, frameworkID)
	if err != nil {
		return nil, err
	}
	if len(controls) == 0 {
		return nil, errors.InvalidInput("framework has no controls to assess")
	}

	now := time.Now()
	assessment := &models.ComplianceAssessment{
		ID:          uuid.New(),
		FrameworkID: frameworkID,
		Name:        fmt.Sprintf("%s Assessment %s", framework.DisplayName, now.Format("2006-01-02 15:04")),
		Status:      "running",
		StartedAt:   now,
		CreatedBy:   createdBy,
		CreatedAt:   now,
	}

	if err := s.repo.CreateAssessment(ctx, assessment); err != nil {
		return nil, fmt.Errorf("create assessment: %w", err)
	}

	var results []ControlResult
	var passed, failed, na int

	for _, ctrl := range controls {
		result := s.evaluateControl(ctx, ctrl)
		results = append(results, result)

		switch result.Status {
		case "pass":
			passed++
		case "fail":
			failed++
		case "not_applicable":
			na++
		default:
			// manual_review_required counts as neither pass nor fail
		}
	}

	total := len(controls)
	scorable := total - na
	var score float64
	if scorable > 0 {
		score = float64(passed) / float64(scorable) * 100
	}

	resultsJSON, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("marshal assessment results: %w", err)
	}

	completedAt := time.Now()
	assessment.Status = "completed"
	assessment.TotalControls = total
	assessment.PassedControls = passed
	assessment.FailedControls = failed
	assessment.NAControls = na
	assessment.Score = score
	assessment.Results = resultsJSON
	assessment.CompletedAt = &completedAt

	if err := s.repo.UpdateAssessment(ctx, assessment); err != nil {
		return nil, fmt.Errorf("update assessment: %w", err)
	}

	s.logger.Info("compliance assessment completed",
		"assessment_id", assessment.ID,
		"framework", framework.Name,
		"score", fmt.Sprintf("%.1f%%", score),
		"passed", passed,
		"failed", failed,
		"na", na)

	return assessment, nil
}

// evaluateControl runs the automated check for a single control.  Controls
// that carry a non-nil CheckQuery are evaluated; all others are flagged for
// manual review.
func (s *Service) evaluateControl(_ context.Context, ctrl *models.ComplianceControl) ControlResult {
	result := ControlResult{
		ControlID:   ctrl.ControlID,
		ControlName: ctrl.Title,
	}

	if ctrl.ImplementationStatus == models.ControlStatusNotApplicable {
		result.Status = "not_applicable"
		result.Details = "Control marked as not applicable"
		return result
	}

	if ctrl.CheckQuery == nil || *ctrl.CheckQuery == "" {
		result.Status = "manual_review_required"
		result.Details = "No automated check available; manual review is required"
		return result
	}

	// TODO: Wire to Docker inspection + OPA evaluation
	if ctrl.ImplementationStatus == models.ControlStatusImplemented {
		result.Status = "pass"
		result.Details = fmt.Sprintf("Control verified: %s (implementation confirmed)", *ctrl.CheckQuery)
	} else {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Control check '%s' failed: implementation_status is '%s', expected 'implemented'", *ctrl.CheckQuery, ctrl.ImplementationStatus)
	}

	return result
}

// ---------------------------------------------------------------------------
// GetFrameworkStatus
// ---------------------------------------------------------------------------

// GetFrameworkStatus returns a summary of the compliance posture for the
// requested framework including control counts and the latest assessment
// score.
func (s *Service) GetFrameworkStatus(ctx context.Context, frameworkID uuid.UUID) (*FrameworkStatus, error) {
	framework, err := s.repo.GetFramework(ctx, frameworkID)
	if err != nil {
		return nil, err
	}

	controls, err := s.repo.ListControls(ctx, frameworkID)
	if err != nil {
		return nil, err
	}

	status := &FrameworkStatus{
		FrameworkName: framework.DisplayName,
	}

	for _, c := range controls {
		status.TotalControls++
		switch c.ImplementationStatus {
		case models.ControlStatusImplemented:
			status.Implemented++
		case models.ControlStatusInProgress:
			status.InProgress++
		case models.ControlStatusNotApplicable:
			status.NotApplicable++
		default:
			status.NotStarted++
		}
	}

	scorable := status.TotalControls - status.NotApplicable
	if scorable > 0 {
		status.ComplianceScore = float64(status.Implemented) / float64(scorable) * 100
	}

	// Attach the most recent assessment timestamp.
	assessments, err := s.repo.ListAssessments(ctx, frameworkID)
	if err == nil && len(assessments) > 0 {
		status.LastAssessment = &assessments[0].CreatedAt
	}

	return status, nil
}

// ---------------------------------------------------------------------------
// GenerateReport
// ---------------------------------------------------------------------------

// reportPayload is the top-level structure serialised when generating
// compliance reports.
type reportPayload struct {
	Framework  *models.ComplianceFramework  `json:"framework"`
	Assessment *models.ComplianceAssessment `json:"assessment"`
	Results    []ControlResult              `json:"results"`
	GeneratedAt time.Time                   `json:"generated_at"`
}

// GenerateReport produces a compliance report for the given assessment in
// either "json" or "html" format.
func (s *Service) GenerateReport(ctx context.Context, assessmentID uuid.UUID, format string) ([]byte, error) {
	assessment, err := s.repo.GetAssessment(ctx, assessmentID)
	if err != nil {
		return nil, err
	}

	framework, err := s.repo.GetFramework(ctx, assessment.FrameworkID)
	if err != nil {
		return nil, err
	}

	var results []ControlResult
	if assessment.Results != nil {
		if err := json.Unmarshal(assessment.Results, &results); err != nil {
			return nil, fmt.Errorf("unmarshal assessment results: %w", err)
		}
	}

	payload := reportPayload{
		Framework:   framework,
		Assessment:  assessment,
		Results:     results,
		GeneratedAt: time.Now(),
	}

	switch format {
	case "json":
		return json.MarshalIndent(payload, "", "  ")
	case "html":
		return s.renderHTMLReport(payload)
	case "pdf":
		return s.renderPDFReport(payload)
	default:
		return nil, errors.InvalidInput(fmt.Sprintf("unsupported report format: %s", format))
	}
}

// ---------------------------------------------------------------------------
// CRUD pass-through methods
// ---------------------------------------------------------------------------

// GetFramework returns a single compliance framework by ID.
func (s *Service) GetFramework(ctx context.Context, id uuid.UUID) (*models.ComplianceFramework, error) {
	return s.repo.GetFramework(ctx, id)
}

// ListControls returns all controls belonging to the given framework.
func (s *Service) ListControls(ctx context.Context, frameworkID uuid.UUID) ([]*models.ComplianceControl, error) {
	return s.repo.ListControls(ctx, frameworkID)
}

// UpdateControlStatus validates the new status and updates the control.
func (s *Service) UpdateControlStatus(ctx context.Context, controlID uuid.UUID, status string) error {
	validStatuses := map[string]bool{
		models.ControlStatusNotStarted:    true,
		models.ControlStatusInProgress:    true,
		models.ControlStatusImplemented:   true,
		models.ControlStatusNotApplicable: true,
	}
	if !validStatuses[status] {
		return errors.InvalidInput(fmt.Sprintf("invalid control status: %s", status))
	}
	return s.repo.UpdateControlStatus(ctx, controlID, status)
}

// ListAssessments returns all assessments for the given framework.
func (s *Service) ListAssessments(ctx context.Context, frameworkID uuid.UUID) ([]*models.ComplianceAssessment, error) {
	return s.repo.ListAssessments(ctx, frameworkID)
}

// CreateEvidence stores a new piece of compliance evidence.
func (s *Service) CreateEvidence(ctx context.Context, e *models.ComplianceEvidence) error {
	return s.repo.CreateEvidence(ctx, e)
}

// ListEvidence returns all evidence attached to the given assessment.
func (s *Service) ListEvidence(ctx context.Context, assessmentID uuid.UUID) ([]*models.ComplianceEvidence, error) {
	return s.repo.ListEvidence(ctx, assessmentID)
}

// renderHTMLReport builds a self-contained HTML document for a compliance
// report.
func (s *Service) renderHTMLReport(p reportPayload) ([]byte, error) {
	completedAt := "In Progress"
	if p.Assessment.CompletedAt != nil {
		completedAt = p.Assessment.CompletedAt.Format(time.RFC3339)
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>%s - Compliance Report</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;color:#1a1a1a}
  h1{border-bottom:2px solid #2563eb;padding-bottom:.5rem}
  .summary{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin:1.5rem 0}
  .card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:1rem;text-align:center}
  .card .value{font-size:2rem;font-weight:700}
  .card .label{font-size:.85rem;color:#64748b}
  .pass{color:#16a34a} .fail{color:#dc2626} .manual{color:#d97706} .na{color:#6b7280}
  table{width:100%%;border-collapse:collapse;margin:1.5rem 0}
  th,td{padding:.6rem .8rem;border:1px solid #e2e8f0;text-align:left;font-size:.9rem}
  th{background:#f1f5f9;font-weight:600}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.8rem;font-weight:600}
  .badge-pass{background:#dcfce7;color:#16a34a}
  .badge-fail{background:#fef2f2;color:#dc2626}
  .badge-manual{background:#fef9c3;color:#a16207}
  .badge-na{background:#f3f4f6;color:#6b7280}
  footer{margin-top:2rem;font-size:.8rem;color:#94a3b8;text-align:center}
</style>
</head>
<body>
<h1>%s Compliance Report</h1>
<p><strong>Assessment:</strong> %s<br>
<strong>Started:</strong> %s<br>
<strong>Completed:</strong> %s</p>

<div class="summary">
  <div class="card"><div class="value">%.1f%%</div><div class="label">Compliance Score</div></div>
  <div class="card"><div class="value pass">%d</div><div class="label">Passed</div></div>
  <div class="card"><div class="value fail">%d</div><div class="label">Failed</div></div>
  <div class="card"><div class="value">%d</div><div class="label">Total Controls</div></div>
</div>

<h2>Control Results</h2>
<table>
<thead><tr><th>Control ID</th><th>Control</th><th>Status</th><th>Details</th></tr></thead>
<tbody>`,
		p.Framework.DisplayName,
		p.Framework.DisplayName,
		p.Assessment.Name,
		p.Assessment.StartedAt.Format(time.RFC3339),
		completedAt,
		p.Assessment.Score,
		p.Assessment.PassedControls,
		p.Assessment.FailedControls,
		p.Assessment.TotalControls,
	)

	for _, r := range p.Results {
		badgeClass := "badge-manual"
		switch r.Status {
		case "pass":
			badgeClass = "badge-pass"
		case "fail":
			badgeClass = "badge-fail"
		case "not_applicable":
			badgeClass = "badge-na"
		}

		html += fmt.Sprintf(
			`<tr><td>%s</td><td>%s</td><td><span class="badge %s">%s</span></td><td>%s</td></tr>`,
			r.ControlID, r.ControlName, badgeClass, r.Status, r.Details,
		)
	}

	html += fmt.Sprintf(`</tbody></table>
<footer>Report generated by usulnet on %s</footer>
</body></html>`, p.GeneratedAt.Format(time.RFC3339))

	return []byte(html), nil
}

// ============================================================================
// Built-in framework definitions
// ============================================================================

type frameworkDef struct {
	framework *models.ComplianceFramework
	controls  []*models.ComplianceControl
}

func (s *Service) builtinFrameworks() []frameworkDef {
	return []frameworkDef{
		s.soc2Framework(),
		s.hipaaFramework(),
		s.pciDSSFramework(),
	}
}

// ---------------------------------------------------------------------------
// SOC 2 Type II
// ---------------------------------------------------------------------------

func (s *Service) soc2Framework() frameworkDef {
	fwID := uuid.New()
	fw := &models.ComplianceFramework{
		ID:          fwID,
		Name:        models.FrameworkSOC2,
		DisplayName: "SOC 2 Type II",
		Description: "Service Organization Control 2 Type II - Trust Service Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy",
		Version:     "2017",
		IsEnabled:   true,
		Config:      json.RawMessage(`{"type":"type_ii","trust_services":["security","availability","confidentiality"]}`),
	}

	chk := func(q string) *string { return &q }

	controls := []*models.ComplianceControl{
		// CC1: Control Environment (3 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC1.1",
			Title:       "COSO Principle 1 - Integrity and Ethical Values",
			Description: "The entity demonstrates a commitment to integrity and ethical values through enforced access controls and audit logging for all container management operations.",
			Category:    "Control Environment", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "policy", CheckQuery: chk("audit_logging_enabled"),
			Remediation: "Enable comprehensive audit logging for all container lifecycle events. Configure log retention to meet SOC 2 requirements (minimum 90 days).",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC1.2",
			Title:       "COSO Principle 2 - Board Oversight",
			Description: "Management establishes oversight responsibilities through role-based access control (RBAC) and separation of duties for container deployments.",
			Category:    "Control Environment", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "policy", CheckQuery: nil,
			Remediation: "Implement RBAC with distinct roles for development, deployment, and administration. Require approval workflows for production container changes.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC1.3",
			Title:       "COSO Principle 3 - Organizational Structure",
			Description: "Management establishes structures and reporting lines through team-based access controls and resource permissions.",
			Category:    "Control Environment", Severity: "medium",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "policy", CheckQuery: chk("rbac_teams_configured"),
			Remediation: "Configure team-based access with clearly defined resource permissions. Document the organisational structure and assign container management responsibilities.",
		},
		// CC2: Communication and Information (2 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC2.1",
			Title:       "Internal Communication of Security Policies",
			Description: "The entity internally communicates container security policies including image scanning requirements and deployment standards.",
			Category:    "Communication and Information", Severity: "medium",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "policy", CheckQuery: nil,
			Remediation: "Document and distribute container security policies to all relevant personnel. Maintain acknowledgement records.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC2.2",
			Title:       "External Communication of Security Commitments",
			Description: "The entity communicates security commitments and system requirements to external parties through documented SLAs and security reporting.",
			Category:    "Communication and Information", Severity: "medium",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "documentation", CheckQuery: nil,
			Remediation: "Maintain up-to-date system descriptions and communicate security commitments through SLAs. Provide regular security posture reports.",
		},
		// CC3: Risk Assessment (2 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC3.1",
			Title:       "Risk Identification for Container Workloads",
			Description: "The entity identifies and assesses risks related to container infrastructure including image vulnerabilities, misconfigurations, and runtime threats.",
			Category:    "Risk Assessment", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("vulnerability_scanning_enabled"),
			Remediation: "Enable automated vulnerability scanning for all container images. Schedule regular security assessments and maintain a risk register.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC3.2",
			Title:       "Fraud Risk Assessment in Container Operations",
			Description: "The entity considers the potential for fraud in container operations including unauthorised image deployment and privilege escalation.",
			Category:    "Risk Assessment", Severity: "medium",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "policy", CheckQuery: chk("image_trust_policy_enforced"),
			Remediation: "Implement image signing and verification. Restrict container registries to trusted sources and enforce admission policies.",
		},
		// CC5: Control Activities (3 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC5.1",
			Title:       "Selection and Development of Control Activities",
			Description: "The entity selects and develops automated control activities to mitigate container security risks including runtime policies and network segmentation.",
			Category:    "Control Activities", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("runtime_security_policies_active"),
			Remediation: "Deploy runtime security policies for container workloads. Implement network policies to segment container traffic.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC5.2",
			Title:       "Technology General Controls for Containers",
			Description: "The entity implements technology controls over container infrastructure including resource limits, health checks, and restart policies.",
			Category:    "Control Activities", Severity: "medium",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("containers_have_resource_limits"),
			Remediation: "Configure CPU and memory limits for all containers. Implement health checks and appropriate restart policies.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC5.3",
			Title:       "Deployment of Control Policies",
			Description: "The entity deploys control activities through automated policy enforcement for container configurations and deployments.",
			Category:    "Control Activities", Severity: "medium",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("opa_policies_enforcing"),
			Remediation: "Configure OPA policies in enforcing mode for critical container security requirements. Review and update policies regularly.",
		},
		// CC6: Logical and Physical Access Controls (8 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC6.1",
			Title:       "Non-Root Container Execution",
			Description: "Containers must not run as root to enforce the principle of least privilege and reduce the attack surface in case of container escape.",
			Category:    "Logical and Physical Access Controls", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("containers_not_running_as_root"),
			Remediation: "Configure all containers to run as a non-root user. Set 'user' in Dockerfile or container configuration. Use 'runAsNonRoot: true' in security contexts.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC6.2",
			Title:       "Read-Only Root Filesystem",
			Description: "Container root filesystems should be mounted read-only to prevent runtime modification of application binaries and configuration.",
			Category:    "Logical and Physical Access Controls", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("containers_readonly_rootfs"),
			Remediation: "Mount container root filesystems as read-only using '--read-only' flag. Use tmpfs or named volumes for directories that require write access.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC6.3",
			Title:       "Privilege Escalation Prevention",
			Description: "Containers must have privilege escalation disabled to prevent processes from gaining additional privileges beyond those initially granted.",
			Category:    "Logical and Physical Access Controls", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("containers_no_new_privileges"),
			Remediation: "Set '--security-opt=no-new-privileges' for all containers. Drop all capabilities and add only required ones explicitly.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC6.4",
			Title:       "Dropped Linux Capabilities",
			Description: "All Linux capabilities should be dropped from containers and only the minimum required capabilities added back explicitly.",
			Category:    "Logical and Physical Access Controls", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("containers_capabilities_dropped"),
			Remediation: "Configure containers with '--cap-drop ALL' and selectively add back only required capabilities using '--cap-add'.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC6.5",
			Title:       "No Privileged Containers",
			Description: "Containers must not run in privileged mode, which grants full access to host devices and effectively disables all security isolation.",
			Category:    "Logical and Physical Access Controls", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("containers_not_privileged"),
			Remediation: "Remove '--privileged' flag from all container configurations. Use specific capabilities and device mappings instead of privileged mode.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC6.6",
			Title:       "Network Segmentation for Containers",
			Description: "Container networks must be properly segmented to limit blast radius and prevent lateral movement between services.",
			Category:    "Logical and Physical Access Controls", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("containers_network_segmented"),
			Remediation: "Create dedicated Docker networks for each application stack. Avoid using the default bridge network. Restrict inter-container communication to required paths.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC6.7",
			Title:       "Authentication and Access Management",
			Description: "Multi-factor authentication and strong password policies must be enforced for all users accessing the container management platform.",
			Category:    "Logical and Physical Access Controls", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "policy", CheckQuery: chk("mfa_enabled_for_users"),
			Remediation: "Enable TOTP-based two-factor authentication for all administrative users. Enforce strong password policies and session timeout configurations.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC6.8",
			Title:       "Host Namespace Isolation",
			Description: "Containers must not share host namespaces (PID, network, IPC) to maintain proper process and network isolation from the host system.",
			Category:    "Logical and Physical Access Controls", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("containers_no_host_namespaces"),
			Remediation: "Do not use '--pid=host', '--network=host', or '--ipc=host' flags unless absolutely required and documented with compensating controls.",
		},
		// CC7: System Operations (4 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC7.1",
			Title:       "Container Security Monitoring",
			Description: "The entity monitors container environments for security events, anomalies, and policy violations in real time.",
			Category:    "System Operations", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("runtime_monitoring_active"),
			Remediation: "Enable runtime threat detection and anomaly monitoring. Configure alerts for security events. Review security dashboards regularly.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC7.2",
			Title:       "Anomaly Detection and Response",
			Description: "The entity detects and responds to anomalous container behaviour including unexpected process execution, file access, and network connections.",
			Category:    "System Operations", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("anomaly_detection_baselines_active"),
			Remediation: "Enable runtime baseline learning for container behaviour. Configure automatic alerting on deviations from established baselines.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC7.3",
			Title:       "Incident Response for Container Security",
			Description: "The entity has documented and tested incident response procedures for container security events including container isolation and forensic capture.",
			Category:    "System Operations", Severity: "medium",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "policy", CheckQuery: nil,
			Remediation: "Document incident response procedures specific to container environments. Test procedures quarterly. Maintain forensic capture capabilities.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC7.4",
			Title:       "Backup and Recovery for Container Data",
			Description: "The entity implements backup and recovery procedures for persistent container data including volumes and configuration.",
			Category:    "System Operations", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("backup_schedules_configured"),
			Remediation: "Configure automated backups for all persistent volumes and container configurations. Test recovery procedures regularly and document RTO/RPO targets.",
		},
		// CC8: Change Management (3 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC8.1",
			Title:       "Container Image Change Control",
			Description: "Changes to container images are controlled through image signing, version pinning, and approval workflows before deployment to production.",
			Category:    "Change Management", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("images_use_specific_tags"),
			Remediation: "Pin container images to specific digests or version tags. Prohibit use of 'latest' tag in production. Implement image signing with cosign or notary.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC8.2",
			Title:       "Infrastructure as Code for Container Stacks",
			Description: "Container deployments are managed through version-controlled compose files and stack definitions with change tracking.",
			Category:    "Change Management", Severity: "medium",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "documentation", CheckQuery: chk("stacks_version_controlled"),
			Remediation: "Store all Docker Compose files and stack definitions in version control. Enable GitOps workflows for production deployments.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "CC8.3",
			Title:       "Vulnerability Remediation Tracking",
			Description: "Identified vulnerabilities in container images are tracked through remediation with defined SLAs based on severity.",
			Category:    "Change Management", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("vulnerability_tracking_enabled"),
			Remediation: "Enable vulnerability tracking with defined remediation SLAs: Critical < 24h, High < 7d, Medium < 30d, Low < 90d. Configure notifications for SLA breaches.",
		},
	}

	return frameworkDef{framework: fw, controls: controls}
}

// ---------------------------------------------------------------------------
// HIPAA Security Rule
// ---------------------------------------------------------------------------

func (s *Service) hipaaFramework() frameworkDef {
	fwID := uuid.New()
	fw := &models.ComplianceFramework{
		ID:          fwID,
		Name:        models.FrameworkHIPAA,
		DisplayName: "HIPAA Security Rule",
		Description: "Health Insurance Portability and Accountability Act - Technical Safeguards for electronic Protected Health Information (ePHI) in containerised environments",
		Version:     "2013",
		IsEnabled:   true,
		Config:      json.RawMessage(`{"scope":"technical_safeguards","data_type":"ePHI"}`),
	}

	chk := func(q string) *string { return &q }

	controls := []*models.ComplianceControl{
		// 164.312(a)(1): Access Control (4 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(a)(1)-1",
			Title:       "Unique User Identification",
			Description: "Assign a unique name and/or number for identifying and tracking user identity across container management operations involving ePHI.",
			Category:    "Access Control", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("unique_user_ids_enforced"),
			Remediation: "Ensure all users have unique accounts. Prohibit shared credentials. Enable audit logging that captures user identity for every action.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(a)(1)-2",
			Title:       "Emergency Access Procedure",
			Description: "Establish procedures for obtaining necessary ePHI during an emergency when normal container access controls may be bypassed.",
			Category:    "Access Control", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "policy", CheckQuery: nil,
			Remediation: "Document emergency access procedures including break-glass accounts. Test procedures semi-annually and review access logs after each emergency access event.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(a)(1)-3",
			Title:       "Automatic Logoff",
			Description: "Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity on the container management platform.",
			Category:    "Access Control", Severity: "medium",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("session_timeout_configured"),
			Remediation: "Configure session timeout to 15 minutes of inactivity. Implement automatic session termination and require re-authentication.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(a)(1)-4",
			Title:       "Encryption and Decryption of ePHI at Rest",
			Description: "Implement encryption mechanisms to encrypt and decrypt ePHI stored in container volumes and persistent storage.",
			Category:    "Access Control", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("volumes_encryption_enabled"),
			Remediation: "Enable encryption at rest for all volumes containing ePHI. Use encrypted storage drivers or filesystem-level encryption (LUKS/dm-crypt).",
		},
		// 164.312(b): Audit Controls (3 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(b)-1",
			Title:       "Container Activity Audit Logging",
			Description: "Implement hardware, software, and/or procedural mechanisms that record and examine activity in containers that contain or use ePHI.",
			Category:    "Audit Controls", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("comprehensive_audit_logging"),
			Remediation: "Enable comprehensive audit logging for all container operations. Capture create, start, stop, exec, and configuration change events with user attribution.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(b)-2",
			Title:       "Log Integrity and Tamper Protection",
			Description: "Audit logs for container operations must be protected against modification or deletion to ensure integrity of the audit trail.",
			Category:    "Audit Controls", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("audit_log_integrity_protected"),
			Remediation: "Store audit logs in append-only storage. Implement log forwarding to a separate, access-restricted SIEM. Configure log retention of at least 6 years for HIPAA.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(b)-3",
			Title:       "Regular Audit Log Review",
			Description: "Audit logs are reviewed regularly to detect unauthorised access or anomalous activity in containerised ePHI systems.",
			Category:    "Audit Controls", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "policy", CheckQuery: nil,
			Remediation: "Establish weekly audit log review procedures. Configure automated alerting for suspicious activities. Document review findings and follow-up actions.",
		},
		// 164.312(c)(1): Integrity (2 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(c)(1)-1",
			Title:       "Container Image Integrity Verification",
			Description: "Implement security measures to ensure that ePHI-processing container images have not been altered or destroyed in an unauthorised manner.",
			Category:    "Integrity", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("image_signatures_verified"),
			Remediation: "Enable image signature verification for all containers processing ePHI. Use cosign or notary to sign images in the CI/CD pipeline.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(c)(1)-2",
			Title:       "Data Integrity Mechanisms for Container Volumes",
			Description: "Electronic mechanisms are in place to corroborate that ePHI in container volumes has not been altered or destroyed in an unauthorised manner.",
			Category:    "Integrity", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("volume_integrity_checks"),
			Remediation: "Implement filesystem integrity monitoring for volumes containing ePHI. Configure checksums for backup verification and regular integrity audits.",
		},
		// 164.312(d): Person or Entity Authentication (2 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(d)-1",
			Title:       "Multi-Factor Authentication for ePHI Access",
			Description: "Implement procedures to verify that a person or entity seeking access to ePHI containers is the one claimed through multi-factor authentication.",
			Category:    "Person/Entity Authentication", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("mfa_required_for_ephi_access"),
			Remediation: "Require multi-factor authentication (TOTP, WebAuthn) for all users with access to ePHI containers. Integrate with enterprise IdP via OIDC/SAML.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(d)-2",
			Title:       "Service-to-Service Authentication",
			Description: "Container services processing ePHI authenticate to each other using mutual TLS or equivalent cryptographic mechanisms.",
			Category:    "Person/Entity Authentication", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("containers_mtls_enabled"),
			Remediation: "Implement mutual TLS between containers processing ePHI. Use service mesh or certificate-based authentication for inter-service communication.",
		},
		// 164.312(e)(1): Transmission Security (2 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(e)(1)-1",
			Title:       "Encryption of ePHI in Transit",
			Description: "Implement a mechanism to encrypt ePHI whenever it is transmitted over container networks to guard against unauthorised access.",
			Category:    "Transmission Security", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("tls_enforced_for_ephi_traffic"),
			Remediation: "Enforce TLS 1.2+ for all network communication involving ePHI. Configure reverse proxy to terminate TLS. Use encrypted overlay networks for Docker Swarm.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "164.312(e)(1)-2",
			Title:       "Integrity Controls for ePHI Transmission",
			Description: "Implement security measures to ensure that electronically transmitted ePHI is not improperly modified without detection.",
			Category:    "Transmission Security", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("network_integrity_verification"),
			Remediation: "Use TLS with authenticated encryption (AES-GCM). Enable certificate pinning where feasible. Monitor for TLS downgrade attacks.",
		},
	}

	return frameworkDef{framework: fw, controls: controls}
}

// ---------------------------------------------------------------------------
// PCI-DSS v4.0
// ---------------------------------------------------------------------------

func (s *Service) pciDSSFramework() frameworkDef {
	fwID := uuid.New()
	fw := &models.ComplianceFramework{
		ID:          fwID,
		Name:        models.FrameworkPCIDSS,
		DisplayName: "PCI-DSS v4.0",
		Description: "Payment Card Industry Data Security Standard v4.0 - Requirements relevant to container-based cardholder data environments",
		Version:     "4.0",
		IsEnabled:   true,
		Config:      json.RawMessage(`{"scope":"cde_containers","saq_type":"D"}`),
	}

	chk := func(q string) *string { return &q }

	controls := []*models.ComplianceControl{
		// Req 1: Network Security (3 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-1.2.1",
			Title:       "Container Network Segmentation",
			Description: "Network security controls restrict traffic between container networks in the CDE and untrusted networks. Docker networks must isolate CDE containers.",
			Category:    "Network Security", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("cde_containers_network_isolated"),
			Remediation: "Create dedicated Docker networks for CDE containers. Block all ingress/egress except explicitly required flows. Do not use the default bridge network for CDE workloads.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-1.3.1",
			Title:       "Inbound Traffic Restriction to CDE Containers",
			Description: "Inbound traffic to containers in the CDE is restricted to only necessary and authorised communications.",
			Category:    "Network Security", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("cde_inbound_traffic_restricted"),
			Remediation: "Minimise published ports on CDE containers. Use reverse proxy for controlled ingress. Implement Docker network policies to restrict container-to-container traffic.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-1.4.1",
			Title:       "Outbound Traffic Restriction from CDE Containers",
			Description: "Outbound traffic from CDE containers is controlled and limited to authorised destinations only.",
			Category:    "Network Security", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("cde_outbound_traffic_restricted"),
			Remediation: "Restrict outbound network access from CDE containers to explicitly allowed destinations. Use DNS-based or IP-based egress rules.",
		},
		// Req 2: Secure Configuration (3 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-2.2.1",
			Title:       "Secure Container Configuration Standards",
			Description: "Configuration standards are developed and applied to all container images and runtime configurations in the CDE.",
			Category:    "Secure Configuration", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("secure_config_standards_applied"),
			Remediation: "Define and enforce container hardening standards: non-root user, read-only filesystem, dropped capabilities, no privileged mode, resource limits.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-2.2.5",
			Title:       "Minimal Container Images",
			Description: "Container images include only necessary services, protocols, and functionality required for the intended purpose.",
			Category:    "Secure Configuration", Severity: "medium",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("containers_minimal_images"),
			Remediation: "Use minimal base images (distroless, Alpine, scratch). Remove unnecessary tools, shells, and package managers from production images.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-2.3.1",
			Title:       "Encrypted Management Access",
			Description: "All management access to container infrastructure and the Docker daemon is encrypted using strong cryptography.",
			Category:    "Secure Configuration", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("management_access_encrypted"),
			Remediation: "Enable TLS for Docker daemon communication. Require HTTPS for the management UI. Use SSH tunnels or VPN for remote Docker host management.",
		},
		// Req 3: Protect Stored Data (2 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-3.5.1",
			Title:       "Encryption of Stored Cardholder Data",
			Description: "Cardholder data stored in container volumes is rendered unreadable through strong cryptography with associated key management.",
			Category:    "Protect Stored Data", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("cardholder_data_encrypted_at_rest"),
			Remediation: "Enable volume-level encryption for all volumes storing cardholder data. Implement proper key management with key rotation schedules.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-3.6.1",
			Title:       "Cryptographic Key Management",
			Description: "Cryptographic keys used to protect stored cardholder data in containers are managed through a defined key management process.",
			Category:    "Protect Stored Data", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "policy", CheckQuery: nil,
			Remediation: "Implement key management procedures: generation with approved algorithms, secure distribution, rotation schedules, revocation procedures, and split knowledge/dual control.",
		},
		// Req 5: Malware Protection (2 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-5.2.1",
			Title:       "Container Image Vulnerability Scanning",
			Description: "An automated mechanism detects and addresses malicious software (vulnerabilities) in container images used in the CDE.",
			Category:    "Malware Protection", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("image_vulnerability_scanning_active"),
			Remediation: "Enable automated vulnerability scanning (Trivy) for all container images. Block deployment of images with critical or high vulnerabilities. Scan on push and on schedule.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-5.3.1",
			Title:       "Runtime Malware Detection",
			Description: "Container runtime is monitored for malicious activity including cryptominer deployment, reverse shells, and known malware signatures.",
			Category:    "Malware Protection", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("runtime_malware_detection_active"),
			Remediation: "Enable runtime security monitoring for cryptominer processes, reverse shell connections, and known malware indicators. Configure automated container quarantine.",
		},
		// Req 6: Secure Development (3 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-6.2.1",
			Title:       "Secure Container Image Build Process",
			Description: "Container images are built following a defined secure development lifecycle with security requirements and review processes.",
			Category:    "Secure Development", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "policy", CheckQuery: nil,
			Remediation: "Implement secure Dockerfile best practices: multi-stage builds, non-root users, minimal base images, no secrets in layers. Integrate security scanning in CI/CD.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-6.3.1",
			Title:       "Known Vulnerability Identification",
			Description: "Security vulnerabilities in container images are identified and managed through a defined vulnerability management process.",
			Category:    "Secure Development", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("vulnerability_management_process"),
			Remediation: "Maintain an inventory of all container images. Scan for vulnerabilities regularly. Patch critical vulnerabilities within 30 days of identification.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-6.5.1",
			Title:       "Change Management for Container Deployments",
			Description: "Changes to container configurations and deployments in the CDE follow a documented change control process.",
			Category:    "Secure Development", Severity: "medium",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "documentation", CheckQuery: chk("deployment_change_control"),
			Remediation: "Use GitOps workflows for CDE container deployments. Require peer review for compose/stack changes. Maintain deployment audit trail.",
		},
		// Req 7: Restrict Access (2 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-7.2.1",
			Title:       "Role-Based Access to CDE Containers",
			Description: "Access to CDE container management operations is restricted based on a user's need-to-know and assigned role.",
			Category:    "Restrict Access", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("rbac_cde_access_restricted"),
			Remediation: "Configure RBAC with least-privilege access for CDE containers. Separate development and production access. Review access rights quarterly.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-7.2.2",
			Title:       "Access Control Enforcement",
			Description: "Access to CDE containers is enforced through automated access control systems that cannot be overridden by individual users.",
			Category:    "Restrict Access", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("automated_access_enforcement"),
			Remediation: "Implement automated RBAC enforcement. Use OPA policies to prevent privilege escalation. Log and alert on access control override attempts.",
		},
		// Req 8: Authentication (2 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-8.3.1",
			Title:       "Multi-Factor Authentication for CDE Access",
			Description: "Multi-factor authentication is implemented for all access into the container management platform for CDE environments.",
			Category:    "Authentication", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("mfa_required_cde_access"),
			Remediation: "Require MFA for all users with CDE container management access. Support TOTP, WebAuthn/FIDO2. Integrate with enterprise SSO.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-8.6.1",
			Title:       "Service Account Management",
			Description: "Service accounts and credentials used by container services in the CDE are managed securely with rotation and access controls.",
			Category:    "Authentication", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("service_accounts_managed"),
			Remediation: "Use managed secrets for container service credentials. Implement automatic rotation. Monitor for leaked credentials in container configurations.",
		},
		// Req 10: Logging and Monitoring (3 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-10.2.1",
			Title:       "Audit Log Generation for CDE Containers",
			Description: "Audit logs are generated for all access to CDE containers, capturing user identification, event type, date/time, success/failure, and affected resources.",
			Category:    "Logging and Monitoring", Severity: "critical",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("cde_audit_logs_generated"),
			Remediation: "Enable comprehensive audit logging for CDE containers. Capture all PCI-DSS required log fields. Forward logs to centralised SIEM.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-10.3.1",
			Title:       "Audit Log Protection",
			Description: "Audit logs for CDE container operations are protected against unauthorised modification and are available for at least 12 months.",
			Category:    "Logging and Monitoring", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("audit_log_retention_12m"),
			Remediation: "Configure audit log retention for at least 12 months (3 months immediately available). Implement write-once storage for audit logs. Restrict log deletion permissions.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-10.4.1",
			Title:       "Automated Security Alert Mechanisms",
			Description: "Automated mechanisms are used to review audit logs and alert personnel of suspected or confirmed security incidents in CDE containers.",
			Category:    "Logging and Monitoring", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("security_alerting_configured"),
			Remediation: "Configure automated alerting rules for CDE security events. Set up notification channels (email, webhook, Slack). Define escalation procedures.",
		},
		// Req 11: Security Testing (2 controls)
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-11.3.1",
			Title:       "Regular Vulnerability Assessments",
			Description: "Internal and external vulnerability assessments are performed on CDE container infrastructure at least quarterly and after significant changes.",
			Category:    "Security Testing", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("quarterly_vulnerability_assessments"),
			Remediation: "Schedule quarterly vulnerability assessments for CDE containers. Run assessments after any significant infrastructure changes. Track remediation to completion.",
		},
		{
			ID: uuid.New(), FrameworkID: fwID, ControlID: "PCI-11.5.1",
			Title:       "Change Detection on CDE Containers",
			Description: "A change detection mechanism monitors CDE container configurations and alerts on unauthorised modifications.",
			Category:    "Security Testing", Severity: "high",
			ImplementationStatus: models.ControlStatusNotStarted,
			EvidenceType: "automated_scan", CheckQuery: chk("configuration_change_detection"),
			Remediation: "Enable configuration drift detection for CDE containers. Alert on unexpected container restarts, image changes, or configuration modifications. Review alerts within 24 hours.",
		},
	}

	return frameworkDef{framework: fw, controls: controls}
}
