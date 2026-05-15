// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Dashboard & Widgets
// ============================================================================

// DashboardLayout represents a user's dashboard layout with widget arrangement.
type DashboardLayout struct {
	ID          uuid.UUID       `db:"id" json:"id"`
	Name        string          `db:"name" json:"name"`
	Description string          `db:"description" json:"description"`
	UserID      *uuid.UUID      `db:"user_id" json:"user_id,omitempty"`
	IsDefault   bool            `db:"is_default" json:"is_default"`
	IsShared    bool            `db:"is_shared" json:"is_shared"`
	LayoutJSON  json.RawMessage `db:"layout_json" json:"layout_json"`
	CreatedAt   time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time       `db:"updated_at" json:"updated_at"`
}

// DashboardWidget represents a single widget on a dashboard.
type DashboardWidget struct {
	ID         uuid.UUID       `db:"id" json:"id"`
	LayoutID   uuid.UUID       `db:"layout_id" json:"layout_id"`
	WidgetType string          `db:"widget_type" json:"widget_type"`
	Title      string          `db:"title" json:"title"`
	Config     json.RawMessage `db:"config" json:"config"`
	PositionX  int             `db:"position_x" json:"position_x"`
	PositionY  int             `db:"position_y" json:"position_y"`
	Width      int             `db:"width" json:"width"`
	Height     int             `db:"height" json:"height"`
	CreatedAt  time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time       `db:"updated_at" json:"updated_at"`
}

// Widget types supported by the dashboard system.
const (
	WidgetTypeCPUGauge         = "cpu_gauge"
	WidgetTypeMemoryGauge      = "memory_gauge"
	WidgetTypeDiskGauge        = "disk_gauge"
	WidgetTypeCPUChart         = "cpu_chart"
	WidgetTypeMemoryChart      = "memory_chart"
	WidgetTypeNetworkChart     = "network_chart"
	WidgetTypeContainerTable   = "container_table"
	WidgetTypeContainerCount   = "container_count"
	WidgetTypeAlertFeed        = "alert_feed"
	WidgetTypeLogStream        = "log_stream"
	WidgetTypeSecurityScore    = "security_score"
	WidgetTypeComplianceStatus = "compliance_status"
	WidgetTypeTopContainers    = "top_containers"
	WidgetTypeHostInfo         = "host_info"
	WidgetTypeCustomMetric     = "custom_metric"
)

// ============================================================================
// Log Aggregation
// ============================================================================

// AggregatedLog represents a structured log entry from any source.
type AggregatedLog struct {
	ID            int64           `db:"id" json:"id"`
	HostID        *uuid.UUID      `db:"host_id" json:"host_id,omitempty"`
	ContainerID   string          `db:"container_id" json:"container_id"`
	ContainerName string          `db:"container_name" json:"container_name"`
	Source        string          `db:"source" json:"source"`
	Stream        string          `db:"stream" json:"stream"`
	Severity      string          `db:"severity" json:"severity"`
	Message       string          `db:"message" json:"message"`
	Fields        json.RawMessage `db:"fields" json:"fields,omitempty"`
	Timestamp     time.Time       `db:"timestamp" json:"timestamp"`
	IngestedAt    time.Time       `db:"ingested_at" json:"ingested_at"`
}

// Log sources (enterprise-specific additions; see also log_entry.go).
const (
	LogSourceDocker = "docker"
	LogSourceSystem = "system"
	LogSourceAudit  = "audit"
)

// Log severity levels (enterprise-specific additions; see also log_entry.go).
const (
	LogSeverityWarn  = "warn"
	LogSeverityFatal = "fatal"
)

// LogSearchQuery represents a saved log search query.
type LogSearchQuery struct {
	ID          uuid.UUID       `db:"id" json:"id"`
	Name        string          `db:"name" json:"name"`
	Description string          `db:"description" json:"description"`
	Query       string          `db:"query" json:"query"`
	Filters     json.RawMessage `db:"filters" json:"filters"`
	UserID      *uuid.UUID      `db:"user_id" json:"user_id,omitempty"`
	IsShared    bool            `db:"is_shared" json:"is_shared"`
	CreatedAt   time.Time       `db:"created_at" json:"created_at"`
}

// AggregatedLogSearchOptions defines filtering options for aggregated log queries.
type AggregatedLogSearchOptions struct {
	Query         string
	ContainerID   string
	ContainerName string
	HostID        *uuid.UUID
	Source        string
	Severity      string
	Since         *time.Time
	Until         *time.Time
	Limit         int
	Offset        int
}

// ============================================================================
// Compliance Frameworks
// ============================================================================

// ComplianceFramework represents a compliance standard (SOC2, HIPAA, PCI-DSS, etc.).
type ComplianceFramework struct {
	ID          uuid.UUID       `db:"id" json:"id"`
	Name        string          `db:"name" json:"name"`
	DisplayName string          `db:"display_name" json:"display_name"`
	Description string          `db:"description" json:"description"`
	Version     string          `db:"version" json:"version"`
	IsEnabled   bool            `db:"is_enabled" json:"is_enabled"`
	Config      json.RawMessage `db:"config" json:"config"`
	CreatedAt   time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time       `db:"updated_at" json:"updated_at"`
}

// Framework names.
const (
	FrameworkSOC2   = "soc2"
	FrameworkHIPAA  = "hipaa"
	FrameworkPCIDSS = "pci-dss"
	FrameworkCIS    = "cis-docker"
	FrameworkCustom = "custom"
)

// ComplianceControl represents a specific control within a framework.
type ComplianceControl struct {
	ID                   uuid.UUID `db:"id" json:"id"`
	FrameworkID          uuid.UUID `db:"framework_id" json:"framework_id"`
	ControlID            string    `db:"control_id" json:"control_id"`
	Title                string    `db:"title" json:"title"`
	Description          string    `db:"description" json:"description"`
	Category             string    `db:"category" json:"category"`
	Severity             string    `db:"severity" json:"severity"`
	ImplementationStatus string    `db:"implementation_status" json:"implementation_status"`
	EvidenceType         string    `db:"evidence_type" json:"evidence_type"`
	CheckQuery           *string   `db:"check_query" json:"check_query,omitempty"`
	Remediation          string    `db:"remediation" json:"remediation"`
	CreatedAt            time.Time `db:"created_at" json:"created_at"`
	UpdatedAt            time.Time `db:"updated_at" json:"updated_at"`
}

// Implementation status values.
const (
	ControlStatusNotStarted    = "not_started"
	ControlStatusInProgress    = "in_progress"
	ControlStatusImplemented   = "implemented"
	ControlStatusNotApplicable = "not_applicable"
)

// ComplianceAssessment represents a run of compliance checks against a framework.
type ComplianceAssessment struct {
	ID             uuid.UUID       `db:"id" json:"id"`
	FrameworkID    uuid.UUID       `db:"framework_id" json:"framework_id"`
	Name           string          `db:"name" json:"name"`
	Status         string          `db:"status" json:"status"`
	TotalControls  int             `db:"total_controls" json:"total_controls"`
	PassedControls int             `db:"passed_controls" json:"passed_controls"`
	FailedControls int             `db:"failed_controls" json:"failed_controls"`
	NAControls     int             `db:"na_controls" json:"na_controls"`
	Score          float64         `db:"score" json:"score"`
	Results        json.RawMessage `db:"results" json:"results"`
	StartedAt      time.Time       `db:"started_at" json:"started_at"`
	CompletedAt    *time.Time      `db:"completed_at" json:"completed_at,omitempty"`
	CreatedBy      *uuid.UUID      `db:"created_by" json:"created_by,omitempty"`
	CreatedAt      time.Time       `db:"created_at" json:"created_at"`
}

// ComplianceEvidence represents collected evidence for a compliance control.
type ComplianceEvidence struct {
	ID           uuid.UUID       `db:"id" json:"id"`
	AssessmentID uuid.UUID       `db:"assessment_id" json:"assessment_id"`
	ControlID    uuid.UUID       `db:"control_id" json:"control_id"`
	EvidenceType string          `db:"evidence_type" json:"evidence_type"`
	Title        string          `db:"title" json:"title"`
	Description  string          `db:"description" json:"description"`
	Data         json.RawMessage `db:"data" json:"data,omitempty"`
	FilePath     *string         `db:"file_path" json:"file_path,omitempty"`
	Status       string          `db:"status" json:"status"`
	CollectedAt  time.Time       `db:"collected_at" json:"collected_at"`
	ExpiresAt    *time.Time      `db:"expires_at" json:"expires_at,omitempty"`
	CreatedBy    *uuid.UUID      `db:"created_by" json:"created_by,omitempty"`
}

// ============================================================================
// OPA Policy Engine
// ============================================================================

// OPAPolicy represents an Open Policy Agent Rego policy.
type OPAPolicy struct {
	ID              uuid.UUID  `db:"id" json:"id"`
	Name            string     `db:"name" json:"name"`
	Description     string     `db:"description" json:"description"`
	Category        string     `db:"category" json:"category"`
	RegoCode        string     `db:"rego_code" json:"rego_code"`
	IsEnabled       bool       `db:"is_enabled" json:"is_enabled"`
	IsEnforcing     bool       `db:"is_enforcing" json:"is_enforcing"`
	Severity        string     `db:"severity" json:"severity"`
	LastEvaluatedAt *time.Time `db:"last_evaluated_at" json:"last_evaluated_at,omitempty"`
	EvaluationCount int64      `db:"evaluation_count" json:"evaluation_count"`
	ViolationCount  int64      `db:"violation_count" json:"violation_count"`
	CreatedBy       *uuid.UUID `db:"created_by" json:"created_by,omitempty"`
	CreatedAt       time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time  `db:"updated_at" json:"updated_at"`
}

// OPA policy categories.
const (
	OPACategoryAdmission = "admission"
	OPACategoryRuntime   = "runtime"
	OPACategoryNetwork   = "network"
	OPACategoryImage     = "image"
	OPACategoryGeneral   = "general"
)

// OPAEvaluationResult represents the result of evaluating a policy against a target.
type OPAEvaluationResult struct {
	ID          int64           `db:"id" json:"id"`
	PolicyID    uuid.UUID       `db:"policy_id" json:"policy_id"`
	TargetType  string          `db:"target_type" json:"target_type"`
	TargetID    string          `db:"target_id" json:"target_id"`
	TargetName  string          `db:"target_name" json:"target_name"`
	Decision    bool            `db:"decision" json:"decision"`
	Violations  json.RawMessage `db:"violations" json:"violations,omitempty"`
	InputHash   string          `db:"input_hash" json:"input_hash"`
	EvaluatedAt time.Time       `db:"evaluated_at" json:"evaluated_at"`
}

// ============================================================================
// Image Signing & Verification
// ============================================================================

// ImageSignature represents a cryptographic signature for a container image.
type ImageSignature struct {
	ID                uuid.UUID  `db:"id" json:"id"`
	ImageRef          string     `db:"image_ref" json:"image_ref"`
	ImageDigest       string     `db:"image_digest" json:"image_digest"`
	SignatureType     string     `db:"signature_type" json:"signature_type"`
	SignatureData     string     `db:"signature_data" json:"signature_data,omitempty"`
	Certificate       string     `db:"certificate" json:"certificate,omitempty"`
	SignerIdentity    string     `db:"signer_identity" json:"signer_identity"`
	Issuer            string     `db:"issuer" json:"issuer"`
	TransparencyLogID string     `db:"transparency_log_id" json:"transparency_log_id,omitempty"`
	Verified          bool       `db:"verified" json:"verified"`
	VerifiedAt        *time.Time `db:"verified_at" json:"verified_at,omitempty"`
	VerificationError string     `db:"verification_error" json:"verification_error,omitempty"`
	CreatedAt         time.Time  `db:"created_at" json:"created_at"`
}

// Signature types.
const (
	SignatureTypeCosign = "cosign"
	SignatureTypeNotary = "notary"
	SignatureTypeGPG    = "gpg"
)

// ImageAttestation represents a signed attestation about an image.
type ImageAttestation struct {
	ID             uuid.UUID       `db:"id" json:"id"`
	ImageRef       string          `db:"image_ref" json:"image_ref"`
	ImageDigest    string          `db:"image_digest" json:"image_digest"`
	PredicateType  string          `db:"predicate_type" json:"predicate_type"`
	Predicate      json.RawMessage `db:"predicate" json:"predicate"`
	SignerIdentity string          `db:"signer_identity" json:"signer_identity"`
	Verified       bool            `db:"verified" json:"verified"`
	CreatedAt      time.Time       `db:"created_at" json:"created_at"`
}

// ImageTrustPolicy defines which images require signatures and from whom.
type ImageTrustPolicy struct {
	ID                 uuid.UUID       `db:"id" json:"id"`
	Name               string          `db:"name" json:"name"`
	Description        string          `db:"description" json:"description"`
	ImagePattern       string          `db:"image_pattern" json:"image_pattern"`
	RequireSignature   bool            `db:"require_signature" json:"require_signature"`
	RequireAttestation bool            `db:"require_attestation" json:"require_attestation"`
	AllowedSigners     json.RawMessage `db:"allowed_signers" json:"allowed_signers"`
	AllowedIssuers     json.RawMessage `db:"allowed_issuers" json:"allowed_issuers"`
	IsEnabled          bool            `db:"is_enabled" json:"is_enabled"`
	IsEnforcing        bool            `db:"is_enforcing" json:"is_enforcing"`
	CreatedAt          time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt          time.Time       `db:"updated_at" json:"updated_at"`
}

// ============================================================================
// Runtime Threat Detection
// ============================================================================

// RuntimeSecurityEvent represents a detected runtime security event.
type RuntimeSecurityEvent struct {
	ID             int64           `db:"id" json:"id"`
	HostID         *uuid.UUID      `db:"host_id" json:"host_id,omitempty"`
	ContainerID    string          `db:"container_id" json:"container_id"`
	ContainerName  string          `db:"container_name" json:"container_name"`
	EventType      string          `db:"event_type" json:"event_type"`
	Severity       string          `db:"severity" json:"severity"`
	RuleID         string          `db:"rule_id" json:"rule_id"`
	RuleName       string          `db:"rule_name" json:"rule_name"`
	Description    string          `db:"description" json:"description"`
	Details        json.RawMessage `db:"details" json:"details,omitempty"`
	Source         string          `db:"source" json:"source"`
	ActionTaken    string          `db:"action_taken" json:"action_taken"`
	Acknowledged   bool            `db:"acknowledged" json:"acknowledged"`
	AcknowledgedBy *uuid.UUID      `db:"acknowledged_by" json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time      `db:"acknowledged_at" json:"acknowledged_at,omitempty"`
	DetectedAt     time.Time       `db:"detected_at" json:"detected_at"`
}

// Runtime event types.
const (
	RuntimeEventProcessExec         = "process_exec"
	RuntimeEventFileAccess          = "file_access"
	RuntimeEventNetworkConnect      = "network_connect"
	RuntimeEventPrivilegeEscalation = "privilege_escalation"
	RuntimeEventAnomaly             = "anomaly"
)

// RuntimeSecurityRule represents a detection rule for runtime security.
type RuntimeSecurityRule struct {
	ID              uuid.UUID       `db:"id" json:"id"`
	Name            string          `db:"name" json:"name"`
	Description     string          `db:"description" json:"description"`
	Category        string          `db:"category" json:"category"`
	RuleType        string          `db:"rule_type" json:"rule_type"`
	Definition      json.RawMessage `db:"definition" json:"definition"`
	Severity        string          `db:"severity" json:"severity"`
	Action          string          `db:"action" json:"action"`
	IsEnabled       bool            `db:"is_enabled" json:"is_enabled"`
	ContainerFilter string          `db:"container_filter" json:"container_filter,omitempty"`
	EventCount      int64           `db:"event_count" json:"event_count"`
	LastTriggeredAt *time.Time      `db:"last_triggered_at" json:"last_triggered_at,omitempty"`
	CreatedAt       time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time       `db:"updated_at" json:"updated_at"`
}

// RuntimeBaseline represents learned normal behavior for anomaly detection.
type RuntimeBaseline struct {
	ID                  uuid.UUID       `db:"id" json:"id"`
	ContainerID         string          `db:"container_id" json:"container_id"`
	ContainerName       string          `db:"container_name" json:"container_name"`
	Image               string          `db:"image" json:"image"`
	BaselineType        string          `db:"baseline_type" json:"baseline_type"`
	BaselineData        json.RawMessage `db:"baseline_data" json:"baseline_data"`
	SampleCount         int             `db:"sample_count" json:"sample_count"`
	Confidence          float64         `db:"confidence" json:"confidence"`
	IsActive            bool            `db:"is_active" json:"is_active"`
	LearningStartedAt   time.Time       `db:"learning_started_at" json:"learning_started_at"`
	LearningCompletedAt *time.Time      `db:"learning_completed_at" json:"learning_completed_at,omitempty"`
	CreatedAt           time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt           time.Time       `db:"updated_at" json:"updated_at"`
}
