// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// ReconLegalNotice is the text shown on the acknowledgement modal before
// the recon module is usable. It is loaded inline so the package has no
// run-time file-system dependency. See docs/recon.md §7.4.
const ReconLegalNotice = `The Privacy & Recon module performs passive and light-active OSINT against ` +
	`identifiers you control. Before enabling it you must acknowledge:

  1. You will only scan targets you own or are explicitly authorized to assess.
  2. Recon jobs may contact third-party services; opt-in connectors (HIBP, ` +
	`Shodan, etc.) require your own API keys and are off by default.
  3. Findings may include personal data subject to GDPR or similar regimes. ` +
	`usulnet stores them encrypted at rest with a tenant retention TTL.
  4. Every scan is recorded in the recon audit log, including the ` +
	`acting user and the target.
  5. Active offensive testing (exploits, port floods, credential probing) is ` +
	`out of scope. The module is passive + light-active recon only.

By acknowledging you accept responsibility for the targets you submit and ` +
	`agree that misuse may be logged and audited.`

// ReconService is the web-layer abstraction over the recon backend. The
// concrete implementation lives in reconAdapter; handlers stay decoupled
// from internal/services/recon so tests can substitute fakes.
type ReconService interface {
	IsEnabled() bool
	IsAcknowledged(ctx context.Context) (bool, error)
	Acknowledge(ctx context.Context, actorID *uuid.UUID, ip string) error

	GetDashboard(ctx context.Context) (*ReconDashboardData, error)
	ListTargets(ctx context.Context) ([]ReconTargetView, error)
	GetTarget(ctx context.Context, id uuid.UUID) (*ReconTargetDetailView, error)
	DeleteTarget(ctx context.Context, id uuid.UUID) error

	ListProfiles(ctx context.Context) ([]ReconProfileView, error)
	ListScans(ctx context.Context, filter ReconScanFilter) ([]ReconScanView, error)
	GetScan(ctx context.Context, id uuid.UUID) (*ReconScanDetailView, error)
	ListFindings(ctx context.Context, scanID uuid.UUID, filter ReconFindingFilter) ([]ReconFindingView, error)
	CancelScan(ctx context.Context, id uuid.UUID) error

	ListConnectors(ctx context.Context) ([]ReconConnectorView, error)
	ListReports(ctx context.Context) ([]ReconReportView, error)
}

// ReconDashboardData is the bundle rendered on /recon/dashboard.
type ReconDashboardData struct {
	TotalTargets   int
	TotalScans     int
	RunningScans   int
	CompletedScans int
	FailedScans    int
	FindingsBySev  map[string]int
	RecentScans    []ReconScanView
	TopFindings    []ReconFindingView
}

// ReconTargetView is one row in the targets list.
type ReconTargetView struct {
	ID                string
	Type              string
	Value             string
	ValueHashPrefix   string
	Label             string
	OwnershipStatus   string
	OwnershipMethod   string
	OwnershipVerified bool
	LastScanAt        string
	ScanCount         int
	CreatedAt         string
	CreatedBy         string
}

// ReconTargetDetailView is the per-target dossier view.
type ReconTargetDetailView struct {
	Target          ReconTargetView
	OwnershipProofs []ReconOwnershipProofView
	Scans           []ReconScanView
	Findings        []ReconFindingView
}

// ReconOwnershipProofView renders one ownership verification record.
type ReconOwnershipProofView struct {
	ID         string
	Method     string
	Status     string
	Challenge  string
	VerifiedAt string
	CreatedAt  string
}

// ReconScanView is one row in the scans list.
type ReconScanView struct {
	ID          string
	TargetID    string
	TargetValue string
	TargetType  string
	ProfileID   string
	ProfileName string
	Status      string
	Engine      string
	Error       string
	StartedAt   string
	FinishedAt  string
	Duration    string
	Progress    int
	CreatedAt   string
}

// ReconScanDetailView wraps a scan with its findings and summary.
type ReconScanDetailView struct {
	Scan     ReconScanView
	Summary  *ReconScanSummaryView
	Findings []ReconFindingView
	Modules  []string
}

// ReconScanSummaryView shows aggregate counts and grade.
type ReconScanSummaryView struct {
	Grade       string
	Counts      map[string]int
	GeneratedAt string
}

// ReconFindingView is one normalized finding row.
type ReconFindingView struct {
	ID         string
	ScanID     string
	TargetID   string
	Module     string
	Category   string
	Severity   string
	Value      string
	Source     string
	Confidence int
	FirstSeen  string
	LastSeen   string
}

// ReconProfileView lists a built-in or user-defined profile.
type ReconProfileView struct {
	ID          string
	Name        string
	Description string
	Kind        string
	TargetTypes []string
	Modules     []string
}

// ReconConnectorView lists one optional API connector (HIBP, Shodan…).
type ReconConnectorView struct {
	Kind        string
	Name        string
	Enabled     bool
	Configured  bool
	Description string
	DocsURL     string
}

// ReconReportView is one generated report.
type ReconReportView struct {
	ID          string
	ScanID      string
	TargetValue string
	Format      string
	SizeBytes   int64
	CreatedAt   string
	DownloadURL string
}

// ReconScanFilter narrows the scans list.
type ReconScanFilter struct {
	TargetID *uuid.UUID
	Status   string
	Limit    int
}

// ReconFindingFilter narrows a findings query.
type ReconFindingFilter struct {
	Severity string
	Module   string
	Limit    int
}

// AckRecorder is the minimal contract the web layer needs to read and
// write the recon acknowledgement state. internal/api/handlers
// MemoryAckStore (and any Postgres-backed replacement) satisfies it.
type AckRecorder interface {
	IsAcknowledged(ctx context.Context) (bool, error)
	Acknowledge(ctx context.Context, actorID *uuid.UUID, ip string) error
}

// reconAdapter is the web-layer concrete ReconService.
type reconAdapter struct {
	svc     recon.Service
	ack     AckRecorder
	enabled bool
}

func (a *reconAdapter) IsEnabled() bool {
	return a != nil && a.enabled
}

func (a *reconAdapter) IsAcknowledged(ctx context.Context) (bool, error) {
	if a == nil || a.ack == nil {
		return false, nil
	}
	return a.ack.IsAcknowledged(ctx)
}

func (a *reconAdapter) Acknowledge(ctx context.Context, actorID *uuid.UUID, ip string) error {
	if a == nil || a.ack == nil {
		return ErrServiceNotConfigured
	}
	return a.ack.Acknowledge(ctx, actorID, ip)
}

func (a *reconAdapter) GetDashboard(ctx context.Context) (*ReconDashboardData, error) {
	if a == nil || a.svc == nil {
		return &ReconDashboardData{FindingsBySev: map[string]int{}}, nil
	}

	targets, err := a.svc.ListTargets(ctx, recon.ListTargetsFilter{Limit: 1000})
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	scans, err := a.svc.ListScans(ctx, recon.ListScansFilter{Limit: 50})
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}

	data := &ReconDashboardData{
		TotalTargets:  len(targets),
		TotalScans:    len(scans),
		FindingsBySev: map[string]int{},
	}

	targetIndex := make(map[uuid.UUID]recon.Target, len(targets))
	for _, t := range targets {
		targetIndex[t.ID] = t
	}

	for _, s := range scans {
		switch s.Status {
		case recon.ScanRunning, recon.ScanQueued:
			data.RunningScans++
		case recon.ScanCompleted:
			data.CompletedScans++
		case recon.ScanFailed:
			data.FailedScans++
		}
		if len(data.RecentScans) < 10 {
			data.RecentScans = append(data.RecentScans, reconScanToView(&s, targetIndex))
		}
	}

	findings, err := a.svc.ListFindings(ctx, recon.ListFindingsFilter{Limit: 200})
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	for _, f := range findings {
		data.FindingsBySev[string(f.Severity)]++
		if len(data.TopFindings) < 10 && (f.Severity == recon.SeverityHigh || f.Severity == recon.SeverityCritical) {
			data.TopFindings = append(data.TopFindings, reconFindingToView(&f))
		}
	}
	return data, nil
}

func (a *reconAdapter) ListTargets(ctx context.Context) ([]ReconTargetView, error) {
	if a == nil || a.svc == nil {
		return nil, nil
	}
	ts, err := a.svc.ListTargets(ctx, recon.ListTargetsFilter{Limit: 200})
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	out := make([]ReconTargetView, 0, len(ts))
	for i := range ts {
		out = append(out, reconTargetToView(&ts[i]))
	}
	return out, nil
}

func (a *reconAdapter) GetTarget(ctx context.Context, id uuid.UUID) (*ReconTargetDetailView, error) {
	if a == nil || a.svc == nil {
		return nil, ErrServiceNotConfigured
	}
	t, err := a.svc.GetTarget(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get target: %w", err)
	}
	if t == nil {
		return nil, errors.New("target not found")
	}

	detail := &ReconTargetDetailView{Target: reconTargetToView(t)}

	scans, err := a.svc.ListScans(ctx, recon.ListScansFilter{TargetID: &id, Limit: 50})
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	targetIndex := map[uuid.UUID]recon.Target{t.ID: *t}
	for _, s := range scans {
		detail.Scans = append(detail.Scans, reconScanToView(&s, targetIndex))
	}

	findings, err := a.svc.ListFindings(ctx, recon.ListFindingsFilter{TargetID: &id, Limit: 200})
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	for i := range findings {
		detail.Findings = append(detail.Findings, reconFindingToView(&findings[i]))
	}
	return detail, nil
}

func (a *reconAdapter) DeleteTarget(ctx context.Context, id uuid.UUID) error {
	if a == nil || a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.DeleteTarget(ctx, id)
}

func (a *reconAdapter) ListProfiles(ctx context.Context) ([]ReconProfileView, error) {
	if a == nil || a.svc == nil {
		return nil, nil
	}
	ps, err := a.svc.ListProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	out := make([]ReconProfileView, 0, len(ps))
	for i := range ps {
		out = append(out, reconProfileToView(&ps[i]))
	}
	return out, nil
}

func (a *reconAdapter) ListScans(ctx context.Context, filter ReconScanFilter) ([]ReconScanView, error) {
	if a == nil || a.svc == nil {
		return nil, nil
	}
	f := recon.ListScansFilter{TargetID: filter.TargetID, Limit: filter.Limit}
	if f.Limit == 0 {
		f.Limit = 100
	}
	if filter.Status != "" {
		st := recon.ScanStatus(filter.Status)
		f.Status = &st
	}
	scans, err := a.svc.ListScans(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	targets, _ := a.svc.ListTargets(ctx, recon.ListTargetsFilter{Limit: 500})
	idx := make(map[uuid.UUID]recon.Target, len(targets))
	for _, t := range targets {
		idx[t.ID] = t
	}
	out := make([]ReconScanView, 0, len(scans))
	for i := range scans {
		out = append(out, reconScanToView(&scans[i], idx))
	}
	return out, nil
}

func (a *reconAdapter) GetScan(ctx context.Context, id uuid.UUID) (*ReconScanDetailView, error) {
	if a == nil || a.svc == nil {
		return nil, ErrServiceNotConfigured
	}
	s, err := a.svc.GetScan(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get scan: %w", err)
	}
	if s == nil {
		return nil, errors.New("scan not found")
	}
	target, _ := a.svc.GetTarget(ctx, s.TargetID)
	idx := map[uuid.UUID]recon.Target{}
	if target != nil {
		idx[target.ID] = *target
	}
	detail := &ReconScanDetailView{Scan: reconScanToView(s, idx)}

	if summary, err := a.svc.GetScanSummary(ctx, id); err == nil && summary != nil {
		v := reconSummaryToView(summary)
		detail.Summary = &v
	}

	findings, err := a.svc.ListFindings(ctx, recon.ListFindingsFilter{ScanID: &id, Limit: 500})
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	seen := make(map[string]struct{})
	for i := range findings {
		detail.Findings = append(detail.Findings, reconFindingToView(&findings[i]))
		if _, ok := seen[findings[i].Module]; !ok {
			seen[findings[i].Module] = struct{}{}
			detail.Modules = append(detail.Modules, findings[i].Module)
		}
	}
	return detail, nil
}

func (a *reconAdapter) ListFindings(ctx context.Context, scanID uuid.UUID, filter ReconFindingFilter) ([]ReconFindingView, error) {
	if a == nil || a.svc == nil {
		return nil, nil
	}
	f := recon.ListFindingsFilter{ScanID: &scanID, Module: filter.Module, Limit: filter.Limit}
	if f.Limit == 0 {
		f.Limit = 200
	}
	if filter.Severity != "" {
		sev := recon.Severity(filter.Severity)
		f.Severity = &sev
	}
	findings, err := a.svc.ListFindings(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	out := make([]ReconFindingView, 0, len(findings))
	for i := range findings {
		out = append(out, reconFindingToView(&findings[i]))
	}
	return out, nil
}

func (a *reconAdapter) CancelScan(ctx context.Context, id uuid.UUID) error {
	if a == nil || a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.CancelScan(ctx, id)
}

func (a *reconAdapter) ListConnectors(_ context.Context) ([]ReconConnectorView, error) {
	if a == nil {
		return nil, nil
	}
	// Connectors are static for v26.5.0 — the service interface does not
	// expose a connector listing yet (lands in S08). We surface the
	// supported kinds so the page renders meaningfully.
	return []ReconConnectorView{
		{
			Kind:        "hibp",
			Name:        "Have I Been Pwned",
			Description: "Look up breach exposure for email targets.",
			DocsURL:     "https://haveibeenpwned.com/API/v3",
		},
		{
			Kind:        "shodan",
			Name:        "Shodan",
			Description: "Discover exposed services for IP and domain targets.",
			DocsURL:     "https://developer.shodan.io/",
		},
	}, nil
}

func (a *reconAdapter) ListReports(_ context.Context) ([]ReconReportView, error) {
	// Report listing is a v26.5.1 deliverable. The page renders an
	// empty state until then.
	return nil, nil
}

// ----------------------------------------------------------------------------
// Conversion helpers — exported so adapter tests can exercise them directly.
// ----------------------------------------------------------------------------

func reconTargetToView(t *recon.Target) ReconTargetView {
	v := ReconTargetView{
		ID:        t.ID.String(),
		Type:      string(t.Type),
		Value:     t.Value,
		Label:     t.Label,
		CreatedAt: t.CreatedAt.Format("2006-01-02 15:04"),
	}
	if len(t.ValueHash) >= 4 {
		v.ValueHashPrefix = hex.EncodeToString(t.ValueHash[:4])
	}
	if t.CreatedBy != nil {
		v.CreatedBy = t.CreatedBy.String()
	}
	return v
}

func reconScanToView(s *recon.Scan, targets map[uuid.UUID]recon.Target) ReconScanView {
	v := ReconScanView{
		ID:        s.ID.String(),
		TargetID:  s.TargetID.String(),
		ProfileID: s.ProfileID.String(),
		Status:    string(s.Status),
		Engine:    s.Engine,
		Error:     s.Error,
		CreatedAt: s.CreatedAt.Format("2006-01-02 15:04"),
	}
	if t, ok := targets[s.TargetID]; ok {
		v.TargetValue = t.Value
		v.TargetType = string(t.Type)
	}
	if s.StartedAt != nil {
		v.StartedAt = s.StartedAt.Format("2006-01-02 15:04:05")
	}
	if s.FinishedAt != nil {
		v.FinishedAt = s.FinishedAt.Format("2006-01-02 15:04:05")
		if s.StartedAt != nil {
			v.Duration = humanDuration(s.FinishedAt.Sub(*s.StartedAt))
		}
	} else if s.StartedAt != nil {
		v.Duration = humanDuration(time.Since(*s.StartedAt))
	}
	switch s.Status {
	case recon.ScanQueued:
		v.Progress = 5
	case recon.ScanRunning:
		v.Progress = 50
	case recon.ScanCompleted:
		v.Progress = 100
	case recon.ScanFailed, recon.ScanCancelled:
		v.Progress = 100
	}
	return v
}

func reconFindingToView(f *recon.Finding) ReconFindingView {
	return ReconFindingView{
		ID:         f.ID.String(),
		ScanID:     f.ScanID.String(),
		TargetID:   f.TargetID.String(),
		Module:     f.Module,
		Category:   f.Category,
		Severity:   string(f.Severity),
		Value:      f.Value,
		Source:     f.Source,
		Confidence: f.Confidence,
		FirstSeen:  f.FirstSeen.Format("2006-01-02 15:04"),
		LastSeen:   f.LastSeen.Format("2006-01-02 15:04"),
	}
}

func reconSummaryToView(s *recon.ScanSummary) ReconScanSummaryView {
	return ReconScanSummaryView{
		Grade:       s.Grade,
		Counts:      s.Counts,
		GeneratedAt: s.GeneratedAt.Format("2006-01-02 15:04"),
	}
}

func reconProfileToView(p *recon.Profile) ReconProfileView {
	tt := make([]string, 0, len(p.TargetTypes))
	for _, t := range p.TargetTypes {
		tt = append(tt, string(t))
	}
	return ReconProfileView{
		ID:          p.ID.String(),
		Name:        p.Name,
		Description: p.Description,
		Kind:        p.Kind,
		TargetTypes: tt,
		Modules:     append([]string{}, p.Modules...),
	}
}

func humanDuration(d time.Duration) string {
	if d <= 0 {
		return "—"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) - h*60
	return fmt.Sprintf("%dh %dm", h, m)
}

// ReconSeverityClass returns the Tailwind classes for a severity badge,
// matching the palette used by the security and vulnerability pages.
func ReconSeverityClass(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "text-red-400 bg-red-500/10 border-red-500/20"
	case "high":
		return "text-orange-400 bg-orange-500/10 border-orange-500/20"
	case "medium":
		return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
	case "low":
		return "text-blue-400 bg-blue-500/10 border-blue-500/20"
	case "info":
		return "text-gray-400 bg-gray-500/10 border-gray-500/20"
	default:
		return "text-gray-400 bg-gray-500/10 border-gray-500/20"
	}
}
