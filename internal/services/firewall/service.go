// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package firewall provides UFW/nftables/iptables firewall rule management
// for hosts managed by usulnet. Rules are persisted in PostgreSQL and
// pushed to remote agents over the existing NATS gateway transport.
//
// The service is a free AGPL feature — no biz gating, no edition checks,
// no call-home. It executes no shell commands itself; the agent on each
// host owns the privileged backend invocation with explicit os/exec arg
// slices.
package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Sentinel errors returned by the service. API handlers map these to
// stable HTTP status codes.
var (
	// ErrInvalidInput is returned when the caller supplies a malformed
	// or out-of-enum rule field.
	ErrInvalidInput = errors.New("firewall: invalid input")

	// ErrSenderNotConfigured is returned when an agent command is
	// requested but no CommandSender has been wired. The CRUD path
	// keeps working without a sender — only Apply/Sync/Detect fail.
	ErrSenderNotConfigured = errors.New("firewall: command sender not configured")
)

// RuleRepository defines persistence for firewall rules.
type RuleRepository interface {
	Create(ctx context.Context, rule *models.FirewallRule) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.FirewallRule, error)
	List(ctx context.Context, hostID uuid.UUID) ([]models.FirewallRule, error)
	Update(ctx context.Context, rule *models.FirewallRule) error
	Delete(ctx context.Context, id uuid.UUID) error
	MarkApplied(ctx context.Context, hostID uuid.UUID) error
	NextPosition(ctx context.Context, hostID uuid.UUID, chain string) (int, error)
}

// AuditRepository defines persistence for firewall audit logs.
type AuditRepository interface {
	Create(ctx context.Context, entry *models.FirewallAuditLog) error
	List(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.FirewallAuditLog, int, error)
}

// CommandSender sends commands to remote agents. It is satisfied by
// gateway.CommandDispatcher. Pass nil for standalone-mode installs
// where rules live in the DB but are not pushed to any agent.
type CommandSender interface {
	SendCommand(ctx context.Context, hostID uuid.UUID, cmd *protocol.Command) (*protocol.CommandResult, error)
}

// Service implements firewall management business logic.
type Service struct {
	rules  RuleRepository
	audit  AuditRepository
	sender CommandSender
	logger *logger.Logger
}

// NewService creates a new firewall service. The logger may be nil — a
// no-op logger is substituted to keep the constructor signature uniform.
func NewService(rules RuleRepository, audit AuditRepository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		rules:  rules,
		audit:  audit,
		logger: log.Named("firewall"),
	}
}

// SetCommandSender configures the gateway for sending commands to agents.
// Safe to call after construction; the standalone-mode app wires this
// only when the NATS gateway is up.
func (s *Service) SetCommandSender(sender CommandSender) {
	s.sender = sender
}

// validChain reports whether c is one of the supported chains.
func validChain(c models.FirewallChain) bool {
	switch c {
	case models.FirewallChainInput,
		models.FirewallChainOutput,
		models.FirewallChainForward,
		models.FirewallChainDockerUser:
		return true
	}
	return false
}

// validAction reports whether a is one of the supported actions.
func validAction(a models.FirewallAction) bool {
	switch a {
	case models.FirewallActionAccept,
		models.FirewallActionDrop,
		models.FirewallActionReject,
		models.FirewallActionLog:
		return true
	}
	return false
}

// validProtocol reports whether p is one of the supported protocols.
// The empty string is rejected at the API surface; the service treats
// it as "all" for backwards-compatible storage.
func validProtocol(p string) bool {
	switch strings.ToLower(p) {
	case "tcp", "udp", "icmp", "all", "":
		return true
	}
	return false
}

// validDirection reports whether d is "inbound" or "outbound".
func validDirection(d string) bool {
	switch d {
	case "inbound", "outbound", "":
		return true
	}
	return false
}

// validateCreateInput enforces the closed enums on chain/action/protocol
// and trims the name. v26.2.7's service skipped this; the audit log
// would happily store nonsense. We catch it at the boundary.
func validateCreateInput(in *models.CreateFirewallRuleInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if !validChain(in.Chain) {
		return fmt.Errorf("%w: unknown chain %q", ErrInvalidInput, in.Chain)
	}
	if !validAction(in.Action) {
		return fmt.Errorf("%w: unknown action %q", ErrInvalidInput, in.Action)
	}
	if !validProtocol(in.Protocol) {
		return fmt.Errorf("%w: unknown protocol %q", ErrInvalidInput, in.Protocol)
	}
	if !validDirection(in.Direction) {
		return fmt.Errorf("%w: unknown direction %q", ErrInvalidInput, in.Direction)
	}
	if in.Direction == "" {
		in.Direction = "inbound"
	}
	if in.Protocol == "" {
		in.Protocol = "all"
	}
	return nil
}

// validateUpdateInput applies the same closed-enum checks as create,
// only on the non-nil fields.
func validateUpdateInput(in *models.UpdateFirewallRuleInput) error {
	if in.Name != nil {
		trimmed := strings.TrimSpace(*in.Name)
		if trimmed == "" {
			return fmt.Errorf("%w: name cannot be empty", ErrInvalidInput)
		}
		*in.Name = trimmed
	}
	if in.Chain != nil && !validChain(*in.Chain) {
		return fmt.Errorf("%w: unknown chain %q", ErrInvalidInput, *in.Chain)
	}
	if in.Action != nil && !validAction(*in.Action) {
		return fmt.Errorf("%w: unknown action %q", ErrInvalidInput, *in.Action)
	}
	if in.Protocol != nil && !validProtocol(*in.Protocol) {
		return fmt.Errorf("%w: unknown protocol %q", ErrInvalidInput, *in.Protocol)
	}
	if in.Direction != nil && !validDirection(*in.Direction) {
		return fmt.Errorf("%w: unknown direction %q", ErrInvalidInput, *in.Direction)
	}
	return nil
}

// ============================================================================
// CRUD
// ============================================================================

// ListRules returns all firewall rules for a host.
func (s *Service) ListRules(ctx context.Context, hostID uuid.UUID) ([]models.FirewallRule, error) {
	return s.rules.List(ctx, hostID)
}

// GetRule returns a firewall rule by ID.
func (s *Service) GetRule(ctx context.Context, id uuid.UUID) (*models.FirewallRule, error) {
	return s.rules.GetByID(ctx, id)
}

// CreateRule creates a new firewall rule. The position is assigned by
// the repo on a per-(host, chain) basis so chains stay independent.
func (s *Service) CreateRule(ctx context.Context, hostID uuid.UUID, input models.CreateFirewallRuleInput, userID *uuid.UUID) (*models.FirewallRule, error) {
	if hostID == uuid.Nil {
		return nil, fmt.Errorf("%w: host_id is required", ErrInvalidInput)
	}
	if err := validateCreateInput(&input); err != nil {
		return nil, err
	}

	pos, err := s.rules.NextPosition(ctx, hostID, string(input.Chain))
	if err != nil {
		return nil, fmt.Errorf("next position: %w", err)
	}

	rule := &models.FirewallRule{
		ID:            uuid.New(),
		HostID:        hostID,
		Name:          input.Name,
		Description:   input.Description,
		Chain:         input.Chain,
		Protocol:      input.Protocol,
		Source:        input.Source,
		Destination:   input.Destination,
		SrcPort:       input.SrcPort,
		DstPort:       input.DstPort,
		Action:        input.Action,
		Direction:     input.Direction,
		InterfaceName: input.InterfaceName,
		Position:      pos,
		Enabled:       input.Enabled,
		ContainerID:   input.ContainerID,
		NetworkName:   input.NetworkName,
		Comment:       input.Comment,
		CreatedBy:     userID,
	}

	if err := s.rules.Create(ctx, rule); err != nil {
		return nil, err
	}

	s.logAudit(ctx, hostID, userID, "create", &rule.ID, ruleSummary(rule), "")

	return rule, nil
}

// UpdateRule patches an existing firewall rule with the non-nil fields
// in input. The applied flag is reset by the repo so the operator sees
// the rule is stale until ApplyRules pushes it to the host.
func (s *Service) UpdateRule(ctx context.Context, id uuid.UUID, input models.UpdateFirewallRuleInput, userID *uuid.UUID) (*models.FirewallRule, error) {
	if err := validateUpdateInput(&input); err != nil {
		return nil, err
	}

	rule, err := s.rules.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		rule.Name = *input.Name
	}
	if input.Description != nil {
		rule.Description = *input.Description
	}
	if input.Chain != nil {
		rule.Chain = *input.Chain
	}
	if input.Protocol != nil {
		rule.Protocol = *input.Protocol
	}
	if input.Source != nil {
		rule.Source = *input.Source
	}
	if input.Destination != nil {
		rule.Destination = *input.Destination
	}
	if input.SrcPort != nil {
		rule.SrcPort = *input.SrcPort
	}
	if input.DstPort != nil {
		rule.DstPort = *input.DstPort
	}
	if input.Action != nil {
		rule.Action = *input.Action
	}
	if input.Direction != nil {
		rule.Direction = *input.Direction
	}
	if input.InterfaceName != nil {
		rule.InterfaceName = *input.InterfaceName
	}
	if input.ContainerID != nil {
		rule.ContainerID = *input.ContainerID
	}
	if input.NetworkName != nil {
		rule.NetworkName = *input.NetworkName
	}
	if input.Comment != nil {
		rule.Comment = *input.Comment
	}
	if input.Enabled != nil {
		rule.Enabled = *input.Enabled
	}

	if err := s.rules.Update(ctx, rule); err != nil {
		return nil, err
	}

	s.logAudit(ctx, rule.HostID, userID, "update", &rule.ID, ruleSummary(rule), "")

	return rule, nil
}

// DeleteRule deletes a firewall rule and writes an audit entry that
// preserves the rule's pre-delete summary so the audit log still tells
// you what was removed.
func (s *Service) DeleteRule(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	rule, err := s.rules.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if err := s.rules.Delete(ctx, id); err != nil {
		return err
	}

	s.logAudit(ctx, rule.HostID, userID, "delete", &rule.ID, ruleSummary(rule), "")

	return nil
}

// ============================================================================
// Agent commands
// ============================================================================

// DetectBackend asks the agent on hostID which firewall implementation
// is available. Returns FirewallBackendUnknown (not an error) when no
// sender is wired — that lets the standalone DB-only mode keep working.
func (s *Service) DetectBackend(ctx context.Context, hostID uuid.UUID) (*models.FirewallHostStatus, error) {
	if s.sender == nil {
		return &models.FirewallHostStatus{Backend: models.FirewallBackendUnknown}, nil
	}

	cmd := &protocol.Command{
		ID:       uuid.NewString(),
		Type:     protocol.CmdFirewallDetect,
		HostID:   hostID.String(),
		Priority: protocol.PriorityNormal,
		Timeout:  15 * time.Second,
		Params:   protocol.CommandParams{},
	}

	result, err := s.sender.SendCommand(ctx, hostID, cmd)
	if err != nil {
		return nil, fmt.Errorf("detect backend: %w", err)
	}
	if result.Error != nil {
		return nil, fmt.Errorf("detect backend: %s", result.Error.Message)
	}

	data, err := json.Marshal(result.Data)
	if err != nil {
		return nil, fmt.Errorf("marshal detect result: %w", err)
	}

	var resp struct {
		Backend string `json:"backend"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal detect result: %w", err)
	}

	status := &models.FirewallHostStatus{
		Backend: models.FirewallBackend(resp.Backend),
		Version: resp.Version,
	}

	rules, listErr := s.rules.List(ctx, hostID)
	if listErr == nil {
		for _, r := range rules {
			if r.Enabled {
				status.ActiveRules++
			}
			status.ManagedRules++
		}
	}

	return status, nil
}

// applyRulePayload is the wire shape sent to the agent. Defined as a
// named type so the JSON contract is reviewable rather than hidden in
// an anonymous struct literal mid-function.
type applyRulePayload struct {
	Chain         string `json:"chain"`
	Protocol      string `json:"protocol"`
	Source        string `json:"source"`
	Destination   string `json:"destination"`
	SrcPort       string `json:"src_port"`
	DstPort       string `json:"dst_port"`
	Action        string `json:"action"`
	InterfaceName string `json:"interface_name"`
	Comment       string `json:"comment"`
	Position      int    `json:"position"`
}

// ApplyRules pushes every enabled rule for hostID to the agent. The
// agent is responsible for translating the rule set into UFW / nftables
// / iptables commands — never this binary, so there is no shell-injection
// surface on the master.
func (s *Service) ApplyRules(ctx context.Context, hostID uuid.UUID, userID *uuid.UUID) error {
	if s.sender == nil {
		return ErrSenderNotConfigured
	}

	rules, err := s.rules.List(ctx, hostID)
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}

	applyRules := make([]applyRulePayload, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		applyRules = append(applyRules, applyRulePayload{
			Chain:         string(r.Chain),
			Protocol:      r.Protocol,
			Source:        r.Source,
			Destination:   r.Destination,
			SrcPort:       r.SrcPort,
			DstPort:       r.DstPort,
			Action:        string(r.Action),
			InterfaceName: r.InterfaceName,
			Comment:       r.Comment,
			Position:      r.Position,
		})
	}

	if len(applyRules) == 0 {
		return nil
	}

	backend := "iptables"
	status, detectErr := s.DetectBackend(ctx, hostID)
	if detectErr == nil && status.Backend != models.FirewallBackendUnknown {
		backend = string(status.Backend)
	}

	payload := struct {
		Backend string             `json:"backend"`
		Rules   []applyRulePayload `json:"rules"`
	}{
		Backend: backend,
		Rules:   applyRules,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}

	cmd := &protocol.Command{
		ID:       uuid.NewString(),
		Type:     protocol.CmdFirewallApply,
		HostID:   hostID.String(),
		Priority: protocol.PriorityHigh,
		Timeout:  2 * time.Minute,
		Params: protocol.CommandParams{
			FirewallRules:   string(payloadJSON),
			FirewallBackend: backend,
		},
	}

	result, err := s.sender.SendCommand(ctx, hostID, cmd)
	if err != nil {
		return fmt.Errorf("apply rules: %w", err)
	}
	if result.Error != nil {
		return fmt.Errorf("apply rules: %s", result.Error.Message)
	}

	if err := s.rules.MarkApplied(ctx, hostID); err != nil {
		s.logger.Error("failed to mark rules as applied", "error", err, "host_id", hostID.String())
	}

	s.logAudit(ctx, hostID, userID, "apply", nil,
		fmt.Sprintf("Applied %d rules (backend=%s)", len(applyRules), backend), "")

	return nil
}

// SyncFromHost reads the current firewall state from the agent. The
// returned string is the raw textual dump (e.g. `ufw status verbose`)
// — the web UI surfaces it as-is.
func (s *Service) SyncFromHost(ctx context.Context, hostID uuid.UUID, userID *uuid.UUID) (string, error) {
	if s.sender == nil {
		return "", ErrSenderNotConfigured
	}

	cmd := &protocol.Command{
		ID:       uuid.NewString(),
		Type:     protocol.CmdFirewallSync,
		HostID:   hostID.String(),
		Priority: protocol.PriorityNormal,
		Timeout:  2 * time.Minute,
		Params:   protocol.CommandParams{},
	}

	result, err := s.sender.SendCommand(ctx, hostID, cmd)
	if err != nil {
		return "", fmt.Errorf("sync from host: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("sync from host: %s", result.Error.Message)
	}

	data, err := json.Marshal(result.Data)
	if err != nil {
		return "", fmt.Errorf("marshal sync result: %w", err)
	}

	var resp struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("unmarshal sync result: %w", err)
	}

	s.logAudit(ctx, hostID, userID, "sync", nil, "Synced firewall state from host", "")

	return resp.Output, nil
}

// ============================================================================
// Audit
// ============================================================================

// ListAuditLogs returns paginated audit logs for a host.
func (s *Service) ListAuditLogs(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.FirewallAuditLog, int, error) {
	return s.audit.List(ctx, hostID, limit, offset)
}

// ruleSummary builds a short human-readable representation of a rule
// for the audit log. Centralized so create / update / delete all write
// the same shape.
func ruleSummary(r *models.FirewallRule) string {
	dst := r.Destination
	if dst == "" {
		dst = "any"
	}
	dstPort := r.DstPort
	if dstPort == "" {
		dstPort = "*"
	}
	src := r.Source
	if src == "" {
		src = "any"
	}
	return fmt.Sprintf("%s %s %s -> %s:%s %s",
		r.Chain, r.Protocol, src, dst, dstPort, r.Action)
}

// logAudit best-effort persists an audit-log entry. A failure here is
// noisy but does not unwind the calling CRUD operation — the user
// already changed the rule; the audit log is supplementary.
func (s *Service) logAudit(ctx context.Context, hostID uuid.UUID, userID *uuid.UUID, action string, ruleID *uuid.UUID, summary, details string) {
	entry := &models.FirewallAuditLog{
		HostID:      hostID,
		UserID:      userID,
		Action:      action,
		RuleID:      ruleID,
		RuleSummary: summary,
		Details:     details,
	}
	if err := s.audit.Create(ctx, entry); err != nil {
		s.logger.Error("failed to create audit log",
			"error", err,
			"host_id", hostID.String(),
			"action", action)
	}
}
