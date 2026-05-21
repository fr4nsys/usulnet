// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package egress implements per-host L7 egress filtering for usulnet.
//
// Operators define allow/deny policies scoped to a host; the in-process
// HTTP forward proxy (proxy.go) at a configurable listener evaluates
// every outbound CONNECT/GET/POST against those policies and 403s the
// denials. Allowed requests are forwarded transparently. Denials are
// recorded in egress_audit_log so the operator can debug "why was my
// call blocked" without grepping logs.
//
// The design is deliberately narrow:
//
//   - Per-host policies, not per-container. Per-container filtering
//     would need network-namespace plumbing on the host — out of scope
//     for v26.5.2; tracked as a follow-up.
//   - SNI-only for HTTPS. The proxy never decrypts TLS; CONNECT is
//     evaluated against the request's Host header (which the client
//     sends in plaintext), then the proxy tunnels bytes.
//   - First-match-wins evaluation in created_at order. When at least
//     one policy exists for a host and none match, the request is
//     denied. A host with zero policies is pass-through — the operator
//     has not opted in to filtering.
package egress

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// PolicyRepo is the persistence surface the service depends on. The
// production implementation lives at
// internal/repository/postgres/egress_repo.go; tests supply a fake.
type PolicyRepo interface {
	Create(ctx context.Context, p *models.EgressPolicy) error
	ListByHost(ctx context.Context, hostID uuid.UUID) ([]models.EgressPolicy, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.EgressPolicy, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// AuditRepo records deny events.
type AuditRepo interface {
	Insert(ctx context.Context, e *models.EgressAuditLog) error
	ListByHost(ctx context.Context, hostID uuid.UUID, limit int) ([]models.EgressAuditLog, error)
}

// ErrInvalidInput is returned when the caller passes an unusable value
// (empty glob, nil host id, etc.). The API and web handlers translate
// it to a 400 Bad Request.
var ErrInvalidInput = errors.New("egress: invalid input")

// Service owns the egress policy CRUD path and the forward-proxy
// evaluator. It does NOT own the HTTP listener directly — that lives
// in proxy.go's Proxy, which is created and started by app bootstrap
// once the default host UUID is known.
type Service struct {
	policies PolicyRepo
	audit    AuditRepo
	logger   *logger.Logger
}

// NewService wires the service. Logger may be nil; the constructor
// substitutes a no-op logger so the service never panics on log calls.
func NewService(policies PolicyRepo, audit AuditRepo, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}
	return &Service{
		policies: policies,
		audit:    audit,
		logger:   log.Named("egress"),
	}
}

// ListPolicies returns every policy for a host, oldest first (the order
// the evaluator scans).
func (s *Service) ListPolicies(ctx context.Context, hostID uuid.UUID) ([]models.EgressPolicy, error) {
	if hostID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	return s.policies.ListByHost(ctx, hostID)
}

// CreatePolicy stores a new allow- or deny-rule. The glob is trimmed
// of surrounding whitespace; lowercase is deferred to evaluation time
// so the stored row reflects the operator's input verbatim.
func (s *Service) CreatePolicy(ctx context.Context, hostID uuid.UUID, in models.CreateEgressPolicyInput) (*models.EgressPolicy, error) {
	if hostID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	glob := strings.TrimSpace(in.TargetGlob)
	if glob == "" {
		return nil, ErrInvalidInput
	}
	p := &models.EgressPolicy{
		HostID:     hostID,
		TargetGlob: glob,
		Allow:      in.Allow,
	}
	if err := s.policies.Create(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// DeletePolicy removes a policy by id.
func (s *Service) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	if id == uuid.Nil {
		return ErrInvalidInput
	}
	return s.policies.Delete(ctx, id)
}

// EvaluateResult is the outcome of a host-vs-policies lookup.
type EvaluateResult struct {
	// Allow is the final decision: true to forward, false to 403.
	Allow bool

	// Matched is the first policy that matched the target. Nil when
	// no policy matched (in which case Allow is true if there are zero
	// policies for the host, false otherwise — see the package doc).
	Matched *models.EgressPolicy

	// PolicyCount is the number of policies the host has in total.
	// The evaluator uses this to distinguish "pass-through" (zero
	// policies) from "default-deny" (≥1 policies, none matched).
	PolicyCount int
}

// Evaluate computes the proxy decision for an outbound request. The
// target is the bare hostname (port stripped). See package doc for the
// match rules.
//
// On a database error this returns the error; the proxy treats that as
// a 502 Bad Gateway so the failure mode is loud, not silently denying
// every request.
func (s *Service) Evaluate(ctx context.Context, hostID uuid.UUID, target string) (EvaluateResult, error) {
	if hostID == uuid.Nil {
		return EvaluateResult{}, ErrInvalidInput
	}
	policies, err := s.policies.ListByHost(ctx, hostID)
	if err != nil {
		return EvaluateResult{}, err
	}
	res := EvaluateResult{PolicyCount: len(policies)}
	if len(policies) == 0 {
		// Pass-through: the operator has not opted in to filtering on
		// this host. The proxy still records latency metrics but does
		// not gate traffic.
		res.Allow = true
		return res, nil
	}
	for i := range policies {
		if models.EgressMatch(policies[i].TargetGlob, target) {
			res.Matched = &policies[i]
			res.Allow = policies[i].Allow
			return res, nil
		}
	}
	// At least one policy exists and none matched — default deny.
	res.Allow = false
	return res, nil
}

// RecordDeny writes one deny event to egress_audit_log. Errors are
// logged at warn level but not returned — the proxy goroutine continues
// serving so a database hiccup never breaks egress evaluation.
func (s *Service) RecordDeny(ctx context.Context, hostID uuid.UUID, target, method string) {
	if hostID == uuid.Nil || s.audit == nil {
		return
	}
	err := s.audit.Insert(ctx, &models.EgressAuditLog{
		HostID:   hostID,
		Target:   target,
		Method:   method,
		Decision: "deny",
	})
	if err != nil {
		s.logger.Warn("egress: record deny failed", "host_id", hostID, "target", target, "error", err)
	}
}

// RecentDenies returns the most-recent N deny events for a host. Used
// by the web UI's recent-denies panel.
func (s *Service) RecentDenies(ctx context.Context, hostID uuid.UUID, limit int) ([]models.EgressAuditLog, error) {
	if hostID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	if s.audit == nil {
		return nil, nil
	}
	return s.audit.ListByHost(ctx, hostID, limit)
}
