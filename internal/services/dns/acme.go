// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dns

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ACMEOrderRequest is the input the proxy module hands to the DNS
// service when it needs a DNS-01 challenge satisfied.
type ACMEOrderRequest struct {
	HostID         uuid.UUID
	ProviderID     uuid.UUID
	Domain         string
	ChallengeValue string
}

// StartOrder writes a new persistent order in the "pending" state.
// The caller invokes ProcessOrder to drive it through the rest of the
// state machine. Splitting the calls lets the proxy module hand the
// challenge value off and continue while DNS work happens in the
// background; reusing the same order id later resumes from whichever
// state it left off in.
func (s *Service) StartOrder(ctx context.Context, req ACMEOrderRequest) (*models.DNSACMEOrder, error) {
	if req.Domain == "" {
		return nil, fmt.Errorf("dns: domain is required")
	}
	if req.ChallengeValue == "" {
		return nil, fmt.Errorf("dns: challenge value is required")
	}

	if _, err := s.providers.GetByID(ctx, req.ProviderID); err != nil {
		return nil, err
	}

	order := &models.DNSACMEOrder{
		ID:             uuid.New(),
		HostID:         req.HostID,
		ProviderID:     req.ProviderID,
		Domain:         req.Domain,
		ChallengeFQDN:  challengeFQDN(req.Domain),
		ChallengeValue: req.ChallengeValue,
		State:          models.ACMEOrderStatePending,
	}
	if err := s.orders.Create(ctx, order); err != nil {
		return nil, err
	}
	s.logAudit(ctx, order.HostID, nil, "start", "acme_order", order.ID, order.Domain, "state=pending")
	return order, nil
}

// ProcessOrder advances an order through its state machine. Idempotent
// — calling ProcessOrder repeatedly on the same id picks up where the
// previous call left off, which is what enables resume-after-restart.
//
// Linear path:
//
//	pending → dropping → propagating → ready
//	ready → completing → completed (after the proxy backend reports
//	    that the CA validated the challenge)
//
// Failure short-circuits to "failed" with the diagnostic in
// error_msg.
func (s *Service) ProcessOrder(ctx context.Context, orderID uuid.UUID) (*models.DNSACMEOrder, error) {
	order, err := s.orders.GetByID(ctx, orderID)
	if err != nil {
		return nil, err
	}

	switch order.State {
	case models.ACMEOrderStatePending:
		return s.dropTXT(ctx, order)
	case models.ACMEOrderStateDropping:
		// A previous restart caught us mid-write. Reconcile by
		// re-attempting the drop — our records table is the source
		// of truth for what we already created.
		return s.dropTXT(ctx, order)
	case models.ACMEOrderStatePropagating:
		return s.checkPropagation(ctx, order)
	case models.ACMEOrderStateReady:
		// Waiting for MarkOrderCompleted from the proxy module.
		return order, nil
	case models.ACMEOrderStateCompleting:
		return s.cleanupTXT(ctx, order)
	case models.ACMEOrderStateCompleted, models.ACMEOrderStateFailed:
		return order, nil
	default:
		return nil, fmt.Errorf("%w: unknown state %q", ErrStateConflict, order.State)
	}
}

// MarkOrderCompleted is called by the proxy backend once the CA
// confirms validation. It moves the order from "ready" to "completing"
// and triggers TXT cleanup.
func (s *Service) MarkOrderCompleted(ctx context.Context, orderID uuid.UUID) (*models.DNSACMEOrder, error) {
	order, err := s.orders.GetByID(ctx, orderID)
	if err != nil {
		return nil, err
	}
	if order.State != models.ACMEOrderStateReady {
		return nil, fmt.Errorf("%w: %s → completing", ErrStateConflict, order.State)
	}
	order.State = models.ACMEOrderStateCompleting
	if err := s.orders.Update(ctx, order); err != nil {
		return nil, err
	}
	s.logAudit(ctx, order.HostID, nil, "mark_completing", "acme_order", order.ID, order.Domain, "")
	return s.cleanupTXT(ctx, order)
}

// FailOrder forces an order into the failed state. Used by the proxy
// module when the CA rejects the challenge so the TXT record is still
// removed.
func (s *Service) FailOrder(ctx context.Context, orderID uuid.UUID, reason string) (*models.DNSACMEOrder, error) {
	order, err := s.orders.GetByID(ctx, orderID)
	if err != nil {
		return nil, err
	}
	if order.State == models.ACMEOrderStateCompleted || order.State == models.ACMEOrderStateFailed {
		return order, nil
	}
	// Best-effort cleanup before marking failed.
	if cleanupErr := s.cleanupTXTRecord(ctx, order); cleanupErr != nil {
		s.logger.Warn("dns: cleanup of failed order TXT failed", "order", order.ID, "error", cleanupErr)
	}

	order.State = models.ACMEOrderStateFailed
	order.ErrorMsg = reason
	now := time.Now()
	order.CompletedAt = &now
	if err := s.orders.Update(ctx, order); err != nil {
		return nil, err
	}
	s.logAudit(ctx, order.HostID, nil, "fail", "acme_order", order.ID, order.Domain, reason)
	return order, nil
}

// ListOrders returns the orders for a host.
func (s *Service) ListOrders(ctx context.Context, hostID uuid.UUID) ([]*models.DNSACMEOrder, error) {
	return s.orders.ListByHost(ctx, hostID)
}

// GetOrder returns one order by ID.
func (s *Service) GetOrder(ctx context.Context, id uuid.UUID) (*models.DNSACMEOrder, error) {
	return s.orders.GetByID(ctx, id)
}

// ResumeInFlightOrders reads the persisted orders that have not
// reached a terminal state and re-runs ProcessOrder on each. The
// wiring layer calls this on boot.
func (s *Service) ResumeInFlightOrders(ctx context.Context) {
	orders, err := s.orders.ListInFlight(ctx)
	if err != nil {
		s.logger.Warn("dns: list in-flight acme orders failed", "error", err)
		return
	}
	if len(orders) == 0 {
		return
	}
	s.logger.Info("dns: resuming in-flight acme orders", "count", len(orders))
	for _, o := range orders {
		if _, err := s.ProcessOrder(ctx, o.ID); err != nil {
			s.logger.Warn("dns: resume acme order failed",
				"order", o.ID, "domain", o.Domain, "error", err)
		}
	}
}

// ============================================================================
// State transitions
// ============================================================================

func (s *Service) dropTXT(ctx context.Context, order *models.DNSACMEOrder) (*models.DNSACMEOrder, error) {
	order.State = models.ACMEOrderStateDropping
	if err := s.orders.Update(ctx, order); err != nil {
		return nil, err
	}
	s.logAudit(ctx, order.HostID, nil, "transition", "acme_order", order.ID, order.Domain, "→ dropping")

	p, plaintext, err := s.loadDecryptedCredentials(ctx, order.ProviderID)
	if err != nil {
		return s.markFailed(ctx, order, fmt.Sprintf("provider load: %v", err))
	}
	plugin, err := s.openPlugin(ctx, p, plaintext)
	if err != nil {
		return s.markFailed(ctx, order, fmt.Sprintf("plugin open: %v", err))
	}
	defer plugin.Close()

	rec := ProviderRecord{
		Name: order.ChallengeFQDN, Type: models.DNSRecordTypeTXT,
		Content: order.ChallengeValue, TTL: 60,
	}
	created, err := plugin.CreateRecord(ctx, rec)
	if err != nil {
		return s.markFailed(ctx, order, fmt.Sprintf("create TXT: %v", err))
	}

	row := &models.DNSRecord{
		ID:               uuid.New(),
		ProviderID:       order.ProviderID,
		HostID:           order.HostID,
		Name:             order.ChallengeFQDN,
		Type:             models.DNSRecordTypeTXT,
		Content:          order.ChallengeValue,
		TTL:              60,
		ProviderRecordID: created.ID,
		ManagedBy:        "acme:" + order.ID.String(),
	}
	if err := s.records.Create(ctx, row); err != nil {
		// Roll back the upstream record so we don't leak it.
		if delErr := plugin.DeleteRecord(ctx, created.ID, rec); delErr != nil &&
			!stderrors.Is(delErr, ErrRecordNotFound) {
			s.logger.Warn("dns: rollback of TXT after persist failure failed", "error", delErr)
		}
		return s.markFailed(ctx, order, fmt.Sprintf("persist TXT: %v", err))
	}

	rid := row.ID
	order.RecordID = &rid
	order.State = models.ACMEOrderStatePropagating
	order.PropagationCheckCount = 0
	if err := s.orders.Update(ctx, order); err != nil {
		return nil, err
	}
	s.logAudit(ctx, order.HostID, nil, "transition", "acme_order", order.ID, order.Domain, "→ propagating")
	return s.checkPropagation(ctx, order)
}

func (s *Service) checkPropagation(ctx context.Context, order *models.DNSACMEOrder) (*models.DNSACMEOrder, error) {
	now := time.Now()
	order.LastCheckAt = &now
	order.PropagationCheckCount++

	values, err := s.resolver.LookupTXT(ctx, order.ChallengeFQDN)
	if err == nil {
		for _, v := range values {
			if strings.TrimSpace(v) == order.ChallengeValue {
				order.State = models.ACMEOrderStateReady
				if uErr := s.orders.Update(ctx, order); uErr != nil {
					return nil, uErr
				}
				s.logAudit(ctx, order.HostID, nil, "transition", "acme_order", order.ID, order.Domain, "→ ready")
				return order, nil
			}
		}
	}

	if s.cfg.PropagationCheckMaxAttempts > 0 &&
		order.PropagationCheckCount >= s.cfg.PropagationCheckMaxAttempts {
		return s.markFailed(ctx, order, ErrPropagationTimeout.Error())
	}
	if uErr := s.orders.Update(ctx, order); uErr != nil {
		return nil, uErr
	}
	return order, nil
}

func (s *Service) cleanupTXT(ctx context.Context, order *models.DNSACMEOrder) (*models.DNSACMEOrder, error) {
	if err := s.cleanupTXTRecord(ctx, order); err != nil {
		s.logger.Warn("dns: cleanup TXT failed; will mark completed anyway",
			"order", order.ID, "error", err)
	}
	now := time.Now()
	order.State = models.ACMEOrderStateCompleted
	order.CompletedAt = &now
	if err := s.orders.Update(ctx, order); err != nil {
		return nil, err
	}
	s.logAudit(ctx, order.HostID, nil, "transition", "acme_order", order.ID, order.Domain, "→ completed")
	return order, nil
}

// cleanupTXTRecord removes the upstream TXT record (if it still
// exists) and the local row. Used by both the happy-path completion
// and the FailOrder cleanup tail.
func (s *Service) cleanupTXTRecord(ctx context.Context, order *models.DNSACMEOrder) error {
	if order.RecordID == nil {
		return nil
	}
	rec, err := s.records.GetByID(ctx, *order.RecordID)
	if err != nil {
		return err
	}
	p, plaintext, err := s.loadDecryptedCredentials(ctx, rec.ProviderID)
	if err != nil {
		return err
	}
	plugin, err := s.openPlugin(ctx, p, plaintext)
	if err != nil {
		return err
	}
	defer plugin.Close()

	pr := ProviderRecord{
		ID: rec.ProviderRecordID, Name: rec.Name, Type: rec.Type,
		Content: rec.Content, TTL: rec.TTL,
	}
	if err := plugin.DeleteRecord(ctx, rec.ProviderRecordID, pr); err != nil &&
		!stderrors.Is(err, ErrRecordNotFound) {
		return err
	}
	return s.records.Delete(ctx, rec.ID)
}

func (s *Service) markFailed(ctx context.Context, order *models.DNSACMEOrder, reason string) (*models.DNSACMEOrder, error) {
	now := time.Now()
	order.State = models.ACMEOrderStateFailed
	order.ErrorMsg = reason
	order.CompletedAt = &now
	if err := s.orders.Update(ctx, order); err != nil {
		return nil, err
	}
	s.logAudit(ctx, order.HostID, nil, "fail", "acme_order", order.ID, order.Domain, reason)
	return order, fmt.Errorf("dns: order failed: %s", reason)
}
