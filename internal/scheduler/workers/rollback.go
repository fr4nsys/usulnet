// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"sync"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	changessvc "github.com/fr4nsys/usulnet/internal/services/changes"
)

// RollbackEventConsumer is the contract the worker requires of the
// rollback service. Satisfied by *rollback.Service in production.
type RollbackEventConsumer interface {
	ExecuteOnEvent(ctx context.Context, e *models.ChangeEvent) (*models.RollbackExecution, error)
}

// ChangeEventSubscriber is the contract the worker requires of the
// changes service. Satisfied by *changes.Service.Subscribe; declaring
// it here lets the worker be unit-tested with a stub.
type ChangeEventSubscriber interface {
	Subscribe(filter changessvc.SubscriptionFilter, bufSize int) *changessvc.Subscription
}

// RollbackEventWorker is a long-running consumer that subscribes to
// the change_events stream and dispatches matching events to the
// rollback service. Unlike the scheduler-registered job workers it
// is not driven by the work queue — it owns a single background
// goroutine started by Start and stopped by Stop.
type RollbackEventWorker struct {
	subscriber ChangeEventSubscriber
	service    RollbackEventConsumer
	logger     *logger.Logger

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// NewRollbackEventWorker constructs a worker.
func NewRollbackEventWorker(subscriber ChangeEventSubscriber, service RollbackEventConsumer, log *logger.Logger) *RollbackEventWorker {
	if log == nil {
		log = logger.Nop()
	}
	return &RollbackEventWorker{
		subscriber: subscriber,
		service:    service,
		logger:     log.Named("rollback-event-worker"),
	}
}

// Start opens the change_events subscription and launches the consumer
// goroutine. Returns immediately. Idempotent: a second Start before
// Stop returns nil without restarting.
func (w *RollbackEventWorker) Start(ctx context.Context) error {
	if w.cancel != nil {
		return nil
	}
	if w.subscriber == nil || w.service == nil {
		w.logger.Warn("rollback event worker: subscriber or service missing; not starting")
		return nil
	}
	consumeCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel

	sub := w.subscriber.Subscribe(changessvc.SubscriptionFilter{
		ResourceType: models.ChangeResourceStack,
		Actions: []string{
			models.ChangeActionDeploy,
			models.ChangeActionRestart,
			models.ChangeActionConfigChange,
			models.ChangeActionStop,
		},
	}, 64)

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		defer sub.Close()
		w.logger.Info("rollback event worker started")
		for {
			select {
			case <-consumeCtx.Done():
				w.logger.Info("rollback event worker stopping")
				return
			case e, ok := <-sub.Events():
				if !ok {
					return
				}
				if e == nil {
					continue
				}
				w.dispatch(consumeCtx, e)
			}
		}
	}()
	return nil
}

// Stop cancels the consumer and waits for the goroutine to exit.
// Safe to call from any goroutine; idempotent.
func (w *RollbackEventWorker) Stop() {
	if w.cancel == nil {
		return
	}
	w.cancel()
	w.cancel = nil
	w.wg.Wait()
}

// dispatch hands a single event off to the rollback service. Failures
// are logged but never crash the worker — one bad event must not stop
// the stream.
func (w *RollbackEventWorker) dispatch(ctx context.Context, e *models.ChangeEvent) {
	defer func() {
		if r := recover(); r != nil {
			w.logger.Error("rollback event worker: panic recovered",
				"panic", r,
				"resource_type", e.ResourceType,
				"action", e.Action,
			)
		}
	}()
	exec, err := w.service.ExecuteOnEvent(ctx, e)
	if err != nil {
		w.logger.Error("rollback event worker: dispatch failed",
			"resource_type", e.ResourceType,
			"action", e.Action,
			"error", err,
		)
		return
	}
	if exec == nil {
		return
	}
	w.logger.Info("rollback fired",
		"execution_id", exec.ID,
		"policy_id", exec.PolicyID,
		"stack_id", exec.StackID,
		"status", exec.Status,
	)
}
