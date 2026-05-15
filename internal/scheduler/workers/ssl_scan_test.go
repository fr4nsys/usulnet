// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

type stubSSLScanService struct {
	scanAllCount    atomic.Int32
	scanTargetCount atomic.Int32
	lastHostID      uuid.UUID
	lastTargetID    uuid.UUID
	scanned         int
	results         []models.SSLScanResult
	scanAllErr      error
	scanTargetErr   error
}

func (s *stubSSLScanService) ScanAll(_ context.Context, hostID uuid.UUID) (int, error) {
	s.scanAllCount.Add(1)
	s.lastHostID = hostID
	return s.scanned, s.scanAllErr
}

func (s *stubSSLScanService) ScanTarget(_ context.Context, id uuid.UUID) ([]models.SSLScanResult, error) {
	s.scanTargetCount.Add(1)
	s.lastTargetID = id
	return s.results, s.scanTargetErr
}

func TestSSLScanWorker_NoService(t *testing.T) {
	w := NewSSLScanWorker(nil, nil)
	if w.Type() != models.JobTypeSSLScan {
		t.Fatalf("type=%v", w.Type())
	}
	_, err := w.Execute(context.Background(), &models.Job{ID: uuid.New(), Type: models.JobTypeSSLScan})
	if err == nil {
		t.Fatal("expected error when no service wired")
	}
}

func TestSSLScanWorker_PerTargetScan(t *testing.T) {
	svc := &stubSSLScanService{
		results: []models.SSLScanResult{{ID: uuid.New()}, {ID: uuid.New()}},
	}
	w := NewSSLScanWorker(svc, nil)
	targetID := uuid.New()
	job := newJob(t, models.JobTypeSSLScan, map[string]any{"target_id": targetID.String()})

	got, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	res, ok := got.(*SSLScanResult)
	if !ok {
		t.Fatalf("result type: %T", got)
	}
	if res.Scope != "target" {
		t.Errorf("scope=%q want target", res.Scope)
	}
	if res.Scanned != 2 {
		t.Errorf("scanned=%d want 2", res.Scanned)
	}
	if svc.scanTargetCount.Load() != 1 || svc.scanAllCount.Load() != 0 {
		t.Errorf("expected one ScanTarget call: target=%d all=%d", svc.scanTargetCount.Load(), svc.scanAllCount.Load())
	}
	if svc.lastTargetID != targetID {
		t.Errorf("last target id mismatch")
	}
}

func TestSSLScanWorker_AllHostsSweep(t *testing.T) {
	svc := &stubSSLScanService{scanned: 12}
	w := NewSSLScanWorker(svc, nil)
	job := newJob(t, models.JobTypeSSLScan, map[string]any{})

	got, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	res := got.(*SSLScanResult)
	if res.Scope != "all" {
		t.Errorf("scope=%q want all", res.Scope)
	}
	if res.Scanned != 12 {
		t.Errorf("scanned=%d want 12", res.Scanned)
	}
	if svc.lastHostID != uuid.Nil {
		t.Errorf("expected nil host id for all-sweep, got %v", svc.lastHostID)
	}
}

func TestSSLScanWorker_HostScopedSweep(t *testing.T) {
	svc := &stubSSLScanService{scanned: 4}
	w := NewSSLScanWorker(svc, nil)
	hostID := uuid.New()
	job := newJob(t, models.JobTypeSSLScan, map[string]any{"host_id": hostID.String()})

	got, err := w.Execute(context.Background(), job)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	res := got.(*SSLScanResult)
	if res.Scope != "host" {
		t.Errorf("scope=%q want host", res.Scope)
	}
	if svc.lastHostID != hostID {
		t.Errorf("host_id mismatch: got %v want %v", svc.lastHostID, hostID)
	}
}

func TestSSLScanWorker_ScanAllError(t *testing.T) {
	svc := &stubSSLScanService{scanned: 3, scanAllErr: errors.New("transient")}
	w := NewSSLScanWorker(svc, nil)
	job := newJob(t, models.JobTypeSSLScan, map[string]any{})
	got, err := w.Execute(context.Background(), job)
	if err == nil {
		t.Fatal("expected error from worker")
	}
	res, ok := got.(*SSLScanResult)
	if !ok {
		t.Fatalf("result still expected to be SSLScanResult, got %T", got)
	}
	if res.Scanned != 3 {
		t.Errorf("partial-success scanned=%d want 3", res.Scanned)
	}
}
